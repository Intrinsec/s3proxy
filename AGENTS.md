# AGENTS.md

Rules for AI-assisted development on this repository.

Project: `s3proxy` — transparent S3 proxy that encrypts PutObject bodies with AES-256-GCM
and decrypts GetObject responses using a KEK derived from configuration. Speaks the S3 HTTP
wire protocol on the client side and forwards signed requests to AWS S3 on the backend.

Tier: **C (shared, critical)**.

## Language

All code comments, documentation, commit messages, ADRs, and inline doc strings must be written
in English, regardless of the team's spoken language.
User-facing strings and UI copy are exempt — use the appropriate language for the audience.

## Code Quality

After modifying any Go file, run `golangci-lint run ./...` before marking work complete.
Fix all lint errors and re-run until the linter exits clean.
Do not consider a task done while lint errors remain.
`gofmt` formatting is non-negotiable — zero diff allowed. Run `gofmt -w .` if in doubt.

## Vulnerability Scanning

After modifying `go.mod` or `go.sum`, run `govulncheck ./...` before marking work complete
(use `govulncheck -mod=vendor ./...` if a `vendor/` directory is present).
Fix called vulnerabilities: `go get <module>@<fixed>`, `go mod tidy`, re-vendor if applicable,
then re-run until clean. Imported-only vulnerabilities must be reported to the user.
Do not consider a task done while called vulnerabilities remain.

## Dependency Management

After any change to `go.mod`, run `go mod tidy` then `go mod vendor`.
The `vendor/` directory must be committed to Git — it must not be gitignored.
Use `go build -mod=vendor` in CI. Never run `go get` inside a Docker build without
updating the vendor directory afterward.

## Testing & Architecture

Follow Red-Green-Refactor: write a failing test before any implementation code.
Use dependency injection via constructors — no package-level globals, no `init()` side effects.
Define small, focused interfaces at the call site. Never inject a concrete type where an
interface suffices. Push all I/O (DB, HTTP, filesystem) to the edges; keep domain logic
free of side effects and testable without external services.

## Project Layout

Layered layout for non-trivial Go services. `internal/` is a compiler-enforced
boundary — packages inside cannot be imported from outside the module, which
keeps domain logic private by construction.

```
cmd/<binary>/main.go        # entrypoint + dependency wiring
internal/domain/            # entities, value objects, core interfaces
internal/usecase/           # business logic, orchestrates domain + ports
internal/repository/        # DB / external-API implementations
internal/delivery/http/     # HTTP handlers, DTOs, middleware
pkg/                        # only if code is intentionally exported
```

Two layers (handler + store) are acceptable for small CRUD services; use the
full four-layer split when domain complexity justifies it. Do not add
`usecase` passthrough files that only forward calls.

Tests live next to the code (`foo.go` + `foo_test.go`). Cross-package
integration tests go under `test/` at the module root.

## Dependency Injection

Choose a DI mechanism once and keep it uniform across the service.

| Mechanism | Use when | Trade-off |
|-----------|----------|-----------|
| Manual (explicit constructors in `main.go`) | Default for most services | Verbose when the graph grows past ~50 wiring lines |
| Google Wire (compile-time codegen) | `main.go` wiring becomes unreadable or diverges per environment | Extra build step, generated code to keep in sync |
| Uber Dig (runtime reflection) | Avoid | Errors surface at runtime, undermines Go's compile-time safety |

Default is manual. Switch to Wire only when manual wiring is demonstrably
unmaintainable. Do not adopt Dig.

## Error Handling

Follow the "crash early, let the orchestrator recover" model:
- Transient errors (network, timeout): retry 1–3 times with exponential backoff, log each
  retry at WARN. If retries exhausted, log at ERROR with full context and exit non-zero.
- Structural errors (missing config, unavailable critical dependency): crash immediately
  at startup. No retry.
Never swallow errors silently. Every error must include enough context for diagnosis
without accessing the running pod.

## Local Development

`docker compose up` must start the complete local environment including all dependencies
(MinIO for S3 backend, mock KMS if applicable). No manual setup steps should be required.
The dev compose file must not require access to the staging cluster or production secrets.

## Logging

Use `slog` (stdlib) with a JSON handler — never `fmt.Println` or `log.Printf`.
Every log entry must include: `timestamp`, `level`, `msg`, `service`, `trace_id` (from span
context when available), `request_id`, and any domain-relevant identifiers.
Log at WARN for each retry; ERROR for terminal failures with full context (service called,
duration, retry count, error chain). Logs go to stdout only — shipped to Loki via Promtail.
Never log secret values, tokens, or credentials (including the KEK, DEKs, AWS credentials,
or `x-amz-server-side-encryption-customer-key*` headers), even at DEBUG level.

Note: the current codebase uses `sirupsen/logrus`. Migration to `slog` is planned; new code
should target `slog` when feasible.

## Metrics

Every service exposes a `/metrics` endpoint using `prometheus/client_golang`.
Mandatory RED metrics for any HTTP or gRPC service:
- `http_requests_total` (counter, labels: method, path, status_code)
- `http_request_duration_seconds` (histogram, labels: method, path) — cover p50/p95/p99
- `errors_total` (counter, labels: type)
- `service_crashes_total` (counter) — increment on any non-zero exit

Domain-specific business metrics for this service:
- `s3proxy_encrypt_duration_seconds` (histogram) — PutObject encryption time
- `s3proxy_decrypt_duration_seconds` (histogram) — GetObject decryption time
- `s3proxy_upstream_errors_total` (counter, labels: operation, code) — AWS S3 upstream failures
- `s3proxy_throttled_total` (counter) — requests rejected by the throttling middleware

Metrics are collected by VictoriaMetrics.

## Alerting

Define Alertmanager rules in `monitoring/alerts/s3proxy.yaml`, versioned in this repository.
Mandatory alerts for every service:
- `HighErrorRate`: error rate > 5% over 5 minutes
- `HighLatency`: p95 latency > 1s over 5 minutes
- `ServiceDown`: `up == 0`
- `HighCrashRate`: any crash in the last 5 minutes
Thresholds must be reviewed against the service's SLA and adjusted accordingly.

## Grafana Dashboards

Provision a dashboard in `monitoring/dashboards/s3proxy.json` (version-controlled,
deployed via Grafana provisioning). It must cover:
- Request rate (RPS) per operation (GetObject / PutObject / forwarded / blocked multipart)
- Error rate per operation and status code
- p50 / p95 / p99 latency histograms (total + encrypt + decrypt + upstream)
- Crash rate
- Throttling rejection rate
Dashboard JSON is committed to the repository and deployed with the monitoring stack.

## Distributed Tracing

This service sits between a client and AWS S3. Instrument with OpenTelemetry (OTLP exporter).
Propagate trace context on every outbound call to S3 (W3C TraceContext headers).
Inject `trace_id` from the span context into every log entry.
Configure the OTLP endpoint via `OTEL_EXPORTER_OTLP_ENDPOINT`.
Traces are collected by the Grafana / VictoriaMetrics / Loki stack.

## Secrets Management

All secrets are sourced from HashiCorp Vault. For this service:
- `S3PROXY_ENCRYPT_KEY` (KEK seed) — from Vault KV, never hardcoded or in plain env files.
- AWS credentials — from Vault AWS secrets engine (dynamic creds) or IRSA when running on EKS.
- TLS certificates (`s3proxy.crt`, `s3proxy.key`) — from Vault PKI engine with short-lived certs.

No secrets in source code, environment variable files, or versioned config files.
Applications retrieve secrets at startup via the Vault API or Vault Agent sidecar injection.
Never log secret values, even at DEBUG level.

## SBOM

Generate a Software Bill of Materials for each release in CycloneDX format using `syft`.
Attach the SBOM to the release artifact alongside the Docker image.
Run `grype <image>` on the SBOM to detect vulnerabilities in the final image before publishing.

## Dependency Upgrade Policy

Configure Renovate on this repository:
- Auto-merge security patches if all CI checks pass.
- Human review required for minor and major version bumps.
- Group updates by category (dev deps, prod deps, build tools).

Cadence:
- Critical CVE (CVSS ≥ 9.0): patch within 48 hours.
- High CVE (CVSS ≥ 7.0): patch within one sprint.
- Minor patches: monthly.
- Minor versions: quarterly with review.
- Major versions: planned, one at a time.

Never let a dependency fall more than 2 minor versions behind.
