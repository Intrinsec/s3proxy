# AGENTS.md

Rules for AI-assisted development on this repository.

Project: `s3proxy` — transparent S3 proxy that encrypts PutObject bodies with AES-256-GCM
and decrypts GetObject responses using a KEK derived from configuration. Speaks the S3 HTTP
wire protocol on the client side and forwards signed requests to AWS S3 on the backend.

Tier: **C (shared, critical)**.

## Language

Default agent response: English, even if user writes French.
French response only when user explicitly asks French.

Caveman compression **mandatory** for all conversational responses (default level: `full`).
Code blocks, commit messages, PR descriptions, security warnings, irreversible-action
confirmations stay normal prose (Caveman auto-clarity rules). Do not disable Caveman unless
user says "stop caveman" or "normal mode".

HARD RULE: all code, comments, identifiers, doc strings, commit messages, ADRs, technical
docs in English — every project type, regardless of team spoken language.
User-facing strings + UI copy exempt — match audience language.

## Workflow Skills (mandatory)

Every agent session in this repo must load + apply these skill packs:

- **superpowers** — process discipline (`brainstorming`, `writing-plans`, `executing-plans`,
  `test-driven-development`, `systematic-debugging`, `verification-before-completion`,
  `requesting-code-review`).
- **caveman** — response compression (see Language section).

Pack missing? Install per iagen-dev `INSTALL.md` before work.

### Session start gate

Before any response, clarification, repository inspection, shell command, or file edit:
run `superpowers:using-superpowers` first, then run `caveman` so compression is active
for every response. Use `superpowers:using-superpowers` to decide which additional
skills apply, then follow the selected skill workflows.

### Plan-writing mandatory before non-trivial implementation

Any feature, refactor, bugfix touching more than one function, or agent cannot reason in
one pass:

1. Run `superpowers:brainstorming` — clarify intent + requirements.
2. Run `superpowers:writing-plans` — persist plan at `docs/superpowers/plans/<short-name>.md`
   (commit to git).
3. Execute via `superpowers:executing-plans` (single-session) or
   `superpowers:subagent-driven-development` (parallelisable steps).
4. Gate completion with `superpowers:verification-before-completion` — no "done" claim
   without evidence (test output, lint output, build output).

**Trivial edits exception:** typos, single-line config tweaks, self-evident one-liners
skip steps 1–3 but still verify before claiming done.

### Bug fixes go through systematic-debugging

Any bug, failing test, unexpected behaviour → `superpowers:systematic-debugging` first.
No symptom patching without root cause.

### Code review before merge

Before merge or PR for non-trivial work: run `superpowers:requesting-code-review`.

## Code Quality

After modifying any Go file: run `golangci-lint run ./...` before marking work complete.
Fix all lint errors, re-run until clean. Lint errors = task not done.
`gofmt` non-negotiable — zero diff allowed. Run `gofmt -w .` if in doubt.

## Vulnerability Scanning

After modifying `go.mod` / `go.sum`: run `govulncheck ./...` before marking work complete.
(`vendor/` is honored via `GOFLAGS=-mod=vendor` in env; govulncheck has no `-mod` CLI flag.)
Fix called vulns: `go get <module>@<fixed>`, `go mod tidy`, re-vendor if applicable,
re-run until clean. Imported-only vulns: report to user.
Called vulns remaining = task not done.

## Dependency Management

Any `go.mod` change → run `go mod tidy` then `go mod vendor`.
`vendor/` must be committed — never gitignored.
CI uses `go build -mod=vendor`. Never `go get` inside Docker build without re-vendoring after.

## Testing & Architecture

Red-Green-Refactor: failing test first, then implementation.
DI via constructors — no package-level globals, no `init()` side effects.
Small, focused interfaces at call site. Never inject concrete type where interface suffices.
Push I/O (DB, HTTP, filesystem) to edges. Domain logic side-effect-free, testable without
external services.

## Project Layout

Layered layout for non-trivial Go services. `internal/` = compiler-enforced boundary —
packages inside not importable outside module → domain logic private by construction.

```
cmd/<binary>/main.go        # entrypoint + dependency wiring
internal/domain/            # entities, value objects, core interfaces
internal/usecase/           # business logic, orchestrates domain + ports
internal/repository/        # DB / external-API implementations
internal/delivery/http/     # HTTP handlers, DTOs, middleware
pkg/                        # only if code is intentionally exported
```

Two layers (handler + store) OK for small CRUD. Full four-layer split when domain
complexity justifies. No `usecase` passthrough files that forward calls.

Tests next to code (`foo.go` + `foo_test.go`). Cross-package integration tests under
`test/` at module root.

## Dependency Injection

Pick one DI mechanism, keep uniform across service.

| Mechanism | Use when | Trade-off |
|-----------|----------|-----------|
| Manual (explicit constructors in `main.go`) | Default for most services | Verbose when graph grows past ~50 wiring lines |
| Google Wire (compile-time codegen) | `main.go` wiring unreadable or diverges per env | Extra build step, generated code to sync |
| Uber Dig (runtime reflection) | Avoid | Errors surface at runtime, undermines Go compile-time safety |

Default = manual. Switch to Wire only if manual wiring demonstrably unmaintainable.
Do not adopt Dig.

## API Design (REST)

OpenAPI 3.x spec at `api/openapi.yaml` before implementing handlers.
JSON for request/response bodies. HTTP status codes match semantics:
200 OK, 201 Created, 400 Bad Request, 401 Unauthorized, 403 Forbidden, 404 Not Found,
422 Unprocessable Entity, 500 Internal Server Error.
Middleware order: recover → logging → metrics → auth → handler.

**Spec-to-code workflow:**

| Workflow | Tooling | Use when |
|----------|---------|----------|
| Schema-first | `oapi-codegen` generates Go server stubs from `api/openapi.yaml` | Public API, contract negotiated with consumers, multiple backends must match |
| Code-first | `huma` generates OpenAPI from annotated Go structs | Internal API iterating fast with implementation |

Both valid. Spec = single source of truth consumed by frontend. Pick one per service,
don't mix.

**Frontend client generation:** Nuxt frontend consuming this API → generate TS types +
fetch client from same spec via `openapi-typescript` + `openapi-fetch`. Commit generated
file, fail CI on diff from fresh regeneration.

**s3proxy exception:** this service implements the AWS S3 HTTP wire protocol on the
client side, not a custom REST API. The "spec" is the S3 API itself; clients are
existing AWS SDKs. The OpenAPI / spec-to-code requirement above does not apply for the
S3-facing surface — only for any management or admin endpoints exposed alongside it.

## Error Handling

"Crash early, let orchestrator recover" model:
- Transient errors (network, timeout): retry 1–3× exponential backoff, log each retry
  at WARN. Retries exhausted → log ERROR with full context, exit non-zero.
- Structural errors (missing config, unavailable critical dep): crash immediately at
  startup. No retry.
Never swallow errors silently. Every error includes enough context for diagnosis
without accessing running pod.

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

Alertmanager rules in `monitoring/alerts/<service>.yaml`, versioned in repo.
Mandatory alerts every service:
- `HighErrorRate`: error rate > 5% over 5 min
- `HighLatency`: p95 latency > 1s over 5 min
- `ServiceDown`: `up == 0`
- `HighCrashRate`: any crash in last 5 min
Review thresholds against service SLA, adjust accordingly.

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

## Authentication

Authentication uses Keycloak with OAuth 2.0 / OIDC.
- Access tokens stored in HttpOnly, Secure, SameSite=Strict cookies — never JS or
  localStorage. Token readable in JS turns any XSS into identity compromise.
- CLI / agent access: Keycloak offline token or service account with restricted scopes.
- No long-lived static tokens. All tokens must be rotatable and revocable.
- Validate JWT signatures against Keycloak JWKS endpoint on every request.
- Never log tokens or authorization headers.

Note: the S3-protocol surface authenticates clients via AWS SigV4 against
credentials proxied/configured locally — this section governs any management,
admin, or operator-facing endpoints exposed alongside the S3 surface.

## Secrets Management

All secrets are sourced from HashiCorp Vault. For this service:
- `S3PROXY_ENCRYPT_KEY` (KEK seed) — from Vault KV, never hardcoded or in plain env files.
- AWS credentials — from Vault AWS secrets engine (dynamic creds) or IRSA when running on EKS.
- TLS certificates (`s3proxy.crt`, `s3proxy.key`) — from Vault PKI engine with short-lived certs.

No secrets in source code, environment variable files, or versioned config files.
Applications retrieve secrets at startup via the Vault API or Vault Agent sidecar injection.
Never log secret values, even at DEBUG level.

## SBOM

Generate Software Bill of Materials per release in CycloneDX format via `syft`.
Attach SBOM to release artifact alongside Docker image.
Run `grype <image>` on SBOM to detect vulns in final image before publishing.

## Dependency Upgrade Policy

Configure Renovate on repo:
- Auto-merge security patches if all CI checks pass.
- Human review required for minor + major version bumps.
- Group updates by category (dev deps, prod deps, build tools).

Cadence:
- Critical CVE (CVSS ≥ 9.0): patch within 48h.
- High CVE (CVSS ≥ 7.0): patch within one sprint.
- Minor patches: monthly.
- Minor versions: quarterly with review.
- Major versions: planned, one at a time.

Never let a dep fall more than 2 minor versions behind.

## Product Validation Workflow

This project opted out of the iagen-dev product-validation skills (`dev-product-shape`,
`dev-product-review`, `dev-arch-review`). Re-enable later via `/dev-update-project`
when the scope grows past a single-file change set or moves toward greenfield work.
