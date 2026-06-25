# Changelog

All notable changes to this project are documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

Two version streams move independently:

- **Application** — versioned via Git tags (`vX.Y.Z`) and tracked by the
  Helm chart's `appVersion`. Drives the published Docker image tag.
- **Chart** — `charts/s3proxy/Chart.yaml` `version`. Bumped independently
  when only chart values/templates change.

## [Unreleased]

### Added

- **Buffered multipart uploads** (opt-in via `S3PROXY_MULTIPART_BUFFER_DIR`).
  s3proxy now accepts the full multipart protocol, buffers each part to a
  node-local disk directory, and on `CompleteMultipartUpload` concatenates the
  parts, encrypts the whole object through the existing AES-256-GCM envelope
  path, and stores it upstream as a **single ciphertext PutObject** — so data at
  rest stays encrypted (unlike `--allow-multipart`, which forwards plaintext).
  - New `internal/multipart` disk-buffer session manager with a background
    sweeper that evicts idle uploads past `S3PROXY_MULTIPART_TTL` (default 24h)
    and reclaims orphaned directories left by a restart.
  - New config knobs: `S3PROXY_MULTIPART_BUFFER_DIR` (enables the mode),
    `S3PROXY_MULTIPART_MAX_SIZE` (assembled-object cap, default/hard cap 5 GiB),
    `S3PROXY_MULTIPART_TTL`. Mutually exclusive with `--allow-multipart`.
  - New metrics: `s3proxy_multipart_uploads_active`,
    `s3proxy_multipart_buffer_bytes`, `s3proxy_multipart_parts_total`,
    `s3proxy_multipart_completed_total`, `s3proxy_multipart_aborted_total`,
    `s3proxy_multipart_assemble_duration_seconds`; Grafana dashboard row and two
    `PrometheusRule` alerts (`S3ProxyMultipartBufferHigh`,
    `S3ProxyMultipartUploadsStuck`).
  - **Constraints (documented):** single-instance / session-affinity required
    (buffers are node-local), assembled object must fit in RAM (~2× peak),
    `ListParts` unsupported. `Complete` acks only after the upstream store
    succeeds, inheriting the single-shot path's durability ordering.
- `ListObjects`/`ListObjectsV2` responses now report the **decrypted plaintext
  size** of each object instead of the larger at-rest ciphertext size. The proxy
  intercepts bucket-level list requests, subtracts the fixed 28-byte encryption
  overhead (12-byte nonce + 16-byte GCM tag) from every `<Size>`, and clamps at 0.
  Bucket sub-resource GETs (acl, versioning, multipart listings, `?versions`, …)
  are still forwarded unchanged.
  - *Known limitation:* objects **not** written through the proxy (legacy
    plaintext, server-side copies, multipart) are reported 28 bytes short (or 0
    after clamp), since a list response carries no per-object encryption metadata.

### Fixed
- **s3cmd `get` compatibility**: intercepted `GetObject` responses now
  carry a `Content-Length` header reflecting the decrypted body size.
  Previously the proxy streamed decrypted objects without a length, so
  Go fell back to chunked transfer encoding and s3cmd 2.4.0 downloaded
  an empty file. Downloads now complete with the correct size.
- **`GetObject` returns the plaintext ETag.** Intercepted GETs decrypt the
  body but previously returned the upstream ETag, which S3 computes over the
  ciphertext at rest. Clients (or SDKs) that validate the body against the
  ETag, or cache by it, saw a mismatch. The proxy now overrides the response
  ETag with `md5(plaintext)` — the ETag S3 would have produced for the
  unencrypted object — computed on the fly from the buffer already held in
  memory, so no stored metadata or migration is needed. Pass-through objects
  (no DEK tag) keep the upstream ETag, which already describes the delivered
  bytes. PUT-response and HEAD ETags still reflect the ciphertext and remain
  a known consistency gap.

### Chart

- **`chart/1.9.3`** — Dashboard usability + Go runtime panels.
  - `Job` picker now defaults to **All** (`allValue: ".*s3proxy.*"`) and
    restricts its dropdown to jobs whose name contains `s3proxy` via the
    template `regex: /s3proxy/`. Multi-release clusters land on a
    populated dashboard out of the box.
  - New **Runtime (Go)** row with six panels backed by the default
    `client_golang` collectors (already registered in s3proxy):
    CPU usage (`process_cpu_seconds_total`), resident memory
    (`process_resident_memory_bytes`), Go heap in use
    (`go_memstats_heap_inuse_bytes` / `_heap_alloc_bytes`), goroutines
    (`go_goroutines`), GC pause quantiles (`go_gc_duration_seconds`),
    and open file descriptors (`process_open_fds`).
- **`chart/1.9.2`** — Fix dashboard panels showing "No data". Every query
  previously filtered on `service="s3proxy"`, but the
  `ServiceMonitor`-applied label is the release-prefixed Service name
  (e.g. `service="cockpit-s3proxy"`), so the filter never matched. Switch
  every panel target and the `instance` variable query to `job=~"$job"`,
  and add a new `Job` template variable (`label_values(http_requests_total, job)`)
  so the dashboard picks up whatever `job` Prometheus actually emits.
- **`chart/1.9.1`** — Make the bundled Grafana dashboard portable. Adds a
  `datasource` template variable (type `datasource`, query `prometheus`)
  so the dashboard binds to whichever Prometheus data source the target
  Grafana exposes instead of hard-coding `uid: prometheus`. The existing
  `instance` variable and every panel target now reference
  `${datasource}`. No values changes; upgrade is in-place.
- **`chart/1.9.0`** — Replace the bundled Grafana dashboard `ConfigMap`
  with a `GrafanaDashboard` CRD (`grafana.integreatly.org/v1beta1`)
  reconciled by grafana-operator. New `grafanaDashboard.instanceSelector`,
  `allowCrossNamespaceImport`, `folder`, `resyncPeriod` knobs; removed
  the sidecar-only `grafanaDashboard.label`. **Breaking** for installs
  that relied on the dashboard sidecar — switch to grafana-operator or
  pin the chart to `1.8.x`.

## [1.8.2] — 2026-05-20

Release tooling pass. No runtime behavior changes — pure CI/CD plumbing,
existing v1.8.1 binary is byte-for-byte equivalent to v1.8.2.

### Added
- **Tag-triggered release pipeline** (`.github/workflows/release.yml`): any
  `v*` tag now produces signed multi-platform release artifacts in addition
  to the existing Docker image. Each release ships static stripped binaries
  for `linux/{amd64,arm64}` and `darwin/{amd64,arm64}`, a per-platform
  CycloneDX SBOM generated by syft against the actual binary, and a
  `SHA256SUMS` file signed with cosign keyless OIDC (verifiable against the
  GitHub Actions issuer). Release is gated on lint, unit tests, generated-code
  drift check, MinIO e2e integration tests, `govulncheck`, and a license
  check that blocks forbidden/restricted/unknown licenses.

## [1.8.1] — 2026-05-20

Patch release. Fixes B2 (and other non-AWS S3-compatible backends)
PutObject failures, and tightens the Helm chart release tag handling.

### Fixed
- **B2 / non-AWS PutObject compatibility** (#34, fixed in #44): the
  AWS SDK was emitting an empty `x-amz-tagging` header on every
  `PutObject` because `Tagging` was always set on the SDK input, even
  when the incoming request carried no tag. Backblaze B2 rejects any
  presence of `x-amz-tagging` with
  `InvalidArgument: Unsupported header 'x-amz-tagging' received for this API call.`
  Tagging is now only forwarded when the client supplied a non-empty
  value, matching the existing pattern used for SSE-C fields.

### CI
- **Helm chart release**: the `helm-push` workflow now honors the
  `version:` field in `Chart.yaml` instead of deriving the chart
  version from the Git tag, and accepts a `chart-v*` tag trigger for
  chart-only releases.

## [1.8.0] — 2026-05-20

Modernization release. Brings the project up to Go 1.26.3, refreshes the
entire dependency tree, replaces the logging backend, ships first-class
observability, hardens the encryption path, and rewrites the documentation
end-to-end.

### Added
- **OpenTelemetry tracing** on every request, correlated with `slog` log
  records via the active span ID (`internal/tracing`).
- **Prometheus `/metrics` endpoint** with request, error, latency and
  cache counters (`internal/monitoring`).
- **Prometheus alert rules and a Grafana dashboard** shipped under
  `deploy/monitoring/` for drop-in observability.
- **`/readyz`** now actively probes the upstream S3 backend instead of
  returning 200 unconditionally; both `/healthz` and `/readyz` bypass the
  throttling middleware so probes survive load spikes.
- **`Config` struct + constructor-based DI** (`internal/config`) replacing
  the previous package-global accessors. Old getters retained as a thin
  facade for callers not yet migrated.
- **PutObject body cap** (`S3PROXY_PUTBODY_MAX`) to bound RAM consumption
  per request.
- **Opt-in startup warning** when `S3PROXY_INSECURE=1` is set, so plaintext
  upstream is never silent.
- **End-to-end MinIO round-trip test** behind the `e2e` build tag,
  including a dedicated test that asserts ciphertext at rest in the
  upstream object.
- **CI pipeline**: unit-test coverage gating, `golangci-lint` workflow,
  Renovate config, vendored dependencies (`-mod=vendor`).
- **`values.schema.json`** (Helm chart): JSON Schema (draft-07) validated
  on `helm install` / `upgrade` / `template` / `lint`. Strict on known
  keys (types, enums, port range, duration patterns, threshold ranges
  0..1 for `prometheusRule.thresholds.highErrorRate`, etc.) but
  permissive on unknown top-level keys so user overrides flow through.
- **Helm chart observability surface**: `ServiceMonitor`, `PrometheusRule`
  and OTLP exporter env wiring exposed via `values.yaml`.

### Changed
- **Go toolchain**: `1.25.x` → **`1.26.3`** (`go.mod`, `go.work`,
  Dockerfile build stage).
- **Logging**: migrated from `sirupsen/logrus` to the standard-library
  `log/slog`. Structured handler, `%w` error wrapping throughout.
- **Encryption**: KEK derivation switched to **HKDF-SHA256**; DEK
  wrapping uses AES-256-GCM-SIV via Tink. Crypto package renamed and
  reorganized for clarity.
- **AWS SDK v2** refreshed across the board: `service/s3` v1.97 → v1.101,
  `config`, `credentials`, `sts`, `smithy-go` v1.25.1, and all transitive
  service clients.
- **OpenTelemetry**, **gRPC** (→ v1.81.1), **grpc-gateway** (→ v2.29.0),
  **prometheus common/procfs**, **tink-go** (→ v2.6.0),
  **golang.org/x/{crypto,net,sys,text}** all updated to current.
- **`koanf` v1 → v2** (`github.com/knadh/koanf/v2`). Removes the
  transitive `go.etcd.io/etcd@v3.5.4` dependency that pinned an old
  `google.golang.org/genproto` and produced ambiguous-import collisions
  against the split `genproto/googleapis/{api,rpc}` modules.
- **HTTP client reuse**: a single shared S3 client is now reused across
  requests with bounded upstream timeouts; redundant per-request MD5
  computation removed from the hot path.
- **Router**: large request/response buffers are explicitly released and
  `runtime.FreeOSMemory()` is triggered between encryption phases to
  keep RSS bounded under bursty PutObject load.
- **Helm chart `1.8.0` → `1.8.1`**: default `--level` switched from `-4`
  (Debug, due to a legacy out-of-range value) to `0` (Info), matching the
  binary's documented default. Verbose logging is now opt-in via
  `args: ["--level=-1"]`.
- **Helm chart `values.yaml`** heavily commented: every key annotated
  with its `S3PROXY_*` mapping, OTLP precedence rules and example
  overrides. Removed a duplicate `extraEnv:` key that silently shadowed
  the first declaration.
- **Helm `Chart.yaml`** enriched with `icon`, `home`, `sources`,
  `keywords` and `maintainers` so the chart renders cleanly on
  Artifact Hub.

### Fixed
- **Upstream checksum headers** are no longer forwarded on transformed
  (encrypted) bodies, eliminating spurious `XAmzContentSHA256Mismatch`
  on the upstream PUT path for some backends.
- **Multipart upload** is blocked by default to prevent accidental
  leakage of unencrypted data.

### Security
- Crypto package hardening pass: package rename, explicit nonce
  handling, KEK rotation via versioned metadata tag
  (`<DEKTAG>-kek-ver`).
- Plaintext-upstream mode (`S3PROXY_INSECURE=1`) now warns loudly at
  startup.

### Docs
- **README rewritten end-to-end**: anchored table of contents, full env
  var matrix, CLI flags, metric/alert tables with real PromQL, OTLP
  tracing notes, security caveats (`S3PROXY_INSECURE`,
  `S3PROXY_DECRYPTION_FALLBACK`, multipart blocked by default), Mermaid
  PUT/GET sequence diagram, Helm chart reference table, development
  workflow.
- **`CONTRIBUTING.md`** refreshed: Go 1.26, vendor mode, `e2e` build
  tag, `golangci-lint` + `govulncheck` invocations, release flow.
- **`AGENTS.md`** added and aligned with current iagen-dev rules
  (API/Auth/product-validation sections, Language section).

## [1.7.2] — 2026-04-23

### Added
- Opt-in `S3PROXY_DECRYPTION_FALLBACK=1` knob that retries failing GetObject
  decryptions with an all-zero KEK, to bridge migrations away from
  legacy/unencrypted objects.

## [1.7.1] — 2026-04-22

### Fixed
- Vulnerable dependency upgrades.
- Router now passes its KEK to object handlers (previously a stale package
  global was used in some paths).
- Healthcheck endpoints (`/healthz`, `/readyz`) bypass the throttling
  middleware so probes do not get rejected under load.
- Reduced memory copies on the object body hot path.

### Added
- `.github/workflows/golangci-lint.yml` runs the linter on every PR.
- Linter configuration `.golangci.yml` with input validation rules.

## [1.7.0] — 2025-10-30

### Added
- TLS certificate handling improvements.
- Project documentation set (`AGENTS.md`, expanded `CONTRIBUTING.md`).

### Changed
- Go toolchain upgrade.
- Dependency refresh.

## [1.6.0] — 2025-07-23

### Changed
- Bumped to Go 1.24.5.
- Helm chart version aligned with app version.

## [1.5.2] — 2025-07-22

### Changed
- Helm chart `args` defaults adjusted.

## [1.5.1] — 2025-07-22

### Fixed
- Helm chart `args` rendering bug.

## [1.5.0] — 2025-07-22

### Added
- Forward-flow request logging including client-cancel and "client closed
  connection" events.
- `context.WithoutCancel` propagation on PUT to avoid aborting an in-flight
  encryption stream when the client disconnects.

### Fixed
- Special-character handling in forwarded URLs.
- Checksum handling on the upstream PUT path.

## [1.4.0] — 2024-11-14

Initial published release line after the fork from
[edgelesssys/constellation](https://github.com/edgelesssys/constellation).
Earlier `v1.0.0` … `v1.3.0` tags exist for the pre-fork lineage; see the Git
log for details.

[Unreleased]: https://github.com/Intrinsec/s3proxy/compare/v1.8.2...HEAD
[1.8.2]: https://github.com/Intrinsec/s3proxy/compare/v1.8.1...v1.8.2
[1.8.1]: https://github.com/Intrinsec/s3proxy/compare/v1.8.0...v1.8.1
[1.8.0]: https://github.com/Intrinsec/s3proxy/compare/v1.7.2...v1.8.0
[1.7.2]: https://github.com/Intrinsec/s3proxy/compare/v1.7.1...v1.7.2
[1.7.1]: https://github.com/Intrinsec/s3proxy/compare/v1.7.0...v1.7.1
[1.7.0]: https://github.com/Intrinsec/s3proxy/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/Intrinsec/s3proxy/compare/v1.5.2...v1.6.0
[1.5.2]: https://github.com/Intrinsec/s3proxy/compare/v1.5.1...v1.5.2
[1.5.1]: https://github.com/Intrinsec/s3proxy/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/Intrinsec/s3proxy/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/Intrinsec/s3proxy/releases/tag/v1.4.0
