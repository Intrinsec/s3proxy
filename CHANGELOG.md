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

### Chart

#### Changed
- `1.8.0` → `1.8.1`: default `--level` switched from `-4` (Debug, due to a
  legacy out-of-range value) to `0` (Info), matching the binary's documented
  default. Verbose logging is now opt-in via `args: ["--level=-1"]`.
- `values.yaml` heavily commented: every key annotated with its
  `S3PROXY_*` mapping, OTLP precedence rules and example overrides. Removed a
  duplicate `extraEnv:` key that silently shadowed the first declaration.
- `Chart.yaml` enriched with `icon`, `home`, `sources`, `keywords` and
  `maintainers` so the chart renders cleanly on Artifact Hub.

### Docs
- README rewritten end-to-end: anchored table of contents, full env var matrix,
  CLI flags, metric/alert tables with real PromQL, OTLP tracing notes,
  security caveats (`S3PROXY_INSECURE`, `S3PROXY_DECRYPTION_FALLBACK`,
  multipart blocked by default), Mermaid PUT/GET sequence diagram, Helm chart
  reference table, development workflow.
- `CONTRIBUTING.md` refreshed: Go 1.26, vendor mode, `e2e` build tag,
  `golangci-lint` + `govulncheck` invocations, release flow.

### Performance
- `internal/router`: release large request/response buffers and trigger
  `runtime.FreeOSMemory()` between encryption phases to keep RSS bounded under
  bursty PutObject load (commit `359168a`).

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

[Unreleased]: https://github.com/Intrinsec/s3proxy/compare/v1.7.2...HEAD
[1.7.2]: https://github.com/Intrinsec/s3proxy/compare/v1.7.1...v1.7.2
[1.7.1]: https://github.com/Intrinsec/s3proxy/compare/v1.7.0...v1.7.1
[1.7.0]: https://github.com/Intrinsec/s3proxy/compare/v1.6.0...v1.7.0
[1.6.0]: https://github.com/Intrinsec/s3proxy/compare/v1.5.2...v1.6.0
[1.5.2]: https://github.com/Intrinsec/s3proxy/compare/v1.5.1...v1.5.2
[1.5.1]: https://github.com/Intrinsec/s3proxy/compare/v1.5.0...v1.5.1
[1.5.0]: https://github.com/Intrinsec/s3proxy/compare/v1.4.0...v1.5.0
[1.4.0]: https://github.com/Intrinsec/s3proxy/releases/tag/v1.4.0
