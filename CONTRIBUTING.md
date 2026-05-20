# Contributing to S3Proxy

Thanks for considering a contribution! This document covers the local dev loop,
the linting and security toolchain, and the conventions used in this repo.

## Setup

The repo ships with a `vendor/` tree, so a working Go 1.26 toolchain is all you
need locally. The instructions below use a containerised Go to keep host tooling
isolated, but a native install works the same.

### Option A — containerised Go (VSCode + Docker)

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/Intrinsec/s3proxy.git
    cd s3proxy
    ```
2.  **Run a Go dev container:**
    ```bash
    docker run --rm -p 4433:4433 -v "$PWD":/app -w /app -it golang:1.26 bash
    ```
    Mounts the working tree at `/app` and exposes the proxy port. Inside the
    container, `go test`, `go build`, etc. run as usual.
3.  **Attach VSCode to the container:**
    -   Command palette: *"Dev Containers: Attach to Running Container…"*
    -   Select the `golang` container, open `/app`.
4.  **Run the proxy locally:**
    ```bash
    export AWS_ACCESS_KEY_ID=…
    export AWS_SECRET_ACCESS_KEY=…
    export S3PROXY_HOST=s3.fr-par.scw.cloud
    export S3PROXY_ENCRYPT_KEY="$(openssl rand -base64 32)"
    go run ./s3proxy/cmd --no-tls --level=-1
    ```
    `--level=-1` enables Debug logging; defaults to Info.

### Option B — native Go

```bash
git clone https://github.com/Intrinsec/s3proxy.git
cd s3proxy
go test ./...                                            # unit tests
go test -tags e2e ./...                                  # + MinIO roundtrip
go run ./s3proxy/cmd --no-tls --level=-1
```

### End-to-end smoke test

With the proxy running on `:4433` and `aws` configured against it:

```bash
echo "test" > test.txt
aws --endpoint-url http://localhost:4433 s3 cp ./test.txt s3://bucket/
aws --endpoint-url http://localhost:4433 s3 cp s3://bucket/test.txt ./test.txt
aws --endpoint-url http://localhost:4433 s3 rm s3://bucket/test.txt
```

## Linting

`golangci-lint` aggregates the linters configured in `.golangci.yml`:

- `bodyclose` — unclosed HTTP response bodies
- `gocognit` / `gocyclo` — function complexity
- `goconst` — repeated strings that should be constants
- `gosec` — security-focused checks
- `misspell` — common English misspellings
- `revive` / `staticcheck` — general code quality

Run:

```bash
golangci-lint run
```

CI runs the same configuration in `.github/workflows/golangci-lint.yml`.

## Vulnerability scanning

```bash
govulncheck ./...
```

CI runs `govulncheck` against the vendored dependencies; PRs that introduce
known-vulnerable code paths will fail.

## Tests

- **Unit tests** — `go test -race ./...` (matches CI).
- **E2E (MinIO roundtrip)** — `go test -tags e2e ./...`. The `e2e` build tag
  gates a test that spins up MinIO and exercises a full encrypt/decrypt
  roundtrip; see `s3proxy/e2e/`.

## Helm chart

```bash
helm lint charts/s3proxy
helm template charts/s3proxy
```

When you change `values.yaml` defaults, render the chart with both the default
values and a representative override (e.g. `serviceMonitor.enabled=true`) to
confirm the templates still produce valid Kubernetes manifests.

## Conventions

- **Commit messages** — Conventional Commits (`feat:`, `fix:`, `chore:`,
  `docs:`, `refactor:`, `test:`, `ci:`, `perf:`). Use the scope to point at the
  affected area (e.g. `fix(router):`, `chore(chart):`).
- **Repo coding rules** — see [AGENTS.md](AGENTS.md) for the project-wide
  conventions (error wrapping, slog field names, package naming, …) that are
  enforced both by review and by `golangci-lint`.
- **Sign-off / co-authors** — co-authoring tools and trailers are accepted; do
  not commit credentials or large binaries (the repo ignore list catches the
  obvious cases but a quick `git status` before staging never hurts).

## Releasing

- The Go binary version is exposed via the Docker image tag, built by
  `.github/workflows/docker-build-push.yml` on tag pushes.
- The Helm chart is published to GHCR as an OCI artifact by
  `.github/workflows/helm-push.yml`. The `version:` field in
  `charts/s3proxy/Chart.yaml` is the chart version; `appVersion:` tracks the
  application release.
- User-facing changes go into [CHANGELOG.md](CHANGELOG.md) under the matching
  release header.
