# S3Proxy by Intrinsec (forked from [constellation](https://github.com/edgelesssys/constellation))

**S3Proxy** is a Docker image that enables seamless encryption (AES-256-GCM) for all communications with an S3 provider, adding an extra layer of security. The proxy intercepts PUT and GET requests, encrypting data before sending it to S3 and decrypting it upon retrieval.

## Features

- **Automatic encryption** for all PUT requests before storage on S3
- **Transparent decryption** of GET requests when retrieving data from S3
- **Easy setup**: run the proxy and direct your HTTP requests through it.

## Usage (Docker)

```bash
docker run ghcr.io/intrinsec/s3proxy --rm -p 80:4433 -e AWS_ACCESS_KEY_ID="XXX" -e AWS_SECRET_ACCESS_KEY="XXX" -e S3PROXY_ENCRYPT_KEY="GENERATE_A_RANDOM_STRING" -e S3PROXY_HOST="s3.fr-par.scw.cloud" -e S3PROXY_DEKTAG_NAME="isec"
```

## Usage (Kubernetes - Helm)

```bash
helm upgrade --install s3proxy oci://ghcr.io/intrinsec/s3proxy/charts/s3proxy
```

## Contribution

[CONTRIBUTING](CONTRIBUTING.md)

## Technical Details

### Architecture

S3Proxy acts as an intermediary, intercepting S3 PUT and GET requests to provide transparent encryption/decryption.

- **PUT Object Flow:**
  1. S3Proxy intercepts a PUT request.
  2. A random Data Encryption Key (DEK) is generated.
  3. The object's data is encrypted using AES-256-GCM with this DEK.
  4. The DEK itself is encrypted using a Key Encryption Key (KEK), derived from the `S3PROXY_ENCRYPT_KEY` environment variable.
  5. This encrypted DEK is stored as a metadata tag (named `isec` by default, configurable via `S3PROXY_DEKTAG_NAME`) on the S3 object.
  6. The encrypted data is then forwarded to the S3 provider.

- **GET Object Flow:**
  1. S3Proxy intercepts a GET request.
  2. It retrieves the encrypted data and the encrypted DEK from the S3 object's metadata.
  3. The encrypted DEK is decrypted using the KEK.
  4. The object's data is decrypted using the recovered DEK.
  5. The plaintext data is returned to the client.

Key components and their roles:
- `cmd/main.go`: The entry point of the application, responsible for parsing command-line flags, setting up structured logging (`log/slog`), loading configuration (`koanf`), bootstrapping OpenTelemetry tracing, and starting the HTTP server.
- `internal/router`: Implements the core request interception and routing logic. It dispatches requests to appropriate handlers based on the HTTP method and URL path, distinguishing between `GetObject`, `PutObject`, and other S3 operations. It also handles health endpoints (`/healthz`, `/readyz`) and applies optional request throttling. All AWS requests are re-signed before being forwarded to the S3 backend to comply with AWS signature requirements.
- `internal/s3`: Provides a thin wrapper around the AWS S3 client (`github.com/aws/aws-sdk-go-v2/service/s3`) for seamless interaction with the S3 backend. It includes custom middleware to capture raw HTTP responses, which is crucial for robust error handling.
- `internal/cryptoutil`: Contains the cryptographic functions for encryption and decryption. It utilizes `github.com/tink-crypto/tink-go/v2` for AES-256-GCM for data encryption and Key Wrapping (KWP) for DEK encryption. The KEK is derived from `S3PROXY_ENCRYPT_KEY` using HKDF-SHA256.
- `internal/monitoring`: Exposes a Prometheus `/metrics` endpoint with request counters, latency histograms and in-flight gauges used by the shipped Grafana dashboard and alert rules.
- `internal/tracing`: Sets up an OTLP/HTTP trace exporter and a `slog` handler that injects the active trace/span IDs into every log record, making logs and traces directly correlatable.

By default, multipart upload requests (`CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload`) are blocked for enhanced security, but this behavior can be optionally configured to forward these requests via a command-line flag.

### Main Libraries Used

- **Configuration:** [`github.com/knadh/koanf`](https://github.com/knadh/koanf) for flexible configuration loading from environment variables (e.g., `S3PROXY_HOST` maps to `s3proxy.host`).
- **Logging:** Go standard library [`log/slog`](https://pkg.go.dev/log/slog) for structured JSON logging, wrapped to inject OpenTelemetry trace/span IDs into every record.
- **AWS SDK:** [`github.com/aws/aws-sdk-go-v2/service/s3`](https://github.com/aws/aws-sdk-go-v2/service/s3) for all interactions with the S3 backend.
- **Cryptography:** [`github.com/tink-crypto/tink-go/v2`](https://github.com/tink-crypto/tink-go) for robust and secure cryptographic operations (AES-256-GCM and Key Wrapping).
- **Metrics:** [`github.com/prometheus/client_golang`](https://github.com/prometheus/client_golang) exposing request/latency/in-flight metrics on `/metrics`.
- **Tracing:** [`go.opentelemetry.io/otel`](https://github.com/open-telemetry/opentelemetry-go) with the OTLP/HTTP exporter for distributed tracing.
- **UUID Generation:** [`github.com/google/uuid`](https://github.com/google/uuid) for generating unique request identifiers.

### Deployment (Helm Chart)

S3Proxy can be easily deployed on Kubernetes using its official Helm chart located at `charts/s3proxy`. The chart provides a flexible way to configure and manage S3Proxy instances.

Key configurable parameters via `values.yaml` include:
- `replicaCount`: Number of S3Proxy instances to run.
- `deploymentStrategy`: Kubernetes Deployment rollout strategy (`RollingUpdate` by default, or `Recreate`).
- `image`: Docker image repository and tag for S3Proxy.
- `args`: Command-line arguments passed to the S3Proxy binary. Common flags: `--no-tls` (disable TLS), `--level` for slog verbosity (`-1`=Debug, `0`=Info — default, `1`=Warn, `2`=Error), `--allow-multipart` (WARNING: forwards multipart uploads unencrypted), `--region`, `--ip`, `--cert`.
- `cert`: Configuration for CertManager integration to automatically provision TLS certificates.
- `config`: Settings for the S3 backend, mapped to `S3PROXY_*` env vars on the container:
  - `host` → `S3PROXY_HOST` (upstream S3 endpoint, required)
  - `throttling` → `S3PROXY_THROTTLING_REQUESTSMAX` (cap on **concurrent in-flight requests**, not RPS; `0` or unset disables it)
  - `accessKey` / `secretKey` → AWS credentials (plumbed via the `s3proxy` Secret)
  - `encryptKey` → `S3PROXY_ENCRYPT_KEY` (KEK seed, required)
  - `otlpEndpoint` / `otlpTracesEndpoint` / `otlpHeaders` → OpenTelemetry OTLP/HTTP exporter (tracing is disabled when both endpoint vars are unset).
- `extraEnv`: Opt-in S3PROXY knobs not exposed in `config` — `S3PROXY_INSECURE=1` (plain HTTP upstream, dev/e2e only), `S3PROXY_PUTBODY_MAX=<bytes>` (PutObject body cap), `S3PROXY_DECRYPTION_FALLBACK=1` (one-shot migration retry with all-zero KEK), `S3PROXY_DEKTAG_NAME` / `S3PROXY_DEKTAG_KEKVER` (S3 metadata key overrides).
- `service`: Kubernetes Service configuration (defaults to `ClusterIP` on port `4433`).
- `ingress`: Optional Ingress configuration for external access.
- `resources`: CPU and memory limits and requests for the S3Proxy pods.
- `livenessProbe` and `readinessProbe`: Health check configurations pointing to `/healthz` and `/readyz`. The readiness probe additionally pings the upstream S3 endpoint so the pod is marked unready when the backend is unreachable.
- `autoscaling`: Horizontal Pod Autoscaler (HPA) settings for automatic scaling based on CPU and memory utilization.
- `serviceMonitor`: Opt-in Prometheus Operator `ServiceMonitor` (requires the `monitoring.coreos.com/v1` CRD) — set `serviceMonitor.enabled=true` and use `serviceMonitor.labels` to match the Prometheus instance selector (e.g. `release: kube-prometheus-stack`).
- `prometheusRule`: Opt-in `PrometheusRule` bundling four alerts (`HighErrorRate`, `HighLatency`, `ServiceDown`, `HighCrashRate`). Thresholds and `for` windows are tunable per environment.
- `grafanaDashboard`: Opt-in `ConfigMap` carrying the bundled Grafana dashboard JSON, labelled for auto-discovery by the grafana-operator or the Grafana sidecar.

The Helm chart deploys S3Proxy as a Kubernetes `Deployment` and exposes it via a `Service`, ensuring high availability and scalability.

### Observability

S3Proxy exposes a full observability surface so deployments can be plugged into existing Prometheus / Grafana / OpenTelemetry stacks without extra plumbing:

- **Metrics** — Prometheus-formatted metrics on `/metrics` (request counters, latency histograms, in-flight gauges, build info). Scrape with the bundled `ServiceMonitor` or any standard Prometheus job.
- **Tracing** — OpenTelemetry OTLP/HTTP traces are emitted when either `OTEL_EXPORTER_OTLP_ENDPOINT` or `OTEL_EXPORTER_OTLP_TRACES_ENDPOINT` is set. Spans cover the full request lifecycle including upstream S3 calls. Trace and span IDs are injected into every JSON log record so logs and traces correlate one-to-one.
- **Logs** — structured JSON via `log/slog` on stdout. Verbosity is controlled by the `--level` flag (see `args` above); set `args: ["--level=-1"]` to enable Debug logging when troubleshooting.
- **Alerts** — the chart ships four `PrometheusRule` alerts (`HighErrorRate`, `HighLatency`, `ServiceDown`, `HighCrashRate`) with tunable thresholds.
- **Dashboard** — a ready-to-import Grafana dashboard is bundled under `charts/s3proxy/dashboards/s3proxy.json` and can be shipped as a `ConfigMap` via the `grafanaDashboard` value.

To enable the metrics/alerts/dashboard surface end-to-end (assumes kube-prometheus-stack and the Grafana sidecar are installed):

```yaml
serviceMonitor:
  enabled: true
  labels:
    release: kube-prometheus-stack
prometheusRule:
  enabled: true
  labels:
    release: kube-prometheus-stack
grafanaDashboard:
  enabled: true
config:
  otlpTracesEndpoint: https://otel-collector.observability.svc.cluster.local:4318/v1/traces
```
