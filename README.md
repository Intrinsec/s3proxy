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
helm ugprade --install s3proxy oci://ghcr.io/intrinsec/s3proxy/charts/s3proxy
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
- `cmd/main.go`: The entry point of the application, responsible for parsing command-line flags, setting up logging (`logrus`), loading configuration (`koanf`), and starting the HTTP server.
- `internal/router`: Implements the core request interception and routing logic. It dispatches requests to appropriate handlers based on the HTTP method and URL path, distinguishing between `GetObject`, `PutObject`, and other S3 operations. It also handles health endpoints (`/healthz`, `/readyz`) and applies optional request throttling. All AWS requests are re-signed before being forwarded to the S3 backend to comply with AWS signature requirements.
- `internal/s3`: Provides a thin wrapper around the AWS S3 client (`github.com/aws/aws-sdk-go-v2/service/s3`) for seamless interaction with the S3 backend. It includes custom middleware to capture raw HTTP responses, which is crucial for robust error handling.
- `internal/crypto`: Contains the cryptographic functions for encryption and decryption. It utilizes `github.com/tink-crypto/tink-go/v2` for AES-256-GCM for data encryption and Key Wrapping (KWP) for DEK encryption.

By default, multipart upload requests (`CreateMultipartUpload`, `UploadPart`, `CompleteMultipartUpload`, `AbortMultipartUpload`) are blocked for enhanced security, but this behavior can be optionally configured to forward these requests via a command-line flag.

### Main Libraries Used

- **Configuration:** [`github.com/knadh/koanf`](https://github.com/knadh/koanf) for flexible configuration loading from environment variables (e.g., `S3PROXY_HOST` maps to `s3proxy.host`).
- **Logging:** [`github.com/sirupsen/logrus`](https://github.com/sirupsen/logrus) for structured and configurable logging.
- **AWS SDK:** [`github.com/aws/aws-sdk-go-v2/service/s3`](https://github.com/aws/aws-sdk-go-v2/service/s3) for all interactions with the S3 backend.
- **Cryptography:** [`github.com/tink-crypto/tink-go/v2`](https://github.com/tink-crypto/tink-go) for robust and secure cryptographic operations (AES-256-GCM and Key Wrapping).
- **UUID Generation:** [`github.com/google/uuid`](https://github.com/google/uuid) for generating unique request identifiers.

### Deployment (Helm Chart)

S3Proxy can be easily deployed on Kubernetes using its official Helm chart located at `charts/s3proxy`. The chart provides a flexible way to configure and manage S3Proxy instances.

Key configurable parameters via `values.yaml` include:
- `replicaCount`: Number of S3Proxy instances to run.
- `image`: Docker image repository and tag for S3Proxy.
- `args`: Command-line arguments passed to the S3Proxy binary (e.g., `--no-tls` to disable TLS, `--level` for log verbosity).
- `cert`: Configuration for CertManager integration to automatically provision TLS certificates.
- `config`: Settings for the S3 backend, including `host`, `throttling` (maximum requests per second), `accessKey`, `secretKey`, and `encryptKey` (the KEK).
- `service`: Kubernetes Service configuration (defaults to `ClusterIP` on port `4433`).
- `ingress`: Optional Ingress configuration for external access.
- `resources`: CPU and memory limits and requests for the S3Proxy pods.
- `livenessProbe` and `readinessProbe`: Health check configurations pointing to `/healthz` and `/readyz` endpoints respectively.
- `autoscaling`: Horizontal Pod Autoscaler (HPA) settings for automatic scaling based on CPU and memory utilization.

The Helm chart deploys S3Proxy as a Kubernetes `Deployment` and exposes it via a `Service`, ensuring high availability and scalability.
