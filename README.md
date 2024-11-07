# S3Proxy by Intrinsec (forked from [constellation](https://github.com/edgelesssys/constellation))

**S3Proxy** is a Docker image that enables seamless encryption (AES-256-GCM) for all communications with an S3 provider, adding an extra layer of security. The proxy intercepts PUT and GET requests, encrypting data before sending it to S3 and decrypting it upon retrieval.

## Features
- **Automatic encryption** for all PUT requests before storage on S3
- **Transparent decryption** of GET requests when retrieving data from S3
- **Easy setup**: simply run the proxy and direct your HTTP requests through it.

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