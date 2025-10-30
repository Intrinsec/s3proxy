# Dev with Docker & VSCode

## Setup

To set up your development environment:

1.  **Clone the repository:**
    ```bash
    git clone https://github.com/intrinsec/s3proxy.git
    cd s3proxy
    ```
2.  **Run a Docker container with Go:**
    ```bash
    docker run --rm -p 4433:4433 -v $PWD:/app -it golang:1.24.5 bash
    ```
    This command launches a Docker container with the specified Go version, mounts your current project directory (`$PWD`) to `/app` inside the container, and exposes port `4433`.
3.  **Attach VSCode to the running container:**
    -   In VSCode, use the "Attach to Running Container..." option.
    -   Select the `golang` container.
    -   Open the `/app` folder within the attached VSCode window. This allows you to develop within a consistent Go environment without installing Go directly on your host machine.
4.  **Run the S3Proxy server:**
    ```bash
    go run s3proxy/cmd/main.go --no-tls --level=-4
    ```
    This command starts the S3Proxy server with TLS disabled and a debug log level.

### Example

```bash
git clone # or gh repo clone Intrinsec/s3proxy
cd s3proxy
docker run --rm -p 4433:4433 -v $PWD:/app -it golang:1.25.3 bash
# In VSCode, use "Attach to Running Container..." option => select golang container => open /app folder
export AWS_ACCESS_KEY_ID=xxx
export AWS_SECRET_ACCESS_KEY=xxx
export S3PROXY_HOST=xxx
export S3PROXY_ENCRYPT_KEY=toto
go run s3proxy/cmd/main.go --no-tls --level=-4

echo "test" > test.txt
aws s3 cp ./test.txt s3://bucket/
aws s3 cp s3://bucket/test.txt ./test.txt
aws s3 rm s3://bucket/test.txt
```

## Linting

`golangci-lint` is used for static code analysis to ensure code quality and consistency. It combines multiple linters into a single tool.

**Enabled Linters:**
- `bodyclose`: Checks for unclosed HTTP response bodies.
- `gocognit`: Computes and checks the cognitive complexity of functions.
- `goconst`: Finds repeated strings that could be replaced by constants.
- `gocyclo`: Computes and checks the cyclomatic complexity of functions.
- `gosec`: Inspects code for security problems.
- `misspell`: Finds commonly misspelled English words.
- `revive`: A fast, configurable, extensible, flexible, and beautiful linter for Go.
- `staticcheck`: A Go static analysis tool that finds bugs and performance issues.

**How to Run:**
To run the linter, execute the following command in your development environment:
```bash
golangci-lint run
```
This will analyze the codebase and report any issues based on the configuration in `.golangci.yml`.
