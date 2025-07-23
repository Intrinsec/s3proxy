# Dev with Docker & VSCode

```bash
git clone # or gh repo clone Intrinsec/s3proxy
cd s3proxy
docker run --rm -p 4433:4433 -v $PWD:/app -it golang:1.24.5 bash
# In VSCode, use "Attach to Running Container..." option => select golang container => open /app folder
go run s3proxy/cmd/main.go --no-tls --level=-4
```