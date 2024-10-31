# Dev with Docker & VSCode

```bash
git clone # git clone project
cd s3proxy
docker run --rm -p 4433:4433 -v $PWD:/app -it golang:1.23 bash
# In VSCode, use "Attach to Running Container..." option => select golang container => open /app folder
go run s3proxy/cmd/main.go --no-tls
```