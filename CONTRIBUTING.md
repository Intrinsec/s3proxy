# Dev with Docker & VSCode

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
```

# Example

```bash
echo "test" > test.txt
aws s3 cp ./test.txt s3://bucket/
aws s3 cp s3://bucket/test.txt ./test.txt
aws s3 rm s3://bucket/test.txt
```