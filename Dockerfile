FROM golang:1.25.3 AS build-stage

WORKDIR /app

ADD go.mod go.sum ./
RUN go mod download

ADD s3proxy ./s3proxy

RUN cd s3proxy/cmd && CGO_ENABLED=0 GOOS=linux go build main.go

# Get CA-certificates from alpine
FROM alpine AS certs
RUN apk update && apk add ca-certificates

# Deploy the application binary into a lean image
FROM busybox:1.36 AS build-release-stage

WORKDIR /app
# ENV AWS_ACCESS_KEY_ID="TEST"
# ENV AWS_SECRET_ACCESS_KEY="TEST"
# ENV S3PROXY_ENCRYPT_KEY="TEST"
# ENV S3PROXY_HOST="TEST"
# ENV S3PROXY_DEKTAG_NAME="isec"

COPY --from=certs /etc/ssl/certs /etc/ssl/certs
COPY --from=build-stage /app/s3proxy/cmd/main /app/isec-s3proxy

EXPOSE 4433
USER 1001
ENTRYPOINT ["/app/isec-s3proxy"]
CMD ["--level=-4", "--no-tls"]
