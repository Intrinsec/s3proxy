//go:build e2e

/*
Copyright (c) Intrinsec 2026

SPDX-License-Identifier: AGPL-3.0-only
*/

// Package e2e contains the opt-in end-to-end tests.
//
// The test in this file is guarded by `//go:build e2e` so the default unit test
// run never requires Docker. To execute it locally:
//
//	GOFLAGS=-mod=mod go test -tags=e2e -count=1 -v ./s3proxy/internal/e2e/...
//
// The -mod=mod override is necessary because testcontainers and its dependency
// graph are not vendored (they are only reachable under the e2e build tag).
package e2e

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/intrinsec/s3proxy/internal/config"
	"github.com/intrinsec/s3proxy/internal/monitoring"
	"github.com/intrinsec/s3proxy/internal/router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcminio "github.com/testcontainers/testcontainers-go/modules/minio"
)

// TestProxyRoundtripAgainstMinio spins up a real MinIO container and verifies
// that a PutObject through the proxy stores ciphertext at rest and that a
// subsequent GetObject through the proxy returns the original plaintext.
//
// The test also checks that /healthz, /readyz and /metrics remain reachable
// while the proxy is wired to MinIO.
func TestProxyRoundtripAgainstMinio(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	minioCtr, err := tcminio.Run(ctx, "minio/minio:RELEASE.2024-10-02T17-50-41Z")
	if err != nil {
		t.Skipf("cannot start minio testcontainer (docker unavailable?): %v", err)
	}
	t.Cleanup(func() {
		if err := minioCtr.Terminate(context.Background()); err != nil {
			t.Logf("terminate minio container: %v", err)
		}
	})

	endpoint, err := minioCtr.ConnectionString(ctx)
	require.NoError(t, err)

	t.Setenv("S3PROXY_HOST", endpoint)
	t.Setenv("S3PROXY_INSECURE", "1")
	t.Setenv("S3PROXY_ENCRYPT_KEY", "e2e-encryption-seed")
	t.Setenv("AWS_ACCESS_KEY_ID", minioCtr.Username)
	t.Setenv("AWS_SECRET_ACCESS_KEY", minioCtr.Password)
	t.Setenv("AWS_REGION", "us-east-1")

	require.NoError(t, config.LoadConfig())

	bucket := "s3proxy-e2e"
	key := "alpha/beta.txt"
	plaintext := []byte("hello through the proxy — this should be ciphertext at rest")

	// A direct SDK client bound to MinIO is used both to create the bucket and to
	// inspect the stored (encrypted) bytes after PutObject through the proxy.
	directCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(minioCtr.Username, minioCtr.Password, "")),
	)
	require.NoError(t, err)
	directClient := awss3.NewFromConfig(directCfg, func(o *awss3.Options) {
		o.UsePathStyle = true
		o.BaseEndpoint = aws.String("http://" + endpoint)
	})

	_, err = directClient.CreateBucket(ctx, &awss3.CreateBucketInput{Bucket: aws.String(bucket)})
	require.NoError(t, err)

	// Proxy wiring. Router.New dials MinIO once; the httptest.Server exposes the
	// full handler stack (including /metrics).
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	metrics := monitoring.New()

	routerInstance, err := router.New(ctx, "us-east-1", false, log, metrics)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.Handle(monitoring.MetricsPath, metrics.Handler())
	mux.HandleFunc("/", routerInstance.Serve)
	proxySrv := httptest.NewServer(metrics.Instrument(mux))
	t.Cleanup(proxySrv.Close)

	proxyURL, err := url.Parse(proxySrv.URL)
	require.NoError(t, err)

	proxyClient := awss3.NewFromConfig(directCfg, func(o *awss3.Options) {
		o.UsePathStyle = true
		o.BaseEndpoint = aws.String(proxySrv.URL)
	})

	_, err = proxyClient.PutObject(ctx, &awss3.PutObjectInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		Body:        bytes.NewReader(plaintext),
		ContentType: aws.String("text/plain"),
	})
	require.NoError(t, err)

	// The object stored in MinIO must be opaque ciphertext, not the plaintext we uploaded.
	stored, err := directClient.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err)
	storedBody, err := io.ReadAll(stored.Body)
	require.NoError(t, err)
	require.NoError(t, stored.Body.Close())
	assert.NotEqual(t, plaintext, storedBody, "stored bytes must differ from plaintext")
	assert.NotEmpty(t, stored.Metadata[config.GetDekTagName()], "DEK metadata must be attached")

	// Round-tripping through the proxy must return the original plaintext.
	got, err := proxyClient.GetObject(ctx, &awss3.GetObjectInput{
		Bucket: aws.String(bucket),
		Key:    aws.String(key),
	})
	require.NoError(t, err)
	gotBody, err := io.ReadAll(got.Body)
	require.NoError(t, err)
	require.NoError(t, got.Body.Close())
	assert.Equal(t, plaintext, gotBody)

	// Housekeeping endpoints stay reachable while traffic is flowing.
	healthResp, err := http.Get(proxyURL.String() + "/healthz")
	require.NoError(t, err)
	require.NoError(t, healthResp.Body.Close())
	assert.Equal(t, http.StatusOK, healthResp.StatusCode)

	readyResp, err := http.Get(proxyURL.String() + "/readyz")
	require.NoError(t, err)
	require.NoError(t, readyResp.Body.Close())
	assert.Equal(t, http.StatusOK, readyResp.StatusCode)

	metricsResp, err := http.Get(proxyURL.String() + monitoring.MetricsPath)
	require.NoError(t, err)
	metricsBody, err := io.ReadAll(metricsResp.Body)
	require.NoError(t, err)
	require.NoError(t, metricsResp.Body.Close())
	assert.Equal(t, http.StatusOK, metricsResp.StatusCode)
	assert.True(t, strings.Contains(string(metricsBody), "http_requests_total"), "metrics endpoint must expose http_requests_total")
	assert.True(t, strings.Contains(string(metricsBody), "s3proxy_encrypt_duration_seconds"), "encrypt histogram must be registered")
}
