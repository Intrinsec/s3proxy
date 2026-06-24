//go:build e2e

/*
Copyright (c) Intrinsec 2026

SPDX-License-Identifier: AGPL-3.0-only
*/

package e2e

import (
	"bytes"
	"context"
	"crypto/rand"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	awsconfig "github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/credentials"
	awss3 "github.com/aws/aws-sdk-go-v2/service/s3"
	s3types "github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/intrinsec/s3proxy/internal/config"
	"github.com/intrinsec/s3proxy/internal/monitoring"
	"github.com/intrinsec/s3proxy/internal/multipart"
	"github.com/intrinsec/s3proxy/internal/router"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	tcminio "github.com/testcontainers/testcontainers-go/modules/minio"
)

// TestMultipartBufferModeRoundtrip spins up a real MinIO container with buffer-mode
// multipart enabled and drives a full Create → UploadPart × N → Complete sequence
// through the proxy. It asserts that:
//
//   - the parts are buffered to disk and assembled into a *single* upstream object
//     (MinIO holds exactly one object, never per-part objects);
//   - that object is ciphertext at rest and carries the DEK metadata tag;
//   - a GetObject through the proxy returns the original plaintext byte-for-byte;
//   - the on-disk buffer directory is reclaimed once the upload completes.
//
// The SDK frames UploadPart bodies as aws-chunked by default, so this also exercises
// the proxy's chunk de-framer on the real client wire format.
func TestMultipartBufferModeRoundtrip(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	minioCtr, err := tcminio.Run(ctx, "minio/minio:RELEASE.2025-09-07T16-13-09Z")
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

	bufferDir := t.TempDir()

	t.Setenv("S3PROXY_HOST", endpoint)
	t.Setenv("S3PROXY_INSECURE", "1")
	t.Setenv("S3PROXY_ENCRYPT_KEY", "e2e-multipart-seed")
	t.Setenv("S3PROXY_MULTIPART_BUFFER_DIR", bufferDir)
	t.Setenv("AWS_ACCESS_KEY_ID", minioCtr.Username)
	t.Setenv("AWS_SECRET_ACCESS_KEY", minioCtr.Password)
	t.Setenv("AWS_REGION", "us-east-1")

	require.NoError(t, config.LoadConfig())
	require.NotEmpty(t, config.GetMultipartBufferDir(), "buffer mode must be enabled for this test")

	bucket := "s3proxy-multipart-e2e"
	key := "large/payload.bin"

	// 12 MiB of incompressible data, split into three parts. Random bytes guarantee
	// the at-rest object cannot accidentally equal the plaintext.
	plaintext := make([]byte, 12<<20)
	_, err = rand.Read(plaintext)
	require.NoError(t, err)
	const partSize = 4 << 20

	directCfg, err := awsconfig.LoadDefaultConfig(ctx,
		awsconfig.WithRegion("us-east-1"),
		awsconfig.WithCredentialsProvider(credentials.NewStaticCredentialsProvider(minioCtr.Username, minioCtr.Password, "")),
	)
	require.NoError(t, err)

	// Direct MinIO client: creates the bucket and inspects what lands at rest.
	directClient := awss3.NewFromConfig(directCfg, func(o *awss3.Options) {
		o.UsePathStyle = true
		o.BaseEndpoint = aws.String("http://" + endpoint)
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationUnset
	})
	_, err = directClient.CreateBucket(ctx, &awss3.CreateBucketInput{Bucket: aws.String(bucket)})
	require.NoError(t, err)

	// Proxy wiring with a live multipart Manager backed by the temp buffer dir.
	log := slog.New(slog.NewJSONHandler(io.Discard, nil))
	metrics := monitoring.New()

	manager, err := multipart.NewManager(bufferDir, config.GetMultipartMaxSize(), config.GetMultipartTTL(), log, metrics)
	require.NoError(t, err)

	routerInstance, err := router.New(ctx, "us-east-1", false, manager, log, metrics)
	require.NoError(t, err)

	mux := http.NewServeMux()
	mux.Handle(monitoring.MetricsPath, metrics.Handler())
	mux.HandleFunc("/", routerInstance.Serve)
	proxySrv := httptest.NewServer(metrics.Instrument(mux))
	t.Cleanup(proxySrv.Close)

	proxyClient := awss3.NewFromConfig(directCfg, func(o *awss3.Options) {
		o.UsePathStyle = true
		o.BaseEndpoint = aws.String(proxySrv.URL)
		// The proxy returns decrypted plaintext and cannot forward an at-rest
		// checksum, so disable response validation on the test client.
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationUnset
	})

	// Create → UploadPart × 3 → Complete, all through the proxy.
	created, err := proxyClient.CreateMultipartUpload(ctx, &awss3.CreateMultipartUploadInput{
		Bucket:      aws.String(bucket),
		Key:         aws.String(key),
		ContentType: aws.String("application/octet-stream"),
	})
	require.NoError(t, err)
	require.NotNil(t, created.UploadId)
	uploadID := *created.UploadId

	var completedParts []s3types.CompletedPart
	for partNumber, off := int32(1), 0; off < len(plaintext); partNumber++ {
		end := min(off+partSize, len(plaintext))
		out, err := proxyClient.UploadPart(ctx, &awss3.UploadPartInput{
			Bucket:     aws.String(bucket),
			Key:        aws.String(key),
			UploadId:   aws.String(uploadID),
			PartNumber: aws.Int32(partNumber),
			Body:       bytes.NewReader(plaintext[off:end]),
		})
		require.NoError(t, err)
		require.NotNil(t, out.ETag)
		completedParts = append(completedParts, s3types.CompletedPart{
			ETag:       out.ETag,
			PartNumber: aws.Int32(partNumber),
		})
		off = end
	}
	require.Len(t, completedParts, 3, "12 MiB at 4 MiB parts must produce three parts")

	_, err = proxyClient.CompleteMultipartUpload(ctx, &awss3.CompleteMultipartUploadInput{
		Bucket:          aws.String(bucket),
		Key:             aws.String(key),
		UploadId:        aws.String(uploadID),
		MultipartUpload: &s3types.CompletedMultipartUpload{Parts: completedParts},
	})
	require.NoError(t, err)

	// MinIO must hold exactly one object: the single assembled ciphertext, never
	// per-part objects (the parts never reach the backend).
	listed, err := directClient.ListObjectsV2(ctx, &awss3.ListObjectsV2Input{Bucket: aws.String(bucket)})
	require.NoError(t, err)
	require.Len(t, listed.Contents, 1, "buffered multipart must store exactly one upstream object")
	require.NotNil(t, listed.Contents[0].Key)
	assert.Equal(t, key, *listed.Contents[0].Key)

	// That object is ciphertext at rest and carries the DEK metadata tag.
	stored, err := directClient.GetObject(ctx, &awss3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	require.NoError(t, err)
	storedBody, err := io.ReadAll(stored.Body)
	require.NoError(t, err)
	require.NoError(t, stored.Body.Close())

	assert.NotEqual(t, plaintext, storedBody, "stored bytes must differ from plaintext")
	assert.False(t, bytes.Contains(storedBody, plaintext), "plaintext must not appear verbatim at rest")
	assert.Greater(t, len(storedBody), len(plaintext), "ciphertext must be longer than plaintext (nonce + auth tag)")
	assert.NotEmpty(t, stored.Metadata[config.GetDekTagName()], "DEK metadata tag must be attached")
	assert.NotEmpty(t, stored.Metadata[config.GetKEKVersionTagName()], "KEK version metadata tag must be attached")

	// Round-trip through the proxy returns the original plaintext.
	got, err := proxyClient.GetObject(ctx, &awss3.GetObjectInput{Bucket: aws.String(bucket), Key: aws.String(key)})
	require.NoError(t, err)
	gotBody, err := io.ReadAll(got.Body)
	require.NoError(t, err)
	require.NoError(t, got.Body.Close())
	assert.Equal(t, plaintext, gotBody, "GetObject through the proxy must return the original plaintext")

	// The on-disk buffer is reclaimed once the upload completes (the session dir is
	// removed; only the base buffer dir remains).
	entries, err := os.ReadDir(bufferDir)
	require.NoError(t, err)
	assert.Empty(t, entries, "buffer directory must be empty after CompleteMultipartUpload")

	// The completion counter is exposed on /metrics.
	metricsResp, err := http.Get(proxySrv.URL + monitoring.MetricsPath)
	require.NoError(t, err)
	metricsBody, err := io.ReadAll(metricsResp.Body)
	require.NoError(t, err)
	require.NoError(t, metricsResp.Body.Close())
	assert.True(t, strings.Contains(string(metricsBody), "s3proxy_multipart_completed_total"),
		"metrics endpoint must expose s3proxy_multipart_completed_total")
}
