/*
Copyright (c) Intrinsec 2026

SPDX-License-Identifier: AGPL-3.0-only
*/

package router

import (
	"bytes"
	"encoding/hex"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/intrinsec/s3proxy/internal/config"
	"github.com/intrinsec/s3proxy/internal/cryptoutil"
	"github.com/intrinsec/s3proxy/internal/multipart"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func newBufferRouter(t *testing.T, seed string) (Router, *multipart.Manager) {
	t.Helper()
	keks := newTestKEKs(t, seed)
	mgr, err := multipart.NewManager(t.TempDir(), config.MaxObjectSize, time.Hour, testLogger(), nil)
	require.NoError(t, err)
	return Router{keks: keks, multipart: mgr, log: testLogger()}, mgr
}

func createUpload(t *testing.T, r Router, client s3Client) string {
	t.Helper()
	req := httptest.NewRequest(http.MethodPost, "/bucket/key?uploads", nil)
	rec := httptest.NewRecorder()
	r.getHandler(req, client, true, "key", "bucket").ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var res InitiateMultipartUploadResult
	require.NoError(t, xml.Unmarshal(rec.Body.Bytes(), &res))
	require.NotEmpty(t, res.UploadID)
	assert.Equal(t, "bucket", res.Bucket)
	assert.Equal(t, "key", res.Key)
	return res.UploadID
}

func uploadPart(t *testing.T, r Router, client s3Client, req *http.Request) {
	t.Helper()
	rec := httptest.NewRecorder()
	r.getHandler(req, client, true, "key", "bucket").ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)
	assert.NotEmpty(t, rec.Header().Get("ETag"))
}

func uploadPartReq(uploadID string, n int, data []byte) *http.Request {
	url := fmt.Sprintf("/bucket/key?partNumber=%d&uploadId=%s", n, uploadID)
	return httptest.NewRequest(http.MethodPut, url, bytes.NewReader(data))
}

func completeBody(t *testing.T, parts ...int) []byte {
	t.Helper()
	c := CompleteMultipartUpload{}
	for _, n := range parts {
		c.Parts = append(c.Parts, CompletedPart{PartNumber: n, ETag: fmt.Sprintf("etag-%d", n)})
	}
	b, err := xml.Marshal(c)
	require.NoError(t, err)
	return b
}

func TestMultipartBufferRoundTrip(t *testing.T) {
	r, _ := newBufferRouter(t, "multipart seed")
	client := &recordingS3Client{}

	uploadID := createUpload(t, r, client)

	part1 := []byte("hello ")
	part2 := []byte("buffered multipart world")
	uploadPart(t, r, client, uploadPartReq(uploadID, 1, part1))
	uploadPart(t, r, client, uploadPartReq(uploadID, 2, part2))

	req := httptest.NewRequest(http.MethodPost, "/bucket/key?uploadId="+uploadID, bytes.NewReader(completeBody(t, 1, 2)))
	rec := httptest.NewRecorder()
	r.getHandler(req, client, true, "key", "bucket").ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	var res CompleteMultipartUploadResult
	require.NoError(t, xml.Unmarshal(rec.Body.Bytes(), &res))
	assert.Equal(t, "bucket", res.Bucket)
	assert.Equal(t, "key", res.Key)

	// The upstream object is a single ciphertext carrying the DEK + KEK-version tags.
	rawDEK, ok := client.metadata[config.GetDekTagName()]
	require.True(t, ok)
	encryptedDEK, err := hex.DecodeString(rawDEK)
	require.NoError(t, err)

	version, kek := r.keks.Current()
	assert.Equal(t, version, client.metadata[config.GetKEKVersionTagName()])

	plaintext, err := cryptoutil.Decrypt(client.body, encryptedDEK, kek)
	require.NoError(t, err)
	assert.Equal(t, append(append([]byte{}, part1...), part2...), plaintext)
}

func TestMultipartCompleteAssemblesInRequestedOrder(t *testing.T) {
	r, _ := newBufferRouter(t, "ordering seed")
	client := &recordingS3Client{}

	uploadID := createUpload(t, r, client)
	uploadPart(t, r, client, uploadPartReq(uploadID, 1, []byte("AAA")))
	uploadPart(t, r, client, uploadPartReq(uploadID, 2, []byte("BBB")))

	// Complete lists the parts out of upload order; assembly must follow the list.
	req := httptest.NewRequest(http.MethodPost, "/bucket/key?uploadId="+uploadID, bytes.NewReader(completeBody(t, 2, 1)))
	rec := httptest.NewRecorder()
	r.getHandler(req, client, true, "key", "bucket").ServeHTTP(rec, req)
	require.Equal(t, http.StatusOK, rec.Code)

	encryptedDEK, err := hex.DecodeString(client.metadata[config.GetDekTagName()])
	require.NoError(t, err)
	_, kek := r.keks.Current()
	plaintext, err := cryptoutil.Decrypt(client.body, encryptedDEK, kek)
	require.NoError(t, err)
	assert.Equal(t, []byte("BBBAAA"), plaintext)
}

func TestMultipartUploadPartAWSChunked(t *testing.T) {
	r, _ := newBufferRouter(t, "chunked seed")
	client := &recordingS3Client{}

	uploadID := createUpload(t, r, client)

	payload := "the quick brown fox"
	framed := fmt.Sprintf("%x;chunk-signature=abc\r\n%s\r\n0;chunk-signature=def\r\n\r\n", len(payload), payload)
	req := httptest.NewRequest(http.MethodPut, fmt.Sprintf("/bucket/key?partNumber=1&uploadId=%s", uploadID), strings.NewReader(framed))
	req.Header.Set("Content-Encoding", "aws-chunked")
	req.Header.Set("x-amz-content-sha256", "STREAMING-AWS4-HMAC-SHA256-PAYLOAD")
	uploadPart(t, r, client, req)

	complete := httptest.NewRequest(http.MethodPost, "/bucket/key?uploadId="+uploadID, bytes.NewReader(completeBody(t, 1)))
	rec := httptest.NewRecorder()
	r.getHandler(complete, client, true, "key", "bucket").ServeHTTP(rec, complete)
	require.Equal(t, http.StatusOK, rec.Code)

	encryptedDEK, err := hex.DecodeString(client.metadata[config.GetDekTagName()])
	require.NoError(t, err)
	_, kek := r.keks.Current()
	plaintext, err := cryptoutil.Decrypt(client.body, encryptedDEK, kek)
	require.NoError(t, err)
	assert.Equal(t, payload, string(plaintext))
}

func TestMultipartAbortCleansUpSession(t *testing.T) {
	r, _ := newBufferRouter(t, "abort seed")
	client := &recordingS3Client{}

	uploadID := createUpload(t, r, client)
	uploadPart(t, r, client, uploadPartReq(uploadID, 1, []byte("data")))

	abort := httptest.NewRequest(http.MethodDelete, "/bucket/key?uploadId="+uploadID, nil)
	rec := httptest.NewRecorder()
	r.getHandler(abort, client, true, "key", "bucket").ServeHTTP(rec, abort)
	require.Equal(t, http.StatusNoContent, rec.Code)

	// The session is gone: a follow-up UploadPart now reports the upload as unknown.
	follow := uploadPartReq(uploadID, 2, []byte("more"))
	rec = httptest.NewRecorder()
	r.getHandler(follow, client, true, "key", "bucket").ServeHTTP(rec, follow)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestMultipartCompleteUnknownUploadReturns404(t *testing.T) {
	r, _ := newBufferRouter(t, "unknown seed")
	client := &recordingS3Client{}

	req := httptest.NewRequest(http.MethodPost, "/bucket/key?uploadId=does-not-exist", bytes.NewReader(completeBody(t, 1)))
	rec := httptest.NewRecorder()
	r.getHandler(req, client, true, "key", "bucket").ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotFound, rec.Code)
}

func TestMultipartBlockedWithoutManager(t *testing.T) {
	r := Router{log: testLogger()}
	client := &recordingS3Client{}

	req := httptest.NewRequest(http.MethodPost, "/bucket/key?uploads", nil)
	rec := httptest.NewRecorder()
	r.getHandler(req, client, true, "key", "bucket").ServeHTTP(rec, req)
	assert.Equal(t, http.StatusNotImplemented, rec.Code)
}

func TestAWSChunkedReaderDecodesSingleChunk(t *testing.T) {
	payload := "abcdefghij"
	framed := fmt.Sprintf("%x;chunk-signature=deadbeef\r\n%s\r\n0;chunk-signature=cafe\r\n\r\n", len(payload), payload)

	out, err := io.ReadAll(newAWSChunkedReader(strings.NewReader(framed)))
	require.NoError(t, err)
	assert.Equal(t, payload, string(out))
}

func TestAWSChunkedReaderDecodesMultipleChunks(t *testing.T) {
	framed := "3;chunk-signature=x\r\nabc\r\n2;chunk-signature=y\r\nde\r\n0;chunk-signature=z\r\n\r\n"

	out, err := io.ReadAll(newAWSChunkedReader(strings.NewReader(framed)))
	require.NoError(t, err)
	assert.Equal(t, "abcde", string(out))
}
