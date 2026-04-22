/*
Copyright (c) Edgeless Systems GmbH

SPDX-License-Identifier: AGPL-3.0-only
*/
package router

import (
	"bytes"
	"context"
	"encoding/hex"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/intrinsec/s3proxy/internal/config"
	"github.com/intrinsec/s3proxy/internal/cryptoutil"
	logger "github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

type recordingS3Client struct {
	body         []byte
	metadata     map[string]string
	getObjectOut *s3.GetObjectOutput
}

func (c *recordingS3Client) GetObject(context.Context, string, string, string, string, string, string) (*s3.GetObjectOutput, error) {
	if c.getObjectOut != nil {
		return c.getObjectOut, nil
	}
	return &s3.GetObjectOutput{}, nil
}

func (c *recordingS3Client) PutObject(_ context.Context, _, _, _, _, _, _, _, _, _ string, _ time.Time, metadata map[string]string, body []byte) (*s3.PutObjectOutput, error) {
	c.body = append([]byte(nil), body...)
	c.metadata = make(map[string]string, len(metadata))
	for key, value := range metadata {
		c.metadata[key] = value
	}
	return &s3.PutObjectOutput{}, nil
}

func testLogger() *logger.Logger {
	log := logger.New()
	log.SetOutput(io.Discard)
	return log
}

func TestValidateContentMD5(t *testing.T) {
	tests := map[string]struct {
		contentMD5     string
		body           []byte
		expectedErrMsg string
	}{
		"empty content-md5": {
			contentMD5: "",
			body:       []byte("hello, world"),
		},
		// https://datatracker.ietf.org/doc/html/rfc1864#section-2
		"valid content-md5": {
			contentMD5: "Q2hlY2sgSW50ZWdyaXR5IQ==",
			body:       []byte("Check Integrity!"),
		},
		"invalid content-md5": {
			contentMD5:     "invalid base64",
			body:           []byte("hello, world"),
			expectedErrMsg: "decoding base64",
		},
	}

	// Iterate over the test cases
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			// Call the validateContentMD5 function
			err := validateContentMD5(tc.contentMD5, tc.body)

			// Check the result against the expected value
			if tc.expectedErrMsg != "" {
				assert.ErrorContains(t, err, tc.expectedErrMsg)
			}
		})
	}
}

func TestByteSliceToByteArray(t *testing.T) {
	tests := map[string]struct {
		input   []byte
		output  [32]byte
		wantErr bool
	}{
		"empty input": {
			input:  []byte{},
			output: [32]byte{},
		},
		"successful input": {
			input:  []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
			output: [32]byte{0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41},
		},
		"input too short": {
			input:   []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
			output:  [32]byte{0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41},
			wantErr: true,
		},
		"input too long": {
			input:   []byte("AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"),
			output:  [32]byte{0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41, 0x41},
			wantErr: true,
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			result, err := byteSliceToByteArray(tc.input)
			if tc.wantErr {
				assert.Error(t, err)
				return
			}

			assert.Equal(t, tc.output, result)
		})
	}
}

func TestReadBodyUsesKnownContentLength(t *testing.T) {
	body, err := readBody(strings.NewReader("hello"), 5, 0)

	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), body)
	assert.Equal(t, 5, cap(body))
}

func TestReadBodyFallsBackWhenContentLengthUnknown(t *testing.T) {
	body, err := readBody(strings.NewReader("hello"), -1, 0)

	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), body)
}

func TestReadBodyReturnsErrorOnShortBody(t *testing.T) {
	_, err := readBody(strings.NewReader("hi"), 5, 0)

	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}

func TestReadBodyRejectsDeclaredSizeOverCap(t *testing.T) {
	_, err := readBody(strings.NewReader("hello"), 5, 3)

	assert.ErrorIs(t, err, errBodyTooLarge)
}

func TestReadBodyRejectsUndeclaredSizeOverCap(t *testing.T) {
	_, err := readBody(strings.NewReader("hello"), -1, 3)

	assert.ErrorIs(t, err, errBodyTooLarge)
}

func TestPutObjectUsesRouterKEK(t *testing.T) {
	keks := newTestKEKs(t, "expected encryption key")
	client := &recordingS3Client{}
	router := Router{keks: keks, log: testLogger()}
	req := httptest.NewRequest(http.MethodPut, "/bucket/key", bytes.NewReader([]byte("secret payload")))
	rec := httptest.NewRecorder()

	router.getHandler(req, client, true, "key", "bucket").ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	rawEncryptedDEK, ok := client.metadata[config.GetDekTagName()]
	require.True(t, ok)
	encryptedDEK, err := hex.DecodeString(rawEncryptedDEK)
	require.NoError(t, err)

	version, curKEK := keks.Current()
	assert.Equal(t, version, client.metadata[config.GetKEKVersionTagName()])

	plaintext, err := cryptoutil.Decrypt(client.body, encryptedDEK, curKEK)
	require.NoError(t, err)
	assert.Equal(t, []byte("secret payload"), plaintext)

	_, err = cryptoutil.Decrypt(client.body, encryptedDEK, [32]byte{})
	assert.Error(t, err)
}

func TestGetObjectUsesRouterKEK(t *testing.T) {
	keks := newTestKEKs(t, "expected encryption key")
	version, curKEK := keks.Current()
	client := newEncryptedGetObjectClient(t, curKEK, version, []byte("secret payload"))
	router := Router{keks: keks, log: testLogger()}
	req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	rec := httptest.NewRecorder()

	router.getHandler(req, client, true, "key", "bucket").ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "secret payload", rec.Body.String())
}

func TestGetObjectFailsWithWrongRouterKEK(t *testing.T) {
	storedKeks := newTestKEKs(t, "old encryption key")
	routerKeks := newTestKEKs(t, "new encryption key")
	version, storedKEK := storedKeks.Current()
	client := newEncryptedGetObjectClient(t, storedKEK, version, []byte("secret payload"))
	router := Router{keks: routerKeks, log: testLogger()}
	req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	rec := httptest.NewRecorder()

	router.getHandler(req, client, true, "key", "bucket").ServeHTTP(rec, req)

	require.Equal(t, http.StatusInternalServerError, rec.Code)
	assert.Contains(t, rec.Body.String(), "failed to decrypt object")
}

func TestGetObjectReadsLegacyObjectWithoutKEKVersion(t *testing.T) {
	keks := newTestKEKs(t, "shared seed")
	legacyKEK, ok := keks.For(cryptoutil.KEKVersionLegacy)
	require.True(t, ok)
	client := newEncryptedGetObjectClient(t, legacyKEK, "", []byte("legacy payload"))
	router := Router{keks: keks, log: testLogger()}
	req := httptest.NewRequest(http.MethodGet, "/bucket/key", nil)
	rec := httptest.NewRecorder()

	router.getHandler(req, client, true, "key", "bucket").ServeHTTP(rec, req)

	require.Equal(t, http.StatusOK, rec.Code)
	assert.Equal(t, "legacy payload", rec.Body.String())
}

func newTestKEKs(t *testing.T, seed string) cryptoutil.KEKProvider {
	t.Helper()
	keks, err := cryptoutil.NewKEKProvider(seed)
	require.NoError(t, err)
	return keks
}

func newEncryptedGetObjectClient(t *testing.T, kek [32]byte, kekVersion string, plaintext []byte) *recordingS3Client {
	t.Helper()

	ciphertext, encryptedDEK, err := cryptoutil.Encrypt(plaintext, kek)
	require.NoError(t, err)

	metadata := map[string]string{
		config.GetDekTagName(): hex.EncodeToString(encryptedDEK),
	}
	if kekVersion != "" {
		metadata[config.GetKEKVersionTagName()] = kekVersion
	}

	return &recordingS3Client{
		getObjectOut: &s3.GetObjectOutput{
			Body:          io.NopCloser(bytes.NewReader(ciphertext)),
			ContentLength: awsInt64(int64(len(ciphertext))),
			Metadata:      metadata,
		},
	}
}

func awsInt64(v int64) *int64 {
	return &v
}
