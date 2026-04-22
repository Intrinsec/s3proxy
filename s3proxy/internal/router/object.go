/*
Copyright (c) Edgeless Systems GmbH
Copyright (c) Intrinsec 2024

SPDX-License-Identifier: AGPL-3.0-only
*/

package router

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"net/url"
	"strings"
	"syscall"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/intrinsec/s3proxy/internal/config"
	"github.com/intrinsec/s3proxy/internal/cryptoutil"
	s3internal "github.com/intrinsec/s3proxy/internal/s3"
)

// s3OperationTimeout bounds the total duration of an individual S3 GetObject/PutObject call.
// We detach from the request context (context.WithoutCancel) so a client disconnect does not
// abort a partially-uploaded PutObject, but we still cap overall work to protect against
// hung upstreams producing zombie requests.
const s3OperationTimeout = 2 * time.Minute

// object bundles data to implement http.Handler methods that use data from incoming requests.
type object struct {
	keks                      cryptoutil.KEKProvider
	client                    s3Client
	key                       string
	bucket                    string
	data                      []byte
	query                     url.Values
	tags                      string
	contentType               string
	metadata                  map[string]string
	objectLockLegalHoldStatus string
	objectLockMode            string
	objectLockRetainUntilDate time.Time
	sseCustomerAlgorithm      string
	sseCustomerKey            string
	sseCustomerKeyMD5         string
	versionID                 string
	log                       *slog.Logger
}

// get is a http.HandlerFunc that implements the GET method for objects.
func (o object) get(w http.ResponseWriter, r *http.Request) {
	requestID := uuid.New().String()
	log := o.log.With("request_id", requestID)

	log.Debug("getObject", "key", o.key, "bucket", o.bucket)

	// Detach from the request cancellation to avoid aborting an S3 operation when
	// the client disconnects mid-flight, but cap the total duration so a hung
	// upstream cannot produce a zombie request.
	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), s3OperationTimeout)
	defer cancel()

	output, err := o.client.GetObject(ctx, o.bucket, o.key, o.versionID, o.sseCustomerAlgorithm, o.sseCustomerKey, o.sseCustomerKeyMD5)

	if err != nil {
		// log with Info as it might be expected behavior (e.g. object not found).
		log.Error("GetObject sending request to S3", "error", err)

		handleGetObjectError(w, err, requestID, o.log)
		return
	}

	setGetObjectHeaders(w, output)

	defer func() {
		if output.Body != nil {
			_ = output.Body.Close()
		}
	}()

	contentLength := int64(-1)
	if output.ContentLength != nil {
		contentLength = *output.ContentLength
	}
	body, err := readBody(output.Body, contentLength, config.MaxObjectSize)
	if err != nil {
		log.Error("GetObject reading S3 response", "error", err)
		http.Error(w, fmt.Sprintf("failed to read response: %v", err), http.StatusInternalServerError)
		return
	}

	plaintext := body
	rawEncryptedDEK, ok := output.Metadata[config.GetDekTagName()]
	if ok {
		encryptedDEK, err := hex.DecodeString(rawEncryptedDEK)
		if err != nil {
			log.Error("GetObject decoding DEK", "error", err)
			http.Error(w, "failed to decode encryption key", http.StatusInternalServerError)
			return
		}

		// Pick the KEK matching the derivation version recorded on the object. Missing
		// tag means the object predates versioning and used the legacy SHA-256 KEK.
		kekVersion := output.Metadata[config.GetKEKVersionTagName()]
		kek, kekOK := o.keks.For(kekVersion)
		if !kekOK {
			log.Error("GetObject unknown KEK version", "kek_version", kekVersion)
			http.Error(w, "unknown KEK version on stored object", http.StatusInternalServerError)
			return
		}

		plaintext, err = cryptoutil.Decrypt(body, encryptedDEK, kek)
		if err != nil {
			log.Error("GetObject decrypting response", "error", err)
			http.Error(w, "failed to decrypt object", http.StatusInternalServerError)
			return
		}
	}

	select {
	case <-r.Context().Done():
		log.Info("Request was canceled by client")
		return
	default:
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(plaintext); err != nil {
			if errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
				log.Info("Client closed the connection")
			} else {
				log.Error("GetObject sending response", "error", err)
			}
		}
	}
}

// put is a http.HandlerFunc that implements the PUT method for objects.
func (o object) put(w http.ResponseWriter, r *http.Request) {
	requestID := uuid.New().String()
	log := o.log.With("request_id", requestID)
	log.Debug("putObject", "key", o.key, "bucket", o.bucket)

	kekVersion, kek := o.keks.Current()
	ciphertext, encryptedDEK, err := cryptoutil.Encrypt(o.data, kek)
	if err != nil {
		log.Error("PutObject", "error", err)
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	o.metadata[config.GetDekTagName()] = hex.EncodeToString(encryptedDEK)
	o.metadata[config.GetKEKVersionTagName()] = kekVersion

	ctx, cancel := context.WithTimeout(context.WithoutCancel(r.Context()), s3OperationTimeout)
	defer cancel()

	output, err := o.client.PutObject(ctx, o.bucket, o.key, o.tags, o.contentType, o.objectLockLegalHoldStatus, o.objectLockMode, o.sseCustomerAlgorithm, o.sseCustomerKey, o.sseCustomerKeyMD5, o.objectLockRetainUntilDate, o.metadata, ciphertext)
	if err != nil {
		log.Error("PutObject sending request to S3", "error", err)
		code := parseErrorCode(err)
		if code != 0 {
			http.Error(w, err.Error(), code)
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}

	setPutObjectHeaders(w, output)

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(nil); err != nil {
		log.Error("PutObject sending response", "error", err)
	}
}

func setPutObjectHeaders(w http.ResponseWriter, output *s3.PutObjectOutput) {
	w.Header().Set("x-amz-server-side-encryption", string(output.ServerSideEncryption))
	if output.VersionId != nil {
		w.Header().Set("x-amz-version-id", *output.VersionId)
	}
	if output.ETag != nil {
		w.Header().Set("ETag", strings.Trim(*output.ETag, "\""))
	}
	if output.Expiration != nil {
		w.Header().Set("x-amz-expiration", *output.Expiration)
	}
	if output.ChecksumCRC32 != nil {
		w.Header().Set("x-amz-checksum-crc32", *output.ChecksumCRC32)
	}
	if output.ChecksumCRC32C != nil {
		w.Header().Set("x-amz-checksum-crc32c", *output.ChecksumCRC32C)
	}
	if output.ChecksumSHA1 != nil {
		w.Header().Set("x-amz-checksum-sha1", *output.ChecksumSHA1)
	}
	if output.ChecksumSHA256 != nil {
		w.Header().Set("x-amz-checksum-sha256", *output.ChecksumSHA256)
	}
	if output.SSECustomerAlgorithm != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-algorithm", *output.SSECustomerAlgorithm)
	}
	if output.SSECustomerKeyMD5 != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-key-MD5", *output.SSECustomerKeyMD5)
	}
	if output.SSEKMSKeyId != nil {
		w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", *output.SSEKMSKeyId)
	}
	if output.SSEKMSEncryptionContext != nil {
		w.Header().Set("x-amz-server-side-encryption-context", *output.SSEKMSEncryptionContext)
	}
}

func handleGetObjectError(w http.ResponseWriter, err error, requestID string, log *slog.Logger) {
	log.Error("GetObject sending request to S3", "request_id", requestID, "error", err)
	var httpResponseErr *awshttp.ResponseError
	if errors.As(err, &httpResponseErr) {
		code := httpResponseErr.HTTPStatusCode()
		log.Error("GetObject sending request to S3 (awshttp.ResponseError)", "request_id", requestID, "code", code, "httpResponseErr", httpResponseErr)
		if code != 0 {
			var s3internalErr *s3internal.ErrorRawResponse
			if errors.As(err, &s3internalErr) && s3internalErr.RawResponse != "" {
				http.Error(w, s3internalErr.RawResponse, code)
			} else {
				http.Error(w, err.Error(), code)
			}
			for key := range httpResponseErr.Response.Header {
				w.Header().Set(key, httpResponseErr.Response.Header.Get(key))
			}
			return
		}
		http.Error(w, err.Error(), http.StatusInternalServerError)
	}
}

func setGetObjectHeaders(w http.ResponseWriter, output *s3.GetObjectOutput) {
	if output.ETag != nil {
		w.Header().Set("ETag", strings.Trim(*output.ETag, "\""))
	}
	if output.Expiration != nil {
		w.Header().Set("x-amz-expiration", *output.Expiration)
	}
	if output.ChecksumCRC32 != nil {
		w.Header().Set("x-amz-checksum-crc32", *output.ChecksumCRC32)
	}
	if output.ChecksumCRC32C != nil {
		w.Header().Set("x-amz-checksum-crc32c", *output.ChecksumCRC32C)
	}
	if output.ChecksumSHA1 != nil {
		w.Header().Set("x-amz-checksum-sha1", *output.ChecksumSHA1)
	}
	if output.ChecksumSHA256 != nil {
		w.Header().Set("x-amz-checksum-sha256", *output.ChecksumSHA256)
	}
	if output.SSECustomerAlgorithm != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-algorithm", *output.SSECustomerAlgorithm)
	}
	if output.SSECustomerKeyMD5 != nil {
		w.Header().Set("x-amz-server-side-encryption-customer-key-MD5", *output.SSECustomerKeyMD5)
	}
	if output.SSEKMSKeyId != nil {
		w.Header().Set("x-amz-server-side-encryption-aws-kms-key-id", *output.SSEKMSKeyId)
	}
	if output.ServerSideEncryption != "" {
		w.Header().Set("x-amz-server-side-encryption-context", string(output.ServerSideEncryption))
	}
}

// parseErrorCode extracts the HTTP status code from an AWS SDK error by unwrapping
// *awshttp.ResponseError. Returns 0 when no HTTP response is attached.
func parseErrorCode(err error) int {
	var httpResponseErr *awshttp.ResponseError
	if errors.As(err, &httpResponseErr) {
		return httpResponseErr.HTTPStatusCode()
	}
	return 0
}

type s3Client interface {
	GetObject(ctx context.Context, bucket, key, versionID, sseCustomerAlgorithm, sseCustomerKey, sseCustomerKeyMD5 string) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, bucket, key, tags, contentType, objectLockLegalHoldStatus, objectLockMode, sseCustomerAlgorithm, sseCustomerKey, sseCustomerKeyMD5 string, objectLockRetainUntilDate time.Time, metadata map[string]string, body []byte) (*s3.PutObjectOutput, error)
}
