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
	"io"
	"net/http"
	"net/url"
	"regexp"
	"runtime/debug"
	"strconv"
	"strings"
	"syscall"
	"time"

	awshttp "github.com/aws/aws-sdk-go-v2/aws/transport/http"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/google/uuid"
	"github.com/intrinsec/s3proxy/internal/config"
	"github.com/intrinsec/s3proxy/internal/crypto"
	s3internal "github.com/intrinsec/s3proxy/internal/s3"
	logger "github.com/sirupsen/logrus"
)

var (
	// dekTag is the name of the header that holds the encrypted data encryption key for the attached object. Presence of the key implies the object needs to be decrypted.
	// Use lowercase only, as AWS automatically lowercases all metadata keys.
	dekTag = config.GetDekTagName()
)

// object bundles data to implement http.Handler methods that use data from incoming requests.
type object struct {
	kek                       [32]byte
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
	log                       *logger.Logger
}

const freeOSMemoryThreshold int = 100 * 1024 * 1024 // 100 MiB

func setHeaderIfNonEmpty(h http.Header, key string, val *string) {
	if val != nil {
		v := strings.TrimSpace(*val)
		if v != "" {
			h.Set(key, v)
		}
	}
}

// get is a http.HandlerFunc that implements the GET method for objects.
func (o object) get(w http.ResponseWriter, r *http.Request) {
	requestID := uuid.New().String()

	o.log.WithField("requestID", requestID).WithField("key", o.key).WithField("bucket", o.bucket).Debug("getObject")

	versionID, ok := o.query["versionId"]
	if !ok {
		versionID = []string{""}
	}

	output, err := o.client.GetObject(context.WithoutCancel(r.Context()), o.bucket, o.key, versionID[0], o.sseCustomerAlgorithm, o.sseCustomerKey, o.sseCustomerKeyMD5)

	if err != nil {
		// log with Info as it might be expected behavior (e.g. object not found).
		o.log.WithField("requestID", requestID).WithField("error", err).Error("GetObject sending request to S3")

		var httpResponseErr *awshttp.ResponseError
		if errors.As(err, &httpResponseErr) {
			// We want to forward error codes from the s3 API to clients as much as possible.
			code := httpResponseErr.HTTPStatusCode()
			o.log.WithField("requestID", requestID).WithField("code", code).WithField("httpResponseErr", httpResponseErr).Error("GetObject sending request to S3 (awshttp.ResponseError)")
			if code != 0 {
				var s3internalErr *s3internal.ErrorRawResponse
				if errors.As(err, &s3internalErr) {
					http.Error(w, s3internalErr.Error(), code)
				} else {
					http.Error(w, err.Error(), code)
				}
				for key := range httpResponseErr.ResponseError.Response.Response.Header {
					w.Header().Set(key, httpResponseErr.ResponseError.Response.Response.Header.Get(key))
				}
				return
			}

			http.Error(w, err.Error(), http.StatusInternalServerError)
		}
		return
	}

	if output.ETag != nil {
		w.Header().Set("ETag", strings.Trim(*output.ETag, "\""))
	}
	if output.Expiration != nil {
		w.Header().Set("x-amz-expiration", *output.Expiration)
	}
	if output.ServerSideEncryption != "" {
		w.Header().Set("x-amz-server-side-encryption-context", string(output.ServerSideEncryption))
	}
	setHeaderIfNonEmpty(w.Header(), "x-amz-expiration", output.Expiration)
	setHeaderIfNonEmpty(w.Header(), "x-amz-checksum-crc32", output.ChecksumCRC32)
	setHeaderIfNonEmpty(w.Header(), "x-amz-checksum-crc32c", output.ChecksumCRC32C)
	setHeaderIfNonEmpty(w.Header(), "x-amz-checksum-sha1", output.ChecksumSHA1)
	setHeaderIfNonEmpty(w.Header(), "x-amz-checksum-sha256", output.ChecksumSHA256)
	setHeaderIfNonEmpty(w.Header(), "x-amz-server-side-encryption-customer-algorithm", output.SSECustomerAlgorithm)
	setHeaderIfNonEmpty(w.Header(), "x-amz-server-side-encryption-customer-key-MD5", output.SSECustomerKeyMD5)
	setHeaderIfNonEmpty(w.Header(), "x-amz-server-side-encryption-aws-kms-key-id", output.SSEKMSKeyId)

	var body []byte
	if output.ContentLength == nil {
		// fallback on io.ReadAll if ContentLength is unknown
		body, err = io.ReadAll(output.Body)
		if err != nil {
			o.log.WithField("requestID", requestID).WithField("error", err).Error("GetObject reading S3 response")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	} else {
		n := int(*output.ContentLength)
		// Preallocate the buffer from Content-Length and fill it with io.ReadFull.
		// This avoids the incremental growth and extra copies that io.ReadAll incurs
		// when the final size is unknown, which can blow up RAM on large payloads.
		// If Content-Length is missing or bogus we fall back to ReadAll below.
		body = make([]byte, n)
		if _, err := io.ReadFull(output.Body, body); err != nil {
			o.log.WithField("requestID", requestID).WithField("error", err).Error("GetObject reading S3 response")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	plaintext := body
	rawEncryptedDEK, ok := output.Metadata[dekTag]
	defer output.Body.Close()
	if ok {
		encryptedDEK, err := hex.DecodeString(rawEncryptedDEK)
		if err != nil {
			o.log.Error("GetObject decoding DEK", "error", err)
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		plaintext, err = crypto.Decrypt(body, encryptedDEK, o.kek)
		// We do not need to keep body anymore. Because it can be gigabytes in size - free it ASAP
		bodyLen := len(body)
		body = nil
		if bodyLen >= freeOSMemoryThreshold {
			debug.FreeOSMemory()
		}
		if err != nil {
			o.log.WithField("requestID", requestID).WithField("error", err).Error("GetObject decrypting response")
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}
	}

	plaintextLen := len(plaintext)
	select {
	case <-r.Context().Done():
		o.log.WithField("requestID", requestID).Info("Request was canceled by client")
		plaintext = nil
		if plaintextLen >= freeOSMemoryThreshold {
			debug.FreeOSMemory()
		}
		return
	default:
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write(plaintext); err != nil {
			if errors.Is(err, syscall.EPIPE) || errors.Is(err, syscall.ECONNRESET) {
				o.log.WithField("requestID", requestID).Info("Client closed the connection")
			} else {
				o.log.WithField("requestID", requestID).WithField("error", err).Error("GetObject sending response")
			}
		}
	}
	plaintext = nil
	if plaintextLen >= freeOSMemoryThreshold {
		debug.FreeOSMemory()
	}
}

// put is a http.HandlerFunc that implements the PUT method for objects.
func (o object) put(w http.ResponseWriter, r *http.Request) {
	requestID := uuid.New().String()

	o.log.WithField("requestID", requestID).WithField("key", o.key).WithField("bucket", o.bucket).Debug("putObject")

	ciphertext, encryptedDEK, err := crypto.Encrypt(o.data, o.kek)
	if err != nil {
		o.log.WithField("requestID", requestID).WithField("error", err).Error("PutObject")
		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	// We do not need to keep data anymore. Because it can be gigabytes in size - free it ASAP
	dataLen := len(o.data)
	o.data = nil
	if dataLen >= freeOSMemoryThreshold {
		debug.FreeOSMemory()
	}
	o.metadata[dekTag] = hex.EncodeToString(encryptedDEK)

	output, err := o.client.PutObject(context.WithoutCancel(r.Context()), o.bucket, o.key, o.tags, o.contentType, o.objectLockLegalHoldStatus, o.objectLockMode, o.sseCustomerAlgorithm, o.sseCustomerKey, o.sseCustomerKeyMD5, o.objectLockRetainUntilDate, o.metadata, ciphertext)
	if err != nil {
		o.log.WithField("requestID", requestID).WithField("error", err).Error("PutObject sending request to S3")

		// We want to forward error codes from the s3 API to clients whenever possible.
		code := parseErrorCode(err)
		if code != 0 {
			http.Error(w, err.Error(), code)
			return
		}

		http.Error(w, err.Error(), http.StatusInternalServerError)
		return
	}
	cipherTextLen := len(ciphertext)
	ciphertext = nil
	if cipherTextLen > freeOSMemoryThreshold {
		debug.FreeOSMemory()
	}
	ssd_enc := string(output.ServerSideEncryption)
	if ssd_enc != "" { // It can be empty for empty files, at least on Hetzner storage
		w.Header().Set("x-amz-server-side-encryption", ssd_enc)
	}
	if output.ETag != nil {
		w.Header().Set("ETag", strings.Trim(*output.ETag, "\""))
	}

	setHeaderIfNonEmpty(w.Header(), "x-amz-version-id", output.VersionId)
	setHeaderIfNonEmpty(w.Header(), "x-amz-expiration", output.Expiration)
	setHeaderIfNonEmpty(w.Header(), "x-amz-checksum-crc32", output.ChecksumCRC32)
	setHeaderIfNonEmpty(w.Header(), "x-amz-checksum-crc32c", output.ChecksumCRC32C)
	setHeaderIfNonEmpty(w.Header(), "x-amz-checksum-sha1", output.ChecksumSHA1)
	setHeaderIfNonEmpty(w.Header(), "x-amz-checksum-sha256", output.ChecksumSHA256)
	setHeaderIfNonEmpty(w.Header(), "x-amz-server-side-encryption-customer-algorithm", output.SSECustomerAlgorithm)
	setHeaderIfNonEmpty(w.Header(), "x-amz-server-side-encryption-customer-key-MD5", output.SSECustomerKeyMD5)
	setHeaderIfNonEmpty(w.Header(), "x-amz-server-side-encryption-aws-kms-key-id", output.SSEKMSKeyId)
	setHeaderIfNonEmpty(w.Header(), "x-amz-server-side-encryption-context", output.SSEKMSEncryptionContext)

	w.WriteHeader(http.StatusOK)
	if _, err := w.Write(nil); err != nil {
		o.log.WithField("requestID", requestID).WithField("error", err).Error("PutObject sending response")
	}
}

func parseErrorCode(err error) int {
	regex := regexp.MustCompile(`https response error StatusCode: (\d+)`)
	matches := regex.FindStringSubmatch(err.Error())
	if len(matches) > 1 {
		code, _ := strconv.Atoi(matches[1])
		return code
	}

	return 0
}

type s3Client interface {
	GetObject(ctx context.Context, bucket, key, versionID, sseCustomerAlgorithm, sseCustomerKey, sseCustomerKeyMD5 string) (*s3.GetObjectOutput, error)
	PutObject(ctx context.Context, bucket, key, tags, contentType, objectLockLegalHoldStatus, objectLockMode, sseCustomerAlgorithm, sseCustomerKey, sseCustomerKeyMD5 string, objectLockRetainUntilDate time.Time, metadata map[string]string, body []byte) (*s3.PutObjectOutput, error)
}
