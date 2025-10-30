/*
Copyright (c) Edgeless Systems GmbH
Copyright (c) Intrinsec 2024

SPDX-License-Identifier: AGPL-3.0-only
*/

/*
Package router implements the main interception logic of s3proxy.
It decides which packages to forward and which to intercept.

The routing logic in this file is taken from this blog post: https://benhoyt.com/writings/go-routing/#regex-switch.
We should be able to replace this once this is part of the stdlib: https://github.com/golang/go/issues/61410.

If the router intercepts a PutObject request it will encrypt the body before forwarding it to the S3 API.
The stored object will have a tag that holds an encrypted data encryption key (DEK).
That DEK is used to encrypt the object's body.
The DEK is generated randomly for each PutObject request.
The DEK is encrypted with a key encryption key (KEK) fetched from Constellation's keyservice.
*/
package router

import (
	"bytes"
	"crypto/md5"
	"crypto/sha256"
	"encoding/base64"
	"encoding/xml"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/intrinsec/s3proxy/internal/config"
	"github.com/intrinsec/s3proxy/internal/s3"
	logger "github.com/sirupsen/logrus"
)

var (
	bucketAndKeyPattern = regexp.MustCompile("/([^/?]+)/(.+)")
)

// Router implements the interception logic for the s3proxy.
type Router struct {
	region string
	kek    [32]byte
	// forwardMultipartReqs controls whether we forward the following requests: CreateMultipartUpload, UploadPart, CompleteMultipartUpload, AbortMultipartUpload.
	// s3proxy does not implement those yet.
	// Setting forwardMultipartReqs to true will forward those requests to the S3 API, otherwise we block them (secure defaults).
	forwardMultipartReqs bool
	log                  *logger.Logger
}

// Function to generate a 32-byte array (KEK) from a string input using SHA-256
func generateKEKFromString(input string) [32]byte {
	hash := sha256.Sum256([]byte(input))
	return hash
}

// New creates a new Router.
func New(region string, forwardMultipartReqs bool, log *logger.Logger) (Router, error) {
	result, err := config.GetEncryptKey()
	if err != nil {
		return Router{}, err
	}
	kekArray := generateKEKFromString(result)
	return Router{region: region, kek: kekArray, forwardMultipartReqs: forwardMultipartReqs, log: log}, nil
}

// Serve implements the routing logic for the s3 proxy.
// It intercepts GetObject and PutObject requests, encrypting/decrypting their bodies if necessary.
// All other requests are forwarded to the S3 API.
// Ideally we could separate routing logic, request handling and s3 interactions.
// Currently routing logic and request handling are integrated.
func (r Router) Serve(w http.ResponseWriter, req *http.Request) {
	if r.handleHealthEndpoints(w, req) {
		return
	}

	client, err := s3.NewClient(r.region, r.log)
	if err != nil {
		r.log.WithError(err).Error("failed to create S3 client")
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}

	var key, bucket string
	matchingPath := match(req.URL.Path, bucketAndKeyPattern, &bucket, &key)

	// Validate bucket and key if we have a matching path
	if matchingPath {
		if err := config.ValidateBucketName(bucket); err != nil {
			r.log.WithError(err).WithField("bucket", bucket).Warn("invalid bucket name")
			http.Error(w, fmt.Sprintf("invalid bucket name: %s", err.Error()), http.StatusBadRequest)
			return
		}
		if err := config.ValidateObjectKey(key); err != nil {
			r.log.WithError(err).WithField("key", key).Warn("invalid object key")
			http.Error(w, fmt.Sprintf("invalid object key: %s", err.Error()), http.StatusBadRequest)
			return
		}
	}

	// Validate content length for PUT requests
	if req.Method == http.MethodPut && req.ContentLength > 0 {
		if err := config.ValidateContentLength(req.ContentLength); err != nil {
			r.log.WithError(err).WithField("content_length", req.ContentLength).Warn("invalid content length")
			http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
			return
		}
	}

	h := r.getHandler(req, client, matchingPath, key, bucket)
	h.ServeHTTP(w, req)
}

func isAbortMultipartUpload(method string, query url.Values) bool {
	_, uploadID := query["uploadId"]

	return method == "DELETE" && uploadID
}

func isCompleteMultipartUpload(method string, query url.Values) bool {
	_, multipart := query["uploadId"]

	return method == "POST" && multipart
}

func isCreateMultipartUpload(method string, query url.Values) bool {
	_, multipart := query["uploads"]

	return method == "POST" && multipart
}

func isUploadPart(method string, query url.Values) bool {
	_, partNumber := query["partNumber"]
	_, uploadID := query["uploadId"]

	return method == "PUT" && partNumber && uploadID
}

// ContentSHA256MismatchError is a helper struct to create an XML formatted error message.
// s3 clients might try to parse error messages, so we need to serve correctly formatted messages.
type ContentSHA256MismatchError struct {
	XMLName                     xml.Name `xml:"Error"`
	Code                        string   `xml:"Code"`
	Message                     string   `xml:"Message"`
	ClientComputedContentSHA256 string   `xml:"ClientComputedContentSHA256"`
	S3ComputedContentSHA256     string   `xml:"S3ComputedContentSHA256"`
}

// NewContentSHA256MismatchError creates a new ContentSHA256MismatchError.
func NewContentSHA256MismatchError(clientComputedContentSHA256, s3ComputedContentSHA256 string) ContentSHA256MismatchError {
	return ContentSHA256MismatchError{
		Code:                        "XAmzContentSHA256Mismatch",
		Message:                     "The provided 'x-amz-content-sha256' header does not match what was computed.",
		ClientComputedContentSHA256: clientComputedContentSHA256,
		S3ComputedContentSHA256:     s3ComputedContentSHA256,
	}
}

// byteSliceToByteArray casts a byte slice to a byte array of length 32.
// It does a length check to prevent the cast from panic'ing.
func byteSliceToByteArray(input []byte) ([32]byte, error) {
	if len(input) != 32 {
		return [32]byte{}, fmt.Errorf("input length mismatch, got: %d", len(input))
	}

	return ([32]byte)(input), nil
}

// containsBucket is a helper to recognizes cases where the bucket name is sent as part of the host.
// In other cases the bucket name is sent as part of the path.
// func containsBucket(host string) bool {
// 	parts := strings.Split(host, ".")
// 	return len(parts) > 4
// }

// isUnwantedGetEndpoint returns true if the request is any of these requests: GetObjectAcl, GetObjectAttributes, GetObjectLegalHold, GetObjectRetention, GetObjectTagging, GetObjectTorrent, ListParts.
// These requests are all structured similarly: they all have a query param that is not present in GetObject.
// Otherwise those endpoints are similar to GetObject.
func isUnwantedGetEndpoint(query url.Values) bool {
	_, acl := query["acl"]
	_, attributes := query["attributes"]
	_, legalHold := query["legal-hold"]
	_, retention := query["retention"]
	_, tagging := query["tagging"]
	_, torrent := query["torrent"]
	_, uploadID := query["uploadId"]

	return acl || attributes || legalHold || retention || tagging || torrent || uploadID
}

// isUnwantedPutEndpoint returns true if the request is any of these requests: UploadPart, PutObjectTagging.
// These requests are all structured similarly: they all have a query param that is not present in PutObject.
// Otherwise those endpoints are similar to PutObject.
func isUnwantedPutEndpoint(header http.Header, query url.Values) bool {
	if header.Get("x-amz-copy-source") != "" {
		return true
	}

	_, partNumber := query["partNumber"]
	_, uploadID := query["uploadId"]
	_, tagging := query["tagging"]
	_, legalHold := query["legal-hold"]
	_, objectLock := query["object-lock"]
	_, retention := query["retention"]
	_, publicAccessBlock := query["publicAccessBlock"]
	_, acl := query["acl"]

	return partNumber || uploadID || tagging || legalHold || objectLock || retention || publicAccessBlock || acl
}

func sha256sum(data []byte) string {
	digest := sha256.Sum256(data)
	return fmt.Sprintf("%x", digest)
}

// getMetadataHeaders parses user-defined metadata headers from a
// http.Header object. Users can define custom headers by taking
// HEADERNAME and prefixing it with "x-amz-meta-".
func getMetadataHeaders(header http.Header) map[string]string {
	result := map[string]string{}

	for key := range header {
		key = strings.ToLower(key)

		if strings.HasPrefix(key, "x-amz-meta-") {
			name := strings.TrimPrefix(key, "x-amz-meta-")
			result[name] = strings.Join(header.Values(key), ",")
		}
	}

	return result
}

func parseRetentionTime(raw string) (time.Time, error) {
	if raw == "" {
		return time.Time{}, nil
	}
	return time.Parse(time.RFC3339, raw)
}

// repackage implements all modifications we need to do to an incoming request that we want to forward to the s3 API.
func repackage(r *http.Request) (*http.Request, error) {
	req := r.Clone(r.Context())
	req.URL.RawPath = ""

	// HTTP clients are not supposed to set this field, however when we receive a request it is set.
	// So, we unset it.
	req.RequestURI = ""

	host, err := config.GetHostConfig()
	if err != nil {
		return nil, fmt.Errorf("getting host config: %w", err)
	}

	req.Host = host
	req.URL.Host = host
	// We always want to use HTTPS when talking to S3.
	req.URL.Scheme = "https"

	headersToRemove := []string{
		"X-Real-Ip",
		"X-Forwarded-Scheme",
		"X-Forwarded-Proto",
		"X-Scheme",
		"X-Forwarded-Host",
		"X-Forwarded-Port",
		"X-Forwarded-For",
	}

	for _, header := range headersToRemove {
		req.Header.Del(header)
	}

	return req, nil
}

// validateContentMD5 checks if the content-md5 header matches the body.
func validateContentMD5(contentMD5 string, body []byte) error {
	if contentMD5 == "" {
		return nil
	}

	expected, err := base64.StdEncoding.DecodeString(contentMD5)
	if err != nil {
		return fmt.Errorf("decoding base64: %w", err)
	}

	if len(expected) != 16 {
		return fmt.Errorf("content-md5 must be 16 bytes long, got %d bytes", len(expected))
	}

	// #nosec G401
	actual := md5.Sum(body)

	if !bytes.Equal(actual[:], expected) {
		return fmt.Errorf("content-md5 mismatch, header is %x, body is %x", expected, actual)
	}

	return nil
}

// match reports whether path matches pattern, and if it matches,
// assigns any capture groups to the *string or *int vars.
func match(path string, pattern *regexp.Regexp, vars ...*string) bool {
	matches := pattern.FindStringSubmatch(path)
	if len(matches) <= 0 {
		return false
	}

	for i, match := range matches[1:] {
		// assign the value of 'match' to the i-th argument.
		*vars[i] = match
	}
	return true
}

// allowMethod takes a HandlerFunc and wraps it in a handler that only
// responds if the request method is the given method, otherwise it
// responds with HTTP 405 Method Not Allowed.
func allowMethod(h http.HandlerFunc, method string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if method != r.Method {
			w.Header().Set("Allow", method)
			http.Error(w, "405 method not allowed", http.StatusMethodNotAllowed)
			return
		}
		h(w, r)
	}
}

// get takes a HandlerFunc and wraps it to only allow the GET method.
func get(h http.HandlerFunc) http.HandlerFunc {
	return allowMethod(h, http.MethodGet)
}

// put takes a HandlerFunc and wraps it to only allow the POST method.
func put(h http.HandlerFunc) http.HandlerFunc {
	return allowMethod(h, http.MethodPut)
}

func (r Router) getHandler(req *http.Request, client s3Client, matchingPath bool, key, bucket string) http.Handler {
	s3Client, ok := client.(*s3.Client)
	if !ok {
		return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
			http.Error(w, "internal server error", http.StatusInternalServerError)
		})
	}

	// Forward if path doesn't match
	if !matchingPath {
		return handleForwards(s3Client, r.log)
	}

	// Check multipart operations first (if not forwarding them)
	if handler := r.getMultipartHandler(req); handler != nil {
		return handler
	}

	// Handle regular object operations
	switch req.Method {
	case http.MethodGet:
		if !isUnwantedGetEndpoint(req.URL.Query()) {
			return handleGetObject(s3Client, key, bucket, r.log)
		}
	case http.MethodPut:
		if !isUnwantedPutEndpoint(req.Header, req.URL.Query()) {
			return handlePutObject(s3Client, key, bucket, r.log)
		}
	}

	// Forward all other requests
	return handleForwards(s3Client, r.log)
}

func (r Router) getMultipartHandler(req *http.Request) http.Handler {
	if r.forwardMultipartReqs {
		return nil
	}

	// Check all multipart operations regardless of HTTP method
	// Let the is* functions determine if they match

	if isUploadPart(req.Method, req.URL.Query()) {
		return handleUploadPart(r.log)
	}

	if isCreateMultipartUpload(req.Method, req.URL.Query()) {
		return handleCreateMultipartUpload(r.log)
	}

	if isCompleteMultipartUpload(req.Method, req.URL.Query()) {
		return handleCompleteMultipartUpload(r.log)
	}

	if isAbortMultipartUpload(req.Method, req.URL.Query()) {
		return handleAbortMultipartUpload(r.log)
	}

	return nil
}

func (r Router) handleHealthEndpoints(w http.ResponseWriter, req *http.Request) bool {
	if req.Method == http.MethodGet && (req.URL.Path == "/healthz" || req.URL.Path == "/readyz") {
		w.WriteHeader(http.StatusOK)
		if _, err := w.Write([]byte("ok")); err != nil {
			// Log the error but don't fail the health check
			r.log.WithError(err).Error("failed to write health check response")
			// Try to set status code in case write partially failed
			w.WriteHeader(http.StatusInternalServerError)
		}
		return true
	}
	return false
}
