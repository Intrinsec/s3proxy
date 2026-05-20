package config

import (
	"errors"
	"fmt"
	"regexp"
)

// Validate asserts that the required s3proxy configuration is present and well-formed.
func (c *Config) Validate() error {
	encryptKey, err := c.EncryptKey()
	if err != nil {
		return fmt.Errorf("validating encryption key: %w", err)
	}
	if encryptKey == "" {
		return errors.New("encryption key cannot be empty")
	}

	host, err := c.Host()
	if err != nil {
		return fmt.Errorf("validating host configuration: %w", err)
	}
	if host == "" {
		return errors.New("host configuration cannot be empty")
	}

	if !hostPattern.MatchString(host) {
		return fmt.Errorf("invalid host format: %s", host)
	}

	return nil
}

// ValidateConfiguration validates the default package-level Config. Prefer
// (*Config).Validate in new code.
func ValidateConfiguration() error {
	return Default().Validate()
}

var hostPattern = regexp.MustCompile(`^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)

// ValidateBucketName validates S3 bucket naming rules
func ValidateBucketName(bucket string) error {
	if bucket == "" {
		return fmt.Errorf("bucket name cannot be empty")
	}

	if len(bucket) < 3 || len(bucket) > 63 {
		return fmt.Errorf("bucket name must be between 3 and 63 characters long")
	}

	// Bucket naming rules
	bucketPattern := regexp.MustCompile(`^[a-z0-9][a-z0-9.-]*[a-z0-9]$`)
	if !bucketPattern.MatchString(bucket) {
		return fmt.Errorf("invalid bucket name format: %s", bucket)
	}

	// Check for consecutive dots or hyphens
	invalidPattern := regexp.MustCompile(`\.\.|-\.|\.-|--`)
	if invalidPattern.MatchString(bucket) {
		return fmt.Errorf("bucket name contains invalid character sequences: %s", bucket)
	}

	// Check if it looks like an IP address
	ipPattern := regexp.MustCompile(`^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}$`)
	if ipPattern.MatchString(bucket) {
		return fmt.Errorf("bucket name cannot be an IP address: %s", bucket)
	}

	return nil
}

// ValidateObjectKey validates S3 object key
func ValidateObjectKey(key string) error {
	if key == "" {
		return fmt.Errorf("object key cannot be empty")
	}

	if len(key) > 1024 {
		return fmt.Errorf("object key exceeds maximum length of 1024 characters")
	}

	return nil
}

// MaxObjectSize is the S3 hard cap on a single PutObject (5 GiB).
const MaxObjectSize = 5 * 1024 * 1024 * 1024

// DefaultMaxPutBodySize is the default per-request PutObject body size ceiling enforced
// by s3proxy. Because PutObject currently buffers the full body in memory to encrypt it,
// this cap bounds memory pressure: N concurrent uploads allocate at most N * cap bytes.
// Operators can raise this via S3PROXY_PUTBODY_MAX (bytes) up to MaxObjectSize once a
// streaming encryption path is introduced.
const DefaultMaxPutBodySize = 256 * 1024 * 1024

// ValidateContentLength validates the content length of a request against the S3 hard cap.
func ValidateContentLength(contentLength int64) error {
	if contentLength < 0 {
		return fmt.Errorf("invalid content length: %d", contentLength)
	}

	if contentLength > MaxObjectSize {
		return fmt.Errorf("content length %d exceeds maximum object size of %d bytes", contentLength, MaxObjectSize)
	}

	return nil
}

// ValidatePutBodySize validates the content length of a PutObject request against the
// in-memory cap enforced by s3proxy (see GetMaxPutBodySize). A content length of 0 or
// below is accepted here — the caller must still protect io.ReadAll against a body that
// has no declared length.
func ValidatePutBodySize(contentLength int64) error {
	maxBytes := GetMaxPutBodySize()
	if contentLength > maxBytes {
		return fmt.Errorf("content length %d exceeds PutObject body cap of %d bytes", contentLength, maxBytes)
	}
	return nil
}
