package config

import (
	"fmt"
	"regexp"
)

// ValidateConfiguration validates all required configuration at startup
func ValidateConfiguration() error {
	// Validate encryption key
	encryptKey, err := GetEncryptKey()
	if err != nil {
		return fmt.Errorf("validating encryption key: %w", err)
	}
	if encryptKey == "" {
		return fmt.Errorf("encryption key cannot be empty")
	}

	// Validate host configuration
	host, err := GetHostConfig()
	if err != nil {
		return fmt.Errorf("validating host configuration: %w", err)
	}
	if host == "" {
		return fmt.Errorf("host configuration cannot be empty")
	}

	// Validate host format (basic check)
	hostPattern := regexp.MustCompile(`^[a-zA-Z0-9.-]+\.[a-zA-Z]{2,}$`)
	if !hostPattern.MatchString(host) {
		return fmt.Errorf("invalid host format: %s", host)
	}

	return nil
}

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

// MaxObjectSize defines the maximum allowed object size (5GB for S3)
const MaxObjectSize = 5 * 1024 * 1024 * 1024

// ValidateContentLength validates the content length of a request
func ValidateContentLength(contentLength int64) error {
	if contentLength < 0 {
		return fmt.Errorf("invalid content length: %d", contentLength)
	}

	if contentLength > MaxObjectSize {
		return fmt.Errorf("content length %d exceeds maximum object size of %d bytes", contentLength, MaxObjectSize)
	}

	return nil
}
