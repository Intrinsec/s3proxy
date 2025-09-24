/*
Copyright (c) Edgeless Systems GmbH
Copyright (c) Intrinsec 2024

SPDX-License-Identifier: AGPL-3.0-only
*/

/*
Package s3 implements a very thin wrapper around the AWS S3 client.
It only exists to enable stubbing of the AWS S3 client in tests.
*/
package s3

import (
	"bytes"
	"context"
	"crypto/md5"
	"encoding/base64"
	"fmt"
	"io"
	"strconv"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/s3"
	"github.com/aws/aws-sdk-go-v2/service/s3/types"
	"github.com/aws/smithy-go/middleware"
	smithyhttp "github.com/aws/smithy-go/transport/http"
	configs3proxy "github.com/intrinsec/s3proxy/internal/config"
)

// Client is a wrapper around the AWS S3 client.
type Client struct {
	s3client *s3.Client
	s3config *aws.Config
}

type RawResponseKey struct{}

type ErrorRawResponse struct {
	err         error
	RawResponse string
}

func (m *ErrorRawResponse) Unwrap() error {
	return m.err
}

func (m *ErrorRawResponse) Error() string {
	return m.RawResponse
}

// Middleware to capture the raw response in the Send phase by cloning and storing the response body
func addCaptureRawResponseDeserializeMiddleware() func(*middleware.Stack) error {
	return func(stack *middleware.Stack) error {
		return stack.Deserialize.Add(middleware.DeserializeMiddlewareFunc("CaptureRawResponseDeserialize", func(
			ctx context.Context, in middleware.DeserializeInput, next middleware.DeserializeHandler,
		) (
			out middleware.DeserializeOutput, metadata middleware.Metadata, err error,
		) {
			out, metadata, err = next.HandleDeserialize(ctx, in)
			if resp, ok := out.RawResponse.(*smithyhttp.Response); ok {
				// It is better not to clone the response body for successful responses
				// because it can consume a lot of memory for large responses and we can not free it ASAP
				if resp.StatusCode >= 400 {
					var bodyBytes []byte

					if cl := resp.Header.Get("Content-Length"); cl != "" {
						if n64, perr := strconv.ParseInt(cl, 10, 64); perr == nil && n64 >= 0 {
							n := int(n64)
							bodyBytes = make([]byte, n)
							// Preallocate the buffer from Content-Length and fill it with io.ReadFull.
							// This avoids the incremental growth and extra copies that io.ReadAll incurs
							// when the final size is unknown, which can blow up RAM on large payloads.
							// If Content-Length is missing or bogus we fall back to ReadAll below.
							if _, rerr := io.ReadFull(resp.Body, bodyBytes); rerr != nil {
								wrap := fmt.Errorf("capture raw response (prealloc) failed: %w", rerr)
								if err != nil {
									return out, metadata, fmt.Errorf("%v; original deserialize error: %w", wrap, err)
								}
								return out, metadata, wrap
							}
						}
					}

					if bodyBytes == nil {
						// Fallback: previous behavior (unbounded ReadAll).
						// NOTE: this may allocate for large bodies; we only use it when CL is missing/invalid.
						b, rerr := io.ReadAll(resp.Body)
						if rerr != nil {
							wrap := fmt.Errorf("capture raw response (ReadAll) failed: %w", rerr)
							if err != nil {
								return out, metadata, fmt.Errorf("%v; original deserialize error: %w", wrap, err)
							}
							return out, metadata, wrap
						}
						bodyBytes = b
					}
					// Restore the original body for further processing
					resp.Body = io.NopCloser(bytes.NewReader(bodyBytes))
				}
			} else {
				metadata.Set(RawResponseKey{}, "")
			}
			return out, metadata, err
		}), middleware.After)
	}
}

func addCaptureRawResponseInitializeMiddleware() func(*middleware.Stack) error {
	return func(stack *middleware.Stack) error {
		return stack.Initialize.Add(middleware.InitializeMiddlewareFunc("CaptureRawResponseInitialize", func(
			ctx context.Context, in middleware.InitializeInput, next middleware.InitializeHandler,
		) (
			out middleware.InitializeOutput, metadata middleware.Metadata, err error,
		) {
			out, metadata, err = next.HandleInitialize(ctx, in)

			if err != nil {
				return out, metadata, &ErrorRawResponse{
					err: err,
					RawResponse: func() string {
						if val, ok := metadata.Get(RawResponseKey{}).(string); ok {
							return val
						}
						return ""
					}(),
				}
			}

			return out, metadata, err

		}), middleware.After)
	}
}

// NewClient creates a new AWS S3 client.
func NewClient(region string) (*Client, error) {
	// Use context.Background here because this context will not influence the later operations of the client.
	// The context given here is used for http requests that are made during client construction.
	// Client construction happens once during proxy setup.
	clientCfg, err := config.LoadDefaultConfig(
		context.Background(),
		config.WithRegion(region),
	)
	if err != nil {
		return nil, fmt.Errorf("loading AWS S3 client config: %w", err)
	}

	host, err := configs3proxy.GetHostConfig()
	if err != nil {
		return nil, fmt.Errorf("loading AWS S3 client config: %w", err)
	}

	client := s3.NewFromConfig(clientCfg, func(o *s3.Options) {
		o.UsePathStyle = true // Ensure "path-style" is used with MinIO
		o.BaseEndpoint = aws.String("https://" + host)
		o.RequestChecksumCalculation = aws.RequestChecksumCalculationWhenRequired
		o.ResponseChecksumValidation = aws.ResponseChecksumValidationWhenRequired
		o.APIOptions = append(o.APIOptions, addCaptureRawResponseDeserializeMiddleware())
		o.APIOptions = append(o.APIOptions, addCaptureRawResponseInitializeMiddleware())
	})

	return &Client{s3client: client, s3config: &clientCfg}, nil
}

func (c Client) GetConfig() *aws.Config {
	return c.s3config
}

// GetObject returns the object with the given key from the given bucket.
// If a versionID is given, the specific version of the object is returned.
func (c Client) GetObject(ctx context.Context, bucket, key, versionID, sseCustomerAlgorithm, sseCustomerKey, sseCustomerKeyMD5 string) (*s3.GetObjectOutput, error) {
	getObjectInput := &s3.GetObjectInput{
		Bucket: &bucket,
		Key:    &key,
	}
	if versionID != "" {
		getObjectInput.VersionId = &versionID
	}
	if sseCustomerAlgorithm != "" {
		getObjectInput.SSECustomerAlgorithm = &sseCustomerAlgorithm
	}
	if sseCustomerKey != "" {
		getObjectInput.SSECustomerKey = &sseCustomerKey
	}
	if sseCustomerKeyMD5 != "" {
		getObjectInput.SSECustomerKeyMD5 = &sseCustomerKeyMD5
	}

	return c.s3client.GetObject(ctx, getObjectInput)
}

// PutObject creates a new object in the given bucket with the given key and body.
// Various optional parameters can be set.
func (c Client) PutObject(ctx context.Context, bucket, key, tags, contentType, objectLockLegalHoldStatus, objectLockMode, sseCustomerAlgorithm, sseCustomerKey, sseCustomerKeyMD5 string, objectLockRetainUntilDate time.Time, metadata map[string]string, body []byte) (*s3.PutObjectOutput, error) {
	// The AWS Go SDK has two versions. V1 does not set the Content-Type header.
	// V2 always sets the Content-Type header. We use V2.
	// The s3 API sets an object's content-type to binary/octet-stream if
	// it receives a request without a Content-Type header set.
	// Since a client using V1 may depend on the Content-Type binary/octet-stream
	// we have to explicitly emulate the S3 API behavior, if we receive a request
	// without a Content-Type.
	if contentType == "" {
		contentType = "binary/octet-stream"
	}

	contentMD5 := md5.Sum(body)
	encodedContentMD5 := base64.StdEncoding.EncodeToString(contentMD5[:])

	putObjectInput := &s3.PutObjectInput{
		Bucket:                    &bucket,
		Key:                       &key,
		Body:                      bytes.NewReader(body),
		Tagging:                   &tags,
		Metadata:                  metadata,
		ContentMD5:                &encodedContentMD5,
		ContentType:               &contentType,
		ObjectLockLegalHoldStatus: types.ObjectLockLegalHoldStatus(objectLockLegalHoldStatus),
	}
	if sseCustomerAlgorithm != "" {
		putObjectInput.SSECustomerAlgorithm = &sseCustomerAlgorithm
	}
	if sseCustomerKey != "" {
		putObjectInput.SSECustomerKey = &sseCustomerKey
	}
	if sseCustomerKeyMD5 != "" {
		putObjectInput.SSECustomerKeyMD5 = &sseCustomerKeyMD5
	}

	// It is not allowed to only set one of these two properties.
	if objectLockMode != "" && !objectLockRetainUntilDate.IsZero() {
		putObjectInput.ObjectLockMode = types.ObjectLockMode(objectLockMode)
		putObjectInput.ObjectLockRetainUntilDate = &objectLockRetainUntilDate
	}

	return c.s3client.PutObject(ctx, putObjectInput)
}
