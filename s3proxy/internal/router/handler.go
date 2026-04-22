/*
Copyright (c) Edgeless Systems GmbH
Copyright (c) Intrinsec 2024

SPDX-License-Identifier: AGPL-3.0-only
*/

package router

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/intrinsec/s3proxy/internal/config"
	"github.com/intrinsec/s3proxy/internal/cryptoutil"
	"github.com/intrinsec/s3proxy/internal/monitoring"
	"github.com/intrinsec/s3proxy/internal/s3"
	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
)

func handleGetObject(client s3Client, key string, bucket string, keks cryptoutil.KEKProvider, log *slog.Logger, metrics *monitoring.Metrics) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		log.Debug("intercepting", "path", req.URL.Path, "method", req.Method, "host", req.Host)
		if req.Header.Get("Range") != "" {
			log.Error("GetObject Range header unsupported")
			http.Error(w, "s3proxy currently does not support Range headers", http.StatusNotImplemented)
			return
		}

		versionID := ""
		if versionIDs, ok := req.URL.Query()["versionId"]; ok && len(versionIDs) > 0 {
			versionID = versionIDs[0]
		}

		obj := object{
			keks:                 keks,
			client:               client,
			key:                  key,
			bucket:               bucket,
			query:                req.URL.Query(),
			versionID:            versionID,
			sseCustomerAlgorithm: req.Header.Get("x-amz-server-side-encryption-customer-algorithm"),
			sseCustomerKey:       req.Header.Get("x-amz-server-side-encryption-customer-key"),
			sseCustomerKeyMD5:    req.Header.Get("x-amz-server-side-encryption-customer-key-MD5"),
			log:                  log,
			metrics:              metrics,
		}
		requireGET(obj.get)(w, req)
	}
}

func handlePutObject(client s3Client, key string, bucket string, keks cryptoutil.KEKProvider, log *slog.Logger, metrics *monitoring.Metrics) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		log.Debug("intercepting", "path", req.URL.Path, "method", req.Method, "host", req.Host)

		body, err := readBody(req.Body, req.ContentLength, config.GetMaxPutBodySize())
		if err != nil {
			if errors.Is(err, errBodyTooLarge) {
				log.Warn("PutObject body too large", "error", err)
				http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
				return
			}
			log.Error("PutObject reading body", "error", err)
			http.Error(w, "failed to read request body", http.StatusInternalServerError)
			return
		}

		clientDigest := req.Header.Get("x-amz-content-sha256")
		serverDigest := sha256sum(body)

		// There may be a client that wants to test that incorrect content digests result in API errors.
		// For encrypting the body we have to recalculate the content digest.
		// If the client intentionally sends a mismatching content digest, we would take the client request, rewrap it,
		// calculate the correct digest for the new body and NOT get an error.
		// Thus we have to check incoming requets for matching content digests.
		// UNSIGNED-PAYLOAD can be used to disabled payload signing. In that case we don't check the content digest.
		if clientDigest != "" && clientDigest != "UNSIGNED-PAYLOAD" && clientDigest != serverDigest {
			log.Debug("PutObject", "error", "x-amz-content-sha256 mismatch")
			// The S3 API responds with an XML formatted error message.
			mismatchErr := NewContentSHA256MismatchError(clientDigest, serverDigest)
			marshalled, err := xml.Marshal(mismatchErr)
			if err != nil {
				log.Error("PutObject", "error", err)
				http.Error(w, fmt.Sprintf("marshalling error: %s", err.Error()), http.StatusInternalServerError)
				return
			}

			http.Error(w, string(marshalled), http.StatusBadRequest)
			return
		}

		metadata := getMetadataHeaders(req.Header)

		raw := req.Header.Get("x-amz-object-lock-retain-until-date")
		retentionTime, err := parseRetentionTime(raw)
		if err != nil {
			log.Error("parsing lock retention time", "data", raw, "error", err)
			http.Error(w, fmt.Sprintf("parsing x-amz-object-lock-retain-until-date: %s", err.Error()), http.StatusInternalServerError)
			return
		}

		err = validateContentMD5(req.Header.Get("content-md5"), body)
		if err != nil {
			log.Error("validating content md5", "error", err)
			http.Error(w, fmt.Sprintf("validating content md5: %s", err.Error()), http.StatusBadRequest)
			return
		}

		obj := object{
			keks:                      keks,
			client:                    client,
			key:                       key,
			bucket:                    bucket,
			data:                      body,
			query:                     req.URL.Query(),
			tags:                      req.Header.Get("x-amz-tagging"),
			contentType:               req.Header.Get("Content-Type"),
			metadata:                  metadata,
			objectLockLegalHoldStatus: req.Header.Get("x-amz-object-lock-legal-hold"),
			objectLockMode:            req.Header.Get("x-amz-object-lock-mode"),
			objectLockRetainUntilDate: retentionTime,
			sseCustomerAlgorithm:      req.Header.Get("x-amz-server-side-encryption-customer-algorithm"),
			sseCustomerKey:            req.Header.Get("x-amz-server-side-encryption-customer-key"),
			sseCustomerKeyMD5:         req.Header.Get("x-amz-server-side-encryption-customer-key-MD5"),
			log:                       log,
			metrics:                   metrics,
		}

		requirePUT(obj.put)(w, req)
	}
}

func handleForwards(client *s3.Client, log *slog.Logger, metrics *monitoring.Metrics) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		log.Debug("forwarding", "path", req.URL.Path, "method", req.Method, "host", req.Host)

		newReq, err := repackage(req)
		if err != nil {
			log.Error("failed to repackage request", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		cfg := client.GetConfig()

		creds, err := cfg.Credentials.Retrieve(context.TODO())
		if err != nil {
			log.Error("unable to retrieve aws creds", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		signer := v4.NewSigner()

		err = signer.SignHTTP(context.TODO(), creds, newReq, newReq.Header.Get("X-Amz-Content-Sha256"), "s3", cfg.Region, time.Now())
		if err != nil {
			log.Error("failed to sign request", "error", err)
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		resp, err := forwardHTTPClient.Do(newReq)
		if err != nil {
			log.Error("do request", "error", err)
			if metrics != nil {
				metrics.UpstreamErrors.Inc()
			}
			http.Error(w, "do request: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer func() {
			if cerr := resp.Body.Close(); cerr != nil {
				log.Error("failed to close upstream response body", "error", cerr)
			}
		}()

		// Preserve multi-value headers (Set-Cookie, Vary, etc.).
		for key, values := range resp.Header {
			w.Header()[key] = values
		}
		w.WriteHeader(resp.StatusCode)

		if _, err := io.Copy(w, resp.Body); err != nil {
			log.Error("failed to stream response", "error", err)
			// Headers already written; cannot send error response.
		}
	}
}

// forwardHTTPClient is the HTTP client used to send signed requests to the upstream S3 API.
// The transport is wrapped in otelhttp so outgoing requests propagate the W3C TraceContext
// and record a client span under the inbound request's span.
var forwardHTTPClient = &http.Client{
	Timeout: 5 * time.Minute,
	Transport: otelhttp.NewTransport(&http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	}),
}

// handleCreateMultipartUpload logs the request and blocks with an error message.
func handleCreateMultipartUpload(log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		log.Debug("intercepting CreateMultipartUpload", "path", req.URL.Path, "method", req.Method, "host", req.Host)

		log.Error("Blocking CreateMultipartUpload request")
		http.Error(w, "s3proxy is configured to block CreateMultipartUpload requests", http.StatusNotImplemented)
	}
}

// handleUploadPart logs the request and blocks with an error message.
func handleUploadPart(log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		log.Debug("intercepting UploadPart", "path", req.URL.Path, "method", req.Method, "host", req.Host)

		log.Error("Blocking UploadPart request")
		http.Error(w, "s3proxy is configured to block UploadPart requests", http.StatusNotImplemented)
	}
}

// handleCompleteMultipartUpload logs the request and blocks with an error message.
func handleCompleteMultipartUpload(log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		log.Debug("intercepting CompleteMultipartUpload", "path", req.URL.Path, "method", req.Method, "host", req.Host)

		log.Error("Blocking CompleteMultipartUpload request")
		http.Error(w, "s3proxy is configured to block CompleteMultipartUpload requests", http.StatusNotImplemented)
	}
}

// handleAbortMultipartUpload logs the request and blocks with an error message.
func handleAbortMultipartUpload(log *slog.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		log.Debug("intercepting AbortMultipartUpload", "path", req.URL.Path, "method", req.Method, "host", req.Host)

		log.Error("Blocking AbortMultipartUpload request")
		http.Error(w, "s3proxy is configured to block AbortMultipartUpload requests", http.StatusNotImplemented)
	}
}
