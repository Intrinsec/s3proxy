/*
Copyright (c) Edgeless Systems GmbH
Copyright (c) Intrinsec 2024

SPDX-License-Identifier: AGPL-3.0-only
*/

package router

import (
	"context"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"time"

	v4 "github.com/aws/aws-sdk-go-v2/aws/signer/v4"
	"github.com/intrinsec/s3proxy/internal/s3"
	logger "github.com/sirupsen/logrus"
)

func handleGetObject(client s3Client, key string, bucket string, kek [32]byte, log *logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		log.WithField("path", req.URL.Path).WithField("method", req.Method).WithField("host", req.Host).Debug("intercepting")
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
			kek:                  kek,
			client:               client,
			key:                  key,
			bucket:               bucket,
			query:                req.URL.Query(),
			versionID:            versionID,
			sseCustomerAlgorithm: req.Header.Get("x-amz-server-side-encryption-customer-algorithm"),
			sseCustomerKey:       req.Header.Get("x-amz-server-side-encryption-customer-key"),
			sseCustomerKeyMD5:    req.Header.Get("x-amz-server-side-encryption-customer-key-MD5"),
			log:                  log,
		}
		requireGET(obj.get)(w, req)
	}
}

func handlePutObject(client s3Client, key string, bucket string, kek [32]byte, log *logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		log.WithField("path", req.URL.Path).WithField("method", req.Method).WithField("host", req.Host).Debug("intercepting")

		body, err := readBody(req.Body, req.ContentLength)
		if err != nil {
			log.WithField("error", err).Error("PutObject reading body")
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
			log.WithField("error", "x-amz-content-sha256 mismatch").Debug("PutObject")
			// The S3 API responds with an XML formatted error message.
			mismatchErr := NewContentSHA256MismatchError(clientDigest, serverDigest)
			marshalled, err := xml.Marshal(mismatchErr)
			if err != nil {
				log.WithField("error", err).Error("PutObject")
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
			log.WithField("data", raw).WithField("error", err).Error("parsing lock retention time")
			http.Error(w, fmt.Sprintf("parsing x-amz-object-lock-retain-until-date: %s", err.Error()), http.StatusInternalServerError)
			return
		}

		err = validateContentMD5(req.Header.Get("content-md5"), body)
		if err != nil {
			log.WithField("error", err).Error("validating content md5")
			http.Error(w, fmt.Sprintf("validating content md5: %s", err.Error()), http.StatusBadRequest)
			return
		}

		obj := object{
			kek:                       kek,
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
		}

		requirePUT(obj.put)(w, req)
	}
}

func handleForwards(client *s3.Client, log *logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		log.WithField("path", req.URL.Path).WithField("method", req.Method).WithField("host", req.Host).Debug("forwarding")

		newReq, err := repackage(req)
		if err != nil {
			log.WithField("error", err).Error("failed to repackage request")
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		cfg := client.GetConfig()

		creds, err := cfg.Credentials.Retrieve(context.TODO())
		if err != nil {
			log.WithField("error", err).Error("unable to retrieve aws creds")
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		signer := v4.NewSigner()

		err = signer.SignHTTP(context.TODO(), creds, newReq, newReq.Header.Get("X-Amz-Content-Sha256"), "s3", cfg.Region, time.Now())
		if err != nil {
			log.WithField("error", err).Error("failed to sign request")
			http.Error(w, "internal server error", http.StatusInternalServerError)
			return
		}

		resp, err := forwardHTTPClient.Do(newReq)
		if err != nil {
			log.WithField("error", err).Error("do request")
			http.Error(w, "do request: "+err.Error(), http.StatusInternalServerError)
			return
		}
		defer func() {
			if cerr := resp.Body.Close(); cerr != nil {
				log.WithError(cerr).Error("failed to close upstream response body")
			}
		}()

		// Preserve multi-value headers (Set-Cookie, Vary, etc.).
		for key, values := range resp.Header {
			w.Header()[key] = values
		}
		w.WriteHeader(resp.StatusCode)

		if _, err := io.Copy(w, resp.Body); err != nil {
			log.WithField("error", err).Error("failed to stream response")
			// Headers already written; cannot send error response.
		}
	}
}

// forwardHTTPClient is the HTTP client used to send signed requests to the upstream S3 API.
// Separate from http.DefaultClient so we can tune timeouts and transport independently.
var forwardHTTPClient = &http.Client{
	Timeout: 5 * time.Minute,
	Transport: &http.Transport{
		MaxIdleConns:        100,
		MaxIdleConnsPerHost: 10,
		IdleConnTimeout:     90 * time.Second,
	},
}

// handleCreateMultipartUpload logs the request and blocks with an error message.
func handleCreateMultipartUpload(log *logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		log.WithField("path", req.URL.Path).WithField("method", req.Method).WithField("host", req.Host).Debug("intercepting CreateMultipartUpload")

		log.Error("Blocking CreateMultipartUpload request")
		http.Error(w, "s3proxy is configured to block CreateMultipartUpload requests", http.StatusNotImplemented)
	}
}

// handleUploadPart logs the request and blocks with an error message.
func handleUploadPart(log *logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		log.WithField("path", req.URL.Path).WithField("method", req.Method).WithField("host", req.Host).Debug("intercepting UploadPart")

		log.Error("Blocking UploadPart request")
		http.Error(w, "s3proxy is configured to block UploadPart requests", http.StatusNotImplemented)
	}
}

// handleCompleteMultipartUpload logs the request and blocks with an error message.
func handleCompleteMultipartUpload(log *logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		log.WithField("path", req.URL.Path).WithField("method", req.Method).WithField("host", req.Host).Debug("intercepting CompleteMultipartUpload")

		log.Error("Blocking CompleteMultipartUpload request")
		http.Error(w, "s3proxy is configured to block CompleteMultipartUpload requests", http.StatusNotImplemented)
	}
}

// handleAbortMultipartUpload logs the request and blocks with an error message.
func handleAbortMultipartUpload(log *logger.Logger) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		log.WithField("path", req.URL.Path).WithField("method", req.Method).WithField("host", req.Host).Debug("intercepting AbortMultipartUpload")

		log.Error("Blocking AbortMultipartUpload request")
		http.Error(w, "s3proxy is configured to block AbortMultipartUpload requests", http.StatusNotImplemented)
	}
}
