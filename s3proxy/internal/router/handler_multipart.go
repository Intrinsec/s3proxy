/*
Copyright (c) Intrinsec 2026

SPDX-License-Identifier: AGPL-3.0-only
*/

package router

import (
	"context"
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"

	"github.com/google/uuid"
	"github.com/intrinsec/s3proxy/internal/multipart"
)

// maxCompleteBodySize caps the CompleteMultipartUpload request body. The body is a
// part list (≤10000 entries of a part number + ETag), so a few MiB is ample and the
// limit guards against a hostile or malformed request forcing an unbounded read.
const maxCompleteBodySize = 8 << 20 // 8 MiB

// handleCreateMultipartUpload (buffer mode) records the request metadata, opens a
// disk-backed session and returns the proxy-generated uploadID.
func (r Router) handleCreateMultipartUpload(key, bucket string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		r.log.Debug("intercepting CreateMultipartUpload (buffer mode)", "path", req.URL.Path, "method", req.Method, "host", req.Host)

		retentionTime, err := parseRetentionTime(req.Header.Get("x-amz-object-lock-retain-until-date"))
		if err != nil {
			r.log.Error("CreateMultipartUpload parsing lock retention time", "error", err)
			r.incError("multipart_create")
			http.Error(w, fmt.Sprintf("parsing x-amz-object-lock-retain-until-date: %s", err.Error()), http.StatusBadRequest)
			return
		}

		meta := multipart.Metadata{
			ContentType:               req.Header.Get("Content-Type"),
			Tags:                      req.Header.Get("x-amz-tagging"),
			UserMetadata:              getMetadataHeaders(req.Header),
			ObjectLockLegalHoldStatus: req.Header.Get("x-amz-object-lock-legal-hold"),
			ObjectLockMode:            req.Header.Get("x-amz-object-lock-mode"),
			ObjectLockRetainUntilDate: retentionTime,
			SSECustomerAlgorithm:      req.Header.Get("x-amz-server-side-encryption-customer-algorithm"),
			SSECustomerKey:            req.Header.Get("x-amz-server-side-encryption-customer-key"),
			SSECustomerKeyMD5:         req.Header.Get("x-amz-server-side-encryption-customer-key-MD5"),
		}

		uploadID, err := r.multipart.Create(bucket, key, meta)
		if err != nil {
			r.log.Error("CreateMultipartUpload", "error", err)
			r.incError("multipart_create")
			http.Error(w, "failed to create multipart upload", http.StatusInternalServerError)
			return
		}

		r.writeXML(w, http.StatusOK, InitiateMultipartUploadResult{
			Bucket:   bucket,
			Key:      key,
			UploadID: uploadID,
		})
	}
}

// handleUploadPart (buffer mode) streams one part to disk, de-framing aws-chunked
// bodies first, and returns the synthesized per-part ETag.
func (r Router) handleUploadPart(key, bucket string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		r.log.Debug("intercepting UploadPart (buffer mode)", "path", req.URL.Path, "method", req.Method, "host", req.Host)

		query := req.URL.Query()
		uploadID := query.Get("uploadId")
		partNumber, err := strconv.Atoi(query.Get("partNumber"))
		if err != nil {
			r.log.Warn("UploadPart invalid part number", "partNumber", query.Get("partNumber"), "error", err)
			r.incError("multipart_upload_part")
			http.Error(w, "invalid partNumber", http.StatusBadRequest)
			return
		}

		var body io.Reader = req.Body
		if isAWSChunked(req.Header) {
			body = newAWSChunkedReader(req.Body)
		}

		etag, err := r.multipart.WritePart(uploadID, partNumber, body)
		if err != nil {
			r.writeMultipartError(w, "UploadPart", err)
			return
		}

		// S3 ETags are quoted; SDKs strip the quotes when collecting parts.
		w.Header().Set("ETag", strconv.Quote(etag))
		w.WriteHeader(http.StatusOK)
	}
}

// handleCompleteMultipartUpload (buffer mode) assembles the buffered parts into one
// plaintext object, encrypts it and stores it upstream as a single PutObject, then
// drops the buffer. It responds 200 only after the upstream store succeeds, mirroring
// the single-shot PutObject ack ordering: an UploadPart ack means "part buffered",
// not "object stored". On upstream failure the session is kept so the client can
// retry Complete.
func (r Router) handleCompleteMultipartUpload(client s3Client, key, bucket string) http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		r.log.Debug("intercepting CompleteMultipartUpload (buffer mode)", "path", req.URL.Path, "method", req.Method, "host", req.Host)

		uploadID := req.URL.Query().Get("uploadId")

		rawBody, err := io.ReadAll(io.LimitReader(req.Body, maxCompleteBodySize+1))
		if err != nil {
			r.log.Error("CompleteMultipartUpload reading body", "error", err)
			r.incError("multipart_complete")
			http.Error(w, "failed to read request body", http.StatusInternalServerError)
			return
		}
		if int64(len(rawBody)) > maxCompleteBodySize {
			r.incError("multipart_complete")
			http.Error(w, "CompleteMultipartUpload body too large", http.StatusRequestEntityTooLarge)
			return
		}

		var complete CompleteMultipartUpload
		if err := xml.Unmarshal(rawBody, &complete); err != nil {
			r.log.Warn("CompleteMultipartUpload malformed body", "error", err)
			r.incError("multipart_complete")
			http.Error(w, "malformed CompleteMultipartUpload body", http.StatusBadRequest)
			return
		}
		if len(complete.Parts) == 0 {
			r.incError("multipart_complete")
			http.Error(w, "CompleteMultipartUpload part list is empty", http.StatusBadRequest)
			return
		}

		parts := make([]int, len(complete.Parts))
		for i, p := range complete.Parts {
			parts[i] = p.PartNumber
		}

		data, meta, err := r.multipart.Assemble(uploadID, parts)
		if err != nil {
			r.writeMultipartError(w, "CompleteMultipartUpload", err)
			return
		}

		obj := object{
			keks:                      r.keks,
			client:                    client,
			key:                       key,
			bucket:                    bucket,
			data:                      data,
			tags:                      meta.Tags,
			contentType:               meta.ContentType,
			metadata:                  meta.UserMetadata,
			objectLockLegalHoldStatus: meta.ObjectLockLegalHoldStatus,
			objectLockMode:            meta.ObjectLockMode,
			objectLockRetainUntilDate: meta.ObjectLockRetainUntilDate,
			sseCustomerAlgorithm:      meta.SSECustomerAlgorithm,
			sseCustomerKey:            meta.SSECustomerKey,
			sseCustomerKeyMD5:         meta.SSECustomerKeyMD5,
			log:                       r.log,
			metrics:                   r.metrics,
		}

		requestID := uuid.New().String()
		log := r.log.With("request_id", requestID)

		// Detach from the request context so a client disconnect cannot abort the
		// in-flight store, but cap the total duration; same as the single-shot path.
		ctx, cancel := context.WithTimeout(context.WithoutCancel(req.Context()), s3OperationTimeout)
		defer cancel()

		output, err := obj.encryptAndUpload(ctx, log)
		if err != nil {
			// Keep the session so the client can retry Complete; never ack a store
			// the upstream did not confirm.
			if code := parseErrorCode(err); code != 0 {
				http.Error(w, err.Error(), code)
				return
			}
			http.Error(w, err.Error(), http.StatusInternalServerError)
			return
		}

		// Object is durably stored upstream; reclaim the on-disk buffer.
		if err := r.multipart.Abort(uploadID); err != nil {
			log.Warn("CompleteMultipartUpload cleaning up buffer", "upload_id", uploadID, "error", err)
		}
		r.incMultipartCompleted()

		etag := ""
		if output.ETag != nil {
			etag = strings.Trim(*output.ETag, "\"")
		}
		r.writeXML(w, http.StatusOK, CompleteMultipartUploadResult{
			Bucket: bucket,
			Key:    key,
			ETag:   strconv.Quote(etag),
		})
	}
}

// handleAbortMultipartUpload (buffer mode) drops the session and its on-disk parts.
// It is idempotent: aborting an unknown upload still returns 204.
func (r Router) handleAbortMultipartUpload() http.HandlerFunc {
	return func(w http.ResponseWriter, req *http.Request) {
		r.log.Debug("intercepting AbortMultipartUpload (buffer mode)", "path", req.URL.Path, "method", req.Method, "host", req.Host)

		uploadID := req.URL.Query().Get("uploadId")
		if err := r.multipart.Abort(uploadID); err != nil {
			r.log.Error("AbortMultipartUpload", "upload_id", uploadID, "error", err)
			r.incError("multipart_abort")
			http.Error(w, "failed to abort multipart upload", http.StatusInternalServerError)
			return
		}
		r.incMultipartAborted()
		w.WriteHeader(http.StatusNoContent)
	}
}

// writeMultipartError maps a Manager error to an HTTP status and writes it.
func (r Router) writeMultipartError(w http.ResponseWriter, op string, err error) {
	switch {
	case errors.Is(err, multipart.ErrUploadNotFound):
		r.log.Warn(op+" upload not found", "error", err)
		r.incError("multipart_not_found")
		http.Error(w, err.Error(), http.StatusNotFound)
	case errors.Is(err, multipart.ErrInvalidPart):
		r.log.Warn(op+" invalid part", "error", err)
		r.incError("multipart_invalid_part")
		http.Error(w, err.Error(), http.StatusBadRequest)
	case errors.Is(err, multipart.ErrObjectTooLarge):
		r.log.Warn(op+" object too large", "error", err)
		r.incError("multipart_too_large")
		http.Error(w, err.Error(), http.StatusRequestEntityTooLarge)
	default:
		r.log.Error(op+" failed", "error", err)
		r.incError("multipart_internal")
		http.Error(w, "internal server error", http.StatusInternalServerError)
	}
}

// writeXML marshals v as an S3-style XML response with the declaration prologue.
func (r Router) writeXML(w http.ResponseWriter, status int, v any) {
	marshalled, err := xml.Marshal(v)
	if err != nil {
		r.log.Error("marshalling XML response", "error", err)
		http.Error(w, "internal server error", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "application/xml")
	w.WriteHeader(status)
	if _, err := w.Write([]byte(xml.Header)); err != nil {
		r.log.Error("writing XML header", "error", err)
		return
	}
	if _, err := w.Write(marshalled); err != nil {
		r.log.Error("writing XML body", "error", err)
	}
}
