/*
Copyright (c) Intrinsec 2026

SPDX-License-Identifier: AGPL-3.0-only
*/

package router

import (
	"bufio"
	"encoding/xml"
	"fmt"
	"io"
	"net/http"
	"strconv"
	"strings"
)

// InitiateMultipartUploadResult is the XML body returned by CreateMultipartUpload.
// It carries the proxy-generated uploadID the client replays on every subsequent
// UploadPart/Complete/Abort request.
type InitiateMultipartUploadResult struct {
	XMLName  xml.Name `xml:"InitiateMultipartUploadResult"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	UploadID string   `xml:"UploadId"`
}

// CompleteMultipartUpload is the XML body sent by the client on
// CompleteMultipartUpload. Only the part numbers are used by the proxy: the parts
// are assembled from the on-disk buffer in the listed order. The per-part ETags are
// ignored because the proxy stores the assembled object as a single encrypted
// PutObject and does not reproduce S3's composite ETag.
type CompleteMultipartUpload struct {
	XMLName xml.Name        `xml:"CompleteMultipartUpload"`
	Parts   []CompletedPart `xml:"Part"`
}

// CompletedPart is one entry of a CompleteMultipartUpload part list.
type CompletedPart struct {
	PartNumber int    `xml:"PartNumber"`
	ETag       string `xml:"ETag"`
}

// CompleteMultipartUploadResult is the XML body returned by CompleteMultipartUpload.
// The ETag is the upstream PutObject ETag (of the ciphertext), not S3's
// "md5-of-md5s-N" composite form; standard SDKs do not validate the composite.
type CompleteMultipartUploadResult struct {
	XMLName  xml.Name `xml:"CompleteMultipartUploadResult"`
	Location string   `xml:"Location"`
	Bucket   string   `xml:"Bucket"`
	Key      string   `xml:"Key"`
	ETag     string   `xml:"ETag"`
}

// isAWSChunked reports whether an UploadPart body carries aws-chunked transfer
// framing. SDKs signal this with Content-Encoding: aws-chunked and/or a streaming
// x-amz-content-sha256 marker (STREAMING-AWS4-HMAC-SHA256-PAYLOAD,
// STREAMING-UNSIGNED-PAYLOAD-TRAILER, …). The raw object bytes are recovered by
// stripping the per-chunk size+signature headers.
func isAWSChunked(header http.Header) bool {
	if strings.Contains(strings.ToLower(header.Get("Content-Encoding")), "aws-chunked") {
		return true
	}
	return strings.HasPrefix(header.Get("x-amz-content-sha256"), "STREAMING-")
}

// awsChunkedReader strips aws-chunked transfer framing from an UploadPart body,
// yielding the raw object bytes. The framing is a sequence of
//
//	<hex-size>;chunk-signature=<sig>\r\n<data>\r\n
//
// terminated by a zero-size chunk (optionally followed by trailing headers, which
// this reader does not need and leaves unread). Only the hex size before the first
// ';' is significant; the signature is ignored because the upstream request is
// re-signed by the proxy.
type awsChunkedReader struct {
	br        *bufio.Reader
	remaining int64 // unread bytes in the current chunk's data
	done      bool
}

func newAWSChunkedReader(r io.Reader) *awsChunkedReader {
	return &awsChunkedReader{br: bufio.NewReader(r)}
}

func (c *awsChunkedReader) Read(p []byte) (int, error) {
	for c.remaining == 0 {
		if c.done {
			return 0, io.EOF
		}
		if err := c.advance(); err != nil {
			return 0, err
		}
	}

	if int64(len(p)) > c.remaining {
		p = p[:c.remaining]
	}
	n, err := c.br.Read(p)
	c.remaining -= int64(n)
	if err != nil {
		if err == io.EOF {
			err = io.ErrUnexpectedEOF
		}
		return n, err
	}
	if c.remaining == 0 {
		if err := c.consumeCRLF(); err != nil {
			return n, err
		}
	}
	return n, nil
}

// advance reads the next chunk header line and sets remaining (or done on the
// terminating zero-size chunk).
func (c *awsChunkedReader) advance() error {
	line, err := c.br.ReadString('\n')
	if err != nil {
		return fmt.Errorf("reading aws-chunked header: %w", err)
	}
	header := strings.TrimRight(line, "\r\n")
	if i := strings.IndexByte(header, ';'); i >= 0 {
		header = header[:i]
	}
	header = strings.TrimSpace(header)
	size, err := strconv.ParseInt(header, 16, 64)
	if err != nil {
		return fmt.Errorf("parsing aws-chunked size %q: %w", header, err)
	}
	if size < 0 {
		return fmt.Errorf("negative aws-chunked size %d", size)
	}
	if size == 0 {
		c.done = true
		return nil
	}
	c.remaining = size
	return nil
}

// consumeCRLF reads and validates the CRLF that terminates a chunk's data.
func (c *awsChunkedReader) consumeCRLF() error {
	var crlf [2]byte
	if _, err := io.ReadFull(c.br, crlf[:]); err != nil {
		return fmt.Errorf("reading aws-chunked CRLF: %w", err)
	}
	if crlf[0] != '\r' || crlf[1] != '\n' {
		return fmt.Errorf("malformed aws-chunked framing: expected CRLF after chunk data")
	}
	return nil
}
