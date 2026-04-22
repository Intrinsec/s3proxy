/*
Copyright (c) Intrinsec 2026

SPDX-License-Identifier: AGPL-3.0-only
*/

package router

import (
	"errors"
	"fmt"
	"io"
)

// errBodyTooLarge is returned when a request body exceeds the configured PutObject cap.
var errBodyTooLarge = errors.New("request body exceeds configured PutObject body cap")

// readBody reads up to maxBytes+1 from body. If contentLength > 0 it pre-sizes the
// destination buffer; otherwise it reads incrementally. Returns errBodyTooLarge when
// the body is strictly larger than maxBytes (detected by reading one sentinel byte
// past the cap).
func readBody(body io.Reader, contentLength, maxBytes int64) ([]byte, error) {
	if maxBytes > 0 && contentLength > maxBytes {
		return nil, errBodyTooLarge
	}
	if contentLength > int64(int(^uint(0)>>1)) {
		return nil, fmt.Errorf("content length %d exceeds maximum supported size", contentLength)
	}

	// When a cap is set we read one extra byte beyond it so we can detect over-cap
	// bodies with unknown ContentLength. With no cap we pass the body reader through
	// untouched.
	reader := body
	if maxBytes > 0 {
		reader = io.LimitReader(body, maxBytes+1)
	}

	var out []byte
	if contentLength > 0 {
		buf := make([]byte, int(contentLength))
		if _, err := io.ReadFull(reader, buf); err != nil {
			return nil, err
		}
		out = buf
	} else {
		b, err := io.ReadAll(reader)
		if err != nil {
			return nil, err
		}
		out = b
	}
	if maxBytes > 0 && int64(len(out)) > maxBytes {
		return nil, errBodyTooLarge
	}
	return out, nil
}
