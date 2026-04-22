/*
Copyright (c) Intrinsec 2026

SPDX-License-Identifier: AGPL-3.0-only
*/

package router

import (
	"fmt"
	"io"
)

func readBody(body io.Reader, contentLength int64) ([]byte, error) {
	if contentLength <= 0 {
		return io.ReadAll(body)
	}
	if contentLength > int64(int(^uint(0)>>1)) {
		return nil, fmt.Errorf("content length %d exceeds maximum supported size", contentLength)
	}

	bodyBytes := make([]byte, int(contentLength))
	if _, err := io.ReadFull(body, bodyBytes); err != nil {
		return nil, err
	}
	return bodyBytes, nil
}
