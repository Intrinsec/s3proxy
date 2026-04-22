/*
Copyright (c) Intrinsec 2026

SPDX-License-Identifier: AGPL-3.0-only
*/

package main

import (
	"net/http"
	"net/http/httptest"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestIsHealthCheckRequest(t *testing.T) {
	tests := map[string]struct {
		method string
		path   string
		want   bool
	}{
		"healthz": {
			method: http.MethodGet,
			path:   "/healthz",
			want:   true,
		},
		"readyz": {
			method: http.MethodGet,
			path:   "/readyz",
			want:   true,
		},
		"wrong method": {
			method: http.MethodPost,
			path:   "/healthz",
		},
		"wrong path": {
			method: http.MethodGet,
			path:   "/bucket/key",
		},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			req := httptest.NewRequest(tc.method, tc.path, nil)

			assert.Equal(t, tc.want, isHealthCheckRequest(req))
		})
	}
}
