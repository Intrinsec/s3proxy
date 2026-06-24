/*
Copyright (c) Intrinsec 2026

SPDX-License-Identifier: AGPL-3.0-only
*/

package config

import (
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMultipartBufferDir(t *testing.T) {
	t.Run("unset disables buffer mode", func(t *testing.T) {
		cfg, err := Load()
		require.NoError(t, err)
		assert.Empty(t, cfg.MultipartBufferDir())
	})

	t.Run("set returns the directory", func(t *testing.T) {
		t.Setenv("S3PROXY_MULTIPART_BUFFER_DIR", "/var/lib/s3proxy/parts")
		cfg, err := Load()
		require.NoError(t, err)
		assert.Equal(t, "/var/lib/s3proxy/parts", cfg.MultipartBufferDir())
	})
}

func TestMultipartMaxSize(t *testing.T) {
	tests := map[string]struct {
		set  bool
		env  string
		want int64
	}{
		"unset defaults to MaxObjectSize": {set: false, want: MaxObjectSize},
		"valid value honoured":            {set: true, env: "104857600", want: 104857600},
		"at limit honoured":               {set: true, env: "5368709120", want: MaxObjectSize},
		"over limit clamps to default":    {set: true, env: "5368709121", want: MaxObjectSize},
		"zero falls back to default":      {set: true, env: "0", want: MaxObjectSize},
		"negative falls back to default":  {set: true, env: "-1", want: MaxObjectSize},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if tc.set {
				t.Setenv("S3PROXY_MULTIPART_MAX_SIZE", tc.env)
			}
			cfg, err := Load()
			require.NoError(t, err)
			assert.Equal(t, tc.want, cfg.MultipartMaxSize())
		})
	}
}

func TestMultipartTTL(t *testing.T) {
	tests := map[string]struct {
		set  bool
		env  string
		want time.Duration
	}{
		"unset defaults to 24h":       {set: false, want: DefaultMultipartTTL},
		"valid duration honoured":     {set: true, env: "1h30m", want: 90 * time.Minute},
		"empty falls back to default": {set: true, env: "", want: DefaultMultipartTTL},
		"unparseable falls back":      {set: true, env: "nope", want: DefaultMultipartTTL},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			if tc.set {
				t.Setenv("S3PROXY_MULTIPART_TTL", tc.env)
			}
			cfg, err := Load()
			require.NoError(t, err)
			assert.Equal(t, tc.want, cfg.MultipartTTL())
		})
	}
}
