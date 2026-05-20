/*
Copyright (c) Intrinsec 2026

SPDX-License-Identifier: AGPL-3.0-only
*/

package config

import (
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestValidateBucketName(t *testing.T) {
	tests := map[string]struct {
		bucket       string
		wantErrMatch string
	}{
		"valid":               {bucket: "my-valid-bucket"},
		"valid dotted":        {bucket: "logs.prod.example"},
		"empty":               {bucket: "", wantErrMatch: "empty"},
		"too short":           {bucket: "ab", wantErrMatch: "between 3 and 63"},
		"too long":            {bucket: strings.Repeat("a", 64), wantErrMatch: "between 3 and 63"},
		"leading dash":        {bucket: "-bad", wantErrMatch: "invalid bucket name format"},
		"trailing dash":       {bucket: "bad-", wantErrMatch: "invalid bucket name format"},
		"uppercase":           {bucket: "BadBucket", wantErrMatch: "invalid bucket name format"},
		"double dots":         {bucket: "bad..name", wantErrMatch: "invalid character sequences"},
		"dash dot":            {bucket: "bad-.name", wantErrMatch: "invalid character sequences"},
		"looks like ipv4":     {bucket: "192.168.0.1", wantErrMatch: "cannot be an IP address"},
		"contains underscore": {bucket: "bad_name", wantErrMatch: "invalid bucket name format"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := ValidateBucketName(tc.bucket)
			if tc.wantErrMatch == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErrMatch)
		})
	}
}

func TestValidateObjectKey(t *testing.T) {
	tests := map[string]struct {
		key          string
		wantErrMatch string
	}{
		"valid":        {key: "path/to/object"},
		"empty":        {key: "", wantErrMatch: "empty"},
		"max length":   {key: strings.Repeat("a", 1024)},
		"over length":  {key: strings.Repeat("a", 1025), wantErrMatch: "maximum length"},
		"unicode-safe": {key: "éléphant.pdf"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := ValidateObjectKey(tc.key)
			if tc.wantErrMatch == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErrMatch)
		})
	}
}

func TestValidateContentLength(t *testing.T) {
	tests := map[string]struct {
		length       int64
		wantErrMatch string
	}{
		"zero":     {length: 0},
		"one":      {length: 1},
		"at limit": {length: MaxObjectSize},
		"over":     {length: MaxObjectSize + 1, wantErrMatch: "exceeds maximum object size"},
		"negative": {length: -1, wantErrMatch: "invalid content length"},
	}

	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			err := ValidateContentLength(tc.length)
			if tc.wantErrMatch == "" {
				require.NoError(t, err)
				return
			}
			require.Error(t, err)
			assert.Contains(t, err.Error(), tc.wantErrMatch)
		})
	}
}

func TestValidatePutBodySize(t *testing.T) {
	assert.NoError(t, ValidatePutBodySize(0))
	assert.NoError(t, ValidatePutBodySize(DefaultMaxPutBodySize))

	err := ValidatePutBodySize(DefaultMaxPutBodySize + 1)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "exceeds PutObject body cap")
}
