/*
Copyright (c) Intrinsec 2026

SPDX-License-Identifier: AGPL-3.0-only
*/

package router

import (
	"net/http"
	"regexp"
	"testing"
	"time"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestMatchReturnsFalseWhenPathHasNoMatch(t *testing.T) {
	var bucket, key string
	pattern := regexp.MustCompile("/([^/?]+)/(.+)")
	assert.False(t, match("/", pattern, &bucket, &key))
	assert.Empty(t, bucket)
	assert.Empty(t, key)
}

func TestMatchExtractsBucketAndKey(t *testing.T) {
	var bucket, key string
	pattern := regexp.MustCompile("/([^/?]+)/(.+)")
	require.True(t, match("/my-bucket/path/to/object", pattern, &bucket, &key))
	assert.Equal(t, "my-bucket", bucket)
	assert.Equal(t, "path/to/object", key)
}

func TestGetMetadataHeadersLowercasesAndStripsPrefix(t *testing.T) {
	h := http.Header{}
	h.Set("X-Amz-Meta-Tag", "value-one")
	h.Add("x-amz-meta-multi", "a")
	h.Add("x-amz-meta-multi", "b")
	h.Set("X-Amz-Other", "ignored")
	h.Set("Content-Type", "ignored/type")

	got := getMetadataHeaders(h)

	assert.Equal(t, "value-one", got["tag"])
	assert.Equal(t, "a,b", got["multi"])
	_, hasOther := got["other"]
	assert.False(t, hasOther, "non-meta headers must be excluded")
}

func TestParseRetentionTimeRFC3339(t *testing.T) {
	empty, err := parseRetentionTime("")
	require.NoError(t, err)
	assert.True(t, empty.IsZero())

	want := time.Date(2031, time.March, 15, 9, 30, 0, 0, time.UTC)
	got, err := parseRetentionTime(want.Format(time.RFC3339))
	require.NoError(t, err)
	assert.True(t, got.Equal(want))

	_, err = parseRetentionTime("not-a-date")
	assert.Error(t, err)
}

func TestSha256Sum(t *testing.T) {
	// Known value: sha256("") = e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
	assert.Equal(t, "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855", sha256sum(nil))
}

func TestIsUnwantedGetEndpoint(t *testing.T) {
	tests := map[string]struct {
		query string
		want  bool
	}{
		"plain get":  {query: "", want: false},
		"acl":        {query: "acl=", want: true},
		"tagging":    {query: "tagging=", want: true},
		"list parts": {query: "uploadId=abc", want: true},
	}
	for name, tc := range tests {
		t.Run(name, func(t *testing.T) {
			req, err := http.NewRequest(http.MethodGet, "http://example/b/k?"+tc.query, nil)
			require.NoError(t, err)
			assert.Equal(t, tc.want, isUnwantedGetEndpoint(req.URL.Query()))
		})
	}
}

func TestIsUnwantedPutEndpoint(t *testing.T) {
	req, err := http.NewRequest(http.MethodPut, "http://example/b/k", nil)
	require.NoError(t, err)
	assert.False(t, isUnwantedPutEndpoint(req.Header, req.URL.Query()))

	// x-amz-copy-source marker
	req.Header.Set("X-Amz-Copy-Source", "other/source")
	assert.True(t, isUnwantedPutEndpoint(req.Header, req.URL.Query()))
}
