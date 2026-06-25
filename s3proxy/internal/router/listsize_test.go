/*
Copyright (c) Intrinsec 2024

SPDX-License-Identifier: AGPL-3.0-only
*/

package router

import (
	"fmt"
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestRewriteListSizes(t *testing.T) {
	tests := map[string]struct {
		in   int
		want int
	}{
		"zero clamps to zero":             {in: 0, want: 0},
		"below overhead clamps to zero":   {in: 5, want: 0},
		"exactly overhead clamps to zero": {in: 28, want: 0},
		"one byte plaintext":              {in: 29, want: 1},
		"large object":                    {in: 1610890, want: 1610862},
	}

	for name, tt := range tests {
		t.Run(name, func(t *testing.T) {
			body := []byte(fmt.Sprintf("<Size>%d</Size>", tt.in))
			got := rewriteListSizes(body)
			assert.Equal(t, fmt.Sprintf("<Size>%d</Size>", tt.want), string(got))
		})
	}
}

// TestRewriteListSizesPreservesStructure asserts only <Size> values change; surrounding XML —
// including CommonPrefixes (directories, which carry no <Size>) — is byte-for-byte preserved.
func TestRewriteListSizesPreservesStructure(t *testing.T) {
	body := []byte(`<?xml version="1.0" encoding="UTF-8"?>` +
		`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">` +
		`<Name>bucket</Name>` +
		`<Contents><Key>a.txt</Key><Size>1610890</Size><ETag>"abc"</ETag></Contents>` +
		`<Contents><Key>b.txt</Key><Size>28</Size></Contents>` +
		`<CommonPrefixes><Prefix>dir/</Prefix></CommonPrefixes>` +
		`</ListBucketResult>`)

	want := []byte(`<?xml version="1.0" encoding="UTF-8"?>` +
		`<ListBucketResult xmlns="http://s3.amazonaws.com/doc/2006-03-01/">` +
		`<Name>bucket</Name>` +
		`<Contents><Key>a.txt</Key><Size>1610862</Size><ETag>"abc"</ETag></Contents>` +
		`<Contents><Key>b.txt</Key><Size>0</Size></Contents>` +
		`<CommonPrefixes><Prefix>dir/</Prefix></CommonPrefixes>` +
		`</ListBucketResult>`)

	assert.Equal(t, string(want), string(rewriteListSizes(body)))
}

func TestRewriteListSizesNoSizeElement(t *testing.T) {
	body := []byte(`<ListBucketResult><CommonPrefixes><Prefix>dir/</Prefix></CommonPrefixes></ListBucketResult>`)
	assert.Equal(t, string(body), string(rewriteListSizes(body)))
}
