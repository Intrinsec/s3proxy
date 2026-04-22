/*
Copyright (c) Intrinsec 2026

SPDX-License-Identifier: AGPL-3.0-only
*/

package s3

import (
	"io"
	"strings"
	"testing"

	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

func TestReadBodyUsesKnownContentLength(t *testing.T) {
	body, err := readBody(strings.NewReader("hello"), 5)

	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), body)
	assert.Equal(t, 5, cap(body))
}

func TestReadBodyFallsBackWhenContentLengthUnknown(t *testing.T) {
	body, err := readBody(strings.NewReader("hello"), -1)

	require.NoError(t, err)
	assert.Equal(t, []byte("hello"), body)
}

func TestReadBodyReturnsErrorOnShortBody(t *testing.T) {
	_, err := readBody(strings.NewReader("hi"), 5)

	assert.ErrorIs(t, err, io.ErrUnexpectedEOF)
}
