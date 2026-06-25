/*
Copyright (c) Intrinsec 2024

SPDX-License-Identifier: AGPL-3.0-only
*/

package router

import (
	"fmt"
	"regexp"
	"strconv"

	"github.com/intrinsec/s3proxy/internal/cryptoutil"
)

// sizeElementPattern matches a <Size>N</Size> element. In ListObjects v1/v2 responses this
// element only appears inside <Contents>, so a targeted byte-preserving substitution avoids
// the namespace/formatting loss of an encoding/xml round-trip that could break S3 clients.
var sizeElementPattern = regexp.MustCompile(`<Size>(\d+)</Size>`)

// rewriteListSizes replaces each <Size>N</Size> in a ListObjects response with
// max(0, N-EncryptionOverhead), reporting the decrypted plaintext size. The clamp at 0 covers
// 0-byte folder markers and objects not written through the proxy (smaller than the overhead).
// Everything outside the matched elements is preserved byte-for-byte.
func rewriteListSizes(body []byte) []byte {
	return sizeElementPattern.ReplaceAllFunc(body, func(m []byte) []byte {
		n, err := strconv.Atoi(string(sizeElementPattern.FindSubmatch(m)[1]))
		if err != nil {
			// Unparseable (e.g. overflows int) — leave the element untouched.
			return m
		}
		dec := n - cryptoutil.EncryptionOverhead
		if dec < 0 {
			dec = 0
		}
		return []byte(fmt.Sprintf("<Size>%d</Size>", dec))
	})
}
