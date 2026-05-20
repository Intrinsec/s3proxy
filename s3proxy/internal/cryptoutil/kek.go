/*
Copyright (c) Intrinsec 2026

SPDX-License-Identifier: AGPL-3.0-only
*/

package cryptoutil

import (
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"
)

// KEK versions tagged on stored objects to identify the derivation scheme used when
// the object's DEK was wrapped. Unknown or missing versions fall back to the legacy
// derivation so data encrypted before this change remains readable.
const (
	// KEKVersionLegacy is the v0 derivation: sha256(seed). Assumed when the metadata
	// tag is absent on an object, for backward compatibility with data written before
	// HKDF was introduced.
	KEKVersionLegacy = ""
	// KEKVersionV1 is HKDF-SHA256 over the seed with a fixed salt and info label.
	KEKVersionV1 = "1"
	// KEKVersionCurrent is the version used for new writes.
	KEKVersionCurrent = KEKVersionV1
)

// kekV1Salt is the HKDF salt for KEK v1. A constant salt is acceptable per RFC 5869
// when the seed (S3PROXY_ENCRYPT_KEY) is already high-entropy; the info string below
// is what makes the derived key context-specific.
var kekV1Salt = sha256.Sum256([]byte("s3proxy-kek-salt-v1"))

// kekV1Info is the HKDF info/context for KEK v1. Changing it produces a new KEK.
const kekV1Info = "s3proxy/kek/v1"

// KEKProvider holds every KEK derivation needed to read and write objects. New
// encryptions use KEKVersionCurrent; decryption picks the derivation matching the
// version tag recorded on the object.
type KEKProvider struct {
	legacy [32]byte
	v1     [32]byte
}

// NewKEKProvider derives every supported KEK from the given seed.
// seed must not be empty.
func NewKEKProvider(seed string) (KEKProvider, error) {
	if seed == "" {
		return KEKProvider{}, fmt.Errorf("KEK seed is empty")
	}

	legacy := sha256.Sum256([]byte(seed))

	var v1 [32]byte
	reader := hkdf.New(sha256.New, []byte(seed), kekV1Salt[:], []byte(kekV1Info))
	if _, err := io.ReadFull(reader, v1[:]); err != nil {
		return KEKProvider{}, fmt.Errorf("deriving HKDF KEK v1: %w", err)
	}

	return KEKProvider{legacy: legacy, v1: v1}, nil
}

// For returns the KEK matching the given version. ok is false when version is unknown.
func (p KEKProvider) For(version string) (kek [32]byte, ok bool) {
	switch version {
	case KEKVersionLegacy:
		return p.legacy, true
	case KEKVersionV1:
		return p.v1, true
	default:
		return [32]byte{}, false
	}
}

// Current returns the version tag and KEK to use for new encryptions.
func (p KEKProvider) Current() (version string, kek [32]byte) {
	return KEKVersionCurrent, p.v1
}
