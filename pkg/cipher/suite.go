// Copyright (C) 2026  mieru authors
//
// This program is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.
//
// This program is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.
//
// You should have received a copy of the GNU General Public License
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package cipher

import (
	"fmt"
	"strings"
)

// Suite identifies a symmetric AEAD cipher suite.
//
// The numeric value of a Suite is part of the wire format: it is carried in
// the handshake request and the handshake response. The value of a suite that
// is already in use must never be changed, and a new suite must be appended
// after the existing ones.
type Suite uint8

const (
	// SuiteXChaCha20Poly1305 is XChaCha20-Poly1305 with a 32 bytes key. Its
	// AEAD nonce is 24 bytes long, which is the whole wire format nonce.
	SuiteXChaCha20Poly1305 Suite = 0

	// SuiteAES256GCM is AES-256-GCM with a 32 bytes key. Its AEAD nonce is the
	// last 12 bytes of the 24 bytes wire format nonce, see aeadNonce().
	SuiteAES256GCM Suite = 1

	// SuiteAES128GCM is AES-128-GCM with a 16 bytes key. Its AEAD nonce is the
	// last 12 bytes of the 24 bytes wire format nonce, see aeadNonce().
	SuiteAES128GCM Suite = 2
)

// AEAD nonce derivation (frozen).
//
// The wire format always carries a DefaultNonceSize (24) bytes nonce, no matter
// which suite protects the data. The AEAD nonce is derived from the wire format
// nonce as:
//
//	aeadNonce = wireNonce[len(wireNonce)-aead.NonceSize():]
//
// That is the last AEAD nonce size bytes of the wire format nonce.
//
//   - XChaCha20-Poly1305 needs 24 bytes, so it consumes the whole wire format
//     nonce and its behavior is identical to before the suite abstraction.
//   - AES-256-GCM and AES-128-GCM need 12 bytes, so they consume
//     wireNonce[12:24].
//
// The first 12 bytes of the wire format nonce must never be used as a GCM
// nonce. The nonce pattern is allowed to rewrite them with bytes chosen by the
// user (NoncePattern minLen, maxLen and the custom hex strings are all
// validated to be at most 12 bytes long), so they may be a deterministic value.
// The last 12 bytes contain the random region [12:20] and the user hint
// [20:24], and the payload nonce flips byte 16, which belongs to that region as
// well. Therefore the metadata AEAD nonce and the payload AEAD nonce of the same
// message stay different for AES-GCM too.

const (
	// minAEADNonceLen is the AEAD nonce size of the supported cipher suite
	// with the shortest nonce, which is AES-GCM.
	minAEADNonceLen = 12

	// maxNoncePatternLen is the maximum number of leading bytes of the wire
	// format nonce that a nonce pattern is allowed to rewrite.
	//
	// A nonce pattern replaces the beginning of the wire nonce with bytes
	// chosen by the user, and those bytes may be a fixed value, while the bytes
	// of the AES-GCM AEAD nonce (the last minAEADNonceLen bytes of the wire
	// nonce) must stay random. If a pattern could rewrite up to
	// DefaultNonceSize bytes, the AES-GCM AEAD nonce would become a
	// deterministic value: two messages could be sealed with the same AEAD
	// nonce, and the payload nonce flip of byte 16 would be applied on top of
	// bytes picked by the pattern instead of random bytes. The wire nonce
	// prefix is therefore clamped to maxNoncePatternLen by nonceRewriteLen()
	// and newNonceTo() in addition to the "at most 12 bytes" validation done by
	// apis/trafficpattern, so this package never relies on the caller to keep
	// the AES-GCM AEAD nonce out of reach of the pattern.
	maxNoncePatternLen = DefaultNonceSize - minAEADNonceLen
)

// String returns the name of the cipher suite.
func (s Suite) String() string {
	switch s {
	case SuiteXChaCha20Poly1305:
		return "XCHACHA20_POLY1305"
	case SuiteAES256GCM:
		return "AES_256_GCM"
	case SuiteAES128GCM:
		return "AES_128_GCM"
	default:
		return fmt.Sprintf("Suite(%d)", uint8(s))
	}
}

// KeyLen returns the length in bytes of the key used by the cipher suite,
// or 0 if the suite is invalid.
func (s Suite) KeyLen() int {
	switch s {
	case SuiteXChaCha20Poly1305, SuiteAES256GCM:
		return 32
	case SuiteAES128GCM:
		return 16
	default:
		return 0
	}
}

// IsValid returns true if the cipher suite is supported by this build.
func (s Suite) IsValid() bool {
	switch s {
	case SuiteXChaCha20Poly1305, SuiteAES256GCM, SuiteAES128GCM:
		return true
	default:
		return false
	}
}

// suiteNameReplacer normalizes the separators used in a cipher suite name, so
// that "AES_256_GCM", "aes-256-gcm" and "Aes256Gcm" are all accepted.
var suiteNameReplacer = strings.NewReplacer("_", "", "-", "", " ", "")

// ParseSuite parses a cipher suite name. The name is case insensitive, and
// '_', '-' and ' ' separators are optional.
func ParseSuite(name string) (Suite, bool) {
	switch suiteNameReplacer.Replace(strings.ToUpper(strings.TrimSpace(name))) {
	case "XCHACHA20POLY1305":
		return SuiteXChaCha20Poly1305, true
	case "AES256GCM":
		return SuiteAES256GCM, true
	case "AES128GCM":
		return SuiteAES128GCM, true
	default:
		return 0, false
	}
}

// AllSuites returns all the cipher suites supported by this build, from the
// most preferred to the least preferred one. The result is a new slice, the
// caller can modify it.
func AllSuites() []Suite {
	return []Suite{SuiteXChaCha20Poly1305, SuiteAES256GCM, SuiteAES128GCM}
}
