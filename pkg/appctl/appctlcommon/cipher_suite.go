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

package appctlcommon

import (
	"fmt"

	pb "github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/cipher"
	"github.com/enfein/mieru/v3/pkg/log"
)

// cipherSuiteMapping maps a cipher suite in the configuration to the cipher
// suite it selects. Every supported suite must have an entry here.
var cipherSuiteMapping = map[pb.CipherSuite]cipher.Suite{
	pb.CipherSuite_CIPHER_SUITE_XCHACHA20_POLY1305: cipher.SuiteXChaCha20Poly1305,
	pb.CipherSuite_CIPHER_SUITE_AES_256_GCM:        cipher.SuiteAES256GCM,
	pb.CipherSuite_CIPHER_SUITE_AES_128_GCM:        cipher.SuiteAES128GCM,
}

// ValidateCipherSuiteList validates a cipher suite list of a server config and
// converts it to cipher suites. It is the validation entry point used for a
// server config cipher suite list, which is the set of suites a server allows
// and never becomes the handshake envelope, so no key length warning applies.
//
// fieldName is the name of the field reported in error messages, which is
// "server config cipherSuites".
//
// An unset or empty list is valid and is returned as an empty list. The
// default suites of an empty list are applied by pkg/protocol: a client uses
// only XChaCha20-Poly1305, and a server accepts every supported suite.
//
// CIPHER_SUITE_UNSPECIFIED and values that are not a supported cipher suite
// are errors, so a misspelled suite is reported instead of being silently
// replaced. Duplicated suites are not an error: they are removed while keeping
// the first occurrence, so the relative preference order is preserved.
//
// A client cipher suite list is a preference list whose first suite is used as
// the handshake envelope. A client config validation path must use
// ValidateClientCipherSuiteList instead, which additionally warns when the list
// limits what the server can negotiate.
func ValidateCipherSuiteList(fieldName string, suites []pb.CipherSuite) ([]cipher.Suite, error) {
	return validateCipherSuiteList(fieldName, suites, false)
}

// ValidateClientCipherSuiteList validates a cipher suite list of a client
// profile, and converts it to cipher suites.
//
// fieldName is the name of the field reported in error messages, which is
// "client profile cipherSuites".
//
// It validates exactly like ValidateCipherSuiteList, and additionally logs a
// warning when the first suite of the list uses a shorter key than a suite
// later in the list. The first suite of a client cipher suite list is the
// handshake envelope, and the server can only negotiate cipher suites whose key
// is not longer than the envelope key, so such a list caps the negotiable
// suites at the key length of its first suite. The warning doesn't change the
// returned suites and doesn't reject the configuration, because the client can
// still connect with the shorter key suites it listed first.
func ValidateClientCipherSuiteList(fieldName string, suites []pb.CipherSuite) ([]cipher.Suite, error) {
	return validateCipherSuiteList(fieldName, suites, true)
}

// validateCipherSuiteList implements ValidateCipherSuiteList and
// ValidateClientCipherSuiteList. clientPreference tells whether suites is a
// client preference list, whose first suite becomes the handshake envelope.
func validateCipherSuiteList(fieldName string, suites []pb.CipherSuite, clientPreference bool) ([]cipher.Suite, error) {
	res := make([]cipher.Suite, 0, len(suites))
	seen := make(map[cipher.Suite]bool, len(suites))
	for i, suite := range suites {
		if suite == pb.CipherSuite_CIPHER_SUITE_UNSPECIFIED {
			return nil, fmt.Errorf("%s[%d] is CIPHER_SUITE_UNSPECIFIED", fieldName, i)
		}
		converted, found := cipherSuiteMapping[suite]
		if !found {
			return nil, fmt.Errorf("%s[%d] is not a supported cipher suite, got value %d", fieldName, i, suite)
		}
		if seen[converted] {
			continue
		}
		seen[converted] = true
		res = append(res, converted)
	}
	if clientPreference {
		warnIfFirstSuiteKeyLenLimitsNegotiation(fieldName, res)
	}
	return res, nil
}

// warnIfFirstSuiteKeyLenLimitsNegotiation logs a warning if the first suite of
// a client cipher suite list uses a shorter key than a later suite of the same
// list. It doesn't return an error: a list like that is a valid configuration,
// it only makes the suites with a longer key unreachable.
func warnIfFirstSuiteKeyLenLimitsNegotiation(fieldName string, suites []cipher.Suite) {
	if len(suites) < 2 {
		return
	}
	first := suites[0]
	for i := 1; i < len(suites); i++ {
		if suites[i].KeyLen() <= first.KeyLen() {
			continue
		}
		log.Warnf("%s[0] is the shorter key cipher suite %v (%d-byte key), while %s[%d] is %v (%d-byte key). The first suite of a client cipher suite list is the handshake envelope, so the server can only negotiate cipher suites with a key of at most %d bytes and %v will never be used; move %v to the front of the list to keep every listed suite negotiable.", fieldName, first, first.KeyLen(), fieldName, i, suites[i], suites[i].KeyLen(), first.KeyLen(), suites[i], suites[i])
		return
	}
}

// CipherSuiteToProtoCipherSuite returns the configuration enum value of a
// cipher suite. It is the inverse of the mapping used by
// ValidateCipherSuiteList, and is used to write or display a resolved cipher
// suite list with the configuration vocabulary.
func CipherSuiteToProtoCipherSuite(suite cipher.Suite) (pb.CipherSuite, bool) {
	for protoSuite, cipherSuite := range cipherSuiteMapping {
		if cipherSuite == suite {
			return protoSuite, true
		}
	}
	return pb.CipherSuite_CIPHER_SUITE_UNSPECIFIED, false
}
