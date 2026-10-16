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
)

// cipherSuiteMapping maps a cipher suite in the configuration to the cipher
// suite it selects. Every supported suite must have an entry here.
var cipherSuiteMapping = map[pb.CipherSuite]cipher.Suite{
	pb.CipherSuite_CIPHER_SUITE_XCHACHA20_POLY1305: cipher.SuiteXChaCha20Poly1305,
	pb.CipherSuite_CIPHER_SUITE_AES_256_GCM:        cipher.SuiteAES256GCM,
	pb.CipherSuite_CIPHER_SUITE_AES_128_GCM:        cipher.SuiteAES128GCM,
}

// ValidateCipherSuiteList validates a cipher suite list of a client profile or
// a server config, and converts it to cipher suites.
//
// fieldName is the name of the field reported in error messages, which is
// "client profile cipherSuites" or "server config cipherSuites".
//
// An unset or empty list is valid and is returned as an empty list. The
// default suites of an empty list are applied by pkg/protocol: a client uses
// only XChaCha20-Poly1305, and a server accepts every supported suite.
//
// CIPHER_SUITE_UNSPECIFIED and values that are not a supported cipher suite
// are errors, so a misspelled suite is reported instead of being silently
// replaced. Duplicated suites are not an error: they are removed while keeping
// the first occurrence, so the relative preference order is preserved.
func ValidateCipherSuiteList(fieldName string, suites []pb.CipherSuite) ([]cipher.Suite, error) {
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
	return res, nil
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
