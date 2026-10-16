// Copyright (C) 2022  mieru authors
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
	"bytes"
	"testing"
	"time"
)

func TestGetBlockCipherList(t *testing.T) {
	password := string([]byte{0x00, 0xff, 0x08, 0x09, 0x06, 0x04})
	ciphers, err := getBlockCipherList(password, SuiteXChaCha20Poly1305, true)
	if err != nil {
		t.Fatalf("getBlockCipherList() failed: %v", err)
	}
	if len(ciphers) != 3 {
		t.Fatalf("number of ciphers = %d, want %d", len(ciphers), 3)
	}
	for _, cipher := range ciphers {
		if !cipher.IsStateless() {
			t.Errorf("IsStateless() = %v, want %v", cipher.IsStateless(), true)
		}
	}

	ciphers, err = getBlockCipherList(password, SuiteXChaCha20Poly1305, false)
	if err != nil {
		t.Fatalf("getBlockCipherList() failed: %v", err)
	}
	if len(ciphers) != 3 {
		t.Fatalf("number of ciphers = %d, want %d", len(ciphers), 3)
	}
	for _, cipher := range ciphers {
		if cipher.IsStateless() {
			t.Errorf("IsStateless() = %v, want %v", cipher.IsStateless(), false)
		}
	}
}

func TestGetCachedCiphersKeyedBySuite(t *testing.T) {
	password := string([]byte{0x11, 0x22, 0x33})
	now := time.Now()
	first, err := getCachedCiphers(password, SuiteXChaCha20Poly1305, now)
	if err != nil {
		t.Fatalf("getCachedCiphers() failed: %v", err)
	}
	// The same password and cipher suite must hit the same cache entry.
	again, err := getCachedCiphers(password, SuiteXChaCha20Poly1305, now)
	if err != nil {
		t.Fatalf("getCachedCiphers() failed: %v", err)
	}
	if first != again {
		t.Errorf("getCachedCiphers() returned a different entry for the same password and suite")
	}
	// A different cipher suite must use a different cache entry.
	//
	// The key material of a suite is the prefix of the PBKDF2 output (see the
	// frozen design), so suites with the same KeyLen() hold identical key bytes
	// by design, and the suite itself is the only thing that separates their
	// ciphertexts. What must be verified here is the suite of the cached cipher
	// and that newBlockCipher() retained only suite.KeyLen() bytes of the
	// PBKDF2 output.
	for _, suite := range []Suite{SuiteAES256GCM, SuiteAES128GCM} {
		other, err := getCachedCiphers(password, suite, now)
		if err != nil {
			t.Fatalf("getCachedCiphers(%s) failed: %v", suite, err)
		}
		if other == first {
			t.Errorf("getCachedCiphers(%s) returned the entry of %s", suite, SuiteXChaCha20Poly1305)
		}
		if got := other.cipherList[1].Suite(); got != suite {
			t.Errorf("cached cipher suite = %s, want %s", got, suite)
		}
		// XChaCha20-Poly1305 uses the whole DefaultKeyLen (32) bytes PBKDF2
		// output as its key, so the key of any other suite must be its prefix.
		keyLen := suite.KeyLen()
		if !bytes.Equal(other.cipherList[1].key[:keyLen], first.cipherList[1].key[:keyLen]) {
			t.Errorf("getCachedCiphers(%s) key is not the PBKDF2 key prefix of %s", suite, SuiteXChaCha20Poly1305)
		}
		for i := keyLen; i < DefaultKeyLen; i++ {
			if other.cipherList[1].key[i] != 0 {
				t.Errorf("getCachedCiphers(%s) retained key byte %d = %d, want 0", suite, i, other.cipherList[1].key[i])
			}
		}
	}
	// A different password must use a different cache entry.
	otherPassword, err := getCachedCiphers(password+"x", SuiteXChaCha20Poly1305, now)
	if err != nil {
		t.Fatalf("getCachedCiphers() failed: %v", err)
	}
	if otherPassword == first {
		t.Errorf("getCachedCiphers() returned the same entry for different passwords")
	}
}
