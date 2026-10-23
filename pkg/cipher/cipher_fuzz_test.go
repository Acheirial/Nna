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
	"testing"
)

// fuzzPasswords are the passwords used by FuzzTryDecrypt. The set is small on
// purpose: every distinct (password, cipher suite) pair pays a key derivation
// and then occupies an entry of the cipher cache, and a fuzz target must stay
// fast without churning that cache.
var fuzzPasswords = [4][]byte{
	[]byte("fuzz-try-decrypt-password-0"),
	[]byte("fuzz-try-decrypt-password-1"),
	[]byte("fuzz-try-decrypt-password-2"),
	[]byte("fuzz-try-decrypt-password-3"),
}

// fuzzStatelessCiphertext encrypts plaintext with a stateless cipher of the
// given cipher suite, which is the same shape a server receives on the wire:
// the nonce, then the sealed plaintext and its tag.
func fuzzStatelessCiphertext(suite Suite, password, plaintext []byte) ([]byte, error) {
	block, err := BlockCipherFromPassword(suite, password, true)
	if err != nil {
		return nil, fmt.Errorf("BlockCipherFromPassword() failed: %w", err)
	}
	if !block.IsStateless() {
		return nil, fmt.Errorf("cipher suite %v is not stateless", suite)
	}
	ciphertext := make([]byte, 0, DefaultNonceSize+len(plaintext)+DefaultOverhead)
	if err := block.Encrypt(ciphertext, plaintext); err != nil {
		return nil, fmt.Errorf("Encrypt() failed: %w", err)
	}
	return ciphertext, nil
}

// fuzzSuiteConfigured returns true when the decryptor was configured to try the
// cipher suite. An empty configuration means all the supported cipher suites.
func fuzzSuiteConfigured(configured []Suite, suite Suite) bool {
	if len(configured) == 0 {
		return suite.IsValid()
	}
	for _, s := range configured {
		if s == suite {
			return true
		}
	}
	return false
}

// FuzzTryDecrypt checks that the stateless decryptor of a server never panics
// for an arbitrary ciphertext, whatever the configured cipher suites and the
// password are, and that a ciphertext it authenticates yields a plaintext of
// the only length the wire format allows: nonce (DefaultNonceSize bytes) and
// AEAD tag (DefaultOverhead bytes) are removed from the ciphertext, and every
// suite uses a 16 bytes tag, so the plaintext is exactly
// len(ciphertext) - DefaultNonceSize - DefaultOverhead bytes long.
//
// The returned cipher must expose one of the configured cipher suites, because
// the caller uses Suite() to decide which suite protects the session.
func FuzzTryDecrypt(f *testing.F) {
	for i, suite := range AllSuites() {
		plaintext := []byte(fmt.Sprintf("shadowlemon try decrypt seed %d", i))
		ciphertext, err := fuzzStatelessCiphertext(suite, fuzzPasswords[0], plaintext)
		if err != nil {
			f.Fatalf("failed to build the seed of cipher suite %v: %v", suite, err)
		}
		f.Add([]byte{byte(i)}, byte(0), ciphertext)
	}
	f.Add([]byte{0, 1, 2}, byte(3), []byte("not an authenticated ciphertext"))
	f.Add([]byte{}, byte(0), []byte{})
	f.Add([]byte{0}, byte(0), make([]byte, DefaultNonceSize+DefaultOverhead))

	f.Fuzz(func(t *testing.T, suiteSeed []byte, passwordSeed byte, ciphertext []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("TryDecrypt(%q) panicked: %v", ciphertext, r)
			}
		}()

		allSuites := AllSuites()
		configured := make([]Suite, 0, len(suiteSeed))
		for _, seed := range suiteSeed {
			configured = append(configured, allSuites[int(seed)%len(allSuites)])
		}
		// A decryptor with dozens of suites is still correct but slow, and the
		// point of this target is the decryption of an arbitrary ciphertext.
		if len(configured) > len(allSuites) {
			configured = configured[:len(allSuites)]
		}
		password := fuzzPasswords[int(passwordSeed)%len(fuzzPasswords)]

		decryptor, err := NewStatelessDecryptor(configured, password)
		if err != nil {
			t.Fatalf("NewStatelessDecryptor(%v) failed: %v", configured, err)
		}
		defer decryptor.Clear()

		block, plaintext, err := decryptor.TryDecrypt(ciphertext, nil)
		if err != nil {
			if block != nil {
				t.Fatalf("TryDecrypt(%q) returned the cipher suite %v along with the error %v", ciphertext, block.Suite(), err)
			}
			if plaintext != nil {
				t.Fatalf("TryDecrypt(%q) returned %d plaintext bytes along with the error %v", ciphertext, len(plaintext), err)
			}
			return
		}
		if block == nil {
			t.Fatalf("TryDecrypt(%q) succeeded without a cipher", ciphertext)
		}
		if suite := block.Suite(); !suite.IsValid() || !fuzzSuiteConfigured(configured, suite) {
			t.Fatalf("TryDecrypt(%q) returned the cipher suite %v, which is not configured", ciphertext, suite)
		}
		if want := len(ciphertext) - DefaultNonceSize - DefaultOverhead; len(plaintext) != want {
			t.Fatalf("TryDecrypt(%q) returned %d plaintext bytes, want %d", ciphertext, len(plaintext), want)
		}
	})
}
