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
	"bytes"
	crand "crypto/rand"
	"crypto/sha256"
	"strings"
	"testing"
	"time"

	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"golang.org/x/crypto/pbkdf2"
	"google.golang.org/protobuf/proto"
)

// randomBytes returns n random bytes.
func randomBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		t.Fatalf("crypto/rand.Read() failed: %v", err)
	}
	return b
}

// cloneBytes returns a copy of b.
func cloneBytes(b []byte) []byte {
	c := make([]byte, len(b))
	copy(c, b)
	return c
}

// sealWithNonce encrypts plaintext with block and the given wire format nonce.
//
// EncryptWithNonce() seals into the backing array of dst and returns only an
// error, so the caller must provide a dst slice whose capacity holds the
// complete result and then expose that result by re-slicing dst to its
// capacity. Returning dst itself would return a zero length slice.
func sealWithNonce(t *testing.T, block BlockCipher, nonce, plaintext []byte) []byte {
	t.Helper()
	ciphertext := make([]byte, 0, len(plaintext)+block.Overhead())
	if err := block.EncryptWithNonce(ciphertext, nonce, plaintext); err != nil {
		t.Fatalf("EncryptWithNonce() failed: %v", err)
	}
	return ciphertext[:cap(ciphertext)]
}

var testSuiteProperties = []struct {
	suite     Suite
	name      string
	keyLen    int
	nonceSize int // AEAD nonce size
}{
	{SuiteXChaCha20Poly1305, "XCHACHA20_POLY1305", 32, 24},
	{SuiteAES256GCM, "AES_256_GCM", 32, 12},
	{SuiteAES128GCM, "AES_128_GCM", 16, 12},
}

func TestSuiteNameKeyLenAndValidity(t *testing.T) {
	for _, test := range testSuiteProperties {
		if got := test.suite.String(); got != test.name {
			t.Errorf("Suite(%d).String() = %q, want %q", uint8(test.suite), got, test.name)
		}
		if got := test.suite.KeyLen(); got != test.keyLen {
			t.Errorf("%s.KeyLen() = %d, want %d", test.name, got, test.keyLen)
		}
		if !test.suite.IsValid() {
			t.Errorf("%s.IsValid() = false, want true", test.name)
		}
	}

	// Invalid suites must not report a name, a key length or validity.
	for _, invalid := range []Suite{3, 4, 255} {
		if invalid.IsValid() {
			t.Errorf("Suite(%d).IsValid() = true, want false", uint8(invalid))
		}
		if got := invalid.KeyLen(); got != 0 {
			t.Errorf("Suite(%d).KeyLen() = %d, want 0", uint8(invalid), got)
		}
		if got := invalid.String(); !strings.HasPrefix(got, "Suite(") {
			t.Errorf("Suite(%d).String() = %q, want the numeric value in the name", uint8(invalid), got)
		}
	}
}

func TestParseSuite(t *testing.T) {
	for _, test := range testSuiteProperties {
		names := []string{
			test.name,
			strings.ToLower(test.name),
			strings.ToLower(strings.ReplaceAll(test.name, "_", "-")),
			strings.ReplaceAll(test.name, "_", ""),
			"  " + strings.ToLower(test.name) + "  ",
		}
		for _, name := range names {
			got, ok := ParseSuite(name)
			if !ok {
				t.Errorf("ParseSuite(%q) failed", name)
				continue
			}
			if got != test.suite {
				t.Errorf("ParseSuite(%q) = %d, want %d", name, uint8(got), uint8(test.suite))
			}
		}
	}

	for _, name := range []string{"", "AES_192_GCM", "CHACHA20_POLY1305", "XCHACHA20", "0", "1", "2"} {
		if got, ok := ParseSuite(name); ok {
			t.Errorf("ParseSuite(%q) = %d, want a parse error", name, uint8(got))
		}
	}
}

func TestAllSuites(t *testing.T) {
	all := AllSuites()
	if len(all) != len(testSuiteProperties) {
		t.Fatalf("AllSuites() has %d suites, want %d", len(all), len(testSuiteProperties))
	}
	for i, test := range testSuiteProperties {
		if all[i] != test.suite {
			t.Errorf("AllSuites()[%d] = %d, want %d", i, uint8(all[i]), uint8(test.suite))
		}
	}
	// The returned slice must be owned by the caller.
	all[0] = Suite(99)
	if got := AllSuites()[0]; got != SuiteXChaCha20Poly1305 {
		t.Errorf("modifying the result of AllSuites() changed the next call: got %d", uint8(got))
	}
}

func TestSuiteRoundTrip(t *testing.T) {
	for _, test := range testSuiteProperties {
		t.Run(test.name, func(t *testing.T) {
			key := randomBytes(t, test.keyLen)
			plaintext := randomBytes(t, 1024)

			// Stateless cipher, in-band wire nonce.
			send, err := NewBlockCipherFromKey(test.suite, key, true)
			if err != nil {
				t.Fatalf("NewBlockCipherFromKey() failed: %v", err)
			}
			if got := send.Suite(); got != test.suite {
				t.Errorf("Suite() = %s, want %s", got, test.suite)
			}
			if !send.IsStateless() {
				t.Errorf("IsStateless() = false, want true")
			}
			if got := send.NonceSize(); got != DefaultNonceSize {
				t.Errorf("NonceSize() = %d, want %d", got, DefaultNonceSize)
			}
			if got := send.Overhead(); got != DefaultOverhead {
				t.Errorf("Overhead() = %d, want %d", got, DefaultOverhead)
			}
			ciphertext := make([]byte, send.NonceSize()+len(plaintext)+send.Overhead())
			if err := send.Encrypt(ciphertext[:0], plaintext); err != nil {
				t.Fatalf("Encrypt() failed: %v", err)
			}
			recv, err := NewBlockCipherFromKey(test.suite, key, true)
			if err != nil {
				t.Fatalf("NewBlockCipherFromKey() failed: %v", err)
			}
			plaintext2, err := recv.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt() failed: %v", err)
			}
			if !bytes.Equal(plaintext, plaintext2) {
				t.Errorf("plaintext after Decrypt() is different")
			}

			// Stateless cipher, explicit wire nonce.
			wireNonce := randomBytes(t, DefaultNonceSize)
			sealed := sealWithNonce(t, send, wireNonce, plaintext)
			opened, err := send.DecryptWithNonce(sealed, wireNonce)
			if err != nil {
				t.Fatalf("DecryptWithNonce() failed: %v", err)
			}
			if !bytes.Equal(plaintext, opened) {
				t.Errorf("plaintext after DecryptWithNonce() is different")
			}
			// The wrong nonce must differ inside the AEAD nonce of the suite,
			// which is the last test.nonceSize bytes of the wire nonce. A
			// difference in the prefix would be invisible to AES-GCM, whose
			// AEAD nonce is wireNonce[12:24], and the decrypt would succeed.
			wrongNonce := cloneBytes(wireNonce)
			wrongNonce[DefaultNonceSize-1] ^= 0x01
			if _, err := send.DecryptWithNonce(sealed, wrongNonce); err == nil {
				t.Errorf("DecryptWithNonce() accepted a wrong nonce")
			}

			// Payload path. EncryptPayloadWithNonce() appends in place, so the
			// result is exposed by re-slicing payload to its capacity.
			payload := make([]byte, 0, len(plaintext)+send.Overhead())
			if err := send.EncryptPayloadWithNonce(payload, wireNonce, plaintext); err != nil {
				t.Fatalf("EncryptPayloadWithNonce() failed: %v", err)
			}
			payload = payload[:cap(payload)]
			openedPayload, err := send.DecryptPayloadWithNonce(payload, wireNonce)
			if err != nil {
				t.Fatalf("DecryptPayloadWithNonce() failed: %v", err)
			}
			if !bytes.Equal(plaintext, openedPayload) {
				t.Errorf("plaintext after DecryptPayloadWithNonce() is different")
			}

			// Stateful cipher, implicit nonce. Every packet must use a
			// distinct AEAD nonce.
			statefulSend, err := NewBlockCipherFromKey(test.suite, key, false)
			if err != nil {
				t.Fatalf("NewBlockCipherFromKey() failed: %v", err)
			}
			if statefulSend.IsStateless() {
				t.Errorf("IsStateless() = true, want false")
			}
			statefulRecv := statefulSend.Clone()
			aead := statefulSend.(*aeadBlockCipher)
			seen := make(map[string]bool)
			for i := range 4 {
				resultLen := len(plaintext) + statefulSend.Overhead()
				if i == 0 {
					resultLen += DefaultNonceSize
				}
				out := make([]byte, 0, resultLen)
				if err := statefulSend.Encrypt(out, plaintext); err != nil {
					t.Fatalf("Encrypt() failed: %v", err)
				}
				out = out[:cap(out)]
				if got := string(aead.aeadNonce(aead.implicitNonce)); seen[got] {
					t.Fatalf("packet %d reused an AEAD nonce", i)
				} else {
					seen[got] = true
				}
				plaintext3, err := statefulRecv.Decrypt(out)
				if err != nil {
					t.Fatalf("Decrypt() failed: %v", err)
				}
				if !bytes.Equal(plaintext, plaintext3) {
					t.Errorf("plaintext after Decrypt() is different")
				}
			}
		})
	}
}

func TestSuiteCrossDecryptFails(t *testing.T) {
	// All the cipher suites use the same key material, so only the suite
	// itself separates the ciphertexts.
	key := randomBytes(t, DefaultKeyLen)
	plaintext := []byte("cross suite plaintext")
	for _, producer := range testSuiteProperties {
		block, err := NewBlockCipherFromKey(producer.suite, key, true)
		if err != nil {
			t.Fatalf("NewBlockCipherFromKey(%s) failed: %v", producer.name, err)
		}
		ciphertext := make([]byte, block.NonceSize()+len(plaintext)+block.Overhead())
		if err := block.Encrypt(ciphertext[:0], plaintext); err != nil {
			t.Fatalf("Encrypt() failed: %v", err)
		}
		for _, consumer := range testSuiteProperties {
			other, err := NewBlockCipherFromKey(consumer.suite, key, true)
			if err != nil {
				t.Fatalf("NewBlockCipherFromKey(%s) failed: %v", consumer.name, err)
			}
			got, err := other.Decrypt(ciphertext)
			if producer.suite == consumer.suite {
				if err != nil {
					t.Fatalf("%s ciphertext can't be decrypted by %s: %v", producer.name, consumer.name, err)
				}
				if !bytes.Equal(got, plaintext) {
					t.Errorf("plaintext after Decrypt() is different")
				}
				continue
			}
			if err == nil {
				t.Errorf("%s ciphertext was decrypted by %s", producer.name, consumer.name)
			}
		}
	}
}

// TestAEADNonceIsDerivedFromWireNonceTail checks the frozen AEAD nonce
// derivation rule against an AEAD object that is instantiated independently.
func TestAEADNonceIsDerivedFromWireNonceTail(t *testing.T) {
	key := randomBytes(t, DefaultKeyLen)
	plaintext := []byte("aead nonce derivation plaintext")
	for _, test := range testSuiteProperties {
		t.Run(test.name, func(t *testing.T) {
			block, err := NewBlockCipherFromKey(test.suite, key, true)
			if err != nil {
				t.Fatalf("NewBlockCipherFromKey() failed: %v", err)
			}
			aead := block.(*aeadBlockCipher).aead
			if got := aead.NonceSize(); got != test.nonceSize {
				t.Fatalf("AEAD nonce size = %d, want %d", got, test.nonceSize)
			}
			if got := aead.Overhead(); got != DefaultOverhead {
				t.Errorf("AEAD overhead = %d, want %d", got, DefaultOverhead)
			}

			wireNonce := randomBytes(t, DefaultNonceSize)
			sealed := sealWithNonce(t, block, wireNonce, plaintext)
			want := aead.Seal(nil, wireNonce[DefaultNonceSize-test.nonceSize:], plaintext, nil)
			if !bytes.Equal(sealed, want) {
				t.Errorf("ciphertext was not produced with wireNonce[%d:%d] as the AEAD nonce",
					DefaultNonceSize-test.nonceSize, DefaultNonceSize)
			}
			if test.nonceSize == DefaultNonceSize {
				// XChaCha20-Poly1305 consumes the whole wire nonce.
				if !bytes.Equal(sealed, aead.Seal(nil, wireNonce, plaintext, nil)) {
					t.Errorf("ciphertext was not produced with the whole wire nonce")
				}
				return
			}
			// AES-GCM must not use the first 12 bytes of the wire nonce, they
			// may be rewritten by the nonce pattern with deterministic bytes.
			if bytes.Equal(sealed, aead.Seal(nil, wireNonce[:12], plaintext, nil)) {
				t.Errorf("AES-GCM used wireNonce[:12] as the AEAD nonce")
			}
			if _, err := aead.Open(nil, wireNonce[:12], sealed, nil); err == nil {
				t.Errorf("ciphertext was opened with wireNonce[:12]")
			}
			// A wire nonce that only differs in the first 12 bytes must
			// produce the same ciphertext, which proves the prefix is unused.
			otherWireNonce := cloneBytes(wireNonce)
			copy(otherWireNonce[:12], randomBytes(t, 12))
			if !bytes.Equal(sealed, sealWithNonce(t, block, otherWireNonce, plaintext)) {
				t.Errorf("changing wireNonce[:12] changed the AES-GCM ciphertext")
			}
			// The hint in the last 4 bytes and the payload flip of byte 16 are
			// inside the AEAD nonce, so changing the tail changes the result.
			tailNonce := cloneBytes(wireNonce)
			tailNonce[DefaultNonceSize-1] ^= 0x01
			if bytes.Equal(sealed, sealWithNonce(t, block, tailNonce, plaintext)) {
				t.Errorf("changing wireNonce[23] did not change the AES-GCM ciphertext")
			}
		})
	}
}

// TestPayloadNonceDomainSeparation checks that the metadata and the payload of
// the same message never share an AEAD nonce, including for AES-GCM where the
// AEAD nonce is a truncation of the wire nonce.
func TestPayloadNonceDomainSeparation(t *testing.T) {
	// payloadNonceOffset must stay outside the nonce pattern region and inside
	// the AEAD nonce of every suite, otherwise flipping it wouldn't change the
	// AES-GCM AEAD nonce.
	if payloadNonceOffset < maxNoncePatternLen {
		t.Fatalf("payloadNonceOffset = %d, want at least %d", payloadNonceOffset, maxNoncePatternLen)
	}

	key := randomBytes(t, DefaultKeyLen)
	plaintext := []byte("metadata and payload of the same message")
	for _, test := range testSuiteProperties {
		t.Run(test.name, func(t *testing.T) {
			block, err := NewBlockCipherFromKey(test.suite, key, true)
			if err != nil {
				t.Fatalf("NewBlockCipherFromKey() failed: %v", err)
			}
			aead := block.(*aeadBlockCipher).aead
			wireNonce := randomBytes(t, DefaultNonceSize)
			metadataAEADNonce := block.(*aeadBlockCipher).aeadNonce(wireNonce)
			payloadWireNonce := payloadNonce(wireNonce)
			payloadAEADNonce := block.(*aeadBlockCipher).aeadNonce(payloadWireNonce)
			if bytes.Equal(metadataAEADNonce, payloadAEADNonce) {
				t.Fatalf("metadata AEAD nonce %x equals payload AEAD nonce %x", metadataAEADNonce, payloadAEADNonce)
			}
			if aead.NonceSize() == 12 {
				// The AES-GCM nonces are the last 12 bytes of the wire nonces.
				if !bytes.Equal(metadataAEADNonce, wireNonce[12:24]) {
					t.Errorf("metadata AEAD nonce = %x, want %x", metadataAEADNonce, wireNonce[12:24])
				}
				if bytes.Equal(wireNonce[12:24], payloadWireNonce[12:24]) {
					t.Fatalf("metadata wire nonce and payload wire nonce share their last 12 bytes")
				}
				if payloadAEADNonce[payloadNonceOffset-12] == wireNonce[payloadNonceOffset] {
					t.Errorf("payload AEAD nonce byte %d was not flipped", payloadNonceOffset-12)
				}
			}

			// The payload must not be readable with the metadata AEAD nonce.
			payload := make([]byte, 0, len(plaintext)+block.Overhead())
			if err := block.EncryptPayloadWithNonce(payload, wireNonce, plaintext); err != nil {
				t.Fatalf("EncryptPayloadWithNonce() failed: %v", err)
			}
			payload = payload[:cap(payload)]
			if _, err := aead.Open(nil, metadataAEADNonce, payload, nil); err == nil {
				t.Errorf("payload was encrypted with the metadata AEAD nonce")
			}
			// The metadata must not be readable with the payload AEAD nonce.
			metadata := sealWithNonce(t, block, wireNonce, plaintext)
			if _, err := aead.Open(nil, payloadAEADNonce, metadata, nil); err == nil {
				t.Errorf("metadata was encrypted with the payload AEAD nonce")
			}
			// Both paths still decrypt with their own nonce.
			openedPayload, err := block.DecryptPayloadWithNonce(payload, wireNonce)
			if err != nil {
				t.Fatalf("DecryptPayloadWithNonce() failed: %v", err)
			}
			if !bytes.Equal(plaintext, openedPayload) {
				t.Errorf("plaintext after DecryptPayloadWithNonce() is different")
			}
			openedMetadata, err := block.DecryptWithNonce(metadata, wireNonce)
			if err != nil {
				t.Fatalf("DecryptWithNonce() failed: %v", err)
			}
			if !bytes.Equal(plaintext, openedMetadata) {
				t.Errorf("plaintext after DecryptWithNonce() is different")
			}
		})
	}
}

func TestNewBlockCipherFromKeyKeyLength(t *testing.T) {
	plaintext := []byte("key length plaintext")
	for _, test := range testSuiteProperties {
		t.Run(test.name, func(t *testing.T) {
			key := randomBytes(t, test.keyLen)
			block, err := NewBlockCipherFromKey(test.suite, key, true)
			if err != nil {
				t.Fatalf("NewBlockCipherFromKey() failed: %v", err)
			}
			// A longer key must be truncated to the first KeyLen bytes.
			longer, err := NewBlockCipherFromKey(test.suite, append(cloneBytes(key), randomBytes(t, 32)...), true)
			if err != nil {
				t.Fatalf("NewBlockCipherFromKey() with a longer key failed: %v", err)
			}
			wireNonce := randomBytes(t, DefaultNonceSize)
			if !bytes.Equal(sealWithNonce(t, block, wireNonce, plaintext), sealWithNonce(t, longer, wireNonce, plaintext)) {
				t.Errorf("extra key bytes changed the ciphertext")
			}
			// A shorter key must be rejected.
			for _, short := range [][]byte{nil, {}, key[:test.keyLen-1]} {
				if _, err := NewBlockCipherFromKey(test.suite, short, true); err == nil {
					t.Errorf("NewBlockCipherFromKey() accepted a %d bytes key, want an error", len(short))
				}
			}
			// An invalid suite must be rejected.
			if _, err := NewBlockCipherFromKey(Suite(3), key, true); err == nil {
				t.Errorf("NewBlockCipherFromKey() accepted an invalid cipher suite")
			}
		})
	}
}

func TestSuiteKeyTruncationFromPassword(t *testing.T) {
	password := []byte("suite key truncation password")
	now := time.Now()
	salts := saltFromTime(now)
	for _, test := range testSuiteProperties {
		t.Run(test.name, func(t *testing.T) {
			blocks, err := newBlockCipherList(password, test.suite, now)
			if err != nil {
				t.Fatalf("newBlockCipherList() failed: %v", err)
			}
			if len(blocks) != 3 {
				t.Fatalf("number of ciphers = %d, want 3", len(blocks))
			}
			for i, block := range blocks {
				// The key material is always 32 bytes long, the cipher suite
				// key is its prefix.
				want := pbkdf2.Key(password, salts[i], KeyIter, DefaultKeyLen, sha256.New)
				if got := block.key[:test.keyLen]; !bytes.Equal(got, want[:test.keyLen]) {
					t.Errorf("slot %d key = %x, want %x", i, got, want[:test.keyLen])
				}
				for j := test.keyLen; j < DefaultKeyLen; j++ {
					if block.key[j] != 0 {
						t.Errorf("slot %d key byte %d = %d, want 0", i, j, block.key[j])
					}
				}
				if got := block.Suite(); got != test.suite {
					t.Errorf("slot %d Suite() = %s, want %s", i, got, test.suite)
				}
			}
		})
	}
}

func TestBlockCipherListFromPassword(t *testing.T) {
	password := []byte("time slot password")
	for _, suite := range AllSuites() {
		t.Run(suite.String(), func(t *testing.T) {
			blocks, err := BlockCipherListFromPassword(suite, password, true)
			if err != nil {
				t.Fatalf("BlockCipherListFromPassword() failed: %v", err)
			}
			if len(blocks) != 3 {
				t.Fatalf("number of ciphers = %d, want 3", len(blocks))
			}
			keys := make(map[string]int)
			for i, block := range blocks {
				if got := block.Suite(); got != suite {
					t.Errorf("block %d Suite() = %s, want %s", i, got, suite)
				}
				if !block.IsStateless() {
					t.Errorf("block %d IsStateless() = false, want true", i)
				}
				key := string(block.(*aeadBlockCipher).key[:suite.KeyLen()])
				if prev, ok := keys[key]; ok {
					t.Errorf("block %d uses the same key as block %d", i, prev)
				}
				keys[key] = i
			}

			stateful, err := BlockCipherListFromPassword(suite, password, false)
			if err != nil {
				t.Fatalf("BlockCipherListFromPassword() failed: %v", err)
			}
			for i, block := range stateful {
				if block.IsStateless() {
					t.Errorf("stateful block %d IsStateless() = true, want false", i)
				}
			}
		})
	}
}

func TestSuiteCloneKeepsSuite(t *testing.T) {
	key := randomBytes(t, DefaultKeyLen)
	for _, test := range testSuiteProperties {
		t.Run(test.name, func(t *testing.T) {
			block, err := NewBlockCipherFromKey(test.suite, key, true)
			if err != nil {
				t.Fatalf("NewBlockCipherFromKey() failed: %v", err)
			}
			if got := block.Clone().Suite(); got != test.suite {
				t.Errorf("Clone().Suite() = %s, want %s", got, test.suite)
			}
			if got := block.CloneStatelessFast().Suite(); got != test.suite {
				t.Errorf("CloneStatelessFast().Suite() = %s, want %s", got, test.suite)
			}
			block.SetImplicitNonceMode(true)
			if got := block.Clone().Suite(); got != test.suite {
				t.Errorf("stateful Clone().Suite() = %s, want %s", got, test.suite)
			}
		})
	}
}

func TestNewStatelessDecryptorMultipleSuites(t *testing.T) {
	password := HashPassword([]byte(t.Name()), []byte("multi-suite-user"))
	plaintext := []byte("decrypt with the correct cipher suite")
	suites := []Suite{SuiteAES128GCM, SuiteAES256GCM, SuiteXChaCha20Poly1305}

	decryptor, err := NewStatelessDecryptor(suites, password)
	if err != nil {
		t.Fatalf("NewStatelessDecryptor() failed: %v", err)
	}
	for _, suite := range suites {
		block, err := BlockCipherFromPassword(suite, password, true)
		if err != nil {
			t.Fatalf("BlockCipherFromPassword(%s) failed: %v", suite, err)
		}
		ciphertext := make([]byte, block.NonceSize()+len(plaintext)+block.Overhead())
		if err := block.Encrypt(ciphertext[:0], plaintext); err != nil {
			t.Fatalf("Encrypt() failed: %v", err)
		}
		winner, got, err := decryptor.TryDecrypt(ciphertext, make([]byte, 0, len(plaintext)))
		if err != nil {
			t.Fatalf("TryDecrypt() failed for %s: %v", suite, err)
		}
		if winner.Suite() != suite {
			t.Errorf("TryDecrypt() hit suite %s, want %s", winner.Suite(), suite)
		}
		if !winner.IsStateless() {
			t.Errorf("TryDecrypt() returned a stateful cipher")
		}
		if !bytes.Equal(got, plaintext) {
			t.Errorf("plaintext after TryDecrypt() is different")
		}
	}

	// A cipher suite that is not configured must not be tried.
	onlyAES, err := NewStatelessDecryptor([]Suite{SuiteAES256GCM}, password)
	if err != nil {
		t.Fatalf("NewStatelessDecryptor() failed: %v", err)
	}
	block, err := BlockCipherFromPassword(SuiteXChaCha20Poly1305, password, true)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}
	ciphertext := make([]byte, block.NonceSize()+len(plaintext)+block.Overhead())
	if err := block.Encrypt(ciphertext[:0], plaintext); err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}
	if _, _, err := onlyAES.TryDecrypt(ciphertext, nil); err == nil {
		t.Errorf("TryDecrypt() decrypted an unconfigured cipher suite")
	}

	// An empty suite list selects all the supported cipher suites.
	defaults, err := NewStatelessDecryptor(nil, password)
	if err != nil {
		t.Fatalf("NewStatelessDecryptor() failed: %v", err)
	}
	for _, suite := range AllSuites() {
		block, err := BlockCipherFromPassword(suite, password, true)
		if err != nil {
			t.Fatalf("BlockCipherFromPassword(%s) failed: %v", suite, err)
		}
		ciphertext := make([]byte, block.NonceSize()+len(plaintext)+block.Overhead())
		if err := block.Encrypt(ciphertext[:0], plaintext); err != nil {
			t.Fatalf("Encrypt() failed: %v", err)
		}
		winner, _, err := defaults.TryDecrypt(ciphertext, nil)
		if err != nil {
			t.Fatalf("TryDecrypt() failed for %s: %v", suite, err)
		}
		if winner.Suite() != suite {
			t.Errorf("TryDecrypt() hit suite %s, want %s", winner.Suite(), suite)
		}
	}

	// Invalid inputs must be rejected.
	if _, err := NewStatelessDecryptor(nil, nil); err == nil {
		t.Errorf("NewStatelessDecryptor() accepted an empty password")
	}
	if _, err := NewStatelessDecryptor([]Suite{Suite(7)}, password); err == nil {
		t.Errorf("NewStatelessDecryptor() accepted an invalid cipher suite")
	}

	// A cleared decryptor must not decrypt anything.
	defaults.Clear()
	if _, _, err := defaults.TryDecrypt(ciphertext, nil); err == nil {
		t.Errorf("TryDecrypt() succeeded after Clear()")
	}
}

// TestNoncePatternClampedToAEADRegion checks that a nonce pattern can never
// rewrite the bytes of the wire format nonce that AES-GCM uses as its AEAD
// nonce, even if the pattern is not constrained by the caller.
func TestNoncePatternClampedToAEADRegion(t *testing.T) {
	if maxNoncePatternLen != DefaultNonceSize-minAEADNonceLen {
		t.Fatalf("maxNoncePatternLen = %d, want %d", maxNoncePatternLen, DefaultNonceSize-minAEADNonceLen)
	}

	key := randomBytes(t, DefaultKeyLen)
	block, err := newBlockCipher(SuiteAES256GCM, key)
	if err != nil {
		t.Fatalf("newBlockCipher() failed: %v", err)
	}

	// A pattern that requests more than maxNoncePatternLen bytes must be
	// clamped, the returned length must stay inside the random region of the
	// wire nonce.
	printable := appctlpb.NonceType_NONCE_TYPE_PRINTABLE
	for _, test := range []struct {
		name   string
		minLen int32
		maxLen int32
	}{
		{name: "above the limit", minLen: maxNoncePatternLen + 2, maxLen: DefaultNonceSize},
		{name: "crossing the limit", minLen: 1, maxLen: DefaultNonceSize},
	} {
		t.Run(test.name, func(t *testing.T) {
			block.SetNoncePattern(&appctlpb.NoncePattern{
				Type:                &printable,
				ApplyToAllUDPPacket: proto.Bool(true),
				MinLen:              proto.Int32(test.minLen),
				MaxLen:              proto.Int32(test.maxLen),
			})
			wantMin := min(int(test.minLen), maxNoncePatternLen)
			for range 64 {
				got := block.nonceRewriteLen()
				if got > maxNoncePatternLen {
					t.Fatalf("nonceRewriteLen() = %d, want at most %d", got, maxNoncePatternLen)
				}
				if got < wantMin {
					t.Fatalf("nonceRewriteLen() = %d, want at least %d", got, wantMin)
				}
			}
		})
	}

	// A fixed pattern longer than maxNoncePatternLen must only rewrite the
	// leading maxNoncePatternLen bytes of the wire nonce.
	fixed := appctlpb.NonceType_NONCE_TYPE_FIXED
	hexString := strings.Repeat("ab", DefaultNonceSize)
	prefix := bytes.Repeat([]byte{0xab}, DefaultNonceSize)
	block.SetNoncePattern(&appctlpb.NoncePattern{
		Type:                &fixed,
		ApplyToAllUDPPacket: proto.Bool(true),
		CustomHexStrings:    []string{hexString},
	})
	for range 8 {
		nonce, err := block.newNonce()
		if err != nil {
			t.Fatalf("newNonce() failed: %v", err)
		}
		if !bytes.Equal(nonce[:maxNoncePatternLen], prefix[:maxNoncePatternLen]) {
			t.Fatalf("nonce prefix = %x, want %x", nonce[:maxNoncePatternLen], prefix[:maxNoncePatternLen])
		}
		if bytes.Equal(nonce[maxNoncePatternLen:], prefix[maxNoncePatternLen:]) {
			t.Fatalf("the nonce pattern rewrote wireNonce[%d:], which is the AES-GCM AEAD nonce", maxNoncePatternLen)
		}
	}
}
