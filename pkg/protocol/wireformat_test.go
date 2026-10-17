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

package protocol

import (
	"fmt"
	"testing"

	"github.com/enfein/mieru/v3/pkg/cipher"
)

// The wire format is shared by every mieru client and server, including the
// older builds that are still deployed, so its lengths must not change.
// These tests assert the numbers directly, so that an accidental change of a
// constant, or of a change of the way a length is derived, fails the test
// instead of silently breaking the compatibility with the deployed peers.
//
// A length that is part of the wire format MUST only be changed together with
// a protocol version bump, and the assertion below MUST be updated in the same
// commit. The tests are intentionally redundant: they check both the value of
// each constant and the relation between the constants that are derived from
// each other.

// TestWireFormatLengths freezes the numeric value of every length that
// describes the wire format.
func TestWireFormatLengths(t *testing.T) {
	tests := []struct {
		name string
		got  int
		want int
	}{
		// Metadata is the encrypted plaintext prefix of every packet and of
		// every stream message.
		{"MetadataLength", MetadataLength, 32},

		// The UDP packet header is nonce, encrypted metadata and AEAD tag. It
		// is also the position of the payload in a UDP packet.
		{"cipher.DefaultNonceSize", cipher.DefaultNonceSize, 24},
		{"cipher.DefaultOverhead", cipher.DefaultOverhead, 16},
		{"packetNonHeaderPosition", packetNonHeaderPosition, 72},

		// A UDP packet is the header above plus the AEAD tag of the payload.
		{"packetOverhead", packetOverhead, 88},

		// A handshake request is a 3 bytes header, which carries the protocol
		// version range and the number of cipher suites, followed by the cipher
		// suite list, the ephemeral public key and the client salt.
		{"handshakeRequestHeaderLen", handshakeRequestHeaderLen, 3},
		{"handshakeRequestFixedLen", handshakeRequestFixedLen, 51},

		// A handshake response is a fixed length message, so its length is part
		// of the wire format.
		{"handshakeResponseLen", handshakeResponseLen, 51},

		// X25519 key exchange key material carried by the handshake.
		{"handshakeEphemeralKeyLen", handshakeEphemeralKeyLen, 32},
		{"handshakeSaltLen", handshakeSaltLen, 16},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if test.got != test.want {
				t.Errorf("%s = %d, want %d", test.name, test.got, test.want)
			}
		})
	}
}

// TestWireFormatDerivedLengths freezes the way the lengths above are combined.
// A change of a derivation is a wire format change even if every constant keeps
// its value, so the relations are asserted on their own.
func TestWireFormatDerivedLengths(t *testing.T) {
	// The UDP packet header, which is also the length of the first read of a
	// stream connection that carries a nonce.
	firstReadLen := MetadataLength + cipher.DefaultOverhead + cipher.DefaultNonceSize
	if packetNonHeaderPosition != firstReadLen {
		t.Errorf("packetNonHeaderPosition = %d, want MetadataLength + cipher.DefaultOverhead + cipher.DefaultNonceSize = %d", packetNonHeaderPosition, firstReadLen)
	}

	// The whole UDP packet overhead: the header plus the AEAD tag of the payload.
	if packetOverhead != packetNonHeaderPosition+cipher.DefaultOverhead {
		t.Errorf("packetOverhead = %d, want packetNonHeaderPosition + cipher.DefaultOverhead = %d", packetOverhead, packetNonHeaderPosition+cipher.DefaultOverhead)
	}

	// A handshake request without a cipher suite list has the same length as a
	// handshake response.
	if handshakeRequestFixedLen != handshakeResponseLen {
		t.Errorf("handshakeRequestFixedLen = %d, want handshakeResponseLen = %d", handshakeRequestFixedLen, handshakeResponseLen)
	}
}

// TestSessionKeyMaterialLengths freezes the key material lengths of the key
// exchange, which is the other half of the handshake wire format.
//
// cipher.x25519KeyLen (32) and cipher.sessionSaltLen (16) are not exported, so
// the lengths are frozen through the behavior of the exported API that
// validates them. The salts carried by the handshake must have the same length
// as cipher.sessionSaltLen, which is asserted by handshakeSaltLen above.
func TestSessionKeyMaterialLengths(t *testing.T) {
	priv, pub, err := cipher.GenerateEphemeralKey()
	if err != nil {
		t.Fatalf("cipher.GenerateEphemeralKey() failed: %v", err)
	}

	t.Run("x25519 public key", func(t *testing.T) {
		if len(pub) != 32 {
			t.Errorf("cipher.GenerateEphemeralKey() returned a %d bytes public key, want 32 (cipher.x25519KeyLen)", len(pub))
		}
		if _, err := cipher.SharedSecret(priv, pub); err != nil {
			t.Errorf("cipher.SharedSecret() rejected a %d bytes peer public key: %v", len(pub), err)
		}
	})

	// cipher.SharedSecret() rejects any peer public key length but x25519KeyLen.
	publicKeyLenTests := []struct {
		name string
		len  int
	}{
		{"empty", 0},
		{"short", 31},
		{"long", 33},
	}
	for _, test := range publicKeyLenTests {
		t.Run(fmt.Sprintf("x25519 public key %s", test.name), func(t *testing.T) {
			if _, err := cipher.SharedSecret(priv, make([]byte, test.len)); err == nil {
				t.Errorf("cipher.SharedSecret() accepted a %d bytes peer public key, want a length other than 32 (cipher.x25519KeyLen) rejected", test.len)
			}
		})
	}

	key := make([]byte, cipher.DefaultKeyLen)
	key[0] = 1
	block, err := cipher.NewBlockCipherFromKey(cipher.SuiteXChaCha20Poly1305, key, true)
	if err != nil {
		t.Fatalf("cipher.NewBlockCipherFromKey() failed: %v", err)
	}
	// The peer public key is a 32 bytes non zero value, which cipher.SharedSecret()
	// accepts, and the session salts are 16 bytes long, which is the length
	// cipher.DeriveSessionKeys() requires.
	shared := pub
	serverSalt := make([]byte, 16)
	if _, _, err := cipher.DeriveSessionKeys(block, cipher.SuiteXChaCha20Poly1305, shared, make([]byte, 16), serverSalt, maxSupportedProtocolVersion); err != nil {
		t.Errorf("cipher.DeriveSessionKeys() rejected 16 bytes session salts: %v", err)
	}

	// cipher.DeriveSessionKeys() rejects any session salt length but sessionSaltLen.
	saltLenTests := []struct {
		name string
		len  int
	}{
		{"empty", 0},
		{"short", 15},
		{"long", 17},
		{"double", 32},
	}
	for _, test := range saltLenTests {
		t.Run(fmt.Sprintf("client salt %s", test.name), func(t *testing.T) {
			if _, _, err := cipher.DeriveSessionKeys(block, cipher.SuiteXChaCha20Poly1305, shared, make([]byte, test.len), serverSalt, maxSupportedProtocolVersion); err == nil {
				t.Errorf("cipher.DeriveSessionKeys() accepted a %d bytes client salt, want a length other than 16 (cipher.sessionSaltLen) rejected", test.len)
			}
		})
	}
	for _, test := range saltLenTests {
		t.Run(fmt.Sprintf("server salt %s", test.name), func(t *testing.T) {
			if _, _, err := cipher.DeriveSessionKeys(block, cipher.SuiteXChaCha20Poly1305, shared, make([]byte, 16), make([]byte, test.len), maxSupportedProtocolVersion); err == nil {
				t.Errorf("cipher.DeriveSessionKeys() accepted a %d bytes server salt, want a length other than 16 (cipher.sessionSaltLen) rejected", test.len)
			}
		})
	}
}
