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
	"crypto/ecdh"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"testing"
)

// RFC 7748 section 6.1 test vectors.
const (
	rfc7748AlicePrivate = "77076d0a7318a57d3c16c17251b26645df4c2f87ebc0992ab177fba51db92c2a"
	rfc7748AlicePublic  = "8520f0098930a754748b7ddcb43ef75a0dbf3a0d26381af4eba4a98eaa9b4e6a"
	rfc7748BobPrivate   = "5dab087e624a8a4b79e17f8b83800ee66f3bb1292618b6fd1c2f8b27ff88e0eb"
	rfc7748BobPublic    = "de9edb7d7b7dc1b4d35b61c2ece435373f8343c85b78674dadfc7e146f882b4f"
	rfc7748SharedSecret = "4a5d9d5ba4ce2de1728e3bf480350f25e07e21c947d19e3376f09b3c1e161742"

	// Session constants used by the tests.
	testVersion    = uint8(2)
	testClientSalt = "0123456789abcdef"
	testServerSalt = "fedcba9876543210"
)

func decodeHex(t *testing.T, s string) []byte {
	t.Helper()
	b, err := hex.DecodeString(s)
	if err != nil {
		t.Fatalf("hex.DecodeString(%q) failed: %v", s, err)
	}
	return b
}

func x25519PrivateKey(t *testing.T, hexKey string) *ecdh.PrivateKey {
	t.Helper()
	priv, err := ecdh.X25519().NewPrivateKey(decodeHex(t, hexKey))
	if err != nil {
		t.Fatalf("ecdh.X25519().NewPrivateKey() failed: %v", err)
	}
	return priv
}

// hkdfSHA256 is an independent HKDF-SHA256 implementation (RFC 5869) used to
// cross check the session key derivation.
func hkdfSHA256(t *testing.T, secret, salt, info []byte, length int) []byte {
	t.Helper()
	if len(salt) == 0 {
		salt = make([]byte, sha256.Size)
	}
	extract := hmac.New(sha256.New, salt)
	extract.Write(secret)
	prk := extract.Sum(nil)

	out := make([]byte, 0, length)
	var block []byte
	for i := byte(1); len(out) < length; i++ {
		expand := hmac.New(sha256.New, prk)
		expand.Write(block)
		expand.Write(info)
		expand.Write([]byte{i})
		block = expand.Sum(nil)
		out = append(out, block...)
	}
	return out[:length]
}

func TestGenerateEphemeralKey(t *testing.T) {
	priv, pub, err := GenerateEphemeralKey()
	if err != nil {
		t.Fatalf("GenerateEphemeralKey() failed: %v", err)
	}
	if priv == nil {
		t.Fatal("GenerateEphemeralKey() returned a nil private key")
	}
	if len(pub) != x25519KeyLen {
		t.Fatalf("public key length = %d, want %d", len(pub), x25519KeyLen)
	}
	if !bytes.Equal(pub, priv.PublicKey().Bytes()) {
		t.Errorf("public key = %x, want %x", pub, priv.PublicKey().Bytes())
	}
	_, pub2, err := GenerateEphemeralKey()
	if err != nil {
		t.Fatalf("GenerateEphemeralKey() failed: %v", err)
	}
	if bytes.Equal(pub, pub2) {
		t.Errorf("two calls to GenerateEphemeralKey() returned the same public key")
	}

	// Both directions must agree.
	priv2, pub2, err := GenerateEphemeralKey()
	if err != nil {
		t.Fatalf("GenerateEphemeralKey() failed: %v", err)
	}
	shared1, err := SharedSecret(priv, pub2)
	if err != nil {
		t.Fatalf("SharedSecret() failed: %v", err)
	}
	shared2, err := SharedSecret(priv2, pub)
	if err != nil {
		t.Fatalf("SharedSecret() failed: %v", err)
	}
	if !bytes.Equal(shared1, shared2) {
		t.Errorf("shared secrets are different: %x and %x", shared1, shared2)
	}
	if len(shared1) != x25519KeyLen {
		t.Errorf("shared secret length = %d, want %d", len(shared1), x25519KeyLen)
	}
}

func TestSharedSecretRFC7748Vector(t *testing.T) {
	alice := x25519PrivateKey(t, rfc7748AlicePrivate)
	bob := x25519PrivateKey(t, rfc7748BobPrivate)
	if got := alice.PublicKey().Bytes(); !bytes.Equal(got, decodeHex(t, rfc7748AlicePublic)) {
		t.Fatalf("Alice public key = %x, want %s", got, rfc7748AlicePublic)
	}
	if got := bob.PublicKey().Bytes(); !bytes.Equal(got, decodeHex(t, rfc7748BobPublic)) {
		t.Fatalf("Bob public key = %x, want %s", got, rfc7748BobPublic)
	}

	want := decodeHex(t, rfc7748SharedSecret)
	fromAlice, err := SharedSecret(alice, bob.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("SharedSecret() failed: %v", err)
	}
	if !bytes.Equal(fromAlice, want) {
		t.Errorf("shared secret = %x, want %x", fromAlice, want)
	}
	fromBob, err := SharedSecret(bob, alice.PublicKey().Bytes())
	if err != nil {
		t.Fatalf("SharedSecret() failed: %v", err)
	}
	if !bytes.Equal(fromBob, want) {
		t.Errorf("shared secret = %x, want %x", fromBob, want)
	}
}

func TestSharedSecretRejectsBadPublicKey(t *testing.T) {
	priv, pub, err := GenerateEphemeralKey()
	if err != nil {
		t.Fatalf("GenerateEphemeralKey() failed: %v", err)
	}
	for _, name := range []string{"nil", "empty", "short", "long", "all zero"} {
		var peer []byte
		switch name {
		case "empty":
			peer = []byte{}
		case "short":
			peer = make([]byte, x25519KeyLen-1)
		case "long":
			peer = make([]byte, x25519KeyLen+1)
		case "all zero":
			peer = make([]byte, x25519KeyLen)
		}
		if _, err := SharedSecret(priv, peer); err == nil {
			t.Errorf("SharedSecret() accepted a %s public key", name)
		}
	}
	if _, err := SharedSecret(nil, pub); err == nil {
		t.Errorf("SharedSecret() accepted a nil private key")
	}
}

func TestDeriveSessionKeysBothSidesAgree(t *testing.T) {
	clientPriv := x25519PrivateKey(t, rfc7748AlicePrivate)
	serverPriv := x25519PrivateKey(t, rfc7748BobPrivate)
	clientPub := clientPriv.PublicKey().Bytes()
	serverPub := serverPriv.PublicKey().Bytes()
	clientSalt := []byte(testClientSalt)
	serverSalt := []byte(testServerSalt)
	plaintext := []byte("session key plaintext")

	for _, test := range testSuiteProperties {
		t.Run(test.name, func(t *testing.T) {
			// Both sides know the same user credential, hence the same static key.
			staticKey := randomBytes(t, test.keyLen)
			clientCipher, err := NewBlockCipherFromKey(test.suite, staticKey, true)
			if err != nil {
				t.Fatalf("NewBlockCipherFromKey() failed: %v", err)
			}
			serverCipher, err := NewBlockCipherFromKey(test.suite, staticKey, true)
			if err != nil {
				t.Fatalf("NewBlockCipherFromKey() failed: %v", err)
			}
			clientShared, err := SharedSecret(clientPriv, serverPub)
			if err != nil {
				t.Fatalf("SharedSecret() failed: %v", err)
			}
			serverShared, err := SharedSecret(serverPriv, clientPub)
			if err != nil {
				t.Fatalf("SharedSecret() failed: %v", err)
			}
			if !bytes.Equal(clientShared, serverShared) {
				t.Fatalf("client and server shared secrets are different")
			}

			// Each side derives the session keys once.
			c2s, s2c, err := DeriveSessionKeys(clientCipher, test.suite, clientShared, clientSalt, serverSalt, testVersion)
			if err != nil {
				t.Fatalf("DeriveSessionKeys() on the client failed: %v", err)
			}
			serverC2S, serverS2C, err := DeriveSessionKeys(serverCipher, test.suite, serverShared, clientSalt, serverSalt, testVersion)
			if err != nil {
				t.Fatalf("DeriveSessionKeys() on the server failed: %v", err)
			}
			if !bytes.Equal(c2s, serverC2S) {
				t.Errorf("c2s keys are different")
			}
			if !bytes.Equal(s2c, serverS2C) {
				t.Errorf("s2c keys are different")
			}
			if len(c2s) != test.keyLen || len(s2c) != test.keyLen {
				t.Errorf("c2s key length = %d and s2c key length = %d, want %d", len(c2s), len(s2c), test.keyLen)
			}
			if bytes.Equal(c2s, s2c) {
				t.Errorf("c2s key equals s2c key, the directions are not separated")
			}

			// Cross check the derivation with the frozen formula.
			saltHash := sha256.New()
			saltHash.Write(staticKey)
			saltHash.Write(clientSalt)
			saltHash.Write(serverSalt)
			salt := saltHash.Sum(nil)
			wantC2S := hkdfSHA256(t, clientShared, salt, append([]byte("mieru-v2 c2s"), testVersion, byte(test.suite)), test.keyLen)
			wantS2C := hkdfSHA256(t, clientShared, salt, append([]byte("mieru-v2 s2c"), testVersion, byte(test.suite)), test.keyLen)
			if !bytes.Equal(c2s, wantC2S) {
				t.Errorf("c2s key = %x, want %x", c2s, wantC2S)
			}
			if !bytes.Equal(s2c, wantS2C) {
				t.Errorf("s2c key = %x, want %x", s2c, wantS2C)
			}

			// The derived keys are usable as AEAD keys of the suite.
			sendCipher, err := NewBlockCipherFromKey(test.suite, c2s, true)
			if err != nil {
				t.Fatalf("NewBlockCipherFromKey(c2s) failed: %v", err)
			}
			recvCipher, err := NewBlockCipherFromKey(test.suite, serverC2S, true)
			if err != nil {
				t.Fatalf("NewBlockCipherFromKey(serverC2S) failed: %v", err)
			}
			if !bytes.Equal(sendCipher.(*aeadBlockCipher).key[:test.keyLen], recvCipher.(*aeadBlockCipher).key[:test.keyLen]) {
				t.Fatalf("client and server c2s ciphers use different keys")
			}
			ciphertext := make([]byte, sendCipher.NonceSize()+len(plaintext)+sendCipher.Overhead())
			if err := sendCipher.Encrypt(ciphertext[:0], plaintext); err != nil {
				t.Fatalf("Encrypt() failed: %v", err)
			}
			got, err := recvCipher.Decrypt(ciphertext)
			if err != nil {
				t.Fatalf("Decrypt() failed: %v", err)
			}
			if !bytes.Equal(got, plaintext) {
				t.Errorf("plaintext after Decrypt() is different")
			}

			// The protocol version and the static key are mixed into the keys.
			otherVersionC2S, _, err := DeriveSessionKeys(clientCipher, test.suite, clientShared, clientSalt, serverSalt, testVersion+1)
			if err != nil {
				t.Fatalf("DeriveSessionKeys() failed: %v", err)
			}
			if bytes.Equal(c2s, otherVersionC2S) {
				t.Errorf("changing the protocol version didn't change the c2s key")
			}
			otherCipher, err := NewBlockCipherFromKey(test.suite, randomBytes(t, test.keyLen), true)
			if err != nil {
				t.Fatalf("NewBlockCipherFromKey() failed: %v", err)
			}
			otherStaticC2S, _, err := DeriveSessionKeys(otherCipher, test.suite, clientShared, clientSalt, serverSalt, testVersion)
			if err != nil {
				t.Fatalf("DeriveSessionKeys() failed: %v", err)
			}
			if bytes.Equal(c2s, otherStaticC2S) {
				t.Errorf("changing the static key didn't change the c2s key")
			}
			otherSaltC2S, _, err := DeriveSessionKeys(clientCipher, test.suite, clientShared, serverSalt, clientSalt, testVersion)
			if err != nil {
				t.Fatalf("DeriveSessionKeys() failed: %v", err)
			}
			if bytes.Equal(c2s, otherSaltC2S) {
				t.Errorf("swapping the client salt and the server salt didn't change the c2s key")
			}
		})
	}
}

func TestDeriveSessionKeysDeterministicPerSuite(t *testing.T) {
	clientPriv := x25519PrivateKey(t, rfc7748AlicePrivate)
	serverPriv := x25519PrivateKey(t, rfc7748BobPrivate)
	clientPub := clientPriv.PublicKey().Bytes()
	serverPub := serverPriv.PublicKey().Bytes()
	shared := mustSharedSecret(t, clientPriv, serverPub)
	if !bytes.Equal(shared, mustSharedSecret(t, serverPriv, clientPub)) {
		t.Fatal("shared secrets are different")
	}
	key := randomBytes(t, DefaultKeyLen)
	clientSalt := []byte(testClientSalt)
	serverSalt := []byte(testServerSalt)

	derived := make(map[string]Suite)
	for _, test := range testSuiteProperties {
		block, err := NewBlockCipherFromKey(test.suite, key, true)
		if err != nil {
			t.Fatalf("NewBlockCipherFromKey() failed: %v", err)
		}
		c2s, s2c, err := DeriveSessionKeys(block, test.suite, shared, clientSalt, serverSalt, testVersion)
		if err != nil {
			t.Fatalf("DeriveSessionKeys() failed: %v", err)
		}
		// The same inputs must always produce the same keys.
		c2s2, s2c2, err := DeriveSessionKeys(block, test.suite, shared, clientSalt, serverSalt, testVersion)
		if err != nil {
			t.Fatalf("DeriveSessionKeys() failed: %v", err)
		}
		if !bytes.Equal(c2s, c2s2) || !bytes.Equal(s2c, s2c2) {
			t.Errorf("DeriveSessionKeys() is not deterministic for %s", test.name)
		}
		// The cipher suite identifier is mixed into the HKDF info, so two
		// different cipher suites never derive the same key.
		if prev, ok := derived[string(c2s)]; ok {
			t.Errorf("suite %s and %s derived the same c2s key", prev, test.name)
		}
		derived[string(c2s)] = test.suite
	}
}

func mustSharedSecret(t *testing.T, priv *ecdh.PrivateKey, peerPub []byte) []byte {
	t.Helper()
	shared, err := SharedSecret(priv, peerPub)
	if err != nil {
		t.Fatalf("SharedSecret() failed: %v", err)
	}
	return shared
}

func TestDeriveSessionKeysErrors(t *testing.T) {
	key := randomBytes(t, DefaultKeyLen)
	block, err := NewBlockCipherFromKey(SuiteXChaCha20Poly1305, key, true)
	if err != nil {
		t.Fatalf("NewBlockCipherFromKey() failed: %v", err)
	}
	shared := randomBytes(t, x25519KeyLen)
	clientSalt := randomBytes(t, sessionSaltLen)
	serverSalt := randomBytes(t, sessionSaltLen)

	tests := []struct {
		name       string
		c          BlockCipher
		suite      Suite
		shared     []byte
		clientSalt []byte
		serverSalt []byte
	}{
		{name: "nil cipher", c: nil, suite: SuiteXChaCha20Poly1305, shared: shared, clientSalt: clientSalt, serverSalt: serverSalt},
		{name: "invalid suite", c: block, suite: Suite(9), shared: shared, clientSalt: clientSalt, serverSalt: serverSalt},
		{name: "nil shared secret", c: block, suite: SuiteXChaCha20Poly1305, shared: nil, clientSalt: clientSalt, serverSalt: serverSalt},
		{name: "short shared secret", c: block, suite: SuiteXChaCha20Poly1305, shared: shared[:x25519KeyLen-1], clientSalt: clientSalt, serverSalt: serverSalt},
		{name: "long shared secret", c: block, suite: SuiteXChaCha20Poly1305, shared: append(cloneBytes(shared), 0), clientSalt: clientSalt, serverSalt: serverSalt},
		{name: "empty client salt", c: block, suite: SuiteXChaCha20Poly1305, shared: shared, clientSalt: nil, serverSalt: serverSalt},
		{name: "short client salt", c: block, suite: SuiteXChaCha20Poly1305, shared: shared, clientSalt: clientSalt[:sessionSaltLen-1], serverSalt: serverSalt},
		{name: "empty server salt", c: block, suite: SuiteXChaCha20Poly1305, shared: shared, clientSalt: clientSalt, serverSalt: nil},
		{name: "long server salt", c: block, suite: SuiteXChaCha20Poly1305, shared: shared, clientSalt: clientSalt, serverSalt: append(cloneBytes(serverSalt), 0)},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			c2s, s2c, err := DeriveSessionKeys(test.c, test.suite, test.shared, test.clientSalt, test.serverSalt, testVersion)
			if err == nil {
				t.Fatalf("DeriveSessionKeys() = (%x, %x, nil), want an error", c2s, s2c)
			}
		})
	}
}

// TestDeriveSessionKeysUsesTheRequestedSuite proves that the suite argument
// selects the HKDF info and the key length, independently of the cipher that
// holds the static key. A version 3 session relies on this: it negotiates a
// suite from the envelope cipher and derives the session keys of the negotiated
// suite, which may be longer than the envelope key.
func TestDeriveSessionKeysUsesTheRequestedSuite(t *testing.T) {
	clientPriv := x25519PrivateKey(t, rfc7748AlicePrivate)
	serverPriv := x25519PrivateKey(t, rfc7748BobPrivate)
	clientPub := clientPriv.PublicKey().Bytes()
	serverPub := serverPriv.PublicKey().Bytes()
	shared := mustSharedSecret(t, clientPriv, serverPub)
	if !bytes.Equal(shared, mustSharedSecret(t, serverPriv, clientPub)) {
		t.Fatal("shared secrets are different")
	}
	clientSalt := []byte(testClientSalt)
	serverSalt := []byte(testServerSalt)

	// A credential key longer than every suite, so that the envelope cipher
	// never limits the derivation.
	staticKey := randomBytes(t, 2*DefaultKeyLen)

	for _, envelope := range testSuiteProperties {
		for _, negotiated := range testSuiteProperties {
			t.Run(envelope.name+" envelope with "+negotiated.name, func(t *testing.T) {
				block, err := NewBlockCipherFromKey(envelope.suite, staticKey, true)
				if err != nil {
					t.Fatalf("NewBlockCipherFromKey() failed: %v", err)
				}
				c2s, s2c, err := DeriveSessionKeys(block, negotiated.suite, shared, clientSalt, serverSalt, 3)
				if err != nil {
					t.Fatalf("DeriveSessionKeys() failed: %v", err)
				}
				// The keys are exactly as long as the negotiated suite needs,
				// even when the envelope cipher is shorter.
				if len(c2s) != negotiated.keyLen || len(s2c) != negotiated.keyLen {
					t.Fatalf("key lengths = (%d, %d), want (%d, %d)", len(c2s), len(s2c), negotiated.keyLen, negotiated.keyLen)
				}
				if bytes.Equal(c2s, s2c) {
					t.Fatal("the c2s key equals the s2c key, the directions are not separated")
				}
				// The negotiated suite is part of the HKDF info, so when it
				// differs from the envelope suite the derived keys differ too.
				if envelope.suite != negotiated.suite {
					envelopeKeys, _, err := DeriveSessionKeys(block, envelope.suite, shared, clientSalt, serverSalt, 3)
					if err != nil {
						t.Fatalf("DeriveSessionKeys() with the envelope suite failed: %v", err)
					}
					if bytes.Equal(c2s[:negotiated.keyLen], envelopeKeys[:negotiated.keyLen]) {
						t.Fatalf("the keys of %s equal the keys of the envelope suite %s", negotiated.name, envelope.name)
					}
				}
				// The keys are usable AEAD keys of the negotiated suite.
				send, err := NewBlockCipherFromKey(negotiated.suite, c2s, true)
				if err != nil {
					t.Fatalf("NewBlockCipherFromKey(c2s) failed: %v", err)
				}
				plaintext := []byte("a data plane message")
				wire := make([]byte, send.NonceSize()+len(plaintext)+send.Overhead())
				if err := send.Encrypt(wire[:0], plaintext); err != nil {
					t.Fatalf("Encrypt() failed: %v", err)
				}
				recv, err := NewBlockCipherFromKey(negotiated.suite, c2s, true)
				if err != nil {
					t.Fatalf("NewBlockCipherFromKey(c2s) failed: %v", err)
				}
				got, err := recv.Decrypt(wire)
				if err != nil {
					t.Fatalf("Decrypt() failed: %v", err)
				}
				if !bytes.Equal(got, plaintext) {
					t.Fatalf("plaintext after Decrypt() = %q, want %q", got, plaintext)
				}
			})
		}
	}
}
