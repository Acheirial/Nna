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
	"crypto/ecdh"
	"crypto/rand"
	"crypto/sha256"
	"fmt"
	"io"

	"golang.org/x/crypto/hkdf"

	"github.com/Acheirial/shadowlemon/v3/pkg/version"
)

const (
	// x25519KeyLen is the length in bytes of an X25519 private key, X25519
	// public key and X25519 shared secret.
	x25519KeyLen = 32

	// sessionSaltLen is the length in bytes of the client salt and the server
	// salt carried by the handshake.
	sessionSaltLen = 16
)

// clientToServerInfo and serverToClientInfo are the HKDF info prefixes of the
// client to server and the server to client session keys. Using a different
// info for each direction prevents the nonce of a direction from being reused
// in the other direction.
var (
	clientToServerInfo = version.ProtocolIdentifier() + " c2s"
	serverToClientInfo = version.ProtocolIdentifier() + " s2c"
)

// GenerateEphemeralKey generates an ephemeral X25519 key pair and returns the
// private key and the 32 bytes public key.
//
// The private key only exists in memory and is never derived from the user
// credential, which provides forward secrecy to the data plane session keys.
// crypto/ecdh doesn't provide a way to erase a private key explicitly, so
// clearing it when the session is closed is best effort: the caller should drop
// its reference to the private key as soon as the session key is derived.
func GenerateEphemeralKey() (*ecdh.PrivateKey, []byte, error) {
	priv, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("ecdh.X25519().GenerateKey() failed: %w", err)
	}
	return priv, priv.PublicKey().Bytes(), nil
}

// SharedSecret computes the X25519 shared secret between the local ephemeral
// private key and the peer ephemeral public key. It returns an error if the
// public key is invalid or if the shared secret is all zero, which means the
// peer public key is a low order point and provides no security.
func SharedSecret(priv *ecdh.PrivateKey, peerPub []byte) ([]byte, error) {
	if priv == nil {
		return nil, fmt.Errorf("ephemeral private key is nil")
	}
	if len(peerPub) != x25519KeyLen {
		return nil, fmt.Errorf("X25519 public key length is %d bytes, want %d bytes", len(peerPub), x25519KeyLen)
	}
	pub, err := ecdh.X25519().NewPublicKey(peerPub)
	if err != nil {
		return nil, fmt.Errorf("invalid X25519 public key: %w", err)
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, fmt.Errorf("ecdh.ECDH() failed: %w", err)
	}
	if isAllZero(shared) {
		return nil, fmt.Errorf("X25519 shared secret is all zero, the peer public key is not usable")
	}
	return shared, nil
}

// DeriveSessionKeys derives the client to server session key and the server to
// client session key from the X25519 shared secret and the handshake salts.
//
// suite selects the key length and the cipher suite identifier mixed into the
// HKDF info, and the returned keys are suite.KeyLen() bytes long. It is the
// negotiated data plane suite, which may differ from the suite of c and may
// need more key material than the handshake envelope provides.
//
// version is the protocol version byte carried by the handshake. It is mixed
// into the HKDF info, so two peers that do not agree on the protocol version
// never derive the same session keys.
//
// The static key of c is mixed into the HKDF salt, so a peer must also know the
// user credential to derive the session keys. c must be the cipher that
// decrypted the handshake envelope, because only the envelope cipher records
// the time slot of the peer.
//
// The session keys are ephemeral: they are not derived from the user credential
// alone, so an attacker who learns the credential later can't decrypt a session
// that has already ended.
func DeriveSessionKeys(c BlockCipher, suite Suite, shared, clientSalt, serverSalt []byte, version uint8) (c2s, s2c []byte, err error) {
	if c == nil {
		return nil, nil, fmt.Errorf("block cipher is nil")
	}
	if !suite.IsValid() {
		return nil, nil, fmt.Errorf("invalid cipher suite %d", uint8(suite))
	}
	_, staticKey, staticKeyErr := suiteAndStaticKey(c)
	if staticKeyErr != nil {
		return nil, nil, staticKeyErr
	}
	if len(shared) != x25519KeyLen {
		return nil, nil, fmt.Errorf("X25519 shared secret length is %d bytes, want %d bytes", len(shared), x25519KeyLen)
	}
	if len(clientSalt) != sessionSaltLen {
		return nil, nil, fmt.Errorf("client salt length is %d bytes, want %d bytes", len(clientSalt), sessionSaltLen)
	}
	if len(serverSalt) != sessionSaltLen {
		return nil, nil, fmt.Errorf("server salt length is %d bytes, want %d bytes", len(serverSalt), sessionSaltLen)
	}

	saltHash := sha256.New()
	saltHash.Write(staticKey)
	saltHash.Write(clientSalt)
	saltHash.Write(serverSalt)
	salt := saltHash.Sum(nil)

	c2s, err = hkdfKey(shared, salt, sessionInfo(clientToServerInfo, version, suite), suite.KeyLen())
	if err != nil {
		return nil, nil, err
	}
	s2c, err = hkdfKey(shared, salt, sessionInfo(serverToClientInfo, version, suite), suite.KeyLen())
	if err != nil {
		return nil, nil, err
	}
	return c2s, s2c, nil
}

// sessionInfo builds the HKDF info of a session key: the info prefix, followed
// by the protocol version and the cipher suite.
func sessionInfo(prefix string, version uint8, suite Suite) []byte {
	info := make([]byte, 0, len(prefix)+2)
	info = append(info, prefix...)
	info = append(info, version, byte(suite))
	return info
}

// hkdfKey derives a key of keyLen bytes from secret with HKDF-SHA256.
func hkdfKey(secret, salt, info []byte, keyLen int) ([]byte, error) {
	key := make([]byte, keyLen)
	if _, err := io.ReadFull(hkdf.New(sha256.New, secret, salt, info), key); err != nil {
		return nil, fmt.Errorf("hkdf.ReadFull() failed: %w", err)
	}
	return key, nil
}

// suiteAndStaticKey returns the cipher suite and the static key of a block
// cipher created by this package.
func suiteAndStaticKey(c BlockCipher) (Suite, []byte, error) {
	block, ok := c.(*aeadBlockCipher)
	if !ok {
		return 0, nil, fmt.Errorf("unsupported BlockCipher implementation %T", c)
	}
	if !block.suite.IsValid() {
		return 0, nil, fmt.Errorf("invalid cipher suite %d", uint8(block.suite))
	}
	return block.suite, block.key[:block.suite.KeyLen()], nil
}

// isAllZero returns true if b only contains zero bytes.
func isAllZero(b []byte) bool {
	for _, v := range b {
		if v != 0 {
			return false
		}
	}
	return true
}
