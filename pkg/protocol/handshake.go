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
	"crypto/ecdh"
	crand "crypto/rand"
	"fmt"
	"log"
	"slices"
	"time"

	"github.com/enfein/mieru/v3/pkg/cipher"
)

const (
	// minSupportedProtocolVersion and maxSupportedProtocolVersion are the
	// protocol version range of this build. Version 2 peers are still
	// supported, so an old client keeps working; the version is negotiated
	// with the peer and a peer that doesn't speak a version in this range is
	// rejected.
	//
	// Version 3 changes the key derivation only and doesn't change the wire
	// format: from version 3 on the session keys are derived from the
	// negotiated cipher suite instead of the cipher that protected the
	// handshake envelope, so a negotiated suite is no longer bounded by the key
	// length of the envelope. The handshake status codes are unchanged.
	minSupportedProtocolVersion uint8 = 2
	maxSupportedProtocolVersion uint8 = 3

	// maxHandshakeSuites is the maximum number of cipher suites a client may
	// offer in one handshake request.
	maxHandshakeSuites = 4

	// handshakeRequestHeaderLen is the length in bytes of the fixed part of a
	// handshake request that precedes the cipher suite list.
	handshakeRequestHeaderLen = 3

	// handshakeRequestFixedLen is the length in bytes of a handshake request
	// without the cipher suite list.
	handshakeRequestFixedLen = 51

	// handshakeResponseLen is the length in bytes of a handshake response.
	handshakeResponseLen = 51

	// handshake status codes.
	handshakeStatusOK        = 0
	handshakeStatusNoVersion = 1
	handshakeStatusNoSuite   = 2

	// handshakeEphemeralKeyLen is the length in bytes of an X25519 ephemeral
	// public key.
	handshakeEphemeralKeyLen = 32

	// handshakeSaltLen is the length in bytes of the client salt and the
	// server salt carried by the handshake.
	handshakeSaltLen = 16

	// handshakeTimeout is the time a client session waits for the handshake
	// response before it closes the session.
	handshakeTimeout = 10 * time.Second
)

// handshakeRequest is the first part of the payload of an openSessionRequest.
// It carries the protocol version range and the cipher suite preference of the
// client, the ephemeral X25519 public key of the client and the client salt.
//
// The handshake request is protected by the static key of the first cipher
// suite of the client, so a server that knows the user credential can decrypt
// it without knowing the session key that is being negotiated.
type handshakeRequest struct {
	versionMin uint8
	versionMax uint8
	suites     []cipher.Suite
	ephPub     [handshakeEphemeralKeyLen]byte
	clientSalt [handshakeSaltLen]byte
}

// Marshal serializes the handshake request.
// The length of the result is handshakeRequestFixedLen + len(h.suites).
func (h *handshakeRequest) Marshal() []byte {
	b := make([]byte, 0, handshakeRequestFixedLen+len(h.suites))
	b = append(b, h.versionMin, h.versionMax, uint8(len(h.suites)))
	for _, suite := range h.suites {
		b = append(b, byte(suite))
	}
	b = append(b, h.ephPub[:]...)
	b = append(b, h.clientSalt[:]...)
	return b
}

// parseHandshakeRequest parses a handshake request from the beginning of b.
// The second return value is the number of bytes consumed, so that the caller
// can find the application data that may follow the handshake request in the
// payload of an openSessionRequest.
//
// A request that is truncated, that carries an unknown or a duplicate cipher
// suite or an invalid version range is rejected with an error.
// parseHandshakeRequest never panics.
func parseHandshakeRequest(b []byte) (*handshakeRequest, int, error) {
	if len(b) < handshakeRequestHeaderLen {
		return nil, 0, fmt.Errorf("handshake request is %d bytes, want at least %d bytes", len(b), handshakeRequestHeaderLen)
	}
	suiteCount := int(b[2])
	if suiteCount < 1 || suiteCount > maxHandshakeSuites {
		return nil, 0, fmt.Errorf("handshake request carries %d cipher suites, want between 1 and %d", suiteCount, maxHandshakeSuites)
	}
	consumed := handshakeRequestFixedLen + suiteCount
	if len(b) < consumed {
		return nil, 0, fmt.Errorf("handshake request is %d bytes, want at least %d bytes", len(b), consumed)
	}
	h := &handshakeRequest{
		versionMin: b[0],
		versionMax: b[1],
		suites:     make([]cipher.Suite, 0, suiteCount),
	}
	for i := range suiteCount {
		raw := b[handshakeRequestHeaderLen+i]
		suite := cipher.Suite(raw)
		if !suite.IsValid() {
			return nil, 0, fmt.Errorf("handshake request carries unknown cipher suite %d", raw)
		}
		h.suites = append(h.suites, suite)
	}
	offset := handshakeRequestHeaderLen + suiteCount
	copy(h.ephPub[:], b[offset:offset+handshakeEphemeralKeyLen])
	copy(h.clientSalt[:], b[offset+handshakeEphemeralKeyLen:consumed])
	if err := h.validate(); err != nil {
		return nil, 0, err
	}
	return h, consumed, nil
}

// validate checks the invariants of a handshake request.
func (h *handshakeRequest) validate() error {
	if h == nil {
		return fmt.Errorf("handshake request is nil")
	}
	if len(h.suites) < 1 || len(h.suites) > maxHandshakeSuites {
		return fmt.Errorf("handshake request carries %d cipher suites, want between 1 and %d", len(h.suites), maxHandshakeSuites)
	}
	for i, suite := range h.suites {
		if !suite.IsValid() {
			return fmt.Errorf("handshake request carries unknown cipher suite %d", uint8(suite))
		}
		// A duplicate entry makes the preference list ambiguous, so it is
		// rejected instead of being collapsed here: a peer that parses an
		// untrusted request must not silently rewrite it.
		if slices.Contains(h.suites[:i], suite) {
			return fmt.Errorf("handshake request carries duplicate cipher suite %d", uint8(suite))
		}
	}
	if h.versionMin > h.versionMax {
		return fmt.Errorf("handshake request version range %d-%d is invalid", h.versionMin, h.versionMax)
	}
	return nil
}

// handshakeResponse is the payload of the openSessionResponse that completes a
// handshake. A status other than handshakeStatusOK means the handshake failed
// and version, suite, ephPub and serverSalt are all zero.
//
// The response is protected by the static key of the cipher suite that
// decrypted the handshake request, because the session keys depend on the
// content of the response itself.
type handshakeResponse struct {
	status     uint8
	version    uint8
	suite      cipher.Suite
	ephPub     [handshakeEphemeralKeyLen]byte
	serverSalt [handshakeSaltLen]byte
}

// Marshal serializes the handshake response. The length of the result is
// handshakeResponseLen.
func (h *handshakeResponse) Marshal() []byte {
	b := make([]byte, 0, handshakeResponseLen)
	b = append(b, h.status, h.version, byte(h.suite))
	b = append(b, h.ephPub[:]...)
	b = append(b, h.serverSalt[:]...)
	return b
}

// parseHandshakeResponse parses a handshake response.
// A response that is truncated or that carries an unknown status is rejected
// with an error. A well formed failure response (status 1 or 2) is returned to
// the caller, which must close the session. parseHandshakeResponse never
// panics.
func parseHandshakeResponse(b []byte) (*handshakeResponse, error) {
	if len(b) != handshakeResponseLen {
		return nil, fmt.Errorf("handshake response is %d bytes, want %d bytes", len(b), handshakeResponseLen)
	}
	h := &handshakeResponse{
		status:  b[0],
		version: b[1],
		suite:   cipher.Suite(b[2]),
	}
	copy(h.ephPub[:], b[3:3+handshakeEphemeralKeyLen])
	copy(h.serverSalt[:], b[3+handshakeEphemeralKeyLen:handshakeResponseLen])
	switch h.status {
	case handshakeStatusOK:
		if !h.suite.IsValid() {
			return nil, fmt.Errorf("handshake response carries unknown cipher suite %d", b[2])
		}
	case handshakeStatusNoVersion, handshakeStatusNoSuite:
		return h, nil
	default:
		return nil, fmt.Errorf("handshake response status %d is unknown", h.status)
	}
	if h.version < minSupportedProtocolVersion || h.version > maxSupportedProtocolVersion {
		return nil, fmt.Errorf("handshake response version %d is not supported", h.version)
	}
	return h, nil
}

// negotiateVersion returns the highest protocol version supported by both
// peers. The second return value is false when there is no common version.
func negotiateVersion(clientMin, clientMax uint8) (uint8, bool) {
	if clientMin > clientMax {
		return 0, false
	}
	version := min(maxSupportedProtocolVersion, clientMax)
	if version < max(minSupportedProtocolVersion, clientMin) {
		return 0, false
	}
	return version, true
}

// negotiateSuiteForEnvelope returns the cipher suite used by both peers under
// protocol version 2. A suite is selected only when it is allowed by the
// server, offered by the client, and needs no more key material than envelope
// provides; the server preference order decides among multiple remaining
// suites. The second return value is false when no candidate satisfies both the
// intersection and the envelope key length bound.
//
// Under version 2 the session keys are derived from the cipher that protected
// the handshake envelope, which only returns envelope.KeyLen() bytes of key
// material, so a candidate with a longer key could not protect the data plane.
// Such a candidate is skipped here instead of being negotiated and rejected
// later, so that a client whose preferred suite is shorter than the one the
// server prefers still completes the handshake. Version 3 peers use
// negotiateSuite() instead, which has no key length bound.
func negotiateSuiteForEnvelope(clientSuites []cipher.Suite, allowed []cipher.Suite, envelope cipher.Suite) (cipher.Suite, bool) {
	if len(allowed) == 0 {
		allowed = cipher.AllSuites()
	}
	for _, serverSuite := range allowed {
		if !serverSuite.IsValid() || serverSuite.KeyLen() > envelope.KeyLen() {
			continue
		}
		for _, clientSuite := range clientSuites {
			if clientSuite == serverSuite {
				return serverSuite, true
			}
		}
	}
	return 0, false
}

// negotiateSuite returns the cipher suite used by both peers under protocol
// version 3 and later. A suite is selected only when it is allowed by the
// server and offered by the client, and the server preference order decides
// among multiple candidates. The second return value is false when the
// intersection is empty.
//
// Unlike negotiateSuiteForEnvelope(), the selection is not bounded by the key
// length of the handshake envelope: from version 3 on the session keys are
// derived from the negotiated suite instead of the envelope cipher, so a
// negotiated suite may need more key material than the envelope provides.
func negotiateSuite(clientSuites []cipher.Suite, allowed []cipher.Suite) (cipher.Suite, bool) {
	if len(allowed) == 0 {
		allowed = cipher.AllSuites()
	}
	for _, serverSuite := range allowed {
		if !serverSuite.IsValid() {
			continue
		}
		for _, clientSuite := range clientSuites {
			if clientSuite == serverSuite {
				return serverSuite, true
			}
		}
	}
	return 0, false
}

// newHandshakeRequest builds a handshake request with a fresh ephemeral X25519
// key pair and a fresh client salt. The returned private key is never derived
// from the user credential, which gives the session keys forward secrecy.
func newHandshakeRequest(suites []cipher.Suite) (*handshakeRequest, *ecdh.PrivateKey, error) {
	normalized := normalizeClientCipherSuites(suites)
	privateKey, publicKey, err := cipher.GenerateEphemeralKey()
	if err != nil {
		return nil, nil, fmt.Errorf("cipher.GenerateEphemeralKey() failed: %w", err)
	}
	h := &handshakeRequest{
		versionMin: minSupportedProtocolVersion,
		versionMax: maxSupportedProtocolVersion,
		suites:     normalized,
	}
	copy(h.ephPub[:], publicKey)
	if _, err := crand.Read(h.clientSalt[:]); err != nil {
		return nil, nil, fmt.Errorf("generate client salt failed: %w", err)
	}
	return h, privateKey, nil
}

// failureResponse returns the handshake response of a failed handshake.
func handshakeFailureResponse(status uint8) *handshakeResponse {
	return &handshakeResponse{status: status}
}

// sessionSuite returns the cipher suite that protects the data plane of a
// version 2 handshake, or an error when the negotiated suite can't be used.
//
// Under version 2 the session keys are derived from the cipher that protected
// the handshake envelope, because it is the only static key both peers can mix
// into the derivation with the same time slot: a peer whose clock is offset may
// be using a different time slot than the local clock, and only the envelope
// cipher records the slot of the peer. The derivation therefore returns
// envelope.KeyLen() bytes of key material, so a negotiated suite with a longer
// key can't be used and the handshake must fail instead of silently using a
// suite the server doesn't allow.
//
// This function is a defensive check for version 2: negotiateSuiteForEnvelope()
// already skips every candidate whose key is longer than the key of the
// envelope, so it only rejects a caller that derived the session keys without
// passing the negotiated suite through that filter. Version 3 peers don't use
// it, because their session keys are derived from the negotiated suite.
func sessionSuite(negotiated, envelope cipher.Suite) (cipher.Suite, error) {
	if !negotiated.IsValid() {
		return 0, fmt.Errorf("negotiated cipher suite is invalid")
	}
	if negotiated.KeyLen() > envelope.KeyLen() {
		return 0, fmt.Errorf("negotiated cipher suite %v needs %d bytes of key, but the handshake envelope of cipher suite %v only provides %d bytes", negotiated, negotiated.KeyLen(), envelope, envelope.KeyLen())
	}
	return negotiated, nil
}

// deriveSessionKeys derives the client to server and the server to client data
// plane ciphers of a handshake. c must be the cipher that decrypted the
// handshake envelope, so that both peers mix the same static key and the same
// time slot into the key derivation. suite is the negotiated cipher suite of
// the data plane, and version selects the derivation:
//
//   - from version 3 on, the session keys are derived from the negotiated suite,
//     so the negotiated suite may need more key material than the envelope
//     provides;
//   - under version 2 they are derived from the cipher that protected the
//     handshake envelope, which keeps the keys of an old peer bit for bit
//     identical, and the negotiated suite must not need more key material than
//     the envelope provides.
func deriveSessionKeys(c cipher.BlockCipher, suite cipher.Suite, privateKey *ecdh.PrivateKey, peerPub, clientSalt, serverSalt []byte, version uint8, stateless bool) (c2s, s2c cipher.BlockCipher, err error) {
	if c == nil {
		return nil, nil, fmt.Errorf("handshake cipher is nil")
	}
	if privateKey == nil {
		return nil, nil, fmt.Errorf("handshake private key is nil")
	}
	// keySuite selects the HKDF info and the key length. dataSuite protects the
	// data plane. They are the negotiated suite from version 3 on; under
	// version 2 the keys are derived from the envelope cipher, and only their
	// first dataSuite.KeyLen() bytes are used.
	dataSuite := suite
	keySuite := suite
	if version < 3 {
		if dataSuite, err = sessionSuite(suite, c.Suite()); err != nil {
			return nil, nil, err
		}
		keySuite = c.Suite()
	}
	shared, err := cipher.SharedSecret(privateKey, peerPub)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher.SharedSecret() failed: %w", err)
	}
	ctx := c.BlockContext()
	pattern := c.NoncePattern()
	c2sKey, s2cKey, err := cipher.DeriveSessionKeys(c, keySuite, shared, clientSalt, serverSalt, version)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher.DeriveSessionKeys() failed: %w", err)
	}
	c2s, err = cipher.NewBlockCipherFromKey(dataSuite, c2sKey, stateless)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher.NewBlockCipherFromKey() failed: %w", err)
	}
	s2c, err = cipher.NewBlockCipherFromKey(dataSuite, s2cKey, stateless)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher.NewBlockCipherFromKey() failed: %w", err)
	}
	// The session keys are protected by the same nonce rules as the static
	// key: the user hint in the wire nonce and the configured nonce pattern
	// must be preserved, otherwise a server can't map a packet to its user and
	// the traffic pattern of the client is lost.
	for _, block := range []cipher.BlockCipher{c2s, s2c} {
		block.SetBlockContext(ctx)
		if pattern != nil {
			block.SetNoncePattern(pattern)
		}
	}
	return c2s, s2c, nil
}

// normalizeClientCipherSuites returns the cipher suite preference list of a
// client: unknown suites and duplicates are dropped, the order is preserved,
// the list is at most maxHandshakeSuites long, and an empty list falls back to
// SuiteXChaCha20Poly1305.
func normalizeClientCipherSuites(suites []cipher.Suite) []cipher.Suite {
	normalized := make([]cipher.Suite, 0, min(len(suites), maxHandshakeSuites))
	for _, suite := range suites {
		if !suite.IsValid() {
			continue
		}
		if len(normalized) == maxHandshakeSuites {
			log.Printf("Ignoring cipher suites after the first %d entries of the client preference list", maxHandshakeSuites)
			break
		}
		if slices.Contains(normalized, suite) {
			continue
		}
		normalized = append(normalized, suite)
	}
	if len(normalized) == 0 {
		return []cipher.Suite{cipher.SuiteXChaCha20Poly1305}
	}
	return normalized
}

// normalizeAllowedCipherSuites returns the cipher suite set that a server
// allows: unknown suites and duplicates are dropped, the order is preserved,
// and an empty list falls back to all the supported suites.
func normalizeAllowedCipherSuites(suites []cipher.Suite) []cipher.Suite {
	normalized := make([]cipher.Suite, 0, len(suites))
	for _, suite := range suites {
		if !suite.IsValid() || slices.Contains(normalized, suite) {
			continue
		}
		normalized = append(normalized, suite)
	}
	if len(normalized) == 0 {
		return cipher.AllSuites()
	}
	return normalized
}
