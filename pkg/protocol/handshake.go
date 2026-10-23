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
	// protocolVersion is the only protocol version supported by this build.
	//
	// A handshake request still carries a version range and a handshake
	// response still carries a version, but the version is never negotiated: a
	// request that doesn't carry protocolVersion is dropped without an answer.
	//
	// The session keys are derived from the negotiated cipher suite instead of
	// the cipher that protected the handshake envelope, so a negotiated suite
	// is not bounded by the key length of the envelope.
	protocolVersion uint8 = 3

	// minSupportedProtocolVersion and maxSupportedProtocolVersion bound the
	// protocol version range of this build. The range holds the single version
	// above, so both bounds equal protocolVersion: a peer that doesn't carry
	// that version is dropped, and the two names are kept because the wire
	// format speaks in version ranges.
	minSupportedProtocolVersion uint8 = protocolVersion
	maxSupportedProtocolVersion uint8 = protocolVersion

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

	// handshake status codes. A handshake response carries either
	// handshakeStatusOK or handshakeStatusNoSuite: a request that doesn't carry
	// the protocol version of this build is dropped without any answer.
	handshakeStatusOK      = 0
	handshakeStatusNoSuite = 2

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
// handshake. handshakeStatusNoSuite means the handshake failed because the
// client and the server share no cipher suite: version, suite, ephPub and
// serverSalt are all zero in that case.
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
// A response that is truncated, that carries an unknown status or that carries
// a version other than protocolVersion is rejected with an error. A well formed
// failure response (status handshakeStatusNoSuite) is returned to the caller,
// which must close the session. parseHandshakeResponse never panics.
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
	case handshakeStatusNoSuite:
		return h, nil
	default:
		return nil, fmt.Errorf("handshake response status %d is unknown", h.status)
	}
	if h.version != protocolVersion {
		return nil, fmt.Errorf("handshake response version %d is not supported", h.version)
	}
	return h, nil
}

// negotiateVersion returns the protocol version supported by both peers. The
// second return value is false when the version range of the client doesn't
// contain protocolVersion, which is the only version this build speaks.
func negotiateVersion(clientMin, clientMax uint8) (uint8, bool) {
	if clientMin > clientMax || clientMin > protocolVersion || clientMax < protocolVersion {
		return 0, false
	}
	return protocolVersion, true
}

// negotiateSuite returns the cipher suite used by both peers. A suite is
// selected only when it is allowed by the server and offered by the client, and
// the server preference order decides among multiple candidates. The second
// return value is false when the intersection is empty.
//
// The selection is not bounded by the key length of the handshake envelope: the
// session keys are derived from the negotiated suite instead of the envelope
// cipher, so a negotiated suite may need more key material than the envelope
// provides.
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

// handshakeFailureResponse returns the handshake response of a failed
// handshake. The only failure a peer is told about is a missing common cipher
// suite, so status is handshakeStatusNoSuite.
func handshakeFailureResponse(status uint8) *handshakeResponse {
	return &handshakeResponse{status: status}
}

// deriveSessionKeys derives the client to server and the server to client data
// plane ciphers of a handshake. c must be the cipher that decrypted the
// handshake envelope, so that both peers mix the same static key and the same
// time slot into the key derivation. suite is the negotiated cipher suite of
// the data plane: the session keys are derived from that suite, so it may need
// more key material than the envelope provides.
func deriveSessionKeys(c cipher.BlockCipher, suite cipher.Suite, privateKey *ecdh.PrivateKey, peerPub, clientSalt, serverSalt []byte, stateless bool) (c2s, s2c cipher.BlockCipher, err error) {
	if c == nil {
		return nil, nil, fmt.Errorf("handshake cipher is nil")
	}
	if privateKey == nil {
		return nil, nil, fmt.Errorf("handshake private key is nil")
	}
	shared, err := cipher.SharedSecret(privateKey, peerPub)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher.SharedSecret() failed: %w", err)
	}
	ctx := c.BlockContext()
	pattern := c.NoncePattern()
	c2sKey, s2cKey, err := cipher.DeriveSessionKeys(c, suite, shared, clientSalt, serverSalt, protocolVersion)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher.DeriveSessionKeys() failed: %w", err)
	}
	c2s, err = cipher.NewBlockCipherFromKey(suite, c2sKey, stateless)
	if err != nil {
		return nil, nil, fmt.Errorf("cipher.NewBlockCipherFromKey() failed: %w", err)
	}
	s2c, err = cipher.NewBlockCipherFromKey(suite, s2cKey, stateless)
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
