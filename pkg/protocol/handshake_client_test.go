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
	"strings"
	"testing"

	"github.com/enfein/mieru/v3/pkg/cipher"
	"github.com/enfein/mieru/v3/pkg/common"
)

// testClientHandshakeSessionID is the session ID of the client sessions that
// the unit tests of the client side of a handshake build.
const testClientHandshakeSessionID uint32 = 601

// testNewClientHandshakeSession returns a client session whose handshake is
// pending: the session offers suites as its cipher suite preference list and
// holds the ephemeral X25519 key pair of a handshake request that waits for
// the response of the server.
//
// The second return value is the public key of that private key, so that a
// test can build a response that the session is able to derive keys with.
func testNewClientHandshakeSession(tb testing.TB, suites []cipher.Suite) (*Session, []byte) {
	tb.Helper()
	privateKey, publicKey, err := cipher.GenerateEphemeralKey()
	if err != nil {
		tb.Fatalf("cipher.GenerateEphemeralKey() failed: %v", err)
	}
	session := NewSession(testClientHandshakeSessionID, true, 1400, nil, nil)
	session.transportProtocol = common.StreamTransport
	session.handshakeMu.Lock()
	session.handshakeSuites = normalizeClientCipherSuites(suites)
	session.handshakePriv = privateKey
	session.handshakeMu.Unlock()
	return session, publicKey
}

// testClientHandshakeResponseSegment returns the open session response segment
// that carries a handshake response payload.
func testClientHandshakeResponseSegment(tb testing.TB, sessionID uint32, payload []byte) *segment {
	tb.Helper()
	seg := testSessionSegment(openSessionResponse, sessionID, common.StreamTransport)
	ss, ok := seg.metadata.(*sessionStruct)
	if !ok {
		tb.Fatalf("test session metadata type = %T, want sessionStruct", seg.metadata)
	}
	ss.payloadLen = uint16(len(payload))
	seg.payload = payload
	return seg
}

// TestSessionSuite verifies the check that rejects a negotiated suite the
// handshake envelope can't provide key material for.
func TestSessionSuite(t *testing.T) {
	testCases := []struct {
		name       string
		negotiated cipher.Suite
		envelope   cipher.Suite
		wantSuite  cipher.Suite
		wantErr    bool
	}{
		{
			name:       "the same suite as the envelope",
			negotiated: cipher.SuiteXChaCha20Poly1305,
			envelope:   cipher.SuiteXChaCha20Poly1305,
			wantSuite:  cipher.SuiteXChaCha20Poly1305,
		},
		{
			name:       "a shorter key than the envelope",
			negotiated: cipher.SuiteAES128GCM,
			envelope:   cipher.SuiteXChaCha20Poly1305,
			wantSuite:  cipher.SuiteAES128GCM,
		},
		{
			name:       "a shorter key than an AES-256 envelope",
			negotiated: cipher.SuiteAES128GCM,
			envelope:   cipher.SuiteAES256GCM,
			wantSuite:  cipher.SuiteAES128GCM,
		},
		{
			name:       "a longer key than the envelope",
			negotiated: cipher.SuiteXChaCha20Poly1305,
			envelope:   cipher.SuiteAES128GCM,
			wantErr:    true,
		},
		{
			name:       "an invalid negotiated suite",
			negotiated: cipher.Suite(9),
			envelope:   cipher.SuiteXChaCha20Poly1305,
			wantErr:    true,
		},
		{
			name:       "an invalid envelope",
			negotiated: cipher.SuiteAES128GCM,
			envelope:   cipher.Suite(9),
			wantErr:    true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			suite, err := sessionSuite(tc.negotiated, tc.envelope)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("sessionSuite(%v, %v) succeeded, want an error", tc.negotiated, tc.envelope)
				}
				if suite != 0 {
					t.Fatalf("sessionSuite(%v, %v) = %v with an error, want the zero suite", tc.negotiated, tc.envelope, suite)
				}
				return
			}
			if err != nil {
				t.Fatalf("sessionSuite(%v, %v) failed: %v", tc.negotiated, tc.envelope, err)
			}
			if suite != tc.wantSuite {
				t.Fatalf("sessionSuite(%v, %v) = %v, want %v", tc.negotiated, tc.envelope, suite, tc.wantSuite)
			}
		})
	}
}

// TestDeriveClientHandshake drives the client side of a handshake with a
// handcrafted response. It covers the rejection paths of the failure statuses
// and of a response that carries a suite the client didn't offer, and the
// success path that derives, but doesn't publish, the data plane ciphers.
func TestDeriveClientHandshake(t *testing.T) {
	password := []byte("a client side handshake test credential")
	envelope, err := cipher.BlockCipherFromPassword(cipher.SuiteAES128GCM, password, false)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}

	testCases := []struct {
		// suites is the cipher suite preference list of the client. status,
		// suite and version build the response of the server, unless rawPayload
		// holds the payload of the response as is. A zero version uses the
		// version of this build.
		name       string
		suites     []cipher.Suite
		status     uint8
		suite      cipher.Suite
		version    uint8
		rawPayload []byte
		wantSuite  cipher.Suite
		wantErr    string
	}{
		{
			name:    "status no common version",
			suites:  []cipher.Suite{cipher.SuiteAES128GCM},
			status:  handshakeStatusNoVersion,
			wantErr: "don't intersect",
		},
		{
			name:    "status no common suite",
			suites:  []cipher.Suite{cipher.SuiteAES128GCM},
			status:  handshakeStatusNoSuite,
			wantErr: "no common cipher suite with the server",
		},
		{
			name:    "status ok with a suite the client didn't offer",
			suites:  []cipher.Suite{cipher.SuiteAES128GCM},
			status:  handshakeStatusOK,
			suite:   cipher.SuiteXChaCha20Poly1305,
			wantErr: "which the client didn't offer",
		},
		{
			name:       "unknown status",
			suites:     []cipher.Suite{cipher.SuiteAES128GCM},
			rawPayload: append([]byte{9}, make([]byte, handshakeResponseLen-1)...),
			wantErr:    "parseHandshakeResponse() failed",
		},
		{
			name:      "status ok",
			suites:    []cipher.Suite{cipher.SuiteAES128GCM, cipher.SuiteXChaCha20Poly1305},
			status:    handshakeStatusOK,
			suite:     cipher.SuiteAES128GCM,
			wantSuite: cipher.SuiteAES128GCM,
		},
		{
			name:      "status ok under version 2 with the envelope suite",
			suites:    []cipher.Suite{cipher.SuiteAES128GCM},
			status:    handshakeStatusOK,
			suite:     cipher.SuiteAES128GCM,
			version:   2,
			wantSuite: cipher.SuiteAES128GCM,
		},
		{
			// From version 3 on the client derives the data plane keys from the
			// negotiated suite, so it accepts a suite that needs more key
			// material than the 16 bytes envelope.
			name:      "status ok with a suite longer than the envelope",
			suites:    []cipher.Suite{cipher.SuiteXChaCha20Poly1305},
			status:    handshakeStatusOK,
			suite:     cipher.SuiteXChaCha20Poly1305,
			version:   3,
			wantSuite: cipher.SuiteXChaCha20Poly1305,
		},
		{
			// Under version 2 the client derives the data plane keys from the
			// envelope cipher, so a suite with a longer key must fail.
			name:    "status ok with a suite longer than the envelope under version 2",
			suites:  []cipher.Suite{cipher.SuiteXChaCha20Poly1305},
			status:  handshakeStatusOK,
			suite:   cipher.SuiteXChaCha20Poly1305,
			version: 2,
			wantErr: "only provides",
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			session, publicKey := testNewClientHandshakeSession(t, tc.suites)
			payload := tc.rawPayload
			if payload == nil {
				response := &handshakeResponse{status: tc.status, suite: tc.suite}
				if tc.status == handshakeStatusOK {
					response.version = tc.version
					if response.version == 0 {
						response.version = maxSupportedProtocolVersion
					}
					copy(response.ephPub[:], publicKey)
				}
				payload = response.Marshal()
			}
			seg := testClientHandshakeResponseSegment(t, session.id, payload)
			c2s, s2c, response, err := session.deriveClientHandshake(seg, envelope, false)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("deriveClientHandshake() succeeded, want an error that contains %q", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("deriveClientHandshake() error = %v, want an error that contains %q", err, tc.wantErr)
				}
				if c2s != nil || s2c != nil || response != nil {
					t.Fatalf("deriveClientHandshake() returned (%v, %v, %v) together with an error", c2s, s2c, response)
				}
				if session.handshakeDone.Load() {
					t.Fatal("a failed handshake was published")
				}
				return
			}
			if err != nil {
				t.Fatalf("deriveClientHandshake() failed: %v", err)
			}
			if c2s == nil || s2c == nil {
				t.Fatal("deriveClientHandshake() didn't derive the data plane ciphers")
			}
			if got := c2s.Suite(); got != tc.wantSuite {
				t.Fatalf("client to server cipher suite = %v, want %v", got, tc.wantSuite)
			}
			if got := s2c.Suite(); got != tc.wantSuite {
				t.Fatalf("server to client cipher suite = %v, want %v", got, tc.wantSuite)
			}
			if response == nil || response.suite != tc.wantSuite {
				t.Fatalf("handshake response = %v, want the negotiated suite %v", response, tc.wantSuite)
			}
			// The response is not application data, but deriving the session
			// keys publishes nothing: the transport commits the handshake
			// after it switched its cipher chain.
			if len(seg.payload) != 0 {
				t.Fatalf("the handshake response payload is %d bytes, want 0", len(seg.payload))
			}
			if session.handshakeDone.Load() {
				t.Fatal("deriveClientHandshake() published the handshake")
			}
			if session.block.Load() != nil || session.sendBlock.Load() != nil {
				t.Fatal("deriveClientHandshake() installed the session ciphers")
			}
		})
	}
}
