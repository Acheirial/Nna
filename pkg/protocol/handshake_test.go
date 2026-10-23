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
	"bytes"
	"reflect"
	"testing"

	"github.com/Acheirial/shadowlemon/v3/pkg/cipher"
	"github.com/Acheirial/shadowlemon/v3/pkg/common"
)

func TestHandshakeRequestRoundTrip(t *testing.T) {
	testCases := []struct {
		name   string
		suites []cipher.Suite
	}{
		{
			name:   "one suite",
			suites: []cipher.Suite{cipher.SuiteXChaCha20Poly1305},
		},
		{
			name:   "two suites",
			suites: []cipher.Suite{cipher.SuiteXChaCha20Poly1305, cipher.SuiteAES256GCM},
		},
		{
			name:   "all suites",
			suites: cipher.AllSuites(),
		},
		{
			name:   "client preference order",
			suites: []cipher.Suite{cipher.SuiteAES128GCM, cipher.SuiteAES256GCM, cipher.SuiteXChaCha20Poly1305},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			request, privateKey, err := newHandshakeRequest(tc.suites)
			if err != nil {
				t.Fatalf("newHandshakeRequest() failed: %v", err)
			}
			if privateKey == nil {
				t.Fatal("newHandshakeRequest() returned a nil private key")
			}
			if got, want := len(request.suites), len(tc.suites); got != want {
				t.Fatalf("number of suites = %d, want %d", got, want)
			}
			b := request.Marshal()
			if got, want := len(b), handshakeRequestFixedLen+len(tc.suites); got != want {
				t.Fatalf("marshaled length = %d, want %d", got, want)
			}

			parsed, consumed, err := parseHandshakeRequest(b)
			if err != nil {
				t.Fatalf("parseHandshakeRequest() failed: %v", err)
			}
			if consumed != len(b) {
				t.Fatalf("consumed %d bytes, want %d", consumed, len(b))
			}
			if parsed.versionMin != protocolVersion || parsed.versionMax != protocolVersion {
				t.Fatalf("version range = %d-%d, want %d-%d", parsed.versionMin, parsed.versionMax, protocolVersion, protocolVersion)
			}
			if !reflect.DeepEqual(parsed.suites, request.suites) {
				t.Fatalf("suites = %v, want %v", parsed.suites, request.suites)
			}
			if parsed.ephPub != request.ephPub {
				t.Fatalf("ephemeral public key is not round tripped")
			}
			if parsed.clientSalt != request.clientSalt {
				t.Fatalf("client salt is not round tripped")
			}
		})
	}
}

func TestParseHandshakeRequestWithApplicationData(t *testing.T) {
	request, _, err := newHandshakeRequest(cipher.AllSuites())
	if err != nil {
		t.Fatalf("newHandshakeRequest() failed: %v", err)
	}
	payload := append(request.Marshal(), []byte("hello world")...)
	parsed, consumed, err := parseHandshakeRequest(payload)
	if err != nil {
		t.Fatalf("parseHandshakeRequest() failed: %v", err)
	}
	if want := handshakeRequestFixedLen + len(cipher.AllSuites()); consumed != want {
		t.Fatalf("consumed %d bytes, want %d", consumed, want)
	}
	if got := string(payload[consumed:]); got != "hello world" {
		t.Fatalf("application data = %q, want %q", got, "hello world")
	}
	if len(parsed.suites) != len(cipher.AllSuites()) {
		t.Fatalf("suites = %v, want %v", parsed.suites, cipher.AllSuites())
	}
}

func TestParseHandshakeRequestRejects(t *testing.T) {
	valid, _, err := newHandshakeRequest([]cipher.Suite{cipher.SuiteXChaCha20Poly1305, cipher.SuiteAES256GCM})
	if err != nil {
		t.Fatalf("newHandshakeRequest() failed: %v", err)
	}
	validBytes := valid.Marshal()

	// A well formed request of one suite, so that the length checks are
	// exercised independently of the suite count.
	oneSuite, _, err := newHandshakeRequest([]cipher.Suite{cipher.SuiteXChaCha20Poly1305})
	if err != nil {
		t.Fatalf("newHandshakeRequest() failed: %v", err)
	}
	oneSuiteBytes := oneSuite.Marshal()

	// A request that offers the same suite twice is rejected even though its
	// length and its suites are otherwise valid.
	duplicateSuites, _, err := newHandshakeRequest([]cipher.Suite{cipher.SuiteAES128GCM, cipher.SuiteAES256GCM})
	if err != nil {
		t.Fatalf("newHandshakeRequest() failed: %v", err)
	}
	duplicateBytes := duplicateSuites.Marshal()
	duplicateBytes[handshakeRequestHeaderLen+1] = duplicateBytes[handshakeRequestHeaderLen]

	testCases := []struct {
		name string
		data []byte
	}{
		{
			name: "empty",
			data: nil,
		},
		{
			name: "header only",
			data: []byte{2, 2, 1},
		},
		{
			name: "one byte short",
			data: oneSuiteBytes[:len(oneSuiteBytes)-1],
		},
		{
			name: "truncated suite list",
			data: validBytes[:4],
		},
		{
			name: "zero suites",
			data: []byte{2, 2, 0},
		},
		{
			name: "too many suites",
			data: []byte{2, 2, maxHandshakeSuites + 1},
		},
		{
			name: "unknown suite",
			data: []byte{2, 2, 1, 3},
		},
		{
			name: "duplicate suite",
			data: duplicateBytes,
		},
		{
			name: "version min above max",
			data: []byte{3, 2, 1},
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("parseHandshakeRequest() panicked: %v", r)
				}
			}()
			if _, _, err := parseHandshakeRequest(tc.data); err == nil {
				t.Fatalf("parseHandshakeRequest(%v) succeeded, want an error", tc.data)
			}
		})
	}
}

func TestHandshakeResponseRoundTrip(t *testing.T) {
	testCases := []struct {
		name     string
		response *handshakeResponse
	}{
		{
			name: "success",
			response: &handshakeResponse{
				status:  handshakeStatusOK,
				version: protocolVersion,
				suite:   cipher.SuiteAES256GCM,
				ephPub:  [handshakeEphemeralKeyLen]byte{1, 2, 3},
			},
		},
		{
			name:     "no common suite",
			response: handshakeFailureResponse(handshakeStatusNoSuite),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			b := tc.response.Marshal()
			if len(b) != handshakeResponseLen {
				t.Fatalf("marshaled length = %d, want %d", len(b), handshakeResponseLen)
			}
			parsed, err := parseHandshakeResponse(b)
			if err != nil {
				t.Fatalf("parseHandshakeResponse() failed: %v", err)
			}
			if *parsed != *tc.response {
				t.Fatalf("parsed response = %+v, want %+v", *parsed, *tc.response)
			}
		})
	}

	// The success response round trips the salts as well.
	response := &handshakeResponse{
		status:     handshakeStatusOK,
		version:    protocolVersion,
		suite:      cipher.SuiteAES128GCM,
		serverSalt: [handshakeSaltLen]byte{9, 8, 7},
	}
	parsed, err := parseHandshakeResponse(response.Marshal())
	if err != nil {
		t.Fatalf("parseHandshakeResponse() failed: %v", err)
	}
	if parsed.serverSalt != response.serverSalt {
		t.Fatalf("server salt = %v, want %v", parsed.serverSalt, response.serverSalt)
	}
}

func TestParseHandshakeResponseRejects(t *testing.T) {
	valid := &handshakeResponse{
		status:  handshakeStatusOK,
		version: protocolVersion,
		suite:   cipher.SuiteXChaCha20Poly1305,
	}
	validBytes := valid.Marshal()
	unknownSuite := *valid
	unknownSuite.suite = cipher.Suite(9)
	previousVersion := *valid
	previousVersion.version = 2
	oldestVersion := *valid
	oldestVersion.version = 1

	testCases := []struct {
		name string
		data []byte
	}{
		{
			name: "empty",
			data: nil,
		},
		{
			name: "one byte short",
			data: validBytes[:len(validBytes)-1],
		},
		{
			name: "one byte long",
			data: append(append([]byte{}, validBytes...), 0),
		},
		{
			name: "unknown status",
			data: append([]byte{9}, validBytes[1:]...),
		},
		{
			name: "unknown suite",
			data: unknownSuite.Marshal(),
		},
		{
			name: "unsupported version of a previous peer",
			data: previousVersion.Marshal(),
		},
		{
			name: "unsupported version of the oldest peer",
			data: oldestVersion.Marshal(),
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			defer func() {
				if r := recover(); r != nil {
					t.Fatalf("parseHandshakeResponse() panicked: %v", r)
				}
			}()
			if _, err := parseHandshakeResponse(tc.data); err == nil {
				t.Fatalf("parseHandshakeResponse(%v) succeeded, want an error", tc.data)
			}
		})
	}
}

// TestNegotiateVersion verifies that the version of a client is accepted only
// when its range contains the single protocol version of this build.
func TestNegotiateVersion(t *testing.T) {
	testCases := []struct {
		name             string
		clientMin        uint8
		clientMax        uint8
		wantVersion      uint8
		wantIntersection bool
	}{
		{
			name:             "client only supports the protocol version of this build",
			clientMin:        protocolVersion,
			clientMax:        protocolVersion,
			wantVersion:      protocolVersion,
			wantIntersection: true,
		},
		{
			name:             "client supports version 1 to 3",
			clientMin:        1,
			clientMax:        protocolVersion,
			wantVersion:      protocolVersion,
			wantIntersection: true,
		},
		{
			name:             "client only supports version 1",
			clientMin:        1,
			clientMax:        1,
			wantIntersection: false,
		},
		{
			name:             "client only supports a version of a previous peer",
			clientMin:        2,
			clientMax:        2,
			wantIntersection: false,
		},
		{
			name:             "client only supports versions above the build",
			clientMin:        4,
			clientMax:        5,
			wantIntersection: false,
		},
		{
			name:             "invalid range",
			clientMin:        3,
			clientMax:        2,
			wantIntersection: false,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			version, ok := negotiateVersion(tc.clientMin, tc.clientMax)
			if ok != tc.wantIntersection {
				t.Fatalf("negotiateVersion(%d, %d) intersection = %v, want %v", tc.clientMin, tc.clientMax, ok, tc.wantIntersection)
			}
			if ok && version != tc.wantVersion {
				t.Fatalf("negotiateVersion(%d, %d) version = %d, want %d", tc.clientMin, tc.clientMax, version, tc.wantVersion)
			}
		})
	}
}

// TestNegotiateSuite verifies the cipher suite selection: the server preference
// order decides and the key length of the handshake envelope is not a bound.
func TestNegotiateSuite(t *testing.T) {
	testCases := []struct {
		name          string
		clientSuites  []cipher.Suite
		allowedSuites []cipher.Suite
		wantSuite     cipher.Suite
		wantCommon    bool
	}{
		{
			name:          "server preference decides",
			clientSuites:  []cipher.Suite{cipher.SuiteAES128GCM, cipher.SuiteXChaCha20Poly1305},
			allowedSuites: []cipher.Suite{cipher.SuiteXChaCha20Poly1305, cipher.SuiteAES128GCM},
			wantSuite:     cipher.SuiteXChaCha20Poly1305,
			wantCommon:    true,
		},
		{
			name:          "a suite with a longer key than the envelope is kept",
			clientSuites:  []cipher.Suite{cipher.SuiteAES128GCM, cipher.SuiteXChaCha20Poly1305},
			allowedSuites: cipher.AllSuites(),
			wantSuite:     cipher.SuiteXChaCha20Poly1305,
			wantCommon:    true,
		},
		{
			name:          "the whole client preference list is considered",
			clientSuites:  []cipher.Suite{cipher.SuiteAES128GCM, cipher.SuiteAES256GCM, cipher.SuiteXChaCha20Poly1305},
			allowedSuites: []cipher.Suite{cipher.SuiteXChaCha20Poly1305, cipher.SuiteAES128GCM},
			wantSuite:     cipher.SuiteXChaCha20Poly1305,
			wantCommon:    true,
		},
		{
			name:          "empty intersection",
			clientSuites:  []cipher.Suite{cipher.SuiteXChaCha20Poly1305},
			allowedSuites: []cipher.Suite{cipher.SuiteAES128GCM},
			wantCommon:    false,
		},
		{
			name:          "empty client list",
			clientSuites:  nil,
			allowedSuites: cipher.AllSuites(),
			wantCommon:    false,
		},
		{
			name:          "empty allowed list means all suites",
			clientSuites:  []cipher.Suite{cipher.SuiteAES128GCM},
			allowedSuites: nil,
			wantSuite:     cipher.SuiteAES128GCM,
			wantCommon:    true,
		},
		{
			name:          "unknown allowed suite is ignored",
			clientSuites:  []cipher.Suite{cipher.SuiteAES256GCM},
			allowedSuites: []cipher.Suite{cipher.Suite(7), cipher.SuiteAES256GCM},
			wantSuite:     cipher.SuiteAES256GCM,
			wantCommon:    true,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			suite, ok := negotiateSuite(tc.clientSuites, tc.allowedSuites)
			if ok != tc.wantCommon {
				t.Fatalf("negotiateSuite(%v, %v) common = %v, want %v", tc.clientSuites, tc.allowedSuites, ok, tc.wantCommon)
			}
			if ok && suite != tc.wantSuite {
				t.Fatalf("negotiateSuite(%v, %v) = %v, want %v", tc.clientSuites, tc.allowedSuites, suite, tc.wantSuite)
			}
		})
	}
}

func TestNormalizeCipherSuites(t *testing.T) {
	all := cipher.AllSuites()
	clientCases := []struct {
		name  string
		input []cipher.Suite
		want  []cipher.Suite
	}{
		{
			name:  "empty uses the default",
			input: nil,
			want:  []cipher.Suite{cipher.SuiteXChaCha20Poly1305},
		},
		{
			name:  "duplicates are dropped and order is kept",
			input: []cipher.Suite{cipher.SuiteAES128GCM, cipher.SuiteAES128GCM, cipher.SuiteAES256GCM},
			want:  []cipher.Suite{cipher.SuiteAES128GCM, cipher.SuiteAES256GCM},
		},
		{
			name:  "unknown suites are dropped",
			input: []cipher.Suite{cipher.Suite(11), cipher.SuiteAES256GCM},
			want:  []cipher.Suite{cipher.SuiteAES256GCM},
		},
		{
			name:  "only unknown suites fall back to the default",
			input: []cipher.Suite{cipher.Suite(11)},
			want:  []cipher.Suite{cipher.SuiteXChaCha20Poly1305},
		},
		{
			name:  "the list is capped",
			input: []cipher.Suite{cipher.SuiteAES128GCM, cipher.SuiteAES256GCM, cipher.SuiteXChaCha20Poly1305, cipher.SuiteAES128GCM},
			want:  []cipher.Suite{cipher.SuiteAES128GCM, cipher.SuiteAES256GCM, cipher.SuiteXChaCha20Poly1305},
		},
	}
	for _, tc := range clientCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeClientCipherSuites(tc.input); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("normalizeClientCipherSuites(%v) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}

	serverCases := []struct {
		name  string
		input []cipher.Suite
		want  []cipher.Suite
	}{
		{
			name:  "empty uses all suites",
			input: nil,
			want:  all,
		},
		{
			name:  "duplicates are dropped",
			input: []cipher.Suite{cipher.SuiteAES256GCM, cipher.SuiteAES256GCM},
			want:  []cipher.Suite{cipher.SuiteAES256GCM},
		},
		{
			name:  "unknown suites are dropped",
			input: []cipher.Suite{cipher.Suite(9)},
			want:  all,
		},
	}
	for _, tc := range serverCases {
		t.Run(tc.name, func(t *testing.T) {
			if got := normalizeAllowedCipherSuites(tc.input); !reflect.DeepEqual(got, tc.want) {
				t.Fatalf("normalizeAllowedCipherSuites(%v) = %v, want %v", tc.input, got, tc.want)
			}
		})
	}
}

// TestDeriveSessionKeysAgree proves that both peers derive the same data plane
// keys, and that the direction separation and the salts are part of the
// derivation.
func TestDeriveSessionKeysAgree(t *testing.T) {
	for _, suite := range cipher.AllSuites() {
		t.Run(suite.String(), func(t *testing.T) {
			password := []byte("a shared user credential")
			clientStatic, err := cipher.BlockCipherFromPassword(suite, password, true)
			if err != nil {
				t.Fatalf("BlockCipherFromPassword() for the client failed: %v", err)
			}
			serverStatic, err := cipher.BlockCipherFromPassword(suite, password, true)
			if err != nil {
				t.Fatalf("BlockCipherFromPassword() for the server failed: %v", err)
			}
			clientPriv, clientPub, err := cipher.GenerateEphemeralKey()
			if err != nil {
				t.Fatalf("GenerateEphemeralKey() for the client failed: %v", err)
			}
			serverPriv, serverPub, err := cipher.GenerateEphemeralKey()
			if err != nil {
				t.Fatalf("GenerateEphemeralKey() for the server failed: %v", err)
			}
			clientSalt := []byte("0123456789abcdef")
			serverSalt := []byte("fedcba9876543210")

			clientC2S, clientS2C, err := deriveSessionKeys(clientStatic, suite, clientPriv, serverPub, clientSalt, serverSalt, true)
			if err != nil {
				t.Fatalf("deriveSessionKeys() for the client failed: %v", err)
			}
			serverC2S, serverS2C, err := deriveSessionKeys(serverStatic, suite, serverPriv, clientPub, clientSalt, serverSalt, true)
			if err != nil {
				t.Fatalf("deriveSessionKeys() for the server failed: %v", err)
			}

			// A client to server message must decrypt with the server side
			// client to server key.
			plaintext := []byte("a data plane message")
			// Encrypt() writes the wire format nonce, the ciphertext and the
			// tag into the destination slice without returning a slice, so the
			// destination must be allocated with its final length. Allocating
			// it with a zero length would leave the test with an empty buffer.
			encrypted := make([]byte, cipher.DefaultNonceSize+len(plaintext)+cipher.DefaultOverhead)
			if err := clientC2S.Encrypt(encrypted[:0], plaintext); err != nil {
				t.Fatalf("Encrypt() failed: %v", err)
			}
			wire := append([]byte{}, encrypted...)
			if len(wire) != cipher.DefaultNonceSize+len(plaintext)+cipher.DefaultOverhead {
				t.Fatalf("encrypted wire is %d bytes, want %d", len(wire), cipher.DefaultNonceSize+len(plaintext)+cipher.DefaultOverhead)
			}
			decrypted, err := serverC2S.Decrypt(wire)
			if err != nil {
				t.Fatalf("Decrypt() with the server c2s key failed: %v", err)
			}
			if !bytes.Equal(decrypted, plaintext) {
				t.Fatalf("decrypted message = %q, want %q", decrypted, plaintext)
			}

			// The server to client key is not the same as the client to server
			// key, so the wrong direction can't decrypt the message.
			if _, err := serverS2C.Decrypt(append([]byte{}, encrypted...)); err == nil {
				t.Fatal("Decrypt() with the wrong direction succeeded")
			}
			if _, err := clientS2C.Decrypt(append([]byte{}, encrypted...)); err == nil {
				t.Fatal("Decrypt() with the s2c key succeeded, want a failure")
			}

			// A different static key changes the session keys.
			otherStatic, err := cipher.BlockCipherFromPassword(suite, []byte("another credential"), true)
			if err != nil {
				t.Fatalf("BlockCipherFromPassword() for another credential failed: %v", err)
			}
			otherC2S, _, err := deriveSessionKeys(otherStatic, suite, clientPriv, serverPub, clientSalt, serverSalt, true)
			if err != nil {
				t.Fatalf("deriveSessionKeys() for another credential failed: %v", err)
			}
			if _, err := otherC2S.Decrypt(append([]byte{}, encrypted...)); err == nil {
				t.Fatal("Decrypt() with the session key of another credential succeeded")
			}
		})
	}
}

// TestAcceptHandshakeSelectsSuite proves the cipher suite selection of a server:
// the server preference order decides, and the key length of the cipher that
// protected the handshake envelope is not a bound, because the session keys are
// derived from the negotiated suite. Both peers must still agree on the data
// plane key in every case.
func TestAcceptHandshakeSelectsSuite(t *testing.T) {
	const userName = "handshake-suite-user"
	password := cipher.HashPassword([]byte(t.Name()), []byte(userName))

	testCases := []struct {
		name          string
		envelopeSuite cipher.Suite
		clientSuites  []cipher.Suite
		allowedSuites []cipher.Suite
		wantSuite     cipher.Suite
	}{
		{
			// The first suite of the client protects the handshake envelope, so
			// the envelope of this case is XChaCha20-Poly1305 and the client
			// prefers AES-128-GCM. The server preference order still decides,
			// because the session keys are derived from the negotiated suite.
			name:          "server preference decides",
			envelopeSuite: cipher.SuiteXChaCha20Poly1305,
			clientSuites:  []cipher.Suite{cipher.SuiteXChaCha20Poly1305, cipher.SuiteAES128GCM},
			wantSuite:     cipher.SuiteXChaCha20Poly1305,
		},
		{
			// The negotiated suite needs 32 bytes of key material, which the
			// 16 bytes envelope of AES-128-GCM doesn't provide. The session
			// keys are derived from the negotiated suite, so the envelope key
			// length is not a bound.
			name:          "negotiated suite longer than the envelope key",
			envelopeSuite: cipher.SuiteAES128GCM,
			clientSuites:  []cipher.Suite{cipher.SuiteAES128GCM, cipher.SuiteXChaCha20Poly1305},
			wantSuite:     cipher.SuiteXChaCha20Poly1305,
		},
		{
			// The negotiated suite is not the suite of the envelope, and it is
			// shorter than the envelope key.
			name:          "negotiated suite differs from the envelope suite",
			envelopeSuite: cipher.SuiteXChaCha20Poly1305,
			clientSuites:  []cipher.Suite{cipher.SuiteXChaCha20Poly1305, cipher.SuiteAES128GCM},
			allowedSuites: []cipher.Suite{cipher.SuiteAES128GCM},
			wantSuite:     cipher.SuiteAES128GCM,
		},
	}
	for i, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			envelope, err := cipher.BlockCipherFromPassword(tc.envelopeSuite, password, false)
			if err != nil {
				t.Fatalf("BlockCipherFromPassword() failed: %v", err)
			}
			sessionID := uint32(500 + i)
			client, payload := newTestHandshakeClientWithSuites(t, envelope, false, tc.clientSuites)
			server := NewSession(sessionID, false, 1400, nil, nil)
			requestSeg := testOpenSessionSegmentWithPayload(t, sessionID, common.StreamTransport, payload)
			response, c2s, s2c, err := server.acceptHandshake(requestSeg, envelope, tc.allowedSuites, false)
			if err != nil {
				t.Fatalf("acceptHandshake() failed: %v", err)
			}
			if response.status != handshakeStatusOK {
				t.Fatalf("handshake status = %d, want %d", response.status, handshakeStatusOK)
			}
			if response.version != protocolVersion {
				t.Fatalf("handshake version = %d, want %d", response.version, protocolVersion)
			}
			if response.suite != tc.wantSuite {
				t.Fatalf("negotiated suite = %v, want %v", response.suite, tc.wantSuite)
			}
			if got := c2s.Suite(); got != tc.wantSuite {
				t.Fatalf("server receive cipher suite = %v, want %v", got, tc.wantSuite)
			}
			if got := s2c.Suite(); got != tc.wantSuite {
				t.Fatalf("server send cipher suite = %v, want %v", got, tc.wantSuite)
			}

			// Both peers derive the same data plane key of the negotiated suite.
			client.complete(t, response)
			if got := client.c2s.Suite(); got != tc.wantSuite {
				t.Fatalf("client to server cipher suite = %v, want %v", got, tc.wantSuite)
			}
			probe := []byte("a negotiated data plane probe")
			wire := testSealProbe(t, client.c2s, probe)
			decrypted, err := c2s.CloneStatelessFast().Decrypt(append([]byte{}, wire...))
			if err != nil {
				t.Fatalf("the server session key didn't decrypt the data plane probe: %v", err)
			}
			if !bytes.Equal(decrypted, probe) {
				t.Fatalf("data plane probe = %q, want %q", decrypted, probe)
			}
		})
	}
}

// TestNewHandshakeRequestIsRandom proves that two handshake requests never
// share their ephemeral key or their client salt.
func TestNewHandshakeRequestIsRandom(t *testing.T) {
	first, _, err := newHandshakeRequest(cipher.AllSuites())
	if err != nil {
		t.Fatalf("newHandshakeRequest() failed: %v", err)
	}
	second, _, err := newHandshakeRequest(cipher.AllSuites())
	if err != nil {
		t.Fatalf("newHandshakeRequest() failed: %v", err)
	}
	if first.ephPub == second.ephPub {
		t.Fatal("two handshake requests share the same ephemeral public key")
	}
	if first.clientSalt == second.clientSalt {
		t.Fatal("two handshake requests share the same client salt")
	}
}

// TestHandshakePublishesClientCiphersAfterChainSwitch verifies the publication
// order of the client side of the handshake: deriving the session ciphers
// publishes nothing, and a transport that owns a cipher chain switches the
// chain to them before it commits the handshake.
//
// A data segment that waited for the handshake response must never leave the
// send queue while the static cipher of the handshake envelope still protects
// the connection, because the server switches to its session key as soon as it
// wrote the response and can't decrypt such a segment any more.
func TestHandshakePublishesClientCiphersAfterChainSwitch(t *testing.T) {
	password := cipher.HashPassword([]byte(t.Name()), []byte("user"))
	envelope, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, password, false)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}
	allowedSuite := cipher.SuiteXChaCha20Poly1305

	// ---- A transport switches the cipher chain and then commits. ----
	const sessionID = 301
	session := NewSession(sessionID, true, 1400, nil, nil)
	session.transportProtocol = common.StreamTransport
	requestPayload, err := session.buildHandshakeRequest()
	if err != nil {
		t.Fatalf("buildHandshakeRequest() failed: %v", err)
	}
	session.handshakeStarted.Store(true)
	// The segment that waits for the handshake response stays in the send
	// queue, because the output loop is not running in this test.
	session.oLock.Lock()
	inserted := session.sendQueue.Insert(testDataSegment(sessionID, 0, []byte("pending data"), common.StreamTransport))
	session.oLock.Unlock()
	if !inserted {
		t.Fatal("Insert() of the pending data segment failed")
	}
	if !session.shouldDeferNextStreamData() {
		t.Fatal("a data segment is eligible while the handshake response is outstanding")
	}

	server := NewSession(sessionID, false, 1400, nil, nil)
	requestSeg := testOpenSessionSegmentWithPayload(t, sessionID, common.StreamTransport, requestPayload)
	response, _, _, err := server.acceptHandshake(requestSeg, envelope, []cipher.Suite{allowedSuite}, false)
	if err != nil {
		t.Fatalf("acceptHandshake() failed: %v", err)
	}
	responseSeg := server.newSessionResponseSegment(response.Marshal(), envelope)

	underlay := &StreamUnderlay{
		baseUnderlay: *newBaseUnderlay(true, 1400, nil),
		block:        envelope,
		recv:         envelope.Clone(),
	}
	underlay.sessionMap.Store(sessionID, session)
	if err := underlay.completeClientHandshake(responseSeg); err != nil {
		t.Fatalf("completeClientHandshake() failed: %v", err)
	}

	// The chain of the connection switched to the session keys, and the first
	// message of the new chain carries the wire format nonce.
	if underlay.send == nil || underlay.recv == nil {
		t.Fatal("the stream underlay didn't switch its cipher chain")
	}
	if underlay.send == underlay.block || underlay.recv == underlay.block {
		t.Fatal("the stream underlay kept the static cipher of the handshake envelope")
	}
	if !underlay.sendNoncePending || !underlay.recvNoncePending {
		t.Fatal("the stream underlay didn't mark the nonce of the first message of the session cipher chain")
	}
	// The handshake is published: the session sends with the session key, and
	// the data segment that waited for the response is eligible again.
	if !session.handshakeDone.Load() {
		t.Fatal("the client session didn't complete its handshake")
	}
	if session.clientHandshakePending() {
		t.Fatal("the client session still reports a pending handshake")
	}
	if session.shouldDeferNextStreamData() {
		t.Fatal("the data segment that waited for the handshake response is still deferred")
	}
	sendBlock := session.sendBlock.Load()
	recvBlock := session.block.Load()
	if sendBlock == nil || recvBlock == nil {
		t.Fatal("the client session didn't install its data plane ciphers")
	}
	if got := (*sendBlock).Suite(); got != allowedSuite {
		t.Fatalf("client to server cipher suite = %v, want %v", got, allowedSuite)
	}
	if got := (*recvBlock).Suite(); got != allowedSuite {
		t.Fatalf("server to client cipher suite = %v, want %v", got, allowedSuite)
	}
	// Both peers derived the same client to server key.
	serverC2S := server.block.Load()
	if serverC2S == nil {
		t.Fatal("the server session didn't install its receive cipher")
	}
	probe := []byte("data plane probe")
	decryptedProbe, err := (*serverC2S).CloneStatelessFast().Decrypt(testSealProbe(t, *sendBlock, probe))
	if err != nil {
		t.Fatalf("the server session key didn't decrypt the data plane probe: %v", err)
	}
	if !bytes.Equal(decryptedProbe, probe) {
		t.Fatalf("data plane probe = %q, want %q", decryptedProbe, probe)
	}

	// ---- Deriving the session keys publishes nothing. ----
	const otherID = 302
	other := NewSession(otherID, true, 1400, nil, nil)
	other.transportProtocol = common.StreamTransport
	otherPayload, err := other.buildHandshakeRequest()
	if err != nil {
		t.Fatalf("buildHandshakeRequest() failed: %v", err)
	}
	other.handshakeStarted.Store(true)
	other.oLock.Lock()
	inserted = other.sendQueue.Insert(testDataSegment(otherID, 0, []byte("pending data"), common.StreamTransport))
	other.oLock.Unlock()
	if !inserted {
		t.Fatal("Insert() of the pending data segment failed")
	}
	// The handshake of the second session uses its own ephemeral key, so its
	// response is built from its own request payload.
	otherServer := NewSession(otherID, false, 1400, nil, nil)
	otherRequestSeg := testOpenSessionSegmentWithPayload(t, otherID, common.StreamTransport, otherPayload)
	otherResponse, _, _, err := otherServer.acceptHandshake(otherRequestSeg, envelope, []cipher.Suite{allowedSuite}, false)
	if err != nil {
		t.Fatalf("acceptHandshake() failed: %v", err)
	}
	otherResponseSeg := otherServer.newSessionResponseSegment(otherResponse.Marshal(), envelope)

	c2s, s2c, resp, err := other.deriveClientHandshake(otherResponseSeg, envelope.Clone(), false)
	if err != nil {
		t.Fatalf("deriveClientHandshake() failed: %v", err)
	}
	if other.handshakeDone.Load() {
		t.Fatal("deriveClientHandshake() published the handshake")
	}
	if other.block.Load() != nil || other.sendBlock.Load() != nil {
		t.Fatal("deriveClientHandshake() installed the session ciphers before the transport switched")
	}
	if !other.clientHandshakePending() {
		t.Fatal("the client handshake is not pending after deriveClientHandshake()")
	}
	if !other.shouldDeferNextStreamData() {
		t.Fatal("deriveClientHandshake() released a data segment that waited for the handshake response")
	}

	// Only the transport commits, after it switched its cipher chain.
	other.commitClientHandshake(c2s, s2c, resp.suite)
	if !other.handshakeDone.Load() || other.clientHandshakePending() {
		t.Fatal("commitClientHandshake() didn't publish the handshake")
	}
	if other.sendBlock.Load() == nil || other.block.Load() == nil {
		t.Fatal("commitClientHandshake() didn't install the session ciphers")
	}
}
