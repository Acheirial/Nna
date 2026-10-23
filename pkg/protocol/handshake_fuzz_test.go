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

	"github.com/enfein/mieru/v3/pkg/cipher"
)

// fuzzRequestSeed returns the wire format of a handshake request that carries
// the given cipher suites, with a deterministic ephemeral public key and a
// deterministic client salt, so that the seeds of FuzzParseHandshakeRequest
// don't change from one run to another.
func fuzzRequestSeed(suites ...cipher.Suite) []byte {
	h := &handshakeRequest{
		versionMin: protocolVersion,
		versionMax: protocolVersion,
		suites:     suites,
	}
	for i := range h.ephPub {
		h.ephPub[i] = byte(i)
	}
	for i := range h.clientSalt {
		h.clientSalt[i] = byte(0xa0 + i)
	}
	return h.Marshal()
}

// fuzzResponseSeed returns the wire format of a handshake response with a
// deterministic ephemeral public key and a deterministic server salt.
func fuzzResponseSeed(status, version uint8, suite cipher.Suite) []byte {
	h := &handshakeResponse{
		status:  status,
		version: version,
		suite:   suite,
	}
	for i := range h.ephPub {
		h.ephPub[i] = byte(i)
	}
	for i := range h.serverSalt {
		h.serverSalt[i] = byte(0x50 + i)
	}
	return h.Marshal()
}

// FuzzParseHandshakeRequest checks that the handshake request parser of a
// server never panics, and that every request it accepts is the one the wire
// format promises:
//
//   - consumed is inside the input and equals the fixed length of a request
//     plus the number of cipher suites it carries;
//   - the version range is well formed and every cipher suite is supported;
//   - the version, the cipher suites, the ephemeral public key and the client
//     salt equal the bytes of the input they are read from;
//   - Marshal() of the result reproduces the consumed bytes and parses back to
//     an identical request, which is what a server relies on when it re-parses
//     or re-encodes a request.
//
// A request whose version range doesn't contain protocolVersion is accepted on
// purpose: the version range is part of the wire format, so a server parses it
// and then drops the request without an answer instead of treating it as
// malformed, see docs/protocol.md.
func FuzzParseHandshakeRequest(f *testing.F) {
	f.Add(fuzzRequestSeed(cipher.SuiteXChaCha20Poly1305))
	f.Add(fuzzRequestSeed(cipher.AllSuites()...))
	f.Add(fuzzRequestSeed(cipher.SuiteXChaCha20Poly1305, cipher.SuiteAES128GCM)[:handshakeRequestHeaderLen])
	f.Add([]byte{protocolVersion, protocolVersion, 1, 0x07})

	f.Fuzz(func(t *testing.T, b []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseHandshakeRequest(%q) panicked: %v", b, r)
			}
		}()

		h, consumed, err := parseHandshakeRequest(b)
		if err != nil {
			if h != nil {
				t.Fatalf("parseHandshakeRequest(%q) returned a request along with the error %v", b, err)
			}
			if consumed != 0 {
				t.Fatalf("parseHandshakeRequest(%q) consumed %d bytes along with the error %v", b, consumed, err)
			}
			return
		}
		if h == nil {
			t.Fatalf("parseHandshakeRequest(%q) succeeded without a request", b)
		}

		// The parser must never claim to have read bytes that don't exist, and
		// the caller uses consumed to find the application data that may
		// follow the request.
		if consumed < handshakeRequestHeaderLen || consumed > len(b) {
			t.Fatalf("parseHandshakeRequest(%q) consumed %d bytes, want between %d and %d", b, consumed, handshakeRequestHeaderLen, len(b))
		}
		if want := handshakeRequestFixedLen + len(h.suites); consumed != want {
			t.Fatalf("parseHandshakeRequest(%q) consumed %d bytes, want %d for %d cipher suites", b, consumed, want, len(h.suites))
		}

		// The result must be internally consistent.
		if err := h.validate(); err != nil {
			t.Fatalf("parseHandshakeRequest(%q) returned a request that fails validate(): %v", b, err)
		}
		if len(h.suites) < 1 || len(h.suites) > maxHandshakeSuites {
			t.Fatalf("parseHandshakeRequest(%q) returned %d cipher suites, want between 1 and %d", b, len(h.suites), maxHandshakeSuites)
		}
		if h.versionMin > h.versionMax {
			t.Fatalf("parseHandshakeRequest(%q) returned the version range %d-%d", b, h.versionMin, h.versionMax)
		}
		// A version range that doesn't contain protocolVersion is accepted on
		// purpose, so that the server drops the request without an answer
		// instead of treating it as malformed. Negotiation must then fail, and
		// a range that does contain the supported version must negotiate it.
		version, ok := negotiateVersion(h.versionMin, h.versionMax)
		contains := h.versionMin <= protocolVersion && h.versionMax >= protocolVersion
		if ok != contains {
			t.Fatalf("negotiateVersion(%d, %d) = (%d, %v), but the range contains the supported version %d: %v", h.versionMin, h.versionMax, version, ok, protocolVersion, contains)
		}
		if ok && version != protocolVersion {
			t.Fatalf("negotiateVersion(%d, %d) = %d, want %d", h.versionMin, h.versionMax, version, protocolVersion)
		}
		if !ok && version != 0 {
			t.Fatalf("negotiateVersion(%d, %d) failed with version %d, want 0", h.versionMin, h.versionMax, version)
		}

		// Every field must come from the bytes it was read from.
		if h.versionMin != b[0] || h.versionMax != b[1] || len(h.suites) != int(b[2]) {
			t.Fatalf("parseHandshakeRequest(%q) returned the header %d-%d with %d cipher suites", b, h.versionMin, h.versionMax, len(h.suites))
		}
		for i, suite := range h.suites {
			if !suite.IsValid() {
				t.Fatalf("parseHandshakeRequest(%q) returned the unsupported cipher suite %d", b, uint8(suite))
			}
			if got, want := byte(suite), b[handshakeRequestHeaderLen+i]; got != want {
				t.Fatalf("parseHandshakeRequest(%q) returned the cipher suite %d at offset %d, want %d", b, got, handshakeRequestHeaderLen+i, want)
			}
		}
		offset := handshakeRequestHeaderLen + len(h.suites)
		if !bytes.Equal(h.ephPub[:], b[offset:offset+handshakeEphemeralKeyLen]) {
			t.Fatalf("parseHandshakeRequest(%q) returned an ephemeral public key that is not in the input", b)
		}
		if !bytes.Equal(h.clientSalt[:], b[offset+handshakeEphemeralKeyLen:consumed]) {
			t.Fatalf("parseHandshakeRequest(%q) returned a client salt that is not in the input", b)
		}

		// A request must survive a marshal and parse round trip, which is how
		// the two peers agree on the bytes of the handshake.
		marshaled := h.Marshal()
		if len(marshaled) != consumed {
			t.Fatalf("Marshal() returned %d bytes, want %d", len(marshaled), consumed)
		}
		if !bytes.Equal(marshaled, b[:consumed]) {
			t.Fatalf("Marshal() returned %q, want %q", marshaled, b[:consumed])
		}
		reparsed, reConsumed, err := parseHandshakeRequest(marshaled)
		if err != nil {
			t.Fatalf("parseHandshakeRequest() failed on the marshaled request %q: %v", marshaled, err)
		}
		if reConsumed != consumed {
			t.Fatalf("parseHandshakeRequest() consumed %d bytes on the marshaled request, want %d", reConsumed, consumed)
		}
		if !reflect.DeepEqual(reparsed, h) {
			t.Fatalf("parseHandshakeRequest() returned %+v on the marshaled request, want %+v", reparsed, h)
		}
	})
}

// FuzzParseHandshakeResponse checks that the handshake response parser of a
// client never panics, and that every response it accepts is the one the wire
// format promises:
//
//   - the status is a known one and, on success, the version is protocolVersion
//     and the cipher suite is supported;
//   - the length is handshakeResponseLen, and every field equals the bytes of
//     the input it is read from;
//   - Marshal() of the result reproduces the input and parses back to an
//     identical response, which is what a client relies on when it re-parses
//     the response to derive the session keys.
func FuzzParseHandshakeResponse(f *testing.F) {
	f.Add(fuzzResponseSeed(handshakeStatusOK, protocolVersion, cipher.SuiteXChaCha20Poly1305))
	f.Add(fuzzResponseSeed(handshakeStatusNoSuite, 0, cipher.SuiteAES256GCM))
	f.Add(fuzzResponseSeed(handshakeStatusOK, protocolVersion, cipher.SuiteAES128GCM)[:3])
	f.Add(fuzzResponseSeed(handshakeStatusOK+3, protocolVersion, cipher.SuiteXChaCha20Poly1305))

	f.Fuzz(func(t *testing.T, b []byte) {
		defer func() {
			if r := recover(); r != nil {
				t.Fatalf("parseHandshakeResponse(%q) panicked: %v", b, r)
			}
		}()

		h, err := parseHandshakeResponse(b)
		if err != nil {
			if h != nil {
				t.Fatalf("parseHandshakeResponse(%q) returned a response along with the error %v", b, err)
			}
			return
		}
		if h == nil {
			t.Fatalf("parseHandshakeResponse(%q) succeeded without a response", b)
		}

		if len(b) != handshakeResponseLen {
			t.Fatalf("parseHandshakeResponse(%q) accepted a response of %d bytes, want %d", b, len(b), handshakeResponseLen)
		}
		switch h.status {
		case handshakeStatusOK:
			if !h.suite.IsValid() {
				t.Fatalf("parseHandshakeResponse(%q) returned the unsupported cipher suite %d", b, uint8(h.suite))
			}
			if h.version != protocolVersion {
				t.Fatalf("parseHandshakeResponse(%q) returned the unsupported version %d, want %d", b, h.version, protocolVersion)
			}
		case handshakeStatusNoSuite:
			// A failure response only carries a status, the caller must close
			// the session.
		default:
			t.Fatalf("parseHandshakeResponse(%q) accepted the unknown status %d", b, h.status)
		}

		// Every field must come from the bytes it was read from.
		if h.status != b[0] || h.version != b[1] || h.suite != cipher.Suite(b[2]) {
			t.Fatalf("parseHandshakeResponse(%q) returned the header %d-%d-%d", b, h.status, h.version, uint8(h.suite))
		}
		if !bytes.Equal(h.ephPub[:], b[3:3+handshakeEphemeralKeyLen]) {
			t.Fatalf("parseHandshakeResponse(%q) returned an ephemeral public key that is not in the input", b)
		}
		if !bytes.Equal(h.serverSalt[:], b[3+handshakeEphemeralKeyLen:handshakeResponseLen]) {
			t.Fatalf("parseHandshakeResponse(%q) returned a server salt that is not in the input", b)
		}

		// A response must survive a marshal and parse round trip, which is how
		// the two peers agree on the bytes of the handshake.
		marshaled := h.Marshal()
		if len(marshaled) != handshakeResponseLen {
			t.Fatalf("Marshal() returned %d bytes, want %d", len(marshaled), handshakeResponseLen)
		}
		if !bytes.Equal(marshaled, b) {
			t.Fatalf("Marshal() returned %q, want %q", marshaled, b)
		}
		reparsed, err := parseHandshakeResponse(marshaled)
		if err != nil {
			t.Fatalf("parseHandshakeResponse() failed on the marshaled response %q: %v", marshaled, err)
		}
		if !reflect.DeepEqual(reparsed, h) {
			t.Fatalf("parseHandshakeResponse() returned %+v on the marshaled response, want %+v", reparsed, h)
		}
	})
}
