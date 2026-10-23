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
	"context"
	"crypto/ecdh"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Acheirial/shadowlemon/v3/pkg/appctl/appctlpb"
	"github.com/Acheirial/shadowlemon/v3/pkg/cipher"
	"github.com/Acheirial/shadowlemon/v3/pkg/common"
	"github.com/Acheirial/shadowlemon/v3/pkg/testtool"
)

// ---------------------------------------------------------------------------
// Handshake test helpers.
// ---------------------------------------------------------------------------

// testHandshakeRequestPayload returns the payload prefix that a client puts at
// the beginning of an open session request.
func testHandshakeRequestPayload(tb testing.TB, suites []cipher.Suite) []byte {
	tb.Helper()
	request, _, err := newHandshakeRequest(suites)
	if err != nil {
		tb.Fatalf("newHandshakeRequest() failed: %v", err)
	}
	return request.Marshal()
}

// testHandshakeRequestPayloadWithVersion returns a handshake request payload
// with the given protocol version range, so that a test can act as a peer that
// doesn't carry the protocol version of this build.
func testHandshakeRequestPayloadWithVersion(tb testing.TB, versionMin, versionMax uint8, suites []cipher.Suite) []byte {
	tb.Helper()
	request, _, err := newHandshakeRequest(suites)
	if err != nil {
		tb.Fatalf("newHandshakeRequest() failed: %v", err)
	}
	request.versionMin = versionMin
	request.versionMax = versionMax
	return request.Marshal()
}

// testOpenSessionSegment returns the open session request of a client: a
// session control segment whose payload carries a handshake request.
func testOpenSessionSegment(tb testing.TB, sessionID uint32, transport common.TransportProtocol) *segment {
	tb.Helper()
	return testOpenSessionSegmentWithPayload(tb, sessionID, transport, testHandshakeRequestPayload(tb, nil))
}

// testOpenSessionSegmentWithPayload returns an open session request with the
// given payload.
func testOpenSessionSegmentWithPayload(tb testing.TB, sessionID uint32, transport common.TransportProtocol, payload []byte) *segment {
	tb.Helper()
	seg := testSessionSegment(openSessionRequest, sessionID, transport)
	ss, ok := seg.metadata.(*sessionStruct)
	if !ok {
		tb.Fatalf("test session metadata type = %T, want sessionStruct", seg.metadata)
	}
	ss.payloadLen = uint16(len(payload))
	seg.payload = payload
	return seg
}

// testHandshakeClient plays the client side of a handshake with a raw cipher.
// It is used by the tests that drive a server without a mux, because such a
// client must build the handshake request payload and derive the session
// ciphers itself.
type testHandshakeClient struct {
	envelope  cipher.BlockCipher
	priv      *ecdh.PrivateKey
	salt      [handshakeSaltLen]byte
	suites    []cipher.Suite
	stateless bool

	c2s cipher.BlockCipher
	s2c cipher.BlockCipher
}

// newTestHandshakeClient creates a raw client whose handshake request is
// protected by envelope, and returns the payload of its open session request.
// stateless selects the cipher mode of the data plane ciphers, which is the
// mode of the transport.
func newTestHandshakeClient(tb testing.TB, envelope cipher.BlockCipher, stateless bool) (*testHandshakeClient, []byte) {
	tb.Helper()
	request, privateKey, err := newHandshakeRequest(nil)
	if err != nil {
		tb.Fatalf("newHandshakeRequest() failed: %v", err)
	}
	c := &testHandshakeClient{
		envelope:  envelope,
		priv:      privateKey,
		salt:      request.clientSalt,
		suites:    request.suites,
		stateless: stateless,
	}
	return c, request.Marshal()
}

// newTestHandshakeClientWithSuites creates a raw client that offers the given
// cipher suites in its handshake request, with the protocol version of this
// build. The envelope cipher of the request is independent of the offered
// suites.
func newTestHandshakeClientWithSuites(tb testing.TB, envelope cipher.BlockCipher, stateless bool, suites []cipher.Suite) (*testHandshakeClient, []byte) {
	tb.Helper()
	request, privateKey, err := newHandshakeRequest(suites)
	if err != nil {
		tb.Fatalf("newHandshakeRequest() failed: %v", err)
	}
	c := &testHandshakeClient{
		envelope:  envelope,
		priv:      privateKey,
		salt:      request.clientSalt,
		suites:    request.suites,
		stateless: stateless,
	}
	return c, request.Marshal()
}

// complete derives the data plane ciphers of the client from the handshake
// response of the server.
func (c *testHandshakeClient) complete(tb testing.TB, response *handshakeResponse) {
	tb.Helper()
	if response.status != handshakeStatusOK {
		tb.Fatalf("handshake response status = %d, want %d", response.status, handshakeStatusOK)
	}
	c2s, s2c, err := deriveSessionKeys(c.envelope, response.suite, c.priv, response.ephPub[:], c.salt[:], response.serverSalt[:], c.stateless)
	if err != nil {
		tb.Fatalf("deriveSessionKeys() failed: %v", err)
	}
	c.c2s = c2s
	c.s2c = s2c
}

// testBuildPacketMessage encrypts the metadata and the payload of a segment
// with a stateless cipher, in the wire format of the packet transport.
func testBuildPacketMessage(tb testing.TB, block cipher.BlockCipher, ss *sessionStruct, payload []byte) []byte {
	tb.Helper()
	plaintextMetadata := ss.Marshal()
	wire := make([]byte, block.NonceSize()+len(plaintextMetadata)+block.Overhead())
	if err := block.Encrypt(wire[:0], plaintextMetadata); err != nil {
		tb.Fatalf("Encrypt(metadata) failed: %v", err)
	}
	if len(payload) > 0 {
		nonce := wire[:cipher.DefaultNonceSize]
		encryptedPayload := make([]byte, len(payload)+block.Overhead())
		if err := block.EncryptPayloadWithNonce(encryptedPayload[:0], nonce, payload); err != nil {
			tb.Fatalf("EncryptPayloadWithNonce(payload) failed: %v", err)
		}
		wire = append(wire, encryptedPayload...)
	}
	return wire
}

// testBuildStreamMessage encrypts the metadata and the payload of a segment
// with a stateful cipher, in the wire format of the stream transport. The
// cipher must not have been used before, because the first message carries the
// nonce.
func testBuildStreamMessage(tb testing.TB, block cipher.BlockCipher, ss *sessionStruct, payload []byte) []byte {
	tb.Helper()
	plaintextMetadata := ss.Marshal()
	wire := make([]byte, block.NonceSize()+len(plaintextMetadata)+block.Overhead())
	if err := block.Encrypt(wire[:0], plaintextMetadata); err != nil {
		tb.Fatalf("Encrypt(metadata) failed: %v", err)
	}
	if len(payload) > 0 {
		encryptedPayload := make([]byte, len(payload)+block.Overhead())
		if err := block.Encrypt(encryptedPayload[:0], payload); err != nil {
			tb.Fatalf("Encrypt(payload) failed: %v", err)
		}
		wire = append(wire, encryptedPayload...)
	}
	return wire
}

// testSealProbe encrypts a data plane probe with a stateless clone of a session
// cipher and returns the wire format message: the wire nonce, the ciphertext
// and the tag.
//
// Encrypt() of a block cipher writes into the spare capacity of the
// destination slice and returns no slice, so the destination must be allocated
// with its final length; a slice with a zero length would stay empty and the
// probe would be meaningless.
func testSealProbe(tb testing.TB, block cipher.BlockCipher, plaintext []byte) []byte {
	tb.Helper()
	wire := make([]byte, cipher.DefaultNonceSize+len(plaintext)+cipher.DefaultOverhead)
	if err := block.CloneStatelessFast().Encrypt(wire[:0], plaintext); err != nil {
		tb.Fatalf("Encrypt() of a data plane probe failed: %v", err)
	}
	return wire
}

// testRot13Payload returns the payload of an exchange with a
// testtool.TestHelperServer after verifying that the server accepts it.
//
// TestHelperRot13() accepts [A-Za-z] bytes only, and TestHelperServeConn()
// closes the connection as soon as it rejects a request. A payload that
// carries any other byte, a space included, therefore makes a test fail even
// when the code under test is correct, so every payload of such an exchange is
// built through this helper.
//
// The payload is reported instead of failing the test on the spot, because a
// caller builds it in a goroutine of its own, and testing.TB.Fatal() must be
// called from the goroutine that runs the test.
func testRot13Payload(tb testing.TB, payload []byte) []byte {
	tb.Helper()
	if _, err := testtool.TestHelperRot13(payload); err == nil {
		return payload
	}
	if len(payload) == 0 {
		tb.Errorf("the payload of a rotate-13 exchange is empty, want at least one letter")
		return payload
	}
	for i, b := range payload {
		if (b >= 'A' && b <= 'Z') || (b >= 'a' && b <= 'z') {
			continue
		}
		tb.Errorf("byte %d of the payload of a rotate-13 exchange is %#x, want a letter of A-Z or a-z: the test server rejects every other byte and closes the connection", i, b)
		return payload
	}
	tb.Errorf("the payload of a rotate-13 exchange is not valid input of testtool.TestHelperRot13")
	return payload
}

// droppedResponseWait is how long a test waits for a response datagram before
// it concludes that a dropped request was not answered at all.
const droppedResponseWait = time.Second

// assertNoPacketResponse verifies that no response datagram arrives at the
// connection of a client: this is how a server drops a request it doesn't
// answer, instead of telling a peer that it doesn't speak this protocol.
func assertNoPacketResponse(tb testing.TB, conn net.PacketConn) {
	tb.Helper()
	buf := make([]byte, 1500)
	if err := conn.SetReadDeadline(time.Now().Add(droppedResponseWait)); err != nil {
		tb.Fatalf("SetReadDeadline() failed: %v", err)
	}
	n, addr, err := conn.ReadFrom(buf)
	if err == nil {
		tb.Fatalf("the server wrote %d bytes to %v as an answer to a dropped request", n, addr)
	}
	if n != 0 {
		tb.Fatalf("the server wrote %d bytes as an answer to a dropped request", n)
	}
}

// assertNoStreamResponse verifies that a stream connection carries no byte as
// an answer to a dropped request: the read of a closed connection returns zero
// bytes, and a connection that stays open without an answer reads zero bytes
// when the deadline expires.
func assertNoStreamResponse(tb testing.TB, conn net.Conn) {
	tb.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(droppedResponseWait)); err != nil {
		tb.Fatalf("SetReadDeadline() failed: %v", err)
	}
	buf := make([]byte, 1500)
	n, err := conn.Read(buf)
	if n != 0 {
		tb.Fatalf("the server wrote %d bytes as an answer to a dropped request", n)
	}
	if err == nil {
		tb.Fatal("read of a dropped request succeeded with an empty buffer, want no answer")
	}
}

// testReadPacketHandshakeResponse reads one handshake response message from a
// packet connection and decrypts it with the stateless cipher of the client.
func testReadPacketHandshakeResponse(tb testing.TB, conn net.PacketConn, envelope cipher.BlockCipher) *handshakeResponse {
	tb.Helper()
	buf := make([]byte, 1500)
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		tb.Fatalf("SetReadDeadline() failed: %v", err)
	}
	n, _, err := conn.ReadFrom(buf)
	if err != nil {
		tb.Fatalf("ReadFrom() the handshake response failed: %v", err)
	}
	if n < packetNonHeaderPosition {
		tb.Fatalf("handshake response is %d bytes, want at least %d", n, packetNonHeaderPosition)
	}
	return testDecodePacketHandshakeResponse(tb, envelope, buf[:n])
}

// testDecodePacketHandshakeResponse decrypts a handshake response datagram.
func testDecodePacketHandshakeResponse(tb testing.TB, envelope cipher.BlockCipher, datagram []byte) *handshakeResponse {
	tb.Helper()
	decryptedMetadata, err := envelope.Decrypt(datagram[:packetNonHeaderPosition])
	if err != nil {
		tb.Fatalf("Decrypt() of the handshake response metadata failed: %v", err)
	}
	ss := &sessionStruct{}
	if err := ss.Unmarshal(decryptedMetadata); err != nil {
		tb.Fatalf("Unmarshal() of the handshake response metadata failed: %v", err)
	}
	if ss.Protocol() != openSessionResponse {
		tb.Fatalf("handshake response protocol = %v, want %v", ss.Protocol(), openSessionResponse)
	}
	payloadLen := int(ss.payloadLen) + cipher.DefaultOverhead
	if packetNonHeaderPosition+payloadLen > len(datagram) {
		tb.Fatalf("handshake response payload is truncated: want %d bytes, have %d", payloadLen, len(datagram)-packetNonHeaderPosition)
	}
	nonce := datagram[:cipher.DefaultNonceSize]
	decryptedPayload, err := envelope.DecryptPayloadWithNonce(datagram[packetNonHeaderPosition:packetNonHeaderPosition+payloadLen], nonce)
	if err != nil {
		tb.Fatalf("DecryptPayloadWithNonce() of the handshake response failed: %v", err)
	}
	response, err := parseHandshakeResponse(decryptedPayload)
	if err != nil {
		tb.Fatalf("parseHandshakeResponse() failed: %v", err)
	}
	return response
}

// testReadStreamHandshakeResponse reads one handshake response message from a
// stream connection and decrypts it with the stateful cipher of the client.
// The cipher must not have decrypted anything before.
func testReadStreamHandshakeResponse(tb testing.TB, conn net.Conn, envelope cipher.BlockCipher) *handshakeResponse {
	tb.Helper()
	if err := conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		tb.Fatalf("SetReadDeadline() failed: %v", err)
	}
	encryptedMetadata := make([]byte, cipher.DefaultNonceSize+MetadataLength+cipher.DefaultOverhead)
	if _, err := io.ReadFull(conn, encryptedMetadata); err != nil {
		tb.Fatalf("read handshake response metadata failed: %v", err)
	}
	decryptedMetadata, err := envelope.Decrypt(encryptedMetadata)
	if err != nil {
		tb.Fatalf("Decrypt() of the handshake response metadata failed: %v", err)
	}
	ss := &sessionStruct{}
	if err := ss.Unmarshal(decryptedMetadata); err != nil {
		tb.Fatalf("Unmarshal() of the handshake response metadata failed: %v", err)
	}
	if ss.Protocol() != openSessionResponse {
		tb.Fatalf("handshake response protocol = %v, want %v", ss.Protocol(), openSessionResponse)
	}
	encryptedPayload := make([]byte, int(ss.payloadLen)+cipher.DefaultOverhead+int(ss.suffixLen))
	if _, err := io.ReadFull(conn, encryptedPayload); err != nil {
		tb.Fatalf("read handshake response payload failed: %v", err)
	}
	decryptedPayload, err := envelope.Decrypt(encryptedPayload[:int(ss.payloadLen)+cipher.DefaultOverhead])
	if err != nil {
		tb.Fatalf("Decrypt() of the handshake response payload failed: %v", err)
	}
	response, err := parseHandshakeResponse(decryptedPayload)
	if err != nil {
		tb.Fatalf("parseHandshakeResponse() failed: %v", err)
	}
	return response
}

// testStartPacketServer starts a server packet underlay that allows the given
// cipher suites.
func testStartPacketServer(tb testing.TB, users map[string]*appctlpb.User, allowed []cipher.Suite) *PacketUnderlay {
	tb.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		tb.Fatalf("net.ListenPacket() server failed: %v", err)
	}
	registry := testServerUserRegistry(users, false)
	if len(allowed) > 0 {
		registry.SetAllowedCipherSuites(allowed)
	}
	server := &PacketUnderlay{
		baseUnderlay:       *newBaseUnderlay(false, 1400, nil),
		conn:               conn,
		sessionCleanTicker: time.NewTicker(sessionCleanInterval),
		serverUsers:        registry,
	}
	done := make(chan error, 1)
	go func() {
		done <- server.RunEventLoop(context.Background())
	}()
	tb.Cleanup(func() {
		_ = server.Close()
		_ = conn.Close()
		select {
		case <-done:
		case <-time.After(5 * time.Second):
			tb.Error("PacketUnderlay.RunEventLoop() didn't stop")
		}
	})
	return server
}

// testServerSession returns the session of a server underlay.
func testServerSession(tb testing.TB, underlay any, sessionID uint32) *Session {
	tb.Helper()
	var found *Session
	switch u := underlay.(type) {
	case *PacketUnderlay:
		if value, ok := u.sessionMap.Load(sessionID); ok {
			found = value.(*Session)
		}
	case *StreamUnderlay:
		if value, ok := u.sessionMap.Load(sessionID); ok {
			found = value.(*Session)
		}
	}
	if found == nil {
		tb.Fatalf("server session %d is not registered", sessionID)
	}
	return found
}

// testSessionMap returns the session map of a server underlay.
func testSessionMap(underlay any) *sync.Map {
	switch u := underlay.(type) {
	case *PacketUnderlay:
		return &u.sessionMap
	case *StreamUnderlay:
		return &u.sessionMap
	default:
		return nil
	}
}

// waitForSessionClose waits until a server underlay has closed the session of a
// request it didn't accept. A cleanup pass removes a closed session from the map
// of the underlay, so a session that was registered and then removed counts as
// closed as well.
func waitForSessionClose(t *testing.T, underlay any, sessionID uint32) {
	t.Helper()
	sessions := testSessionMap(underlay)
	if sessions == nil {
		t.Fatalf("underlay %T has no session map", underlay)
	}
	seenRegistered := false
	waitForCondition(t, 5*time.Second, "the server to close the session of the request", func() bool {
		value, ok := sessions.Load(sessionID)
		if !ok {
			return seenRegistered
		}
		seenRegistered = true
		session := value.(*Session)
		select {
		case <-session.closedChan:
			return true
		default:
			return false
		}
	})
}

// ---------------------------------------------------------------------------
// End to end tests.
// ---------------------------------------------------------------------------

// TestHandshakeEndToEnd establishes a session with the real client mux and the
// real server mux over both transports, exchanges application data in both
// directions, and verifies that the data plane of the session uses session
// keys instead of the static key.
func TestHandshakeEndToEnd(t *testing.T) {
	testCases := []struct {
		name          string
		network       string
		transport     common.TransportProtocol
		clientSuites  []cipher.Suite
		allowedSuites []cipher.Suite
		wantDataSuite cipher.Suite
		envelopeLen   int
	}{
		{
			name:          "tcp default suites",
			network:       "tcp",
			transport:     common.StreamTransport,
			wantDataSuite: cipher.SuiteXChaCha20Poly1305,
		},
		{
			name:          "udp default suites",
			network:       "udp",
			transport:     common.PacketTransport,
			wantDataSuite: cipher.SuiteXChaCha20Poly1305,
		},
		{
			name:          "udp server prefers another suite from the client list",
			network:       "udp",
			transport:     common.PacketTransport,
			clientSuites:  []cipher.Suite{cipher.SuiteXChaCha20Poly1305, cipher.SuiteAES256GCM},
			allowedSuites: []cipher.Suite{cipher.SuiteAES256GCM},
			wantDataSuite: cipher.SuiteAES256GCM,
		},
		{
			// The first suite of the client protects the handshake envelope, so
			// this case negotiates a 32 bytes key suite out of a 16 bytes
			// envelope. The session keys are derived from the negotiated suite,
			// so the server preference order selects XChaCha20-Poly1305 even
			// though the client prefers the shorter key of AES-128-GCM.
			name:          "tcp client prefers a suite with a short key",
			network:       "tcp",
			transport:     common.StreamTransport,
			clientSuites:  []cipher.Suite{cipher.SuiteAES128GCM, cipher.SuiteXChaCha20Poly1305},
			wantDataSuite: cipher.SuiteXChaCha20Poly1305,
			envelopeLen:   cipher.SuiteAES128GCM.KeyLen(),
		},
		{
			// Without a candidate that the envelope key length rules out, the
			// server preference order still selects the suite it selected
			// before the envelope filter was introduced.
			name:          "tcp server preference is unchanged when every candidate fits",
			network:       "tcp",
			transport:     common.StreamTransport,
			clientSuites:  []cipher.Suite{cipher.SuiteXChaCha20Poly1305, cipher.SuiteAES128GCM},
			wantDataSuite: cipher.SuiteXChaCha20Poly1305,
		},
	}
	for _, tc := range testCases {
		t.Run(tc.name, func(t *testing.T) {
			userName := "handshake-user"
			password := []byte(t.Name())
			credential := cipher.HashPassword(password, []byte(userName))
			serverMux := NewMux(false).SetServerUsers(userMap(makeTestUser(userName, credential)))
			if len(tc.allowedSuites) > 0 {
				serverMux.SetAllowedCipherSuites(tc.allowedSuites)
			}

			var port int
			var err error
			if tc.transport == common.StreamTransport {
				port, err = common.UnusedTCPPort()
			} else {
				port, err = common.UnusedUDPPort()
			}
			if err != nil {
				t.Fatalf("unused port lookup failed: %v", err)
			}
			var serverAddr, clientAddr net.Addr
			if tc.transport == common.StreamTransport {
				serverAddr = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
			} else {
				serverAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
			}
			serverMux.SetEndpoints([]UnderlayProperties{NewUnderlayProperties(1400, tc.transport, serverAddr, nil)})
			if err := serverMux.Start(); err != nil {
				t.Fatalf("serverMux.Start() failed: %v", err)
			}
			t.Cleanup(func() {
				if err := serverMux.Close(); err != nil {
					t.Errorf("serverMux.Close() failed: %v", err)
				}
			})

			testServer := testtool.NewTestHelperServer()
			go func() {
				if err := testServer.Serve(serverMux); err != nil {
					t.Errorf("test server Serve() failed: %v", err)
				}
			}()
			t.Cleanup(func() { testServer.Close() })

			if tc.transport == common.StreamTransport {
				clientAddr = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
			} else {
				clientAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
			}
			clientMux := NewMux(true).
				SetClientUserNamePassword(userName, credential).
				SetEndpoints([]UnderlayProperties{NewUnderlayProperties(1400, tc.transport, nil, clientAddr)})
			if len(tc.clientSuites) > 0 {
				clientMux.SetCipherSuites(tc.clientSuites)
			}
			t.Cleanup(func() {
				if err := clientMux.Close(); err != nil {
					t.Errorf("clientMux.Close() failed: %v", err)
				}
			})

			dialCtx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
			defer cancelFunc()
			conn, err := clientMux.DialContext(dialCtx)
			if err != nil {
				t.Fatalf("DialContext() failed: %v", err)
			}
			defer conn.Close()
			session, ok := conn.(*Session)
			if !ok {
				t.Fatalf("DialContext() returned %T, want *Session", conn)
			}

			// The first write carries the handshake request, and the reply can
			// only be read after the handshake completed on both peers.
			//
			// The payload is built by testRot13Payload(), because the test
			// server serves it with testtool.TestHelperRot13, which rejects
			// every other byte and closes the connection.
			payload := testRot13Payload(t, []byte("amessagethatmustsurvivethehandshake"))
			if _, err := session.Write(payload); err != nil {
				t.Fatalf("Write() failed: %v", err)
			}
			response := make([]byte, len(payload))
			if _, err := io.ReadFull(session, response); err != nil {
				t.Fatalf("ReadFull() failed: %v", err)
			}
			rot13, err := testtool.TestHelperRot13(response)
			if err != nil {
				t.Fatalf("TestHelperRot13() failed: %v", err)
			}
			if !bytes.Equal(payload, rot13) {
				t.Fatalf("response = %q, want the rot13 of %q", response, payload)
			}

			// A second round trip proves that the switched data plane is
			// stable in both directions.
			payload2 := testRot13Payload(t, []byte("anothermessageonthesessionkey"))
			if _, err := session.Write(payload2); err != nil {
				t.Fatalf("second Write() failed: %v", err)
			}
			response2 := make([]byte, len(payload2))
			if _, err := io.ReadFull(session, response2); err != nil {
				t.Fatalf("second ReadFull() failed: %v", err)
			}
			rot13b, err := testtool.TestHelperRot13(response2)
			if err != nil {
				t.Fatalf("second TestHelperRot13() failed: %v", err)
			}
			if !bytes.Equal(payload2, rot13b) {
				t.Fatalf("second response = %q, want the rot13 of %q", response2, payload2)
			}

			if !session.handshakeDone.Load() {
				t.Fatal("the client session didn't complete its handshake")
			}
			c2s := session.sendBlock.Load()
			s2c := session.block.Load()
			if c2s == nil || s2c == nil {
				t.Fatal("the client session didn't install its data plane ciphers")
			}
			if got := (*c2s).Suite(); got != tc.wantDataSuite {
				t.Fatalf("client to server cipher suite = %v, want %v", got, tc.wantDataSuite)
			}
			if got := (*s2c).Suite(); got != tc.wantDataSuite {
				t.Fatalf("server to client cipher suite = %v, want %v", got, tc.wantDataSuite)
			}
			// The data plane may negotiate a suite with a longer key than the
			// cipher that protected the handshake envelope, because the session
			// keys are derived from the negotiated suite. The envelope cipher is
			// the first suite the client offers.
			if tc.envelopeLen > 0 {
				if got := clientStaticCipher(t, session).Suite().KeyLen(); got != tc.envelopeLen {
					t.Fatalf("client handshake envelope key length = %d, want %d", got, tc.envelopeLen)
				}
			}

			// The server side of the session installed the mirror image keys.
			serverSession := testServerSession(t, findServerUnderlay(t, serverMux), session.id)
			serverC2S := serverSession.block.Load()
			serverS2C := serverSession.sendBlock.Load()
			if serverC2S == nil || serverS2C == nil {
				t.Fatal("the server session didn't install its data plane ciphers")
			}
			if got := (*serverC2S).Suite(); got != tc.wantDataSuite {
				t.Fatalf("server receive cipher suite = %v, want %v", got, tc.wantDataSuite)
			}
			if got := (*serverS2C).Suite(); got != tc.wantDataSuite {
				t.Fatalf("server send cipher suite = %v, want %v", got, tc.wantDataSuite)
			}

			// The data plane is not protected by the static key of the client:
			// a message that the client session encrypted can't be decrypted
			// with the static cipher of the connection.
			static := clientStaticCipher(t, session)
			probe := []byte("a data plane probe")
			encryptedProbe := testSealProbe(t, *c2s, probe)
			if _, err := static.CloneStatelessFast().Decrypt(append([]byte{}, encryptedProbe...)); err == nil {
				t.Fatal("the static key decrypted a data plane message")
			}
			// The server session key decrypts the same message, which proves
			// that both peers derived the same client to server session key.
			decryptedProbe, err := (*serverC2S).CloneStatelessFast().Decrypt(append([]byte{}, encryptedProbe...))
			if err != nil {
				t.Fatalf("the server session key didn't decrypt the data plane message: %v", err)
			}
			if !bytes.Equal(decryptedProbe, probe) {
				t.Fatalf("data plane probe = %q, want %q", decryptedProbe, probe)
			}
		})
	}
}

// clientStaticCipher returns a copy of the static cipher that protects the
// handshake envelope of a client session.
func clientStaticCipher(t *testing.T, session *Session) cipher.BlockCipher {
	t.Helper()
	switch underlay := session.conn.(type) {
	case *StreamUnderlay:
		if underlay.block == nil {
			t.Fatal("the client stream underlay has no static cipher")
		}
		return underlay.block
	case *PacketUnderlay:
		if underlay.block == nil {
			t.Fatal("the client packet underlay has no static cipher")
		}
		return underlay.block
	default:
		t.Fatalf("session connection type = %T, want a client underlay", session.conn)
		return nil
	}
}

// findServerUnderlay returns the first underlay of a server mux that owns a
// session.
func findServerUnderlay(t *testing.T, mux *Mux) Underlay {
	t.Helper()
	mux.mu.Lock()
	defer mux.mu.Unlock()
	for _, underlay := range mux.underlays {
		if underlay.SessionCount() > 0 {
			return underlay
		}
	}
	t.Fatal("the server mux has no underlay with a session")
	return nil
}

// TestHandshakeRejectsIncompatibleRequests verifies that the server drops a
// request it can't handshake with, without writing any byte and without a
// session that reaches the application, and that a peer which speaks the
// protocol version but no common cipher suite is still told why the handshake
// failed.
func TestHandshakeRejectsIncompatibleRequests(t *testing.T) {
	const userName = "handshake-reject-user"
	password := []byte(t.Name())
	credential := cipher.HashPassword(password, []byte(userName))
	users := userMap(makeTestUser(userName, credential))
	server := testStartPacketServer(t, users, []cipher.Suite{cipher.SuiteXChaCha20Poly1305})

	envelope, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, credential, true)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}
	envelope.SetBlockContext(cipher.BlockContext{UserName: userName, Pepper: cipher.HintPepper(userName, string(credential))})

	// The second entry of the suite list copies the first one, so the request
	// offers the same suite twice and its preference list is malformed.
	duplicateSuites := testHandshakeRequestPayloadWithVersion(t, protocolVersion, protocolVersion, []cipher.Suite{cipher.SuiteXChaCha20Poly1305, cipher.SuiteAES128GCM})
	duplicateSuites[handshakeRequestHeaderLen+1] = duplicateSuites[handshakeRequestHeaderLen]

	// A request that is not a handshake of protocolVersion is dropped without an
	// answer, so the server writes no byte for it.
	droppedTestCases := []struct {
		name    string
		payload []byte
	}{
		{
			name:    "protocol version of a previous peer",
			payload: append([]byte{2, 2, 1, byte(cipher.SuiteXChaCha20Poly1305)}, make([]byte, 48)...),
		},
		{
			name:    "protocol version of the oldest peer",
			payload: append([]byte{1, 1, 1, byte(cipher.SuiteXChaCha20Poly1305)}, make([]byte, 48)...),
		},
		{
			name:    "payload shorter than the handshake request header",
			payload: []byte{protocolVersion, protocolVersion},
		},
		{
			name:    "truncated handshake request",
			payload: []byte{protocolVersion, protocolVersion, 1},
		},
		{
			name:    "zero cipher suites",
			payload: []byte{protocolVersion, protocolVersion, 0},
		},
		{
			name:    "unknown cipher suite",
			payload: append([]byte{protocolVersion, protocolVersion, 1, 7}, make([]byte, 48)...),
		},
		{
			name:    "duplicate cipher suite",
			payload: duplicateSuites,
		},
		{
			name:    "version range below the protocol version",
			payload: testHandshakeRequestPayloadWithVersion(t, 1, 2, nil),
		},
		{
			name:    "version range above the protocol version",
			payload: testHandshakeRequestPayloadWithVersion(t, protocolVersion+1, protocolVersion+1, nil),
		},
		{
			name:    "invalid version range",
			payload: testHandshakeRequestPayloadWithVersion(t, protocolVersion, 2, nil),
		},
	}

	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket() client failed: %v", err)
	}
	defer clientConn.Close()

	var sentBytes int64
	for i, tc := range droppedTestCases {
		t.Run(tc.name, func(t *testing.T) {
			sessionID := uint32(100 + i)
			ss := &sessionStruct{
				baseStruct: baseStruct{protocol: uint8(openSessionRequest)},
				sessionID:  sessionID,
				payloadLen: uint16(len(tc.payload)),
			}
			wire := testBuildPacketMessage(t, envelope, ss, tc.payload)
			if _, err := clientConn.WriteTo(wire, server.conn.LocalAddr()); err != nil {
				t.Fatalf("WriteTo() failed: %v", err)
			}
			sentBytes += int64(len(wire))

			// The event loop of the underlay reads a datagram and dispatches it
			// in one pass, so waiting for the bytes of the request and for the
			// session of the request to be closed makes the assertions below
			// independent of the scheduling of that loop.
			waitForCondition(t, 5*time.Second, "the server to read the open session request", func() bool {
				return server.inBytes.Load() >= sentBytes
			})
			// The session of the request must be closed, and it must never
			// reach the application.
			waitForSessionClose(t, server, sessionID)
			if got := server.outBytes.Load(); got != 0 {
				t.Fatalf("the server wrote %d bytes in answer to a dropped request", got)
			}
			// The dropped session must not be visible to the application.
			select {
			case conn := <-server.readySessions:
				t.Fatalf("server accepted a session for a dropped request: %v", conn)
			default:
			}
		})
	}
	// None of the dropped requests was answered with a datagram.
	assertNoPacketResponse(t, clientConn)

	// A peer that speaks the protocol version and shares no cipher suite is
	// answered, because the handshake itself is compatible.
	t.Run("no common cipher suite", func(t *testing.T) {
		const sessionID = 200
		payload := testHandshakeRequestPayloadWithVersion(t, protocolVersion, protocolVersion, []cipher.Suite{cipher.SuiteAES256GCM})
		ss := &sessionStruct{
			baseStruct: baseStruct{protocol: uint8(openSessionRequest)},
			sessionID:  sessionID,
			payloadLen: uint16(len(payload)),
		}
		if _, err := clientConn.WriteTo(testBuildPacketMessage(t, envelope, ss, payload), server.conn.LocalAddr()); err != nil {
			t.Fatalf("WriteTo() failed: %v", err)
		}
		response := testReadPacketHandshakeResponse(t, clientConn, envelope)
		if response.status != handshakeStatusNoSuite {
			t.Fatalf("handshake status = %d, want %d", response.status, handshakeStatusNoSuite)
		}
		if response.version != 0 || response.suite != 0 {
			t.Fatalf("failed handshake response = (version %d, suite %d), want zero values", response.version, response.suite)
		}
		// The rejected session must not be visible to the application, and it
		// must be closed.
		select {
		case conn := <-server.readySessions:
			t.Fatalf("server accepted a session for a rejected request: %v", conn)
		default:
		}
		waitForSessionClose(t, server, sessionID)
	})
}

// TestHandshakeAcceptsPeerClockOffset verifies that a peer whose clock is one
// key refresh interval behind or ahead of the server still completes the
// handshake, and that both peers derive the same session keys.
func TestHandshakeAcceptsPeerClockOffset(t *testing.T) {
	const userName = "handshake-offset-user"
	password := []byte(t.Name())
	credential := cipher.HashPassword(password, []byte(userName))
	users := userMap(makeTestUser(userName, credential))
	server := testStartPacketServer(t, users, nil)

	// Element 0 uses the salt of the previous key refresh interval and element
	// 2 uses the salt of the next one, so a peer that encrypts its handshake
	// request with one of them behaves like a peer whose clock is offset by
	// one interval.
	for _, slot := range []int{0, 2} {
		slotCiphers, err := cipher.BlockCipherListFromPassword(cipher.SuiteXChaCha20Poly1305, credential, true)
		if err != nil {
			t.Fatalf("BlockCipherListFromPassword() failed: %v", err)
		}
		envelope := slotCiphers[slot]
		envelope.SetBlockContext(cipher.BlockContext{UserName: userName, Pepper: cipher.HintPepper(userName, string(credential))})

		client, requestPayload := newTestHandshakeClient(t, envelope, true)
		sessionID := uint32(200 + slot)
		ss := &sessionStruct{
			baseStruct: baseStruct{protocol: uint8(openSessionRequest)},
			sessionID:  sessionID,
			payloadLen: uint16(len(requestPayload)),
		}
		wire := testBuildPacketMessage(t, envelope, ss, requestPayload)

		clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
		if err != nil {
			t.Fatalf("net.ListenPacket() client failed: %v", err)
		}
		defer clientConn.Close()
		if _, err := clientConn.WriteTo(wire, server.conn.LocalAddr()); err != nil {
			t.Fatalf("WriteTo() failed: %v", err)
		}

		response := testReadPacketHandshakeResponse(t, clientConn, envelope)
		if response.status != handshakeStatusOK {
			t.Fatalf("handshake with a clock offset in slot %d failed with status %d", slot, response.status)
		}
		client.complete(t, response)

		// Both peers must have derived the same client to server session key.
		serverSession := testServerSession(t, server, sessionID)
		serverC2S := serverSession.block.Load()
		if serverC2S == nil {
			t.Fatalf("the server session of the clock offset case didn't install its cipher")
		}
		probe := []byte("a probe across the clock offset")
		encryptedProbe := testSealProbe(t, client.c2s, probe)
		serverRecv := (*serverC2S).CloneStatelessFast()
		decryptedProbe, err := serverRecv.Decrypt(append([]byte{}, encryptedProbe...))
		if err != nil {
			t.Fatalf("the server session key didn't decrypt the probe of an offset peer: %v", err)
		}
		if !bytes.Equal(decryptedProbe, probe) {
			t.Fatalf("probe = %q, want %q", decryptedProbe, probe)
		}
		// The server to client key must not decrypt the client to server
		// probe, otherwise the probe above would prove nothing.
		serverS2C := serverSession.sendBlock.Load()
		if serverS2C == nil {
			t.Fatalf("the server session of the clock offset case didn't install its send cipher")
		}
		if _, err := (*serverS2C).CloneStatelessFast().Decrypt(append([]byte{}, encryptedProbe...)); err == nil {
			t.Fatal("the server to client session key decrypted a client to server probe")
		}
	}
}

// TestHandshakeStreamDropsUnsupportedRequest verifies that a stream underlay
// doesn't answer an open session request that doesn't carry the handshake of
// this protocol version: it writes no byte, it closes the connection, and no
// session reaches the application.
func TestHandshakeStreamDropsUnsupportedRequest(t *testing.T) {
	const userName = "handshake-stream-reject-user"
	password := []byte(t.Name())
	credential := cipher.HashPassword(password, []byte(userName))
	users := userMap(makeTestUser(userName, credential))
	mux := NewMux(false).SetServerUsers(users)
	t.Cleanup(func() { _ = mux.Close() })

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	defer listener.Close()
	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial() failed: %v", err)
	}
	defer clientConn.Close()
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept() failed: %v", err)
	}
	underlay := mux.serverWrapTCPConn(serverConn, 1400, nil).(*StreamUnderlay)
	t.Cleanup(func() { underlay.sessionCleanTicker.Stop() })

	envelope, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, credential, false)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}
	envelope.SetBlockContext(cipher.BlockContext{UserName: userName, Pepper: cipher.HintPepper(userName, string(credential))})

	// The payload of a peer that doesn't speak this protocol version: a client
	// of a previous version sends application data where a client of this build
	// sends its handshake request.
	const sessionID = 300
	payload := bytes.Repeat([]byte{0x17}, handshakeRequestFixedLen)
	ss := &sessionStruct{
		baseStruct: baseStruct{protocol: uint8(openSessionRequest)},
		sessionID:  sessionID,
		payloadLen: uint16(len(payload)),
	}
	if _, err := clientConn.Write(testBuildStreamMessage(t, envelope, ss, payload)); err != nil {
		t.Fatalf("Write() of the unsupported request failed: %v", err)
	}

	seg, err := underlay.readOneSegment()
	if err != nil {
		t.Fatalf("readOneSegment() failed: %v", err)
	}
	if err := underlay.onOpenSessionRequest(seg); err != nil {
		t.Fatalf("onOpenSessionRequest() failed: %v", err)
	}

	// The connection is closed without an answer, with no panic.
	select {
	case <-underlay.done:
	default:
		t.Error("the underlay of a dropped request is still open")
	}
	assertNoStreamResponse(t, clientConn)

	// No session of a dropped request reaches the application.
	select {
	case conn := <-underlay.readySessions:
		t.Fatalf("server accepted a session for an unsupported request: %v", conn)
	default:
	}
	waitForSessionClose(t, underlay, sessionID)
}

// TestHandshakeStreamEndToEndRejectsWrongKey verifies that the stream data
// plane of a session is not the static key: a message sealed with the static
// key of the client is not accepted as session data by the server.
func TestHandshakeStreamEndToEndRejectsWrongKey(t *testing.T) {
	// The end to end test above proves that both peers agree on the session
	// keys. This test proves the same for the stream transport by checking
	// that the static cipher can't decrypt a message that the session cipher
	// produced.
	const userName = "handshake-stream-key-user"
	password := []byte(t.Name())
	credential := cipher.HashPassword(password, []byte(userName))
	users := userMap(makeTestUser(userName, credential))
	mux := NewMux(false).SetServerUsers(users)
	t.Cleanup(func() { _ = mux.Close() })

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	defer listener.Close()
	clientConn, err := net.Dial("tcp", listener.Addr().String())
	if err != nil {
		t.Fatalf("net.Dial() failed: %v", err)
	}
	defer clientConn.Close()
	serverConn, err := listener.Accept()
	if err != nil {
		t.Fatalf("Accept() failed: %v", err)
	}
	underlay := mux.serverWrapTCPConn(serverConn, 1400, nil).(*StreamUnderlay)
	t.Cleanup(func() { underlay.sessionCleanTicker.Stop() })

	envelope, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, credential, false)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}
	envelope.SetBlockContext(cipher.BlockContext{UserName: userName, Pepper: cipher.HintPepper(userName, string(credential))})
	client, requestPayload := newTestHandshakeClientWithSuites(t, envelope, false, []cipher.Suite{cipher.SuiteXChaCha20Poly1305, cipher.SuiteAES256GCM})

	const sessionID = 400
	ss := &sessionStruct{
		baseStruct: baseStruct{protocol: uint8(openSessionRequest)},
		sessionID:  sessionID,
		payloadLen: uint16(len(requestPayload)),
	}
	if _, err := clientConn.Write(testBuildStreamMessage(t, envelope, ss, requestPayload)); err != nil {
		t.Fatalf("Write() of the open session request failed: %v", err)
	}
	seg, err := underlay.readOneSegment()
	if err != nil {
		t.Fatalf("readOneSegment() failed: %v", err)
	}
	if err := underlay.onOpenSessionRequest(seg); err != nil {
		t.Fatalf("onOpenSessionRequest() failed: %v", err)
	}

	responseEnvelope, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, credential, false)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}
	responseEnvelope.SetBlockContext(cipher.BlockContext{UserName: userName, Pepper: cipher.HintPepper(userName, string(credential))})
	response := testReadStreamHandshakeResponse(t, clientConn, responseEnvelope)
	client.complete(t, response)

	// The connection of the server switched to the session keys, and the
	// static key of the client can't decrypt what it produces.
	probe := []byte("stream data plane probe")
	encryptedProbe := testSealProbe(t, client.c2s, probe)
	if _, err := envelope.CloneStatelessFast().Decrypt(append([]byte{}, encryptedProbe...)); err == nil {
		t.Fatal("the static key decrypted a stream data plane message")
	}
	serverSession := testServerSession(t, underlay, sessionID)
	serverC2S := serverSession.block.Load()
	if serverC2S == nil {
		t.Fatal("the server session didn't install its cipher")
	}
	decrypted, err := (*serverC2S).CloneStatelessFast().Decrypt(append([]byte{}, encryptedProbe...))
	if err != nil {
		t.Fatalf("the server session key didn't decrypt the probe: %v", err)
	}
	if !bytes.Equal(decrypted, probe) {
		t.Fatalf("probe = %q, want %q", decrypted, probe)
	}
	if underlay.send == underlay.block || underlay.recv == underlay.block {
		t.Fatal("the stream underlay didn't switch its cipher chain to the session keys")
	}
	if got := (*serverC2S).Suite(); got != cipher.SuiteXChaCha20Poly1305 {
		t.Fatalf("server receive cipher suite = %v, want %v", got, cipher.SuiteXChaCha20Poly1305)
	}
}
