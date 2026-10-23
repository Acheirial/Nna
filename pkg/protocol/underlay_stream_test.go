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
	"errors"
	"io"
	"net"
	"os"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enfein/mieru/v3/pkg/cipher"
	"github.com/enfein/mieru/v3/pkg/stderror"
)

func TestStreamUnderlayEventLoopTerminalTimeout(t *testing.T) {
	conn := &readErrorConn{readErr: terminalTimeoutError{}}
	underlay := &StreamUnderlay{
		baseUnderlay:       *newBaseUnderlay(true, 1400, nil),
		conn:               conn,
		sessionCleanTicker: time.NewTicker(time.Hour),
	}
	defer underlay.sessionCleanTicker.Stop()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	loopDone := make(chan error, 1)
	go func() {
		loopDone <- underlay.RunEventLoop(ctx)
	}()

	select {
	case err := <-loopDone:
		if !errors.Is(err, net.ErrClosed) {
			t.Errorf("RunEventLoop() error = %v, want error wrapping net.ErrClosed", err)
		}
		if got := conn.readCalls.Load(); got != 1 {
			t.Errorf("Read() calls = %d, want 1; terminal timeouts must not be retried", got)
		}
		if !conn.closed.Load() {
			t.Error("RunEventLoop() did not close the connection")
		}
	case <-time.After(time.Second):
		// Stop a loop that incorrectly retries the terminal timeout.
		cancel()
		select {
		case <-loopDone:
		case <-time.After(time.Second):
			t.Error("RunEventLoop() did not stop after cancellation")
		}
		t.Fatalf("RunEventLoop() did not stop after terminal timeout; Read() calls = %d", conn.readCalls.Load())
	}
}

func TestStreamUnderlayReadDeadline(t *testing.T) {
	reader, writer := net.Pipe()
	defer reader.Close()
	defer writer.Close()
	underlay := &StreamUnderlay{conn: shortReadDeadlineConn{reader}}

	// With no data available, a read deadline lets the event loop retry.
	segment, err := underlay.readOneSegment()
	if segment != nil || err != nil {
		t.Fatalf("readOneSegment() = (%v, %v), want (nil, nil) so the event loop can retry", segment, err)
	}

	// A subsequent read must still report the peer closing the connection.
	if err := writer.Close(); err != nil {
		t.Fatalf("writer.Close() failed: %v", err)
	}
	segment, err = underlay.readOneSegment()
	if segment != nil {
		t.Errorf("readOneSegment() segment = %v, want nil", segment)
	}
	if !errors.Is(err, io.EOF) {
		t.Errorf("readOneSegment() error = %v, want error wrapping io.EOF", err)
	}
}

func TestStreamUnderlayTimeoutClassification(t *testing.T) {
	tests := []struct {
		name      string
		readErr   error
		readBytes int
		wantRetry bool
	}{
		{
			name:    "terminal timeout",
			readErr: terminalTimeoutError{},
		},
		{
			name:    "wrapped terminal timeout",
			readErr: &net.OpError{Op: "read", Net: "quic", Err: terminalTimeoutError{}},
		},
		{
			name:      "read deadline",
			readErr:   os.ErrDeadlineExceeded,
			wantRetry: true,
		},
		{
			name:      "wrapped read deadline",
			readErr:   &net.OpError{Op: "read", Net: "tcp", Err: os.ErrDeadlineExceeded},
			wantRetry: true,
		},
		{
			// Retrying after consuming metadata would lose segment framing.
			name:      "partial metadata timeout",
			readErr:   os.ErrDeadlineExceeded,
			readBytes: 1,
		},
		{
			name:    "closed connection",
			readErr: net.ErrClosed,
		},
		{
			name:    "end of stream",
			readErr: io.EOF,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := &readErrorConn{readErr: test.readErr, readBytes: test.readBytes}
			underlay := &StreamUnderlay{conn: conn}
			segment, err := underlay.readOneSegment()
			if segment != nil {
				t.Fatalf("readOneSegment() segment = %v, want nil", segment)
			}
			if test.wantRetry {
				if err != nil {
					t.Fatalf("readOneSegment() error = %v, want nil so the event loop can retry", err)
				}
				return
			}
			if !errors.Is(err, test.readErr) {
				t.Errorf("readOneSegment() error = %v, want error wrapping %v", err, test.readErr)
			}
			if got := stderror.GetErrorType(err); got != stderror.NETWORK_ERROR {
				t.Errorf("readOneSegment() error type = %v, want NETWORK_ERROR", got)
			}
		})
	}
}

// terminalTimeoutError models a transport timeout that also closes the
// connection.
type terminalTimeoutError struct{}

func (terminalTimeoutError) Error() string   { return "terminal transport timeout" }
func (terminalTimeoutError) Timeout() bool   { return true }
func (terminalTimeoutError) Temporary() bool { return false }
func (terminalTimeoutError) Unwrap() error   { return net.ErrClosed }

// readErrorConn returns a configured read result and records event-loop cleanup.
// Only Read, SetReadDeadline, and Close are supported; other methods are unused.
type readErrorConn struct {
	net.Conn
	readErr   error
	readBytes int
	readCalls atomic.Int64
	closed    atomic.Bool
}

func (c *readErrorConn) Read([]byte) (int, error) {
	c.readCalls.Add(1)
	return c.readBytes, c.readErr
}

func (c *readErrorConn) SetReadDeadline(time.Time) error { return nil }

func (c *readErrorConn) Close() error {
	c.closed.Store(true)
	return nil
}

// shortReadDeadlineConn exercises a real net.Conn deadline without waiting for
// the production read timeout. Zero deadlines still clear the timeout normally.
type shortReadDeadlineConn struct{ net.Conn }

func (c shortReadDeadlineConn) SetReadDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		deadline = time.Now().Add(100 * time.Millisecond)
	}
	return c.Conn.SetReadDeadline(deadline)
}

// TestStreamUnderlayReusesMessageBuffers verifies that the reusable send and
// receive buffers of the underlay carry the full content of every message.
// A message that reuses a buffer must not leak the bytes of the previous one,
// whatever the size of both messages is.
func TestStreamUnderlayReusesMessageBuffers(t *testing.T) {
	password := cipher.HashPassword([]byte(t.Name()), []byte("user"))
	block, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, password, false)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}
	left, right := net.Pipe()
	defer left.Close()
	defer right.Close()
	sender := &StreamUnderlay{
		baseUnderlay: *newBaseUnderlay(true, 1400, nil),
		conn:         left,
		block:        block.Clone(),
	}
	receiver := &StreamUnderlay{
		baseUnderlay: *newBaseUnderlay(false, 1400, nil),
		conn:         right,
		serverUsers:  testServerUserRegistry(userMap(makeTestUser("user", password)), false),
	}

	// The sizes must go up and down, so that a buffer that was grown for a
	// large message is reused by a small one and the other way round.
	for i, size := range []int{1200, 1, 900} {
		payload := make([]byte, size)
		for j := range payload {
			payload[j] = byte(i + j)
		}
		seg := &segment{
			metadata: &dataAckStruct{
				baseStruct: baseStruct{protocol: uint8(dataClientToServer)},
				sessionID:  7,
				seq:        uint32(i),
				windowSize: segmentTreeCapacity,
				payloadLen: uint16(len(payload)),
			},
			payload: payload,
		}
		writeDone := make(chan error, 1)
		go func() {
			writeDone <- sender.writeOneSegment(seg)
		}()
		received, err := receiver.readOneSegment()
		if err != nil {
			t.Fatalf("message %d: readOneSegment() failed: %v", i, err)
		}
		if err := <-writeDone; err != nil {
			t.Fatalf("message %d: writeOneSegment() failed: %v", i, err)
		}
		if received.Protocol() != dataClientToServer {
			t.Errorf("message %d: received protocol = %v, want %v", i, received.Protocol(), dataClientToServer)
		}
		if !bytes.Equal(received.payload, payload) {
			t.Errorf("message %d: received %d payload bytes %v, want %v", i, len(received.payload), received.payload, payload)
		}
		if got := received.metadata.(*dataAckStruct).payloadLen; got != uint16(len(payload)) {
			t.Errorf("message %d: received payload length = %d, want %d", i, got, len(payload))
		}
	}
	if sender.OutBytes() != receiver.InBytes() {
		t.Errorf("stream wire byte counts = sent %d, received %d", sender.OutBytes(), receiver.InBytes())
	}
}

// countingReadConn returns as many bytes of a message as the caller asks for,
// so every ReadFull() of the reader costs exactly one Read() call. It counts
// the Read() calls, which is how the tests observe the read pattern of the
// event loop. Only Read, SetReadDeadline, and Close are supported.
type countingReadConn struct {
	net.Conn
	src   []byte
	reads atomic.Int64
}

func (c *countingReadConn) Read(p []byte) (int, error) {
	c.reads.Add(1)
	if len(c.src) < len(p) {
		return copy(p, c.src), io.ErrUnexpectedEOF
	}
	n := copy(p, c.src)
	c.src = c.src[n:]
	return n, nil
}

func (c *countingReadConn) SetReadDeadline(time.Time) error { return nil }

func (c *countingReadConn) Close() error { return nil }

// TestStreamUnderlayReadsMessageBodyInOneRead verifies that the reader takes
// the metadata of a message with one Read() call and the rest of the message,
// however many padding regions it carries, with a second one. The padding
// regions are sliced out of the buffer of the body instead of being read
// separately.
func TestStreamUnderlayReadsMessageBodyInOneRead(t *testing.T) {
	password := cipher.HashPassword([]byte(t.Name()), []byte("user"))
	payload := []byte("the payload of a message with padding on both sides")
	prefixPadding := []byte{0x01, 0x02, 0x03, 0x04}
	suffixPadding := []byte{0x05, 0x06, 0x07}

	tests := []struct {
		name     string
		metadata metadata
		prefix   []byte
		suffix   []byte
	}{
		{
			name: "data message with prefix and suffix padding",
			metadata: &dataAckStruct{
				baseStruct: baseStruct{protocol: uint8(dataClientToServer)},
				sessionID:  7,
				seq:        1,
				windowSize: segmentTreeCapacity,
				prefixLen:  uint8(len(prefixPadding)),
				payloadLen: uint16(len(payload)),
				suffixLen:  uint8(len(suffixPadding)),
			},
			prefix: prefixPadding,
			suffix: suffixPadding,
		},
		{
			name: "session message with suffix padding",
			metadata: &sessionStruct{
				baseStruct: baseStruct{protocol: uint8(closeSessionRequest)},
				sessionID:  7,
				payloadLen: uint16(len(payload)),
				suffixLen:  uint8(len(suffixPadding)),
			},
			suffix: suffixPadding,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			// The sender cipher writes the wire bytes and an independent copy
			// of the same key reads them back. Both start a chain, so the
			// metadata of the message carries the nonce and the payload that
			// follows it does not.
			sender, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, password, false)
			if err != nil {
				t.Fatalf("BlockCipherFromPassword() failed: %v", err)
			}
			receiverBlock := sender.Clone()
			encryptedMetadata := make([]byte, cipher.DefaultNonceSize+MetadataLength+cipher.DefaultOverhead)
			if err := sender.Encrypt(encryptedMetadata[:0], test.metadata.Marshal()); err != nil {
				t.Fatalf("Encrypt(metadata) failed: %v", err)
			}
			encryptedPayload := make([]byte, len(payload)+cipher.DefaultOverhead)
			if err := sender.Encrypt(encryptedPayload[:0], payload); err != nil {
				t.Fatalf("Encrypt(payload) failed: %v", err)
			}
			wire := append([]byte(nil), encryptedMetadata...)
			wire = append(wire, test.prefix...)
			wire = append(wire, encryptedPayload...)
			wire = append(wire, test.suffix...)

			conn := &countingReadConn{src: wire}
			receiver := &StreamUnderlay{
				baseUnderlay: *newBaseUnderlay(true, 1400, nil),
				conn:         conn,
				block:        receiverBlock,
			}
			seg, err := receiver.readOneSegment()
			if err != nil {
				t.Fatalf("readOneSegment() failed: %v", err)
			}
			if got := conn.reads.Load(); got != 2 {
				t.Errorf("readOneSegment() took %d Read() calls, want 2: the metadata and the body of a message", got)
			}
			if got := seg.Protocol(); got != test.metadata.Protocol() {
				t.Errorf("segment protocol = %v, want %v", got, test.metadata.Protocol())
			}
			if !bytes.Equal(seg.payload, payload) {
				t.Errorf("segment payload = %q, want %q", seg.payload, payload)
			}
		})
	}
}

// testBuildStreamDataMessage encrypts a data segment with a stateful session
// cipher, in the wire format of the stream transport. The cipher must have sent
// a message before, because the nonce of the chain start is not part of the
// framing of the messages that follow it.
func testBuildStreamDataMessage(tb testing.TB, block cipher.BlockCipher, sessionID uint32, payload []byte) []byte {
	tb.Helper()
	das := &dataAckStruct{
		baseStruct: baseStruct{protocol: uint8(dataClientToServer)},
		sessionID:  sessionID,
		windowSize: segmentTreeCapacity,
		payloadLen: uint16(len(payload)),
	}
	wire := make([]byte, MetadataLength+cipher.DefaultOverhead+len(payload)+cipher.DefaultOverhead)
	if err := block.Encrypt(wire[:0], das.Marshal()); err != nil {
		tb.Fatalf("Encrypt(metadata) failed: %v", err)
	}
	offset := MetadataLength + cipher.DefaultOverhead
	if err := block.Encrypt(wire[offset:offset], payload); err != nil {
		tb.Fatalf("Encrypt(payload) failed: %v", err)
	}
	return wire
}

// TestStreamUnderlaySecondOpenSessionRequestDoesNotRekey verifies that a server
// drops a second openSessionRequest received after the handshake of the first
// session switched the cipher chain of the connection to the session keys.
// Answering it would rekey a connection that carries a running session, and the
// peer of that session can't follow the new keys.
func TestStreamUnderlaySecondOpenSessionRequestDoesNotRekey(t *testing.T) {
	const userName = "stream-second-request-user"
	password := []byte(t.Name())
	credential := cipher.HashPassword(password, []byte(userName))
	mux := NewMux(false).SetServerUsers(userMap(makeTestUser(userName, credential)))
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
	t.Cleanup(func() {
		_ = underlay.Close()
		underlay.sessionCleanTicker.Stop()
	})

	envelope, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, credential, false)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}
	envelope.SetBlockContext(cipher.BlockContext{UserName: userName, Pepper: cipher.HintPepper(userName, string(credential))})
	client, requestPayload := newTestHandshakeClient(t, envelope, false)

	// The first session completes its handshake and switches the chain.
	const firstSessionID = 500
	firstRequest := &sessionStruct{
		baseStruct: baseStruct{protocol: uint8(openSessionRequest)},
		sessionID:  firstSessionID,
		payloadLen: uint16(len(requestPayload)),
	}
	if _, err := clientConn.Write(testBuildStreamMessage(t, envelope, firstRequest, requestPayload)); err != nil {
		t.Fatalf("Write() of the first open session request failed: %v", err)
	}
	firstSeg, err := underlay.readOneSegment()
	if err != nil {
		t.Fatalf("readOneSegment() of the first open session request failed: %v", err)
	}
	if err := underlay.onOpenSessionRequest(firstSeg); err != nil {
		t.Fatalf("onOpenSessionRequest() of the first request failed: %v", err)
	}
	// The event loop records the authenticated user of the first segment right
	// after the dispatch returns.
	underlay.commitServerUserAuthentication(firstSeg)

	responseEnvelope, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, credential, false)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}
	responseEnvelope.SetBlockContext(cipher.BlockContext{UserName: userName, Pepper: cipher.HintPepper(userName, string(credential))})
	client.complete(t, testReadStreamHandshakeResponse(t, clientConn, responseEnvelope))

	if !underlay.chainSwitched {
		t.Fatal("the server didn't switch the cipher chain of the connection after the first handshake")
	}
	recvCipher, sendCipher := underlay.recv, underlay.send

	// The second request carries a complete handshake, so a server that
	// answered it would install a second key pair. The peer protects it with
	// the session keys of the first session, which is what a duplicated or a
	// forked peer can do.
	secondHandshake, _, err := newHandshakeRequest(nil)
	if err != nil {
		t.Fatalf("newHandshakeRequest() failed: %v", err)
	}
	secondPayload := secondHandshake.Marshal()
	const secondSessionID = 501
	secondRequest := &sessionStruct{
		baseStruct: baseStruct{protocol: uint8(openSessionRequest)},
		sessionID:  secondSessionID,
		payloadLen: uint16(len(secondPayload)),
	}
	if _, err := clientConn.Write(testBuildStreamMessage(t, client.c2s, secondRequest, secondPayload)); err != nil {
		t.Fatalf("Write() of the second open session request failed: %v", err)
	}
	secondSeg, err := underlay.readOneSegment()
	if err != nil {
		t.Fatalf("readOneSegment() of the second open session request failed: %v", err)
	}
	if got := secondSeg.metadata.(*sessionStruct).sessionID; got != secondSessionID {
		t.Fatalf("second segment session ID = %d, want %d", got, secondSessionID)
	}
	if err := underlay.onOpenSessionRequest(secondSeg); err != nil {
		t.Fatalf("onOpenSessionRequest() of the second request = %v, want nil: the connection must survive the request", err)
	}
	if underlay.recv != recvCipher || underlay.send != sendCipher {
		t.Error("the second open session request rekeyed the cipher chain of the connection")
	}
	if _, ok := underlay.sessionMap.Load(uint32(secondSessionID)); ok {
		t.Error("the second open session request created a session")
	}
	firstValue, ok := underlay.sessionMap.Load(uint32(firstSessionID))
	if !ok {
		t.Fatal("the session of the first handshake is not registered any more")
	}
	firstSession := firstValue.(*Session)
	select {
	case <-firstSession.closedChan:
		t.Error("the session of the first handshake is closed")
	default:
	}

	// The chain of the first session still carries the data plane: a segment
	// sealed with the session key of the client is accepted by the server.
	probe := []byte("a probe on the session of the first handshake")
	if _, err := clientConn.Write(testBuildStreamDataMessage(t, client.c2s, firstSessionID, probe)); err != nil {
		t.Fatalf("Write() of a data segment after the second request failed: %v", err)
	}
	dataSeg, err := underlay.readOneSegment()
	if err != nil {
		t.Fatalf("readOneSegment() of a data segment after the second request failed: %v", err)
	}
	if got := dataSeg.Protocol(); got != dataClientToServer {
		t.Errorf("data segment protocol = %v, want %v", got, dataClientToServer)
	}
	if !bytes.Equal(dataSeg.payload, probe) {
		t.Errorf("data segment payload = %q, want %q", dataSeg.payload, probe)
	}
}

// TestStreamUnderlayCleanSessionsRemovesIdleSessions verifies that the session
// cleanup of the stream underlay reclaims the sessions that received no segment
// within idleStreamSessionTimeout, and keeps the sessions that received one
// shortly before the timeout. The receive time of a session is moved into the
// past instead of waiting for the idle timeout.
func TestStreamUnderlayCleanSessionsRemovesIdleSessions(t *testing.T) {
	local, remote := net.Pipe()
	underlay := &StreamUnderlay{
		baseUnderlay:       *newBaseUnderlay(false, 1400, nil),
		conn:               local,
		sessionCleanTicker: time.NewTicker(sessionCleanInterval),
	}
	underlay.baseUnderlay.rawConn = local
	t.Cleanup(func() {
		_ = underlay.Close()
		_ = remote.Close()
		underlay.sessionCleanTicker.Stop()
	})
	// A peer that keeps reading lets a removed session flush its close session
	// request instead of waiting for the graceful close timeout.
	go func() {
		_, _ = io.Copy(io.Discard, remote)
	}()

	for _, sessionID := range []uint32{1, 2, 3} {
		if err := underlay.AddSession(NewSession(sessionID, false, 1400, nil, nil), nil); err != nil {
			t.Fatalf("AddSession(%d) failed: %v", sessionID, err)
		}
	}
	loadSession := func(sessionID uint32) *Session {
		value, ok := underlay.sessionMap.Load(sessionID)
		if !ok {
			t.Fatalf("session %d is not registered to the underlay", sessionID)
		}
		return value.(*Session)
	}
	recent := loadSession(1)
	almostIdle := loadSession(2)
	idle := loadSession(3)

	now := time.Now()
	almostIdle.lastRXTime.Store(now.Add(-(idleStreamSessionTimeout - 10*time.Second)).UnixMicro())
	idle.lastRXTime.Store(now.Add(-2 * idleStreamSessionTimeout).UnixMicro())

	underlay.cleanSessions()

	if got := underlay.SessionCount(); got != 2 {
		t.Errorf("session count after cleanSessions() = %d, want 2", got)
	}
	if _, ok := underlay.sessionMap.Load(uint32(3)); ok {
		t.Error("idle session 3 is still registered")
	}
	select {
	case <-idle.closedChan:
	default:
		t.Error("idle session 3 is not closed")
	}
	for _, session := range []*Session{recent, almostIdle} {
		if _, ok := underlay.sessionMap.Load(session.id); !ok {
			t.Errorf("session %d is removed, want it to be kept", session.id)
		}
		select {
		case <-session.closedChan:
			t.Errorf("session %d is closed, want it to be kept", session.id)
		default:
		}
	}
}

// shortWriteDeadlineConn shrinks the write deadline of a connection to a small
// value, so a test observes the write timeout of the stream send path without
// waiting for the production timeout. A zero deadline still clears the timeout,
// like a real connection does.
type shortWriteDeadlineConn struct {
	net.Conn
	timeout time.Duration
	// entered is closed when the first Write() starts, if it is not nil. It
	// tells a test when the send path reached a blocking write.
	entered chan struct{}
	once    sync.Once
}

func (c *shortWriteDeadlineConn) Write(p []byte) (int, error) {
	if c.entered != nil {
		c.once.Do(func() { close(c.entered) })
	}
	return c.Conn.Write(p)
}

func (c *shortWriteDeadlineConn) SetWriteDeadline(deadline time.Time) error {
	if !deadline.IsZero() {
		deadline = time.Now().Add(c.timeout)
	}
	return c.Conn.SetWriteDeadline(deadline)
}

// testStreamDataSegment builds a data segment of a server session with the
// given payload.
func testStreamDataSegment(payload []byte) *segment {
	return &segment{
		metadata: &dataAckStruct{
			baseStruct: baseStruct{protocol: uint8(dataServerToClient)},
			sessionID:  9,
			seq:        1,
			windowSize: segmentTreeCapacity,
			payloadLen: uint16(len(payload)),
		},
		payload: payload,
	}
}

// TestStreamUnderlayWriteTimeout verifies that a write to a peer that stopped
// reading fails within streamWriteTimeout instead of blocking the send path
// forever, and that a caller can tell the timeout apart from a broken
// connection.
func TestStreamUnderlayWriteTimeout(t *testing.T) {
	const writeTimeout = 100 * time.Millisecond
	block, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, cipher.HashPassword([]byte(t.Name()), []byte("user")), false)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}

	tests := []struct {
		name      string
		closePeer bool
	}{
		{name: "peer stopped reading"},
		{name: "peer closed the connection", closePeer: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			peer, local := net.Pipe()
			defer peer.Close()
			defer local.Close()
			if test.closePeer {
				peer.Close()
			}
			underlay := &StreamUnderlay{
				baseUnderlay: *newBaseUnderlay(false, 1400, nil),
				conn:         &shortWriteDeadlineConn{Conn: local, timeout: writeTimeout},
				send:         block.Clone(),
			}

			start := time.Now()
			err := underlay.writeOneSegment(testStreamDataSegment([]byte("a payload that the peer doesn't read")))
			elapsed := time.Since(start)
			if err == nil {
				t.Fatal("writeOneSegment() = nil, want an error")
			}
			if test.closePeer {
				if stderror.IsTimeout(err) {
					t.Errorf("stderror.IsTimeout() = true for %v, want false: the peer closed the connection", err)
				}
				if !stderror.IsClosed(err) {
					t.Errorf("writeOneSegment() error = %v, want a closed connection error", err)
				}
				return
			}
			if !stderror.IsTimeout(err) {
				t.Errorf("stderror.IsTimeout() = false for %v, want true: the write must be reported as a timeout", err)
			}
			if got := stderror.GetErrorType(err); got != stderror.NETWORK_ERROR {
				t.Errorf("writeOneSegment() error type = %v, want NETWORK_ERROR", got)
			}
			if elapsed < writeTimeout {
				t.Errorf("writeOneSegment() returned after %v, want at least %v", elapsed, writeTimeout)
			}
			if elapsed > time.Second {
				t.Errorf("writeOneSegment() returned after %v, want it bounded by the write timeout", elapsed)
			}

			// The write that follows a timed out write must arm its own
			// deadline instead of reusing the expired one, so it blocks for
			// the timeout again rather than failing right away.
			start = time.Now()
			err = underlay.writeOneSegment(testStreamDataSegment([]byte("another payload that the peer doesn't read")))
			if !stderror.IsTimeout(err) {
				t.Errorf("the write that follows a timeout = %v, want a timeout error", err)
			}
			if elapsed := time.Since(start); elapsed < writeTimeout {
				t.Errorf("the write that follows a timeout returned after %v, want at least %v: an expired deadline must not be reused", elapsed, writeTimeout)
			}
		})
	}
}

// TestStreamUnderlaySessionRemovalIsBoundedByWriteTimeout verifies that a peer
// that stopped reading doesn't hang the removal of the session and the close of
// the underlay: the write of the session fails within streamWriteTimeout, which
// releases the output loop that both wait for.
func TestStreamUnderlaySessionRemovalIsBoundedByWriteTimeout(t *testing.T) {
	const writeTimeout = 100 * time.Millisecond
	block, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, cipher.HashPassword([]byte(t.Name()), []byte("user")), false)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}

	// newUnderlay returns an underlay with one session whose output loop is
	// blocked in a write to a peer that never reads.
	newUnderlay := func(t *testing.T) (*StreamUnderlay, *Session) {
		t.Helper()
		peer, local := net.Pipe()
		entered := make(chan struct{})
		underlay := &StreamUnderlay{
			baseUnderlay:       *newBaseUnderlay(false, 1400, nil),
			conn:               &shortWriteDeadlineConn{Conn: local, timeout: writeTimeout, entered: entered},
			sessionCleanTicker: time.NewTicker(time.Hour),
			send:               block.Clone(),
		}
		underlay.baseUnderlay.rawConn = local
		session := NewSession(11, false, 1400, nil, nil)
		if err := underlay.AddSession(session, nil); err != nil {
			t.Fatalf("AddSession() failed: %v", err)
		}
		t.Cleanup(func() {
			_ = session.Close()
			_ = local.Close()
			_ = peer.Close()
		})
		if _, err := session.Write([]byte("a payload that the peer doesn't read")); err != nil {
			t.Fatalf("Write() failed: %v", err)
		}
		select {
		case <-entered:
		case <-time.After(time.Second):
			t.Fatal("the output loop of the session didn't reach the write")
		}
		return underlay, session
	}

	t.Run("RemoveSession", func(t *testing.T) {
		underlay, session := newUnderlay(t)
		start := time.Now()
		if err := underlay.RemoveSession(session); err != nil {
			t.Fatalf("RemoveSession() failed: %v", err)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("RemoveSession() returned after %v, want it bounded by the write timeout", elapsed)
		}
		if got := underlay.SessionCount(); got != 0 {
			t.Errorf("session count after RemoveSession() = %d, want 0", got)
		}
		select {
		case <-session.closedChan:
		default:
			t.Error("RemoveSession() didn't close the session")
		}
	})

	t.Run("Close", func(t *testing.T) {
		underlay, _ := newUnderlay(t)
		start := time.Now()
		if err := underlay.Close(); err != nil {
			t.Fatalf("Close() failed: %v", err)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Errorf("Close() returned after %v, want it bounded by the write timeout", elapsed)
		}
	})
}

// TestBaseUnderlayRemoveSessionWaitTimeout verifies that RemoveSession() gives
// up waiting for the goroutines of a session that never stops instead of
// blocking its caller forever, and that the session is closed and detached
// when the wait is abandoned. The test shrinks the wait, so the production
// timeout is not part of the test duration.
func TestBaseUnderlayRemoveSessionWaitTimeout(t *testing.T) {
	const waitTimeout = 50 * time.Millisecond
	underlay := newBaseUnderlay(false, 1400, nil)
	underlay.sessionWaitTimeout = waitTimeout
	session := NewSession(3, false, 1400, nil, nil)
	if err := underlay.AddSession(session, nil); err != nil {
		t.Fatalf("AddSession() failed: %v", err)
	}
	// A goroutine of the session that never stops.
	session.wg.Add(1)
	defer session.wg.Done()

	start := time.Now()
	if err := underlay.RemoveSession(session); err != nil {
		t.Fatalf("RemoveSession() failed: %v", err)
	}
	elapsed := time.Since(start)
	if elapsed < waitTimeout/2 {
		t.Errorf("RemoveSession() returned after %v, want at least %v: the wait must be bounded, not skipped", elapsed, waitTimeout/2)
	}
	if elapsed > time.Second {
		t.Errorf("RemoveSession() returned after %v, want it bounded by the session wait timeout", elapsed)
	}
	if got := underlay.SessionCount(); got != 0 {
		t.Errorf("session count after RemoveSession() = %d, want 0", got)
	}
	if _, ok := underlay.sessionMap.Load(uint32(3)); ok {
		t.Error("RemoveSession() left the session in the registry")
	}
	select {
	case <-session.closedChan:
	default:
		t.Error("RemoveSession() didn't close the session")
	}
}

// recordingReadConn records every byte that is read from it, so a test can
// inspect the wire bytes of the messages that the peer of the connection sent.
type recordingReadConn struct {
	net.Conn
	mu   sync.Mutex
	read []byte
}

func (c *recordingReadConn) Read(p []byte) (int, error) {
	n, err := c.Conn.Read(p)
	c.mu.Lock()
	c.read = append(c.read, p[:n]...)
	c.mu.Unlock()
	return n, err
}

func (c *recordingReadConn) bytes() []byte {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]byte(nil), c.read...)
}

// TestStreamUnderlayPaddingUsesScratchBuffer verifies that the send path
// generates the middle padding and the end padding of a data message into its
// reusable scratch buffer without the two regions overwriting each other, and
// that the generated padding keeps the properties of the padding strategy:
// every message is framed with the lengths that its metadata reports, the
// payload survives the round trip, and the padding lengths vary between
// messages instead of collapsing to one value.
func TestStreamUnderlayPaddingUsesScratchBuffer(t *testing.T) {
	const (
		userName = "stream-padding-scratch-user"
		messages = 40
	)
	password := cipher.HashPassword([]byte(t.Name()), []byte(userName))
	block, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, password, false)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}
	left, right := net.Pipe()
	recorder := &recordingReadConn{Conn: right}
	sender := &StreamUnderlay{
		baseUnderlay: *newBaseUnderlay(true, 1400, nil),
		conn:         left,
		block:        block,
	}
	receiver := &StreamUnderlay{
		baseUnderlay: *newBaseUnderlay(false, 1400, nil),
		conn:         recorder,
		serverUsers:  testServerUserRegistry(userMap(makeTestUser(userName, password)), false),
	}
	t.Cleanup(func() {
		_ = left.Close()
		_ = right.Close()
	})

	payload := []byte("the payload of a message whose padding regions must not overwrite each other")
	prefixLengths := make(map[int]struct{})
	suffixLengths := make(map[int]struct{})
	consumed := 0
	comparable := 0
	equalRegions := 0
	for i := range messages {
		seg := &segment{
			metadata: &dataAckStruct{
				baseStruct: baseStruct{protocol: uint8(dataClientToServer)},
				sessionID:  7,
				seq:        uint32(i),
				windowSize: segmentTreeCapacity,
				payloadLen: uint16(len(payload)),
			},
			payload: payload,
		}
		writeDone := make(chan error, 1)
		go func() {
			writeDone <- sender.writeOneSegment(seg)
		}()
		received, err := receiver.readOneSegment()
		if err != nil {
			t.Fatalf("message %d: readOneSegment() failed: %v", i, err)
		}
		if err := <-writeDone; err != nil {
			t.Fatalf("message %d: writeOneSegment() failed: %v", i, err)
		}
		das, ok := received.metadata.(*dataAckStruct)
		if !ok {
			t.Fatalf("message %d: metadata %T, want *dataAckStruct", i, received.metadata)
		}
		if !bytes.Equal(received.payload, payload) {
			t.Fatalf("message %d: payload = %q, want %q", i, received.payload, payload)
		}

		// The first message of a cipher chain carries the wire format nonce,
		// the messages that follow it don't.
		encryptedMetadataLen := MetadataLength + cipher.DefaultOverhead
		if i == 0 {
			encryptedMetadataLen += cipher.DefaultNonceSize
		}
		messageLen := encryptedMetadataLen + int(das.prefixLen) + int(das.payloadLen) + cipher.DefaultOverhead + int(das.suffixLen)
		wire := recorder.bytes()
		if consumed+messageLen != len(wire) {
			t.Fatalf("message %d: the underlay read %d wire bytes, want %d: the padding lengths of the metadata and the framing of the message disagree", i, len(wire)-consumed, messageLen)
		}
		message := wire[consumed : consumed+messageLen]
		consumed += messageLen
		prefix := message[encryptedMetadataLen : encryptedMetadataLen+int(das.prefixLen)]
		suffix := message[messageLen-int(das.suffixLen):]
		prefixLengths[len(prefix)] = struct{}{}
		suffixLengths[len(suffix)] = struct{}{}
		// The padding bytes are random, so one of two regions of the same
		// length can match by chance. A scratch buffer that the two regions
		// share makes the overlapping part of every message identical instead,
		// which is what the counters detect below.
		if n := min(len(prefix), len(suffix)); n > 0 {
			comparable++
			if bytes.Equal(prefix[:n], suffix[:n]) {
				equalRegions++
			}
		}
	}
	if len(prefixLengths) < 2 {
		t.Errorf("the middle padding took %d distinct lengths %v, want at least 2", len(prefixLengths), sortedLengths(prefixLengths))
	}
	if len(suffixLengths) < 2 {
		t.Errorf("the end padding took %d distinct lengths %v, want at least 2", len(suffixLengths), sortedLengths(suffixLengths))
	}
	if comparable > 0 && equalRegions == comparable {
		t.Errorf("the middle padding and the end padding are equal in all %d comparable messages; the two regions must be generated into different parts of the scratch buffer", comparable)
	}
}

// sortedLengths returns the keys of a set of padding lengths in ascending
// order, for a readable test failure message.
func sortedLengths(lengths map[int]struct{}) []int {
	result := make([]int, 0, len(lengths))
	for length := range lengths {
		result = append(result, length)
	}
	sort.Ints(result)
	return result
}
