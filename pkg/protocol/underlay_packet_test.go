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
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/enfein/mieru/v3/pkg/cipher"
	"github.com/enfein/mieru/v3/pkg/common"
)

// errTestPacketWriteTo is the error of the test connection that fails every
// write of the underlay that it serves.
var errTestPacketWriteTo = errors.New("test: packet WriteTo failed")

// writeFailPacketConn is a net.PacketConn whose writes fail while a test asks
// them to.
//
// The reads and the deadline calls are served by the wrapped connection, so the
// underlay of a test reads the real datagrams of its socket while the writes
// fail, and the writes that the test allows reach the peer.
type writeFailPacketConn struct {
	net.PacketConn

	// failing is read once per write, before the write is attempted, so a test
	// that stops the failures after it observed one doesn't race with the
	// decision of a write whose attempt it already saw.
	failing atomic.Bool

	// failedWrites counts the writes that failed.
	failedWrites atomic.Int64

	// failedWrite receives one value per failed write, so a test can wait for
	// one without polling. It is buffered, and a signal is dropped when the
	// buffer is full.
	failedWrite chan struct{}
}

func (c *writeFailPacketConn) WriteTo(b []byte, addr net.Addr) (int, error) {
	if c.failing.Load() {
		c.failedWrites.Add(1)
		select {
		case c.failedWrite <- struct{}{}:
		default:
		}
		return 0, errTestPacketWriteTo
	}
	return c.PacketConn.WriteTo(b, addr)
}

func TestPacketServerDropsInvalidControl(t *testing.T) {
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket() server failed: %v", err)
	}
	senderConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		serverConn.Close()
		t.Fatalf("net.ListenPacket() sender failed: %v", err)
	}
	defer senderConn.Close()

	userName := "user"
	password := cipher.HashPassword([]byte(t.Name()), []byte(userName))
	block, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, password, true)
	if err != nil {
		serverConn.Close()
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}
	block.SetBlockContext(cipher.BlockContext{UserName: userName})

	server := &PacketUnderlay{
		baseUnderlay:       *newBaseUnderlay(false, 1400, nil),
		conn:               serverConn,
		sessionCleanTicker: time.NewTicker(sessionCleanInterval),
		serverUsers:        testServerUserRegistry(userMap(makeTestUser(userName, password)), false),
	}
	sender := &PacketUnderlay{
		baseUnderlay: *newBaseUnderlay(true, 1400, nil),
		conn:         senderConn,
		serverAddr:   serverConn.LocalAddr(),
		block:        block.Clone(),
	}

	loopDone := make(chan error, 1)
	go func() {
		loopDone <- server.RunEventLoop(context.Background())
	}()
	defer func() {
		_ = server.Close()
		_ = serverConn.Close()
		select {
		case <-loopDone:
		case <-time.After(time.Second):
			t.Error("PacketUnderlay.RunEventLoop() didn't stop")
		}
	}()

	invalid := testSessionSegment(openSessionResponse, 1, common.PacketTransport)
	if err := sender.writeOneSegment(invalid, serverConn.LocalAddr()); err != nil {
		t.Fatalf("writeOneSegment(invalid control) failed: %v", err)
	}
	select {
	case err := <-loopDone:
		t.Fatalf("RunEventLoop() stopped after invalid control message: %v", err)
	case <-time.After(100 * time.Millisecond):
	}

	valid := testOpenSessionSegment(t, 2, common.PacketTransport)
	if err := sender.writeOneSegment(valid, serverConn.LocalAddr()); err != nil {
		t.Fatalf("writeOneSegment(valid control) failed: %v", err)
	}
	acceptDone := make(chan net.Conn, 1)
	go func() {
		conn, _ := server.Accept()
		acceptDone <- conn
	}()
	select {
	case conn := <-acceptDone:
		if conn == nil {
			t.Fatal("Accept() returned a nil connection")
		}
		if got := conn.(*Session).id; got != 2 {
			t.Fatalf("accepted session ID = %d, want 2", got)
		}
	case <-time.After(time.Second):
		t.Fatal("server didn't accept a valid session after invalid control message")
	}
}

func TestPacketClientClosesUnknownSession(t *testing.T) {
	clientConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket() client failed: %v", err)
	}
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		clientConn.Close()
		t.Fatalf("net.ListenPacket() server failed: %v", err)
	}
	defer serverConn.Close()

	block, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, []byte(t.Name()), true)
	if err != nil {
		clientConn.Close()
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}
	block.SetBlockContext(cipher.BlockContext{UserName: "user"})

	client := &PacketUnderlay{
		baseUnderlay:       *newBaseUnderlay(true, 1400, nil),
		conn:               clientConn,
		sessionCleanTicker: time.NewTicker(sessionCleanInterval),
		serverAddr:         serverConn.LocalAddr(),
		block:              block.Clone(),
	}
	sender := &PacketUnderlay{
		baseUnderlay: *newBaseUnderlay(true, 1400, nil),
		conn:         serverConn,
		serverAddr:   clientConn.LocalAddr(),
		block:        block.Clone(),
	}

	loopDone := make(chan error, 1)
	go func() {
		loopDone <- client.RunEventLoop(context.Background())
	}()
	defer func() {
		_ = client.Close()
		_ = clientConn.Close()
		select {
		case <-loopDone:
		case <-time.After(time.Second):
			t.Error("PacketUnderlay.RunEventLoop() didn't stop")
		}
	}()

	const sessionID = 42
	payload := []byte("data for a stale session")
	data := &segment{
		metadata: &dataAckStruct{
			baseStruct: baseStruct{protocol: uint8(dataServerToClient)},
			sessionID:  sessionID,
			seq:        10,
			unAckSeq:   7,
			windowSize: segmentTreeCapacity,
			payloadLen: uint16(len(payload)),
		},
		payload:   payload,
		transport: common.PacketTransport,
	}
	if err := sender.writeOneSegment(data, clientConn.LocalAddr()); err != nil {
		t.Fatalf("writeOneSegment(data) failed: %v", err)
	}

	wire := readPacketForTest(t, serverConn)
	if len(wire) < packetNonHeaderPosition {
		t.Fatalf("close request length = %d, want at least %d", len(wire), packetNonHeaderPosition)
	}
	decryptedMetadata, err := block.Decrypt(wire[:packetNonHeaderPosition])
	if err != nil {
		t.Fatalf("Decrypt(close request metadata) failed: %v", err)
	}
	closeMetadata := &sessionStruct{}
	if err := closeMetadata.Unmarshal(decryptedMetadata); err != nil {
		t.Fatalf("Unmarshal(close request metadata) failed: %v", err)
	}
	if closeMetadata.Protocol() != closeSessionRequest || closeMetadata.sessionID != sessionID {
		t.Fatalf("received metadata = %v, want closeSessionRequest for session %d", closeMetadata, sessionID)
	}
}

// TestPacketServerDropsSegmentOfAnotherUser verifies that a UDP data segment
// sealed with the credential of user B can't be injected into a session that
// belongs to user A, even when both users use the same session ID. Before the
// user identity check was added to the UDP dispatch path, such a segment was
// delivered to Session.input(), which panics on the cipher user name mismatch
// and takes down the process that runs the server.
func TestPacketServerDropsSegmentOfAnotherUser(t *testing.T) {
	const userA = "dispatch-user-a"
	const userB = "dispatch-user-b"
	credentialA := cipher.HashPassword([]byte(t.Name()), []byte(userA))
	credentialB := cipher.HashPassword([]byte(t.Name()), []byte(userB))

	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket() server failed: %v", err)
	}
	server := &PacketUnderlay{
		baseUnderlay:       *newBaseUnderlay(false, 1400, nil),
		conn:               serverConn,
		sessionCleanTicker: time.NewTicker(sessionCleanInterval),
		serverUsers:        testServerUserRegistry(userMap(makeTestUser(userA, credentialA), makeTestUser(userB, credentialB)), false),
	}
	senderA := newServerUserPacketSender(t, serverConn.LocalAddr(), credentialA, userA)
	defer func() { _ = senderA.conn.Close() }()
	senderB := newServerUserPacketSender(t, serverConn.LocalAddr(), credentialB, userB)
	defer func() { _ = senderB.conn.Close() }()

	loopDone := make(chan error, 1)
	go func() {
		loopDone <- server.RunEventLoop(context.Background())
	}()
	defer func() {
		_ = server.Close()
		_ = serverConn.Close()
		select {
		case <-loopDone:
		case <-time.After(5 * time.Second):
			t.Error("PacketUnderlay.RunEventLoop() didn't stop")
		}
	}()

	// User A opens a session.
	const sessionID = 11
	if err := senderA.writeOneSegment(testOpenSessionSegment(t, sessionID, common.PacketTransport), serverConn.LocalAddr()); err != nil {
		t.Fatalf("writeOneSegment(open session request) failed: %v", err)
	}
	acceptDone := make(chan net.Conn, 1)
	go func() {
		conn, _ := server.Accept()
		acceptDone <- conn
	}()
	var session *Session
	select {
	case conn := <-acceptDone:
		if conn == nil {
			t.Fatal("Accept() returned a nil connection")
		}
		session = conn.(*Session)
	case <-time.After(5 * time.Second):
		t.Fatal("server didn't accept the session of user A")
	}
	if got := session.id; got != sessionID {
		t.Fatalf("accepted session ID = %d, want %d", got, sessionID)
	}
	// Wait until the open session request is processed. An established session
	// owns user A and its receive state doesn't change anymore.
	establishDeadline := time.Now().Add(5 * time.Second)
	for !session.isState(sessionEstablished) {
		if time.Now().After(establishDeadline) {
			t.Fatal("session of user A is not established")
		}
		time.Sleep(time.Millisecond)
	}
	if got := sessionUserName(session); got != userA {
		t.Fatalf("session of user A is owned by user %q, want %q", got, userA)
	}

	// A segment sealed by user B is not deliverable to the session of user A,
	// while a segment sealed by user A is.
	foreignBlock, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, credentialB, true)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() for user B failed: %v", err)
	}
	foreignBlock.SetBlockContext(cipher.BlockContext{UserName: userB})
	foreign := testDataSegment(sessionID, 0, []byte("payload of user B"), common.PacketTransport)
	foreign.block = foreignBlock
	if server.mayDeliverToSession(session, foreign) {
		t.Fatal("mayDeliverToSession() accepted a segment sealed by user B for the session of user A")
	}
	ownBlock, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, credentialA, true)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() for user A failed: %v", err)
	}
	ownBlock.SetBlockContext(cipher.BlockContext{UserName: userA})
	own := testDataSegment(sessionID, 0, []byte("payload of user A"), common.PacketTransport)
	own.block = ownBlock
	if !server.mayDeliverToSession(session, own) {
		t.Fatal("mayDeliverToSession() rejected a segment sealed by user A for its own session")
	}

	// The user registry decrypts the segment of user B. The server answers a
	// session that is not registered with a close session request, which shows
	// that the segment of user B passes user discovery and reaches data
	// dispatch, so the only reason to reject the following segment is the user
	// identity check.
	const unknownSessionID = sessionID + 1000
	if err := senderB.writeOneSegment(testDataSegment(unknownSessionID, 0, []byte("probe of user B"), common.PacketTransport), serverConn.LocalAddr()); err != nil {
		t.Fatalf("writeOneSegment(probe of user B) failed: %v", err)
	}
	if err := senderB.conn.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() failed: %v", err)
	}
	probeReply := make([]byte, 1500)
	probeReplyLen, _, err := senderB.conn.ReadFrom(probeReply)
	if err != nil {
		t.Fatalf("ReadFrom() the probe reply failed: %v", err)
	}
	if probeReplyLen < packetNonHeaderPosition {
		t.Fatalf("probe reply length = %d, want at least %d", probeReplyLen, packetNonHeaderPosition)
	}
	decryptedProbeReply, err := senderB.block.Decrypt(probeReply[:packetNonHeaderPosition])
	if err != nil {
		t.Fatalf("Decrypt() the probe reply failed: %v", err)
	}
	probeReplyMetadata := &sessionStruct{}
	if err := probeReplyMetadata.Unmarshal(decryptedProbeReply); err != nil {
		t.Fatalf("Unmarshal() the probe reply failed: %v", err)
	}
	if probeReplyMetadata.Protocol() != closeSessionRequest || probeReplyMetadata.sessionID != unknownSessionID {
		t.Fatalf("probe reply = %v, want closeSessionRequest for session %d", probeReplyMetadata, unknownSessionID)
	}

	lastRXTime := session.lastRXTime.Load()
	nextRecv := session.nextRecv.Load()
	recvBufLen := session.recvBuf.Len()
	recvQueueLen := session.recvQueue.Len()
	serverInBytes := server.InBytes()

	// User B injects a data segment into the session of user A. The segment
	// carries the session ID of user A and the sequence number that the
	// session expects, so the identity of its user is the only reason to
	// reject it.
	if err := senderB.writeOneSegment(testDataSegment(sessionID, nextRecv, []byte("payload of user B"), common.PacketTransport), serverConn.LocalAddr()); err != nil {
		t.Fatalf("writeOneSegment(data of user B) failed: %v", err)
	}
	// The underlay counts every segment that it reads, so the counter shows
	// that the injected segment reached the server.
	readDeadline := time.Now().Add(5 * time.Second)
	for server.InBytes() <= serverInBytes {
		if time.Now().After(readDeadline) {
			t.Fatal("server didn't read the injected segment of user B")
		}
		time.Sleep(time.Millisecond)
	}

	if got := session.lastRXTime.Load(); got != lastRXTime {
		t.Errorf("session of user A received the injected segment: lastRXTime = %d, want %d", got, lastRXTime)
	}
	if got := session.nextRecv.Load(); got != nextRecv {
		t.Errorf("session of user A received the injected segment: nextRecv = %d, want %d", got, nextRecv)
	}
	if got := session.recvBuf.Len(); got != recvBufLen {
		t.Errorf("receive buffer length of session of user A = %d, want %d", got, recvBufLen)
	}
	if got := session.recvQueue.Len(); got != recvQueueLen {
		t.Errorf("receive queue length of session of user A = %d, want %d", got, recvQueueLen)
	}

	// The session of user A still receives the data of user A.
	ownPayload := []byte("payload of user A")
	if err := senderA.writeOneSegment(testDataSegment(sessionID, nextRecv, ownPayload, common.PacketTransport), serverConn.LocalAddr()); err != nil {
		t.Fatalf("writeOneSegment(data of user A) failed: %v", err)
	}
	if err := session.SetReadDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() failed: %v", err)
	}
	readBuf := make([]byte, 1500)
	readLen, err := session.Read(readBuf)
	if err != nil {
		t.Fatalf("Read() from the session of user A failed: %v", err)
	}
	if got := string(readBuf[:readLen]); got != string(ownPayload) {
		t.Fatalf("session of user A read %q, want %q", got, string(ownPayload))
	}
}

// TestPacketServerCleanSessions verifies that the server session cleanup
// removes the sessions that didn't receive any segment within
// idleSessionTimeout, and keeps the sessions that received a segment shortly
// before the idle timeout.
func TestPacketServerCleanSessions(t *testing.T) {
	const userName = "dispatch-idle-user"
	credential := cipher.HashPassword([]byte(t.Name()), []byte(userName))

	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket() server failed: %v", err)
	}
	server := &PacketUnderlay{
		baseUnderlay:       *newBaseUnderlay(false, 1400, nil),
		conn:               serverConn,
		sessionCleanTicker: time.NewTicker(sessionCleanInterval),
		serverUsers:        testServerUserRegistry(userMap(makeTestUser(userName, credential)), false),
	}
	sender := newServerUserPacketSender(t, serverConn.LocalAddr(), credential, userName)
	defer func() { _ = sender.conn.Close() }()

	loopDone := make(chan error, 1)
	go func() {
		loopDone <- server.RunEventLoop(context.Background())
	}()
	defer func() {
		_ = server.Close()
		_ = serverConn.Close()
		select {
		case <-loopDone:
		case <-time.After(5 * time.Second):
			t.Error("PacketUnderlay.RunEventLoop() didn't stop")
		}
	}()

	// A session receives its open session request on creation, so its last
	// receive time is the creation time.
	for _, sessionID := range []uint32{21, 22, 23} {
		if err := sender.writeOneSegment(testOpenSessionSegment(t, sessionID, common.PacketTransport), serverConn.LocalAddr()); err != nil {
			t.Fatalf("writeOneSegment(open session request %d) failed: %v", sessionID, err)
		}
	}
	loadSession := func(id uint32) *Session {
		v, ok := server.sessionMap.Load(id)
		if !ok {
			t.Fatalf("session %d is not registered to the server", id)
		}
		return v.(*Session)
	}
	// Wait until the open session requests are processed. An established
	// session doesn't receive anything else, so its last receive time stays
	// where the test sets it below.
	establishDeadline := time.Now().Add(5 * time.Second)
	for _, sessionID := range []uint32{21, 22, 23} {
		for {
			v, ok := server.sessionMap.Load(sessionID)
			if ok && v.(*Session).isState(sessionEstablished) {
				break
			}
			if time.Now().After(establishDeadline) {
				t.Fatalf("session %d is not established, session count is %d", sessionID, server.SessionCount())
			}
			time.Sleep(time.Millisecond)
		}
	}
	recent := loadSession(21)
	almostIdle := loadSession(22)
	idle := loadSession(23)

	// Move the last receive time of the sessions into the past, instead of
	// waiting for one minute. Session 22 is still short of the idle timeout by
	// ten seconds, so the cleanup must keep it.
	now := time.Now()
	almostIdle.lastRXTime.Store(now.Add(-(idleSessionTimeout - 10*time.Second)).UnixMicro())
	idle.lastRXTime.Store(now.Add(-2 * idleSessionTimeout).UnixMicro())

	server.cleanSessions()

	if got := server.SessionCount(); got != 2 {
		t.Errorf("server session count = %d, want 2", got)
	}
	if _, ok := server.sessionMap.Load(uint32(23)); ok {
		t.Error("idle session 23 is still registered")
	}
	select {
	case <-idle.closedChan:
	default:
		t.Error("idle session 23 is not closed")
	}
	for _, session := range []*Session{recent, almostIdle} {
		if _, ok := server.sessionMap.Load(session.id); !ok {
			t.Errorf("session %d is removed, want it to be kept", session.id)
		}
		select {
		case <-session.closedChan:
			t.Errorf("session %d is closed, want it to be kept", session.id)
		default:
		}
	}
	if got := time.Now().UnixMicro() - recent.lastRXTime.Load(); got > idleSessionTimeout.Microseconds() {
		t.Errorf("session 21 received data %v ago, want less than %v", time.Duration(got)*time.Microsecond, idleSessionTimeout)
	}
}

// TestPacketUnderlayReusesDatagramBuffers verifies that the reusable datagram
// buffers of the underlay carry the full content of every datagram. A datagram
// that reuses a buffer must not leak the bytes of the previous one, whatever
// the size of both datagrams is.
func TestPacketUnderlayReusesDatagramBuffers(t *testing.T) {
	credential := cipher.HashPassword([]byte(t.Name()), []byte("user"))
	receiverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket() receiver failed: %v", err)
	}
	defer receiverConn.Close()
	sender := newServerUserPacketSender(t, receiverConn.LocalAddr(), credential, "user")
	defer sender.conn.Close()
	block, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, credential, true)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}
	receiver := &PacketUnderlay{
		baseUnderlay: *newBaseUnderlay(true, 1400, nil),
		conn:         receiverConn,
		serverAddr:   sender.conn.LocalAddr(),
		block:        block,
	}

	// The sizes must go up and down, so that a buffer that was grown for a
	// large datagram is reused by a small one and the other way round.
	for i, size := range []int{500, 1, 400} {
		payload := make([]byte, size)
		for j := range payload {
			payload[j] = byte(i*31 + j)
		}
		seg := &segment{
			metadata: &dataAckStruct{
				baseStruct: baseStruct{protocol: uint8(dataServerToClient)},
				sessionID:  7,
				seq:        uint32(i),
				windowSize: segmentTreeCapacity,
				payloadLen: uint16(len(payload)),
			},
			payload: payload,
		}
		if err := sender.writeOneSegment(seg, receiverConn.LocalAddr()); err != nil {
			t.Fatalf("message %d: writeOneSegment() failed: %v", i, err)
		}
		received, addr, err := receiver.readOneSegment()
		if err != nil {
			t.Fatalf("message %d: readOneSegment() failed: %v", i, err)
		}
		if addr.String() != sender.conn.LocalAddr().String() {
			t.Errorf("message %d: sender address = %v, want %v", i, addr, sender.conn.LocalAddr())
		}
		if received.Protocol() != dataServerToClient {
			t.Errorf("message %d: received protocol = %v, want %v", i, received.Protocol(), dataServerToClient)
		}
		if !bytes.Equal(received.payload, payload) {
			t.Errorf("message %d: received %d payload bytes %v, want %v", i, len(received.payload), received.payload, payload)
		}
		if got := received.metadata.(*dataAckStruct).payloadLen; got != uint16(len(payload)) {
			t.Errorf("message %d: received payload length = %d, want %d", i, got, len(payload))
		}
	}
	if sender.OutBytes() != receiver.InBytes() {
		t.Errorf("packet wire byte counts = sent %d, received %d", sender.OutBytes(), receiver.InBytes())
	}
}

// indexedTestSession is a session that is attached to an underlay, with the
// encrypted metadata that only its cipher can decrypt.
type indexedTestSession struct {
	session   *Session
	addr      net.Addr
	encrypted []byte
}

// newIndexedTestSession creates a server session of an address, with a cipher
// that the returned ciphertext is encrypted with.
func newIndexedTestSession(t *testing.T, id uint32, credential []byte, addr net.Addr) indexedTestSession {
	t.Helper()
	block, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, credential, true)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}
	session := NewSession(id, false, 1400, nil, nil)
	session.block.Store(&block)
	encrypted := make([]byte, MetadataLength+block.NonceSize()+block.Overhead())
	if err := block.Encrypt(encrypted[:0], make([]byte, MetadataLength)); err != nil {
		t.Fatalf("Encrypt() failed: %v", err)
	}
	return indexedTestSession{session: session, addr: addr, encrypted: encrypted}
}

// TestPacketUnderlaySessionAddrIndex verifies that the address index of an
// underlay follows the sessions that are added and removed, that one address
// can own several sessions, and that the lookup of an existing session uses
// the index.
func TestPacketUnderlaySessionAddrIndex(t *testing.T) {
	// Every session of the test owns a key of its own, so a ciphertext only
	// decrypts with the session that the test encrypted it with.
	credentialA1 := cipher.HashPassword([]byte(t.Name()), []byte("index-user-a1"))
	credentialA2 := cipher.HashPassword([]byte(t.Name()), []byte("index-user-a2"))
	credentialB := cipher.HashPassword([]byte(t.Name()), []byte("index-user-b"))
	credentialStream := cipher.HashPassword([]byte(t.Name()), []byte("index-user-stream"))

	addrA := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 10), Port: 41000}
	addrB := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 11), Port: 41001}
	addrUnknown := &net.UDPAddr{IP: net.IPv4(192, 0, 2, 99), Port: 41999}

	underlay := &PacketUnderlay{baseUnderlay: *newBaseUnderlay(false, 1400, nil)}
	a1 := newIndexedTestSession(t, 1, credentialA1, addrA)
	a2 := newIndexedTestSession(t, 2, credentialA2, addrA)
	b := newIndexedTestSession(t, 3, credentialB, addrB)
	for _, attached := range []indexedTestSession{a1, a2, b} {
		if err := underlay.baseUnderlay.AddSession(attached.session, attached.addr); err != nil {
			t.Fatalf("AddSession(%d) failed: %v", attached.session.id, err)
		}
		attached.session.forwardStateTo(sessionAttached)
	}

	// One address owns two sessions, and the lookup of a packet of that
	// address finds the session that its cipher belongs to.
	sessions, complete := underlay.sessionsByRemoteAddr(addrA)
	if !complete {
		t.Fatal("sessionsByRemoteAddr() reported an incomplete index for a UDP address")
	}
	if len(sessions) != 2 {
		t.Fatalf("sessions of %v = %d, want 2", addrA, len(sessions))
	}
	decryptedMeta, blockCipher, _, decrypted := underlay.tryDecryptExistingSession(a2.encrypted, addrA)
	if !decrypted {
		t.Fatal("tryDecryptExistingSession() didn't decrypt with the session of the address")
	}
	if len(decryptedMeta) != MetadataLength {
		t.Errorf("decrypted metadata length = %d, want %d", len(decryptedMeta), MetadataLength)
	}
	if blockCipher == nil {
		t.Error("tryDecryptExistingSession() reported a successful decryption without a cipher")
	}

	// A packet of an address that owns no session tries no cipher, and the
	// index still answers the lookup completely.
	sessions, complete = underlay.sessionsByRemoteAddr(addrUnknown)
	if !complete || len(sessions) != 0 {
		t.Errorf("sessions of %v = %d (complete %v), want 0 and a complete index", addrUnknown, len(sessions), complete)
	}
	if _, _, _, decrypted := underlay.tryDecryptExistingSession(a2.encrypted, addrUnknown); decrypted {
		t.Error("a packet of an address without a session decrypted with the cipher of another address")
	}

	// A detached session leaves the index, and its packet is not decrypted
	// anymore.
	if err := underlay.baseUnderlay.detachSession(a1.session); err != nil {
		t.Fatalf("detachSession() failed: %v", err)
	}
	if got := underlay.sessionCount.Load(); got != 2 {
		t.Errorf("session count after detachSession() = %d, want 2", got)
	}
	sessions, complete = underlay.sessionsByRemoteAddr(addrA)
	if !complete || len(sessions) != 1 || sessions[0] != a2.session {
		t.Errorf("sessions of %v after the removal of session 1 = %v, want the session 2 only", addrA, sessions)
	}
	if _, _, _, decrypted := underlay.tryDecryptExistingSession(a1.encrypted, addrA); decrypted {
		t.Error("the removed session still decrypts a packet of its address")
	}

	// RemoveSession() removes the session through the same path.
	if err := underlay.RemoveSession(a2.session); err != nil {
		t.Fatalf("RemoveSession() failed: %v", err)
	}
	if sessions, complete := underlay.sessionsByRemoteAddr(addrA); !complete || len(sessions) != 0 {
		t.Errorf("sessions of %v after RemoveSession() = %v (complete %v), want none", addrA, sessions, complete)
	}
	if got := underlay.sessionCount.Load(); got != 1 {
		t.Errorf("session count after RemoveSession() = %d, want 1", got)
	}

	// A session whose address the index can't describe, which is the case for
	// a byte stream transport, makes the index incomplete, so the lookup falls
	// back to the scan of the whole session registry.
	stream := newIndexedTestSession(t, 4, credentialStream, &net.TCPAddr{IP: net.IPv4(198, 51, 100, 9), Port: 51000})
	if err := underlay.baseUnderlay.AddSession(stream.session, stream.addr); err != nil {
		t.Fatalf("AddSession(%d) failed: %v", stream.session.id, err)
	}
	stream.session.forwardStateTo(sessionAttached)
	if _, complete := underlay.sessionsByRemoteAddr(addrB); complete {
		t.Error("sessionsByRemoteAddr() reported a complete index while an unindexable session is attached")
	}
	if _, _, _, decrypted := underlay.tryDecryptExistingSession(stream.encrypted, stream.addr); !decrypted {
		t.Error("the fallback scan of the session registry didn't find the session of a non-UDP address")
	}
	if _, _, _, decrypted := underlay.tryDecryptExistingSession(b.encrypted, addrB); !decrypted {
		t.Error("the fallback scan of the session registry didn't find the session of an indexed address")
	}
	if _, _, _, decrypted := underlay.tryDecryptExistingSession(a1.encrypted, addrA); decrypted {
		t.Error("the fallback scan decrypted a packet with the cipher of a removed session")
	}
}

// TestUnderlaySessionLimit verifies that an underlay rejects the session that
// would push its registry over maxSessionsPerUnderlay, and that the rejection
// doesn't consume or leak a slot.
func TestUnderlaySessionLimit(t *testing.T) {
	underlay := newBaseUnderlay(false, 1400, nil)
	addr := &net.UDPAddr{IP: net.IPv4(203, 0, 113, 5), Port: 40000}

	// The counter of the registry follows the sessions that are added and
	// removed.
	const attachedSessions = 4
	sessions := make([]*Session, 0, attachedSessions)
	for i := 1; i <= attachedSessions; i++ {
		session := &Session{id: uint32(i)}
		if err := underlay.AddSession(session, addr); err != nil {
			t.Fatalf("AddSession(%d) failed: %v", i, err)
		}
		sessions = append(sessions, session)
	}
	if got := underlay.sessionCount.Load(); got != attachedSessions {
		t.Fatalf("session count = %d, want %d", got, attachedSessions)
	}
	first := sessions[0]
	first.forwardStateTo(sessionAttached)
	if err := underlay.detachSession(first); err != nil {
		t.Fatalf("detachSession() failed: %v", err)
	}
	if got := underlay.sessionCount.Load(); got != attachedSessions-1 {
		t.Fatalf("session count after the removal of a session = %d, want %d", got, attachedSessions-1)
	}

	// The registry is reported as full. A test can't attach
	// maxSessionsPerUnderlay real sessions, so it moves the counter to the
	// limit instead: the limit is a property of the counter that AddSession()
	// keeps exact, and the check above shows that the counter is exact.
	underlay.sessionCount.Store(maxSessionsPerUnderlay)
	rejected := &Session{id: uint32(maxSessionsPerUnderlay + 1)}
	if err := underlay.AddSession(rejected, addr); err == nil {
		t.Fatal("AddSession() accepted a session above the limit")
	}
	if _, ok := underlay.sessionMap.Load(rejected.id); ok {
		t.Error("the rejected session is registered to the underlay")
	}
	// The rejected session didn't consume a slot: the counter is still exactly
	// at the limit, and a registry that is one slot below the limit accepts a
	// session again.
	if got := underlay.sessionCount.Load(); got != maxSessionsPerUnderlay {
		t.Errorf("session count after a rejected session = %d, want %d", got, maxSessionsPerUnderlay)
	}
	underlay.sessionCount.Store(maxSessionsPerUnderlay - 1)
	accepted := &Session{id: uint32(maxSessionsPerUnderlay + 2)}
	if err := underlay.AddSession(accepted, addr); err != nil {
		t.Fatalf("AddSession() rejected a session below the limit: %v", err)
	}
	if got := underlay.sessionCount.Load(); got != maxSessionsPerUnderlay {
		t.Errorf("session count after the slot was used = %d, want %d", got, maxSessionsPerUnderlay)
	}
}

// TestPacketUnderlayReadySessionHandoverTimeout verifies that the handover of
// a new session to the accept queue of the underlay doesn't block the event
// loop when the application doesn't consume the queue.
func TestPacketUnderlayReadySessionHandoverTimeout(t *testing.T) {
	underlay := &PacketUnderlay{baseUnderlay: *newBaseUnderlay(false, 1400, nil)}
	underlay.readySessionTimeoutOverride = 10 * time.Millisecond
	for range sessionChanCapacity {
		// The accept queue is full, so the handover below can't complete. The
		// content of the queue doesn't matter, the underlay never reads it in
		// this test.
		underlay.readySessions <- &Session{}
	}

	timeout := underlay.readySessionTimeoutOverride
	session := NewSession(1000, false, 1400, nil, nil)
	start := time.Now()
	err := underlay.enqueueReadySession(session)
	elapsed := time.Since(start)
	if err == nil {
		t.Fatal("enqueueReadySession() accepted a session while the accept queue was full")
	}
	if elapsed < timeout {
		t.Errorf("enqueueReadySession() returned after %v, want at least %v", elapsed, timeout)
	}
	if elapsed > time.Second {
		t.Errorf("enqueueReadySession() waited %v for the accept queue", elapsed)
	}
	select {
	case <-session.closedChan:
	default:
		t.Error("the session that timed out is not closed")
	}

	// A closed underlay reports a closed pipe to the caller without waiting for
	// the timeout.
	closedUnderlay := &PacketUnderlay{baseUnderlay: *newBaseUnderlay(false, 1400, nil)}
	closedUnderlay.readySessionTimeoutOverride = time.Hour
	for range sessionChanCapacity {
		closedUnderlay.readySessions <- &Session{}
	}
	if err := closedUnderlay.baseUnderlay.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	start = time.Now()
	err = closedUnderlay.enqueueReadySession(NewSession(1001, false, 1400, nil, nil))
	if !errors.Is(err, io.ErrClosedPipe) {
		t.Errorf("enqueueReadySession() error = %v, want %v", err, io.ErrClosedPipe)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("enqueueReadySession() waited %v for a closed underlay", elapsed)
	}
}

// TestPacketUnderlayCleanSessionsRemovesInBackground verifies that the cleanup
// of the event loop detaches a session and marks it closed, and that the
// blocking part of the removal runs in the reaper goroutine.
func TestPacketUnderlayCleanSessionsRemovesInBackground(t *testing.T) {
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket() failed: %v", err)
	}
	defer serverConn.Close()
	underlay := &PacketUnderlay{
		baseUnderlay:       *newBaseUnderlay(false, 1400, nil),
		conn:               serverConn,
		sessionCleanTicker: time.NewTicker(sessionCleanInterval),
	}

	addr := &net.UDPAddr{IP: net.IPv4(198, 51, 100, 11), Port: 52000}
	session := NewSession(11, false, 1400, nil, nil)
	if err := underlay.baseUnderlay.AddSession(session, addr); err != nil {
		t.Fatalf("AddSession() failed: %v", err)
	}
	session.forwardStateTo(sessionAttached)
	session.lastRXTime.Store(time.Now().Add(-2 * idleSessionTimeout).UnixMicro())

	// A goroutine of the session is still running, and it doesn't stop before
	// the test releases it.
	release := make(chan struct{})
	session.wg.Add(1)
	go func() {
		defer session.wg.Done()
		<-release
	}()

	start := time.Now()
	underlay.cleanSessions()
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Errorf("cleanSessions() waited %v for the teardown of a session", elapsed)
	}

	// The session is out of the registry and out of the index, and it is
	// marked closed, as soon as the cleanup returns.
	if _, ok := underlay.sessionMap.Load(uint32(11)); ok {
		t.Error("the idle session is still registered after cleanSessions()")
	}
	if sessions, _ := underlay.sessionsByRemoteAddr(addr); len(sessions) != 0 {
		t.Errorf("the idle session is still indexed after cleanSessions(): %d sessions", len(sessions))
	}
	if got := underlay.sessionCount.Load(); got != 0 {
		t.Errorf("session count after cleanSessions() = %d, want 0", got)
	}
	select {
	case <-session.closedChan:
	default:
		t.Error("the idle session is not closed after cleanSessions()")
	}

	// The reaper is a single goroutine, and it is busy with the teardown of
	// the detached session, so a session that is handed over later waits in
	// the queue.
	queue, _ := underlay.sessionReaper()
	extra := NewSession(12, false, 1400, nil, nil)
	underlay.reapSession(extra)
	pickupDeadline := time.Now().Add(5 * time.Second)
	for len(queue) > 1 {
		if time.Now().After(pickupDeadline) {
			t.Fatal("the reaper didn't pick up the detached session")
		}
		time.Sleep(time.Millisecond)
	}
	// The queue can only hold the session that was handed over last: the
	// removal of the first session waits for the goroutine that the test
	// releases below, so the reaper can't have removed the second one yet.
	if got := len(queue); got != 1 {
		t.Errorf("reaper queue length = %d, want 1: the reaper didn't wait for the teardown of the first session", got)
	}
	close(release)
	// The reaper removes the session that the test handed over last once the
	// goroutine of the first session stopped, which is visible through the
	// closed channel of that session.
	select {
	case <-extra.closedChan:
	case <-time.After(5 * time.Second):
		t.Fatal("the reaper didn't remove the sessions of its queue")
	}

	// Close() stops the reaper and waits for it, so no session goroutine of
	// the underlay is left behind.
	_, reaperDone := underlay.sessionReaper()
	if err := underlay.Close(); err != nil {
		t.Errorf("Close() failed: %v", err)
	}
	select {
	case <-reaperDone:
	case <-time.After(time.Second):
		t.Error("the session reaper didn't stop after Close()")
	}
}

// TestPacketEventLoopSurvivesWriteFailure verifies that a datagram whose answer
// can't be written doesn't end the read loop of a packet underlay: the failure
// belongs to the peer that sent the datagram, so the endpoint has to keep
// serving every other peer instead of making the mux rebuild its listener.
func TestPacketEventLoopSurvivesWriteFailure(t *testing.T) {
	const userName = "write-failure-user"
	credential := cipher.HashPassword([]byte(t.Name()), []byte(userName))

	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket() server failed: %v", err)
	}
	failingConn := &writeFailPacketConn{PacketConn: serverConn, failedWrite: make(chan struct{}, 4)}
	failingConn.failing.Store(true)
	server := &PacketUnderlay{
		baseUnderlay:       *newBaseUnderlay(false, 1400, nil),
		conn:               failingConn,
		sessionCleanTicker: time.NewTicker(sessionCleanInterval),
		serverUsers:        testServerUserRegistry(userMap(makeTestUser(userName, credential)), false),
	}
	sender := newServerUserPacketSender(t, serverConn.LocalAddr(), credential, userName)
	defer func() { _ = sender.conn.Close() }()

	loopDone := make(chan error, 1)
	go func() {
		loopDone <- server.RunEventLoop(context.Background())
	}()
	defer func() {
		_ = server.Close()
		_ = serverConn.Close()
		select {
		case <-loopDone:
		case <-time.After(5 * time.Second):
			t.Error("PacketUnderlay.RunEventLoop() didn't stop")
		}
	}()

	// A data segment of a session that this server doesn't serve makes the
	// event loop answer its peer with a close session request, and that answer
	// is the write that fails. The loop has to keep reading the socket after
	// the failure, so a second such segment is answered as well while every
	// write still fails.
	probes := []struct {
		sessionID uint32
		payload   string
	}{
		{sessionID: 91, payload: "probe of an unknown session"},
		{sessionID: 93, payload: "probe of another unknown session"},
	}
	for i, probe := range probes {
		if err := sender.writeOneSegment(testDataSegment(probe.sessionID, uint32(i), []byte(probe.payload), common.PacketTransport), serverConn.LocalAddr()); err != nil {
			t.Fatalf("writeOneSegment(probe %d) failed: %v", i, err)
		}
		select {
		case <-failingConn.failedWrite:
		case <-time.After(5 * time.Second):
			t.Fatalf("the event loop didn't answer the segment of unknown session %d", probe.sessionID)
		}
		select {
		case err := <-loopDone:
			t.Fatalf("RunEventLoop() returned after a datagram level write failure: %v", err)
		default:
		}
	}
	if got := failingConn.failedWrites.Load(); got != int64(len(probes)) {
		t.Errorf("failed writes = %d, want %d: the event loop didn't answer every unknown session", got, len(probes))
	}

	// The failures stop, so that the loop can answer the open session request
	// below and the test can see that it still serves its socket.
	failingConn.failing.Store(false)

	const sessionID = 92
	if err := sender.writeOneSegment(testOpenSessionSegment(t, sessionID, common.PacketTransport), serverConn.LocalAddr()); err != nil {
		t.Fatalf("writeOneSegment(open session request) failed: %v", err)
	}
	acceptDone := make(chan net.Conn, 1)
	go func() {
		conn, _ := server.Accept()
		acceptDone <- conn
	}()
	select {
	case conn := <-acceptDone:
		if conn == nil {
			t.Fatal("Accept() returned a nil connection")
		}
		if got := conn.(*Session).id; got != sessionID {
			t.Fatalf("accepted session ID = %d, want %d", got, sessionID)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the event loop didn't serve a datagram after the write of a datagram failed")
	}
}

// concurrentTestPayload builds the payload of one datagram of the concurrent
// assembly test. The payload carries the session and the sequence number of its
// datagram, and the value of every byte depends on its own position, so a
// buffer that mixed the bytes of two assemblies is visible in a comparison.
func concurrentTestPayload(sessionID uint32, seq, size int) []byte {
	payload := make([]byte, size)
	payload[0] = byte(sessionID)
	payload[1] = byte(seq)
	for j := 2; j < size; j++ {
		payload[j] = byte((sessionID*17 + uint32(seq)*31 + uint32(j)) % 251)
	}
	return payload
}

// concurrentTestPayloadSize returns the size of the payload of one datagram of
// the concurrent assembly test. The sizes differ per datagram, so a datagram
// that carries the payload of another one is visible even in its length.
func concurrentTestPayloadSize(seq int) int {
	return 600 + (seq*53)%500
}

// TestPacketUnderlayConcurrentDatagramAssembly verifies that two sessions that
// assemble and encrypt their datagrams at the same time produce the bytes of
// their own datagram. The send path of the underlay shares the pool of the
// datagram buffers and the cipher of the underlay, but not the content of a
// datagram.
func TestPacketUnderlayConcurrentDatagramAssembly(t *testing.T) {
	const (
		userName  = "concurrent-assembly-user"
		datagrams = 40
	)
	senderConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket() sender failed: %v", err)
	}
	defer senderConn.Close()
	receiverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket() receiver failed: %v", err)
	}
	defer receiverConn.Close()

	newBlock := func() cipher.BlockCipher {
		t.Helper()
		block, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, []byte(t.Name()), true)
		if err != nil {
			t.Fatalf("BlockCipherFromPassword() failed: %v", err)
		}
		block.SetBlockContext(cipher.BlockContext{UserName: userName})
		return block
	}
	// The two senders share one cipher, which is what a client underlay uses
	// before the handshake of a session installs the session key.
	sender := &PacketUnderlay{baseUnderlay: *newBaseUnderlay(false, 1400, nil), conn: senderConn}
	decode := newBlock()
	receiver := &PacketUnderlay{baseUnderlay: *newBaseUnderlay(true, 1400, nil)}

	sendBlock := newBlock()
	var senders sync.WaitGroup
	sendErr := make(chan error, 2)
	for id := uint32(1); id <= 2; id++ {
		senders.Add(1)
		go func(sessionID uint32) {
			defer senders.Done()
			for seq := 0; seq < datagrams; seq++ {
				payload := concurrentTestPayload(sessionID, seq, concurrentTestPayloadSize(seq))
				seg := &segment{
					metadata: &dataAckStruct{
						baseStruct: baseStruct{protocol: uint8(dataClientToServer)},
						sessionID:  sessionID,
						seq:        uint32(seq),
						windowSize: segmentTreeCapacity,
						payloadLen: uint16(len(payload)),
					},
					payload:   payload,
					transport: common.PacketTransport,
					block:     sendBlock,
				}
				if err := sender.writeOneSegment(seg, receiverConn.LocalAddr()); err != nil {
					sendErr <- fmt.Errorf("session %d datagram %d: %w", sessionID, seq, err)
					return
				}
			}
		}(id)
	}

	// Every datagram carries the identity of its own session and of its own
	// sequence number, and the framing of a datagram is validated against its
	// metadata, so the reader sees a datagram that lost or mixed bytes.
	received := map[uint32]map[int]bool{1: {}, 2: {}}
	readBuf := make([]byte, 2048)
	for i := 0; i < 2*datagrams; i++ {
		if err := receiverConn.SetReadDeadline(time.Now().Add(10 * time.Second)); err != nil {
			t.Fatalf("SetReadDeadline() failed: %v", err)
		}
		n, addr, err := receiverConn.ReadFrom(readBuf)
		if err != nil {
			t.Fatalf("ReadFrom() datagram %d failed: %v", i, err)
		}
		if addr.String() != senderConn.LocalAddr().String() {
			t.Fatalf("datagram %d came from %v, want %v", i, addr, senderConn.LocalAddr())
		}
		wire := readBuf[:n]
		if len(wire) < packetNonHeaderPosition {
			t.Fatalf("datagram %d has %d bytes, want at least %d", i, len(wire), packetNonHeaderPosition)
		}
		decryptedMeta, err := decode.Decrypt(wire[:packetNonHeaderPosition])
		if err != nil {
			t.Fatalf("datagram %d: Decrypt(metadata) failed: %v", i, err)
		}
		das := &dataAckStruct{}
		if err := das.Unmarshal(decryptedMeta); err != nil {
			t.Fatalf("datagram %d: Unmarshal(metadata) failed: %v", i, err)
		}
		seg, err := receiver.parseDataAckSegment(das, wire[:cipher.DefaultNonceSize], wire[packetNonHeaderPosition:], decode)
		if err != nil {
			t.Fatalf("datagram %d: parseDataAckSegment() failed: %v", i, err)
		}
		sessionID := das.sessionID
		if len(seg.payload) < 2 {
			t.Errorf("datagram %d of session %d carries %d payload bytes, want the sequence number of its sender", i, sessionID, len(seg.payload))
			continue
		}
		seq := int(seg.payload[1])
		if got := concurrentTestPayloadSize(seq); len(seg.payload) != got {
			t.Errorf("datagram %d of session %d carries %d payload bytes, want %d", i, sessionID, len(seg.payload), got)
			continue
		}
		if want := concurrentTestPayload(sessionID, seq, len(seg.payload)); !bytes.Equal(seg.payload, want) {
			t.Errorf("datagram %d of session %d carries the payload of another assembly", i, sessionID)
			continue
		}
		if received[sessionID] == nil {
			received[sessionID] = map[int]bool{}
		}
		if received[sessionID][seq] {
			t.Errorf("session %d received the datagram of sequence number %d twice", sessionID, seq)
			continue
		}
		received[sessionID][seq] = true
	}
	for _, sessionID := range []uint32{1, 2} {
		if got := len(received[sessionID]); got != datagrams {
			t.Errorf("session %d received %d datagrams, want %d", sessionID, got, datagrams)
		}
	}
	senders.Wait()
	select {
	case err := <-sendErr:
		t.Errorf("writeOneSegment() failed: %v", err)
	default:
	}
}

// TestPacketUnderlayReturnsDatagramBuffers verifies that the send path returns
// the buffer of every datagram to the pool of the underlay: a run of datagrams
// of different sizes reuses one buffer instead of allocating one per datagram.
func TestPacketUnderlayReturnsDatagramBuffers(t *testing.T) {
	const sends = 200
	credential := cipher.HashPassword([]byte(t.Name()), []byte("user"))
	receiverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket() receiver failed: %v", err)
	}
	defer receiverConn.Close()
	sender := newServerUserPacketSender(t, receiverConn.LocalAddr(), credential, "user")
	defer func() { _ = sender.conn.Close() }()

	// The pool counts the buffers that it has to allocate, which makes the
	// return of a buffer observable: the send path of a datagram takes one
	// buffer from the pool for the whole of its assembly, and a datagram whose
	// buffer is not returned makes the next datagram allocate a new one.
	var allocated atomic.Int64
	sender.sendBufPool = sync.Pool{New: func() any {
		allocated.Add(1)
		return &packetSendBuf{}
	}}

	for i := 0; i < sends; i++ {
		// The sizes go up and down, so a buffer that was grown for a large
		// datagram is reused by a small one and the other way round.
		payload := make([]byte, 100+(i*97)%1000)
		for j := range payload {
			payload[j] = byte(i + j)
		}
		// The two assembly paths of a packet underlay are exercised: a session
		// segment and a data or ack segment.
		var seg *segment
		if i%2 == 0 {
			seg = &segment{
				metadata: &sessionStruct{
					baseStruct: baseStruct{protocol: uint8(openSessionRequest)},
					sessionID:  5,
					payloadLen: uint16(len(payload)),
				},
				payload:   payload,
				transport: common.PacketTransport,
			}
		} else {
			seg = &segment{
				metadata: &dataAckStruct{
					baseStruct: baseStruct{protocol: uint8(dataServerToClient)},
					sessionID:  5,
					seq:        uint32(i),
					windowSize: segmentTreeCapacity,
					payloadLen: uint16(len(payload)),
				},
				payload:   payload,
				transport: common.PacketTransport,
			}
		}
		if err := sender.writeOneSegment(seg, receiverConn.LocalAddr()); err != nil {
			t.Fatalf("writeOneSegment(%d) failed: %v", i, err)
		}
		// Reading the datagram keeps the receive buffer of the socket from
		// filling up, and it shows that every datagram of the run is a
		// complete datagram.
		wire := readPacketForTest(t, receiverConn)
		if len(wire) < packetNonHeaderPosition {
			t.Fatalf("datagram %d has %d bytes, want at least %d", i, len(wire), packetNonHeaderPosition)
		}
	}
	// A send path that doesn't return the buffer of a datagram allocates one
	// per datagram, which is far above this bound. The bound is not exactly one
	// because the garbage collector can drop the buffer that the pool holds,
	// which is not part of the contract of the send path.
	if got := allocated.Load(); got > sends/4 {
		t.Errorf("the underlay allocated %d datagram buffers for %d datagrams: the send path didn't return the buffer of a datagram", got, sends)
	}
}
