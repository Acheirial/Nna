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
	"context"
	"net"
	"testing"
	"time"

	"github.com/enfein/mieru/v3/pkg/cipher"
	"github.com/enfein/mieru/v3/pkg/common"
)

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
	block, err := cipher.BlockCipherFromPassword(password, true)
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

	valid := testSessionSegment(openSessionRequest, 2, common.PacketTransport)
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

	block, err := cipher.BlockCipherFromPassword([]byte(t.Name()), true)
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
	if err := senderA.writeOneSegment(testSessionSegment(openSessionRequest, sessionID, common.PacketTransport), serverConn.LocalAddr()); err != nil {
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
	foreignBlock, err := cipher.BlockCipherFromPassword(credentialB, true)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() for user B failed: %v", err)
	}
	foreignBlock.SetBlockContext(cipher.BlockContext{UserName: userB})
	foreign := testDataSegment(sessionID, 0, []byte("payload of user B"), common.PacketTransport)
	foreign.block = foreignBlock
	if server.mayDeliverToSession(session, foreign) {
		t.Fatal("mayDeliverToSession() accepted a segment sealed by user B for the session of user A")
	}
	ownBlock, err := cipher.BlockCipherFromPassword(credentialA, true)
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
		if err := sender.writeOneSegment(testSessionSegment(openSessionRequest, sessionID, common.PacketTransport), serverConn.LocalAddr()); err != nil {
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
