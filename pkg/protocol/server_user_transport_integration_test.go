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
	"errors"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/enfein/mieru/v3/pkg/cipher"
	"github.com/enfein/mieru/v3/pkg/common"
	"github.com/enfein/mieru/v3/pkg/protocol/serveruser"
	"github.com/enfein/mieru/v3/pkg/stderror"
)

type serverUserTestRemoteConn struct {
	net.Conn
	remoteAddr net.Addr
}

func (c *serverUserTestRemoteConn) RemoteAddr() net.Addr {
	return c.remoteAddr
}

func TestStreamServerSourceUserCacheIntegration(t *testing.T) {
	const userName = "stream-cache-user"
	credential := cipher.HashPassword([]byte(t.Name()), []byte(userName))
	mux := NewMux(false).SetServerUsers(userMap(makeTestUser(userName, credential)))
	t.Cleanup(func() { _ = mux.Close() })

	firstAddr := &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 12001}
	firstWire := buildServerUserStreamWire(t, credential, userName, testSessionSegment(openSessionRequest, 1, common.StreamTransport), nil, nil)
	firstUnderlay, firstSegment, err := readServerUserStreamWire(t, mux, firstAddr, firstWire)
	if err != nil {
		t.Fatalf("first readOneSegment() failed: %v", err)
	}
	firstUnderlay.commitServerUserAuthentication(firstSegment)
	if firstSegment.serverUserAuthentication.Valid() {
		t.Fatal("TCP commit retained the discovery generation")
	}

	// The second socket uses a different source port but the same source IP.
	secondAddr := &net.TCPAddr{IP: net.ParseIP("198.51.100.20"), Port: 12002}
	secondWire := buildServerUserStreamWire(t, credential, userName, testSessionSegment(openSessionRequest, 2, common.StreamTransport), nil, nil)
	_, _, err = readServerUserStreamWire(t, mux, secondAddr, secondWire)
	if err != nil {
		t.Fatalf("second readOneSegment() failed: %v", err)
	}
	// TCP and UDP share the cache owned by the same user generation.
	packet := &PacketUnderlay{
		serverUsers: &mux.serverUsers,
	}
	metadata := testSessionSegment(openSessionRequest, 3, common.PacketTransport).metadata.Marshal()
	encrypted := encryptDiscoveryMetadata(t, credential, userName, userMap(makeTestUser(userName, credential)), true, metadata)
	source := serveruser.SourceFromAddr(&net.UDPAddr{IP: net.ParseIP("198.51.100.20"), Port: 32000})
	_, _, _, err = packet.serverTryDecryptMetadataForNewSession(encrypted, source)
	if err != nil {
		t.Fatalf("UDP discovery after TCP activity failed: %v", err)
	}
}

func TestStreamServerInvalidInitialSegmentsDoNotRefreshCache(t *testing.T) {
	const userName = "stream-invalid-user"
	credential := cipher.HashPassword([]byte(t.Name()), []byte(userName))
	users := userMap(makeTestUser(userName, credential))
	mux := NewMux(false).SetServerUsers(users)
	t.Cleanup(func() { _ = mux.Close() })
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("203.0.113.30"), Port: 13001}

	validPayload := []byte("authenticated payload")
	invalidPayloadTag := buildServerUserStreamWire(t, credential, userName, testSessionSegment(openSessionRequest, 10, common.StreamTransport), validPayload, nil)
	invalidPayloadTag[len(invalidPayloadTag)-1] ^= 0x80
	invalidPadding := buildServerUserStreamWire(t, credential, userName, testSessionSegment(openSessionRequest, 11, common.StreamTransport), nil, []byte{0})
	invalidPadding = invalidPadding[:len(invalidPadding)-1]

	tests := []struct {
		name      string
		wire      []byte
		errorType stderror.ErrorType
	}{
		{
			name:      "invalid_payload_tag",
			wire:      invalidPayloadTag,
			errorType: stderror.CRYPTO_ERROR,
		},
		{
			name:      "invalid_padding",
			wire:      invalidPadding,
			errorType: stderror.NETWORK_ERROR,
		},
		{
			name:      "wrong_direction",
			wire:      buildServerUserStreamWire(t, credential, userName, testSessionSegment(openSessionResponse, 12, common.StreamTransport), nil, nil),
			errorType: stderror.PROTOCOL_ERROR,
		},
		{
			name:      "reserved_session_id",
			wire:      buildServerUserStreamWire(t, credential, userName, testSessionSegment(openSessionRequest, 0, common.StreamTransport), nil, nil),
			errorType: stderror.PROTOCOL_ERROR,
		},
		{
			name:      "malformed_metadata",
			wire:      buildServerUserStreamWire(t, credential, userName, nil, nil, nil),
			errorType: stderror.PROTOCOL_ERROR,
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			underlay, err := runServerUserStreamEventLoop(t, mux, remoteAddr, test.wire)
			if err == nil {
				t.Fatal("RunEventLoop() accepted an invalid initial segment, want rejection")
			}
			if got := serverUserStreamErrorType(err); got != test.errorType {
				t.Fatalf("error type = %v, want %v: %v", got, test.errorType, err)
			}
			assertNoServerUserSession(t, underlay)
		})
	}

	// A client that closes before its first write sends closeSessionRequest as
	// the initial segment. The new-session gate applies only to
	// openSessionRequest, so this segment must reach close-session dispatch
	// instead of being rejected as a new session.
	t.Run("close_before_first_write", func(t *testing.T) {
		wire := buildServerUserStreamWire(t, credential, userName, testSessionSegment(closeSessionRequest, 13, common.StreamTransport), nil, nil)
		underlay, err := runServerUserStreamEventLoop(t, mux, remoteAddr, wire)
		if err == nil {
			t.Fatal("RunEventLoop() returned without a terminal read error")
		}
		// The loop ends only when the closed connection makes the next read
		// fail; a PROTOCOL_ERROR here would mean the close was rejected by the
		// new-session gate.
		if got := serverUserStreamErrorType(err); got != stderror.NETWORK_ERROR {
			t.Fatalf("close-first segment error type = %v, want %v: %v", got, stderror.NETWORK_ERROR, err)
		}
		assertNoServerUserSession(t, underlay)
	})
}

func TestStreamServerReplayDoesNotRefreshCache(t *testing.T) {
	const userName = "stream-replay-user"
	credential := cipher.HashPassword([]byte(t.Name()), []byte(userName))
	mux := NewMux(false).SetServerUsers(userMap(makeTestUser(userName, credential)))
	t.Cleanup(func() { _ = mux.Close() })
	remoteAddr := &net.TCPAddr{IP: net.ParseIP("192.0.2.40"), Port: 14001}
	wire := buildServerUserStreamWire(t, credential, userName, testSessionSegment(openSessionRequest, 20, common.StreamTransport), nil, nil)

	_, first, err := readServerUserStreamWire(t, mux, remoteAddr, wire)
	if err != nil {
		t.Fatalf("first readOneSegment() failed: %v", err)
	}
	// Do not dispatch or commit the first copy. The identical second metadata
	// must be rejected by replay protection and still leave the cache cold.
	first.serverUserAuthentication = serveruser.Authentication{}
	_, _, err = readServerUserStreamWire(t, mux, remoteAddr, wire)
	if err == nil || stderror.GetErrorType(err) != stderror.REPLAY_ERROR {
		t.Fatalf("replayed readOneSegment() error = %v, want replay error", err)
	}
}

func TestPacketServerSourceUserCacheIntegration(t *testing.T) {
	const userName = "packet-cache-user"
	credential := cipher.HashPassword([]byte(t.Name()), []byte(userName))
	mux := NewMux(false).SetServerUsers(userMap(makeTestUser(userName, credential)))
	t.Cleanup(func() { _ = mux.Close() })

	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket() server failed: %v", err)
	}
	server := &PacketUnderlay{
		baseUnderlay:       *newBaseUnderlay(false, 1400, nil),
		conn:               serverConn,
		sessionCleanTicker: time.NewTicker(sessionCleanInterval),
		serverUsers:        &mux.serverUsers,
	}
	t.Cleanup(func() {
		_ = server.Close()
		_ = serverConn.Close()
	})

	first := newServerUserPacketSender(t, serverConn.LocalAddr(), credential, userName)
	defer first.conn.Close()
	second := newServerUserPacketSender(t, serverConn.LocalAddr(), credential, userName)
	defer second.conn.Close()

	// An authenticated wrong-direction control is discarded inside parsing and
	// cannot populate the source cache.
	if err := first.writeOneSegment(testSessionSegment(openSessionResponse, 30, common.PacketTransport), serverConn.LocalAddr()); err != nil {
		t.Fatalf("writeOneSegment(wrong direction) failed: %v", err)
	}
	firstClient, firstRequestPayload := newTestHandshakeClient(t, first.block, true)
	if err := first.writeOneSegment(testOpenSessionSegmentWithPayload(t, 31, common.PacketTransport, firstRequestPayload), serverConn.LocalAddr()); err != nil {
		t.Fatalf("writeOneSegment(first open) failed: %v", err)
	}
	firstSegment, firstAddr, err := server.readOneSegment()
	if err != nil {
		t.Fatalf("first readOneSegment() failed: %v", err)
	}
	if err := server.onOpenSessionRequest(firstSegment, firstAddr); err != nil {
		t.Fatalf("onOpenSessionRequest(first) failed: %v", err)
	}
	// The handshake response travels through the send queue of the new
	// session, so the raw client can derive the session keys of the session.
	firstClient.complete(t, testReadPacketHandshakeResponse(t, first.conn, first.block))

	// A duplicate ID authenticated from a different source port is dropped by
	// dispatch and must not refresh the cache or enqueue another session. The
	// duplicate is rejected before its payload is interpreted, so it doesn't
	// carry a handshake request.
	readyBeforeDuplicate := len(server.readySessions)
	if err := second.writeOneSegment(testSessionSegment(openSessionRequest, 31, common.PacketTransport), serverConn.LocalAddr()); err != nil {
		t.Fatalf("writeOneSegment(duplicate open) failed: %v", err)
	}
	duplicateSegment, duplicateAddr, err := server.readOneSegment()
	if err != nil {
		t.Fatalf("duplicate readOneSegment() failed: %v", err)
	}
	if err := server.onOpenSessionRequest(duplicateSegment, duplicateAddr); err != nil {
		t.Fatalf("onOpenSessionRequest(duplicate) failed: %v", err)
	}
	if got := len(server.readySessions); got != readyBeforeDuplicate {
		t.Fatalf("duplicate UDP open changed ready session count from %d to %d", readyBeforeDuplicate, got)
	}

	// A second source port on the same IP uses the learned candidate.
	secondClient, secondRequestPayload := newTestHandshakeClient(t, second.block, true)
	if err := second.writeOneSegment(testOpenSessionSegmentWithPayload(t, 32, common.PacketTransport, secondRequestPayload), serverConn.LocalAddr()); err != nil {
		t.Fatalf("writeOneSegment(second open) failed: %v", err)
	}
	secondSegment, secondAddr, err := server.readOneSegment()
	if err != nil {
		t.Fatalf("second readOneSegment() failed: %v", err)
	}
	if err := server.onOpenSessionRequest(secondSegment, secondAddr); err != nil {
		t.Fatalf("onOpenSessionRequest(second) failed: %v", err)
	}
	secondClient.complete(t, testReadPacketHandshakeResponse(t, second.conn, second.block))

	// Once the first session has installed its session key, messages from its
	// original address stay on the existing-session path and do not query the
	// user cache.
	firstSessionValue, ok := server.sessionMap.Load(uint32(31))
	if !ok {
		t.Fatal("first UDP session was not installed")
	}
	firstSession := firstSessionValue.(*Session)
	waitForServerUserSessionBlock(t, firstSession)
	data := testDataSegment(31, 1, []byte("existing session"), common.PacketTransport)
	data.block = firstClient.c2s
	if err := first.writeOneSegment(data, serverConn.LocalAddr()); err != nil {
		t.Fatalf("writeOneSegment(existing data) failed: %v", err)
	}
	existingSegment, _, err := server.readOneSegment()
	if err != nil {
		t.Fatalf("existing-session readOneSegment() failed: %v", err)
	}
	if existingSegment.serverUserAuthentication.Valid() {
		t.Fatal("existing UDP session unexpectedly performed user discovery")
	}

	// UDP-learned activity is immediately visible to TCP underlays sharing the
	// same generation.
	stream := &StreamUnderlay{
		serverUsers: &mux.serverUsers,
	}
	stream.serverUserSource = serveruser.SourceFromAddr(&net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: 45000})
	metadata := testSessionSegment(openSessionRequest, 33, common.StreamTransport).metadata.Marshal()
	encrypted := encryptDiscoveryMetadata(t, credential, userName, userMap(makeTestUser(userName, credential)), true, metadata)
	_, _, err = stream.serverInitRecvBlockCipherAndDecryptMetadata(encrypted)
	if err != nil {
		t.Fatalf("TCP discovery after UDP activity failed: %v", err)
	}
}

func TestPacketServerInvalidNewSessionsDoNotRefreshCache(t *testing.T) {
	const userName = "packet-invalid-user"
	credential := cipher.HashPassword([]byte(t.Name()), []byte(userName))
	mux := NewMux(false).SetServerUsers(userMap(makeTestUser(userName, credential)))
	t.Cleanup(func() { _ = mux.Close() })
	serverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket() server failed: %v", err)
	}
	defer serverConn.Close()
	server := &PacketUnderlay{
		baseUnderlay: *newBaseUnderlay(false, 1400, nil),
		conn:         serverConn,
		serverUsers:  &mux.serverUsers,
	}
	senderConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket() sender failed: %v", err)
	}
	defer senderConn.Close()
	replayConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket() replay sender failed: %v", err)
	}
	defer replayConn.Close()

	invalidPayloadTag := buildServerUserPacketWire(t, credential, userName, testSessionSegment(openSessionRequest, 50, common.PacketTransport), []byte("authenticated payload"), nil)
	invalidPayloadTag[len(invalidPayloadTag)-1] ^= 0x80
	invalidPadding := buildServerUserPacketWire(t, credential, userName, testSessionSegment(openSessionRequest, 51, common.PacketTransport), nil, []byte{0})
	invalidPadding = invalidPadding[:len(invalidPadding)-1]
	tests := []struct {
		name string
		wire []byte
	}{
		{"invalid_payload_tag", invalidPayloadTag},
		{"invalid_padding", invalidPadding},
		{"wrong_direction", buildServerUserPacketWire(t, credential, userName, testSessionSegment(openSessionResponse, 52, common.PacketTransport), nil, nil)},
		{"reserved_session_id", buildServerUserPacketWire(t, credential, userName, testSessionSegment(openSessionRequest, 0, common.PacketTransport), nil, nil)},
		{"malformed_metadata", buildServerUserPacketWire(t, credential, userName, nil, nil, nil)},
	}

	for i, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			if _, err := senderConn.WriteTo(test.wire, serverConn.LocalAddr()); err != nil {
				t.Fatalf("WriteTo(invalid) failed: %v", err)
			}
			valid := buildServerUserPacketWire(t, credential, userName, testSessionSegment(openSessionRequest, uint32(60+i), common.PacketTransport), nil, nil)
			if _, err := senderConn.WriteTo(valid, serverConn.LocalAddr()); err != nil {
				t.Fatalf("WriteTo(valid) failed: %v", err)
			}
			seg, _, err := server.readOneSegment()
			if err != nil {
				t.Fatalf("readOneSegment() failed: %v", err)
			}
			if got, _ := seg.SessionID(); got != uint32(60+i) {
				t.Fatalf("returned session ID = %d, want %d", got, 60+i)
			}
			seg.serverUserAuthentication = serveruser.Authentication{}
		})
	}

	// The first copy is authenticated but intentionally not dispatched. The
	// replayed copy is discarded, and a fresh packet unblocks the read loop.
	replayed := buildServerUserPacketWire(t, credential, userName, testSessionSegment(openSessionRequest, 70, common.PacketTransport), nil, nil)
	if _, err := senderConn.WriteTo(replayed, serverConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(first replay copy) failed: %v", err)
	}
	first, _, err := server.readOneSegment()
	if err != nil {
		t.Fatalf("readOneSegment(first replay copy) failed: %v", err)
	}
	first.serverUserAuthentication = serveruser.Authentication{}
	if _, err := replayConn.WriteTo(replayed, serverConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(replay) failed: %v", err)
	}
	fresh := buildServerUserPacketWire(t, credential, userName, testSessionSegment(openSessionRequest, 71, common.PacketTransport), nil, nil)
	if _, err := senderConn.WriteTo(fresh, serverConn.LocalAddr()); err != nil {
		t.Fatalf("WriteTo(fresh) failed: %v", err)
	}
	seg, _, err := server.readOneSegment()
	if err != nil {
		t.Fatalf("readOneSegment(after replay) failed: %v", err)
	}
	if got, _ := seg.SessionID(); got != 71 {
		t.Fatalf("returned session ID after replay = %d, want 71", got)
	}
}

func TestPacketServerReloadMandatoryHintRace(t *testing.T) {
	const userName = "packet-race-user"
	credential := cipher.HashPassword([]byte(t.Name()), []byte(userName))
	users := userMap(makeTestUser(userName, credential))
	mux := NewMux(false).SetServerUsers(users)
	t.Cleanup(func() { _ = mux.Close() })
	packet := &PacketUnderlay{
		serverUsers: &mux.serverUsers,
	}
	source := serveruser.SourceFromAddr(&net.UDPAddr{IP: net.ParseIP("192.0.2.60"), Port: 16001})
	metadata := testSessionSegment(openSessionRequest, 80, common.PacketTransport).metadata.Marshal()
	encrypted := encryptDiscoveryMetadata(t, credential, userName, users, true, metadata)

	const iterations = 16
	errCh := make(chan error, iterations)
	var wg sync.WaitGroup
	wg.Add(3)
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			mux.SetServerUsers(users)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			mux.SetServerUserHintIsMandatory(i%2 == 0)
		}
	}()
	go func() {
		defer wg.Done()
		for i := 0; i < iterations; i++ {
			_, _, authentication, err := packet.serverTryDecryptMetadataForNewSession(encrypted, source)
			if err != nil {
				errCh <- err
				continue
			}
			authentication.Record()
		}
	}()
	wg.Wait()
	close(errCh)
	for err := range errCh {
		t.Errorf("concurrent UDP discovery failed: %v", err)
	}
}

func TestRetiredGenerationAuthenticationRecordIsNoOp(t *testing.T) {
	const userName = "retired-record-user"
	credential := cipher.HashPassword([]byte(t.Name()), []byte(userName))
	mux := NewMux(false).SetServerUsers(userMap(makeTestUser(userName, credential)))
	t.Cleanup(func() { _ = mux.Close() })
	source := serveruser.SourceFromAddr(&net.UDPAddr{IP: net.ParseIP("192.0.2.50"), Port: 15001})
	metadata := testSessionSegment(openSessionRequest, 40, common.PacketTransport).metadata.Marshal()
	encrypted := encryptDiscoveryMetadata(t, credential, userName, userMap(makeTestUser(userName, credential)), true, metadata)
	packet := &PacketUnderlay{
		serverUsers: &mux.serverUsers,
	}
	_, _, authentication, err := packet.serverTryDecryptMetadataForNewSession(encrypted, source)
	if err != nil {
		t.Fatalf("serverTryDecryptMetadataForNewSession() failed: %v", err)
	}

	mux.SetServerUsers(rawUserMap("replacement-user", "replacement-password"))
	authentication.Record()
	if authentication.Valid() {
		t.Fatal("retired cache record retained its generation")
	}
}

// runServerUserStreamEventLoop drives a server StreamUnderlay through its real
// read loop so the production validation and dispatch path handles the wire.
func runServerUserStreamEventLoop(t *testing.T, mux *Mux, remoteAddr net.Addr, wire []byte) (*StreamUnderlay, error) {
	t.Helper()
	reader, writer := net.Pipe()
	conn := &serverUserTestRemoteConn{Conn: reader, remoteAddr: remoteAddr}
	underlay := mux.serverWrapTCPConn(conn, 1400, nil).(*StreamUnderlay)
	writeDone := make(chan struct{})
	go func() {
		_, _ = writer.Write(wire)
		_ = writer.Close()
		close(writeDone)
	}()
	err := underlay.RunEventLoop(context.Background())
	underlay.sessionCleanTicker.Stop()
	select {
	case <-writeDone:
	case <-time.After(time.Second):
		t.Fatal("stream test writer didn't stop")
	}
	return underlay, err
}

// serverUserStreamErrorType extracts the typed error from the errors returned
// by StreamUnderlay.RunEventLoop, which wraps read errors with fmt.Errorf.
func serverUserStreamErrorType(err error) stderror.ErrorType {
	for err != nil {
		if t := stderror.GetErrorType(err); t != stderror.UNKNOWN_ERROR {
			return t
		}
		err = errors.Unwrap(err)
	}
	return stderror.UNKNOWN_ERROR
}

// assertNoServerUserSession verifies that a rejected initial segment neither
// registered a session nor enqueued one as ready.
func assertNoServerUserSession(t *testing.T, underlay *StreamUnderlay) {
	t.Helper()
	count := 0
	underlay.sessionMap.Range(func(_, _ any) bool {
		count++
		return true
	})
	if count != 0 {
		t.Fatalf("underlay registered %d sessions for a rejected initial segment", count)
	}
	if got := len(underlay.readySessions); got != 0 {
		t.Fatalf("underlay enqueued %d ready sessions for a rejected initial segment", got)
	}
}

func readServerUserStreamWire(t *testing.T, mux *Mux, remoteAddr net.Addr, wire []byte) (*StreamUnderlay, *segment, error) {
	t.Helper()
	reader, writer := net.Pipe()
	conn := &serverUserTestRemoteConn{Conn: reader, remoteAddr: remoteAddr}
	underlay := mux.serverWrapTCPConn(conn, 1400, nil).(*StreamUnderlay)
	writeDone := make(chan struct{})
	go func() {
		_, _ = writer.Write(wire)
		_ = writer.Close()
		close(writeDone)
	}()
	seg, err := underlay.readOneSegment()
	_ = reader.Close()
	underlay.sessionCleanTicker.Stop()
	select {
	case <-writeDone:
	case <-time.After(time.Second):
		t.Fatal("stream test writer didn't stop")
	}
	return underlay, seg, err
}

func buildServerUserStreamWire(t *testing.T, credential []byte, userName string, seg *segment, payload, padding []byte) []byte {
	t.Helper()
	var plaintextMetadata []byte
	if seg == nil {
		plaintextMetadata = newDummyMetadata()
	} else {
		ss, ok := seg.metadata.(*sessionStruct)
		if !ok {
			t.Fatalf("stream test metadata type = %T, want sessionStruct", seg.metadata)
		}
		ss.payloadLen = uint16(len(payload))
		ss.suffixLen = uint8(len(padding))
		plaintextMetadata = ss.Marshal()
	}
	block, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, credential, false)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}
	block.SetBlockContext(cipher.BlockContext{UserName: userName})
	encryptedMetadata := make([]byte, block.NonceSize()+len(plaintextMetadata)+block.Overhead())
	if err := block.Encrypt(encryptedMetadata[:0], plaintextMetadata); err != nil {
		t.Fatalf("Encrypt(metadata) failed: %v", err)
	}
	wire := append([]byte(nil), encryptedMetadata...)
	if len(payload) > 0 {
		encryptedPayload := make([]byte, len(payload)+block.Overhead())
		if err := block.Encrypt(encryptedPayload[:0], payload); err != nil {
			t.Fatalf("Encrypt(payload) failed: %v", err)
		}
		wire = append(wire, encryptedPayload...)
	}
	wire = append(wire, padding...)
	return wire
}

func buildServerUserPacketWire(t *testing.T, credential []byte, userName string, seg *segment, payload, padding []byte) []byte {
	t.Helper()
	var plaintextMetadata []byte
	if seg == nil {
		plaintextMetadata = newDummyMetadata()
	} else {
		ss, ok := seg.metadata.(*sessionStruct)
		if !ok {
			t.Fatalf("packet test metadata type = %T, want sessionStruct", seg.metadata)
		}
		ss.payloadLen = uint16(len(payload))
		ss.suffixLen = uint8(len(padding))
		plaintextMetadata = ss.Marshal()
	}
	block, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, credential, true)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}
	block.SetBlockContext(cipher.BlockContext{UserName: userName})
	encryptedMetadata := make([]byte, block.NonceSize()+len(plaintextMetadata)+block.Overhead())
	if err := block.Encrypt(encryptedMetadata[:0], plaintextMetadata); err != nil {
		t.Fatalf("Encrypt(metadata) failed: %v", err)
	}
	nonce := encryptedMetadata[:cipher.DefaultNonceSize]
	wire := append([]byte(nil), encryptedMetadata...)
	if len(payload) > 0 {
		encryptedPayload := make([]byte, len(payload)+block.Overhead())
		if err := block.EncryptPayloadWithNonce(encryptedPayload[:0], nonce, payload); err != nil {
			t.Fatalf("EncryptPayloadWithNonce(payload) failed: %v", err)
		}
		wire = append(wire, encryptedPayload...)
	}
	wire = append(wire, padding...)
	return wire
}

func newServerUserPacketSender(t *testing.T, serverAddr net.Addr, credential []byte, userName string) *PacketUnderlay {
	t.Helper()
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket() sender failed: %v", err)
	}
	block, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, credential, true)
	if err != nil {
		conn.Close()
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}
	block.SetBlockContext(cipher.BlockContext{UserName: userName})
	return &PacketUnderlay{
		baseUnderlay: *newBaseUnderlay(true, 1400, nil),
		conn:         conn,
		serverAddr:   serverAddr,
		block:        block,
	}
}

func waitForServerUserSessionBlock(t *testing.T, session *Session) {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for session.block.Load() == nil {
		if time.Now().After(deadline) {
			t.Fatal("session didn't install its block cipher")
		}
		time.Sleep(time.Millisecond)
	}
}
