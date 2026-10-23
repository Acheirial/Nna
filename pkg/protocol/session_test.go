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
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/Acheirial/shadowlemon/v3/pkg/appctl/appctlpb"
	"github.com/Acheirial/shadowlemon/v3/pkg/cipher"
	"github.com/Acheirial/shadowlemon/v3/pkg/common"
	"github.com/Acheirial/shadowlemon/v3/pkg/stderror"
)

func TestDeliverSegmentUnblocksOnSessionClose(t *testing.T) {
	underlay := newBaseUnderlay(false, 1400, nil)
	session := NewSession(1, false, 1400, nil, nil)
	seg := testDataSegment(1, 1, []byte("a"), common.StreamTransport)

	for i := 0; i < segmentChanCapacity; i++ {
		session.recvChan <- seg
	}

	done := make(chan bool)
	go func() {
		done <- underlay.deliverSegmentToSession(session, seg)
	}()

	select {
	case delivered := <-done:
		t.Fatalf("deliverSegmentToSession() returned before close: %v", delivered)
	case <-time.After(100 * time.Millisecond):
	}

	if err := session.Close(); err != nil {
		t.Fatalf("session.Close() failed: %v", err)
	}

	select {
	case delivered := <-done:
		if delivered {
			t.Fatalf("deliverSegmentToSession() = true, want false")
		}
	case <-time.After(time.Second):
		t.Fatalf("deliverSegmentToSession() didn't return after session close")
	}
}

func TestStreamUnderlayIgnoresResponsesForClosedSession(t *testing.T) {
	underlay := &StreamUnderlay{
		baseUnderlay: *newBaseUnderlay(true, 1400, nil),
	}
	session := NewSession(1, true, 1400, nil, nil)
	if err := underlay.baseUnderlay.AddSession(session, nil); err != nil {
		t.Fatalf("AddSession() failed: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("session.Close() failed: %v", err)
	}

	if err := underlay.onOpenSessionResponse(testSessionSegment(openSessionResponse, 1, common.StreamTransport)); err != nil {
		t.Fatalf("onOpenSessionResponse() failed: %v", err)
	}
	if err := underlay.onCloseSession(testSessionSegment(closeSessionResponse, 1, common.StreamTransport)); err != nil {
		t.Fatalf("onCloseSession() failed: %v", err)
	}
}

func TestPacketUnderlayIgnoresResponsesForClosedSession(t *testing.T) {
	underlay := &PacketUnderlay{
		baseUnderlay: *newBaseUnderlay(true, 1400, nil),
	}
	session := NewSession(1, true, 1400, nil, nil)
	if err := underlay.baseUnderlay.AddSession(session, nil); err != nil {
		t.Fatalf("AddSession() failed: %v", err)
	}
	if err := session.Close(); err != nil {
		t.Fatalf("session.Close() failed: %v", err)
	}

	if err := underlay.onOpenSessionResponse(testSessionSegment(openSessionResponse, 1, common.PacketTransport)); err != nil {
		t.Fatalf("onOpenSessionResponse() failed: %v", err)
	}
	if err := underlay.onCloseSession(testSessionSegment(closeSessionResponse, 1, common.PacketTransport)); err != nil {
		t.Fatalf("onCloseSession() failed: %v", err)
	}
}

// TestStreamLowEntropyWriteChunk verifies framing metadata, fragmentation,
// and plaintext preservation for all low-entropy modes.
func TestStreamLowEntropyWriteChunk(t *testing.T) {
	tests := []struct {
		mode              appctlpb.LowEntropyMode
		rotation          appctlpb.LowEntropyMaskRotation
		wantFragments     int
		wantFirstPartLen  int
		wantSecondPartLen int
	}{
		{appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_32, appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION, 2, 24573, 8195},
		{appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_40, appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_ROTATE_RIGHT_7, 2, 32764, 4},
		{appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_48, appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_ROTATE_LEFT_3, 1, maxPDU, 0},
		{appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_56, appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_ROTATE_RIGHT_15, 1, maxPDU, 0},
	}
	payload := make([]byte, maxPDU)
	for i := range payload {
		payload[i] = byte(i)
	}
	for _, test := range tests {
		t.Run(test.mode.String(), func(t *testing.T) {
			s := NewSession(1, true, 1400, nil, testLowEntropyTrafficPattern(test.mode, test.rotation))
			s.transportProtocol = common.StreamTransport
			segments, n, err := collectSessionSegments(t, s, test.wantFragments, func() (int, error) {
				return s.writeChunk(payload)
			})
			if err != nil || n != len(payload) {
				t.Fatalf("writeChunk() = (%d, %v), want (%d, nil)", n, err, len(payload))
			}
			var reconstructed []byte
			for i, seg := range segments {
				das := seg.metadata.(*dataAckStruct)
				if das.Protocol() != dataClientToServerLowEntropy {
					t.Errorf("fragment %d protocol = %v, want %v", i, das.Protocol(), dataClientToServerLowEntropy)
				}
				if das.lowEntropyMode != uint8(test.mode) || das.lowEntropyMaskRotation != uint8(test.rotation) {
					t.Errorf("fragment %d low entropy config = (%d, %d), want (%d, %d)", i, das.lowEntropyMode, das.lowEntropyMaskRotation, test.mode, test.rotation)
				}
				if das.extractedPayloadLen != uint16(len(seg.payload)) {
					t.Errorf("fragment %d extracted length = %d, want %d", i, das.extractedPayloadLen, len(seg.payload))
				}
				wantEncodedLen, err := lowEntropyNominalEncodedPayloadLen(len(seg.payload), test.mode)
				if err != nil {
					t.Fatalf("lowEntropyNominalEncodedPayloadLen() failed: %v", err)
				}
				if das.payloadLen != wantEncodedLen || das.lowEntropyMask != 0 {
					t.Errorf("fragment %d metadata = %v, want encoded length %d and deferred mask", i, das, wantEncodedLen)
				}
				reconstructed = append(reconstructed, seg.payload...)
			}
			if len(segments[0].payload) != test.wantFirstPartLen {
				t.Errorf("first fragment length = %d, want %d", len(segments[0].payload), test.wantFirstPartLen)
			}
			if test.wantSecondPartLen > 0 && len(segments[1].payload) != test.wantSecondPartLen {
				t.Errorf("second fragment length = %d, want %d", len(segments[1].payload), test.wantSecondPartLen)
			}
			if !bytes.Equal(reconstructed, payload) {
				t.Fatal("fragment payloads don't reconstruct the original plaintext")
			}
		})
	}
}

// TestPacketLowEntropyWriteChunk verifies framing metadata, MTU-bounded
// fragmentation, and plaintext preservation for all low-entropy modes.
func TestPacketLowEntropyWriteChunk(t *testing.T) {
	tests := []struct {
		mode     appctlpb.LowEntropyMode
		rotation appctlpb.LowEntropyMaskRotation
	}{
		{appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_32, appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION},
		{appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_40, appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_ROTATE_RIGHT_7},
		{appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_48, appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_ROTATE_LEFT_3},
		{appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_56, appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_ROTATE_RIGHT_15},
	}
	payload := make([]byte, maxPDU)
	for i := range payload {
		payload[i] = byte(i)
	}
	for _, test := range tests {
		t.Run(test.mode.String(), func(t *testing.T) {
			s := NewSession(1, true, 1400, nil, testLowEntropyTrafficPattern(test.mode, test.rotation))
			s.transportProtocol = common.PacketTransport
			fragmentSize, err := maxFragmentSize(s.mtu, s.transportProtocol, test.mode)
			if err != nil {
				t.Fatalf("maxFragmentSize() failed: %v", err)
			}
			wantFragments := (len(payload)-1)/fragmentSize + 1
			segments, n, err := collectSessionSegments(t, s, wantFragments, func() (int, error) {
				return s.writeChunk(payload)
			})
			if err != nil || n != len(payload) {
				t.Fatalf("writeChunk() = (%d, %v), want (%d, nil)", n, err, len(payload))
			}
			var reconstructed []byte
			for i, seg := range segments {
				das := seg.metadata.(*dataAckStruct)
				if das.Protocol() != dataClientToServerLowEntropy {
					t.Errorf("fragment %d protocol = %v, want %v", i, das.Protocol(), dataClientToServerLowEntropy)
				}
				if das.lowEntropyMode != uint8(test.mode) || das.lowEntropyMaskRotation != uint8(test.rotation) {
					t.Errorf("fragment %d low entropy config = (%d, %d), want (%d, %d)", i, das.lowEntropyMode, das.lowEntropyMaskRotation, test.mode, test.rotation)
				}
				if len(seg.payload) > fragmentSize || das.extractedPayloadLen != uint16(len(seg.payload)) {
					t.Errorf("fragment %d plaintext length = %d, limit %d, extracted length %d", i, len(seg.payload), fragmentSize, das.extractedPayloadLen)
				}
				wantEncodedLen, err := lowEntropyNominalEncodedPayloadLen(len(seg.payload), test.mode)
				if err != nil {
					t.Fatalf("lowEntropyNominalEncodedPayloadLen() failed: %v", err)
				}
				if das.payloadLen != wantEncodedLen || int(das.payloadLen)+packetOverhead > s.mtu {
					t.Errorf("fragment %d encoded length = %d, want %d within MTU %d", i, das.payloadLen, wantEncodedLen, s.mtu)
				}
				reconstructed = append(reconstructed, seg.payload...)
			}
			if !bytes.Equal(reconstructed, payload) {
				t.Fatal("fragment payloads don't reconstruct the original plaintext")
			}
		})
	}
}

func TestFirstPacketWritePiggyback(t *testing.T) {
	payload := []byte("first packet write")
	s := NewSession(1, true, 1400, nil, nil)
	s.transportProtocol = common.PacketTransport
	s.forwardStateTo(sessionAttached)
	segments, n, err := collectSessionSegments(t, s, 1, func() (int, error) {
		return s.Write(payload)
	})
	if err != nil || n != len(payload) {
		t.Fatalf("Write() = (%d, %v), want (%d, nil)", n, err, len(payload))
	}
	ss := segments[0].metadata.(*sessionStruct)
	// The payload of the first packet is the handshake request of the session
	// followed by the application data of the first Write, so the server can
	// deliver the application data as soon as the handshake completes.
	handshakeLen := firstPacketHandshakeLen(t, segments[0])
	wantLen := handshakeLen + len(payload)
	if ss.Protocol() != openSessionRequest || len(segments[0].payload) != wantLen || int(ss.payloadLen) != wantLen {
		t.Fatalf("openSessionRequest segment = %v, want a %d bytes handshake request followed by the %d bytes application payload", segments[0], handshakeLen, len(payload))
	}
	if piggyback := segments[0].payload[handshakeLen:]; !bytes.Equal(piggyback, payload) {
		t.Fatalf("piggybacked payload = %q, want %q", piggyback, payload)
	}
}

// firstPacketHandshakeLen returns the length of the handshake request that
// prefixes the payload of an open session request. It fails the test when the
// payload doesn't hold a well formed handshake request, so that a test which
// asserts "no piggyback" can't silently accept "no handshake" either.
func firstPacketHandshakeLen(t *testing.T, seg *segment) int {
	t.Helper()
	ss, ok := seg.metadata.(*sessionStruct)
	if !ok {
		t.Fatalf("segment metadata = %T, want *sessionStruct", seg.metadata)
	}
	if ss.Protocol() != openSessionRequest {
		t.Fatalf("segment protocol = %v, want %v", ss.Protocol(), openSessionRequest)
	}
	_, consumed, err := parseHandshakeRequest(seg.payload)
	if err != nil {
		t.Fatalf("the payload of the open session request doesn't start with a handshake request: %v", err)
	}
	if consumed > len(seg.payload) {
		t.Fatalf("handshake request is %d bytes, but the payload is only %d bytes", consumed, len(seg.payload))
	}
	return consumed
}

func TestLowEntropyFirstPacketNoPiggyback(t *testing.T) {
	payload := []byte("low entropy first packet write")
	s := NewSession(1, true, 1400, nil, testLowEntropyTrafficPattern(appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_32, appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_ROTATE_LEFT_3))
	s.transportProtocol = common.PacketTransport
	s.forwardStateTo(sessionAttached)
	segments, n, err := collectSessionSegments(t, s, 2, func() (int, error) {
		return s.Write(payload)
	})
	if err != nil || n != len(payload) {
		t.Fatalf("Write() = (%d, %v), want (%d, nil)", n, err, len(payload))
	}
	ss := segments[0].metadata.(*sessionStruct)
	// Low entropy metadata doesn't fit in a session control message, so the
	// first packet carries the handshake request and no application data. The
	// handshake request must still be there, and that is what distinguishes
	// "no piggyback" from "no handshake".
	handshakeLen := firstPacketHandshakeLen(t, segments[0])
	if ss.Protocol() != openSessionRequest || len(segments[0].payload) != handshakeLen || int(ss.payloadLen) != handshakeLen {
		t.Fatalf("openSessionRequest segment = %v, want exactly the %d bytes handshake request with no application data", segments[0], handshakeLen)
	}
	if das := segments[1].metadata.(*dataAckStruct); das.Protocol() != dataClientToServerLowEntropy || !bytes.Equal(segments[1].payload, payload) {
		t.Fatalf("data segment = %v, want low entropy metadata and original payload", segments[1])
	}
}

func TestPacketLowEntropyDuplicateAndReordering(t *testing.T) {
	s := NewSession(1, true, 1400, nil, nil)
	s.transportProtocol = common.PacketTransport
	newSegment := func(seq uint32, payload string) *segment {
		return &segment{
			metadata: &dataAckStruct{
				baseStruct: baseStruct{protocol: uint8(dataServerToClientLowEntropy)},
				sessionID:  1,
				seq:        seq,
				windowSize: segmentTreeCapacity,
				payloadLen: uint16(len(payload)),
				fragment:   0,
			},
			payload:   []byte(payload),
			transport: common.PacketTransport,
		}
	}
	if err := s.input(newSegment(1, "second")); err != nil {
		t.Fatalf("input(out of order) failed: %v", err)
	}
	if err := s.input(newSegment(1, "second")); err != nil {
		t.Fatalf("input(duplicate) failed: %v", err)
	}
	if got := s.recvQueue.Len(); got != 0 {
		t.Fatalf("recvQueue length before gap closes = %d, want 0", got)
	}
	if err := s.input(newSegment(0, "first")); err != nil {
		t.Fatalf("input(first) failed: %v", err)
	}

	// Received segments should be in order and have no duplicates.
	for i, want := range []string{"first", "second"} {
		got, ok := s.recvQueue.DeleteMin()
		if !ok {
			t.Fatalf("recvQueue item %d is missing", i)
		}
		if string(got.payload) != want {
			t.Errorf("recvQueue item %d = %q, want %q", i, got.payload, want)
		}
	}
	if got := s.recvBuf.Len(); got != 0 {
		t.Errorf("recvBuf length = %d, want 0", got)
	}
}

// TestServerLowEntropySignalIsSticky verifies that the server keeps using
// low entropy after a client switches back to regular data segments.
func TestServerLowEntropySignalIsSticky(t *testing.T) {
	s := NewSession(1, false, 1400, nil, testLowEntropyTrafficPattern(
		appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_48,
		appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_ROTATE_LEFT_1,
	))
	s.transportProtocol = common.StreamTransport

	for seq, protocol := range []protocolType{dataClientToServerLowEntropy, dataClientToServer} {
		seg := testDataSegment(1, uint32(seq), []byte{byte(seq)}, common.StreamTransport)
		seg.metadata.(*dataAckStruct).baseStruct.protocol = uint8(protocol)
		if err := s.input(seg); err != nil {
			t.Fatalf("input(%v) failed: %v", protocol, err)
		}
		if !s.clientUseLowEntropy.Load() {
			t.Fatalf("client signal is false after receiving %v", protocol)
		}
	}

	segments, _, err := collectSessionSegments(t, s, 1, func() (int, error) {
		return s.writeChunk([]byte("sticky response"))
	})
	if err != nil {
		t.Fatalf("writeChunk() failed: %v", err)
	}
	if got := segments[0].Protocol(); got != dataServerToClientLowEntropy {
		t.Fatalf("response protocol = %v, want %v", got, dataServerToClientLowEntropy)
	}
}

func TestSessionReceiveWindowSize(t *testing.T) {
	s := NewSession(1, false, 1400, nil, nil)
	if got := s.recvQueue.Remaining(); got != segmentTreeCapacity {
		t.Fatalf("recvQueue capacity = %d, want %d", got, segmentTreeCapacity)
	}
	if got := s.receiveWindowSize(); got != segmentTreeCapacity {
		t.Fatalf("receiveWindowSize() = %d, want %d", got, segmentTreeCapacity)
	}

	if !s.recvBuf.Insert(testDataSegment(1, 1, []byte("a"), common.PacketTransport)) {
		t.Fatalf("insert segment to recvBuf failed")
	}
	if got := s.receiveWindowSize(); got != segmentTreeCapacity-1 {
		t.Fatalf("receiveWindowSize() with recvBuf = %d, want %d", got, segmentTreeCapacity-1)
	}

	if !s.recvQueue.Insert(testDataSegment(1, 2, []byte("b"), common.PacketTransport)) {
		t.Fatalf("insert segment to recvQueue failed")
	}
	if got := s.receiveWindowSize(); got != segmentTreeCapacity-2 {
		t.Fatalf("receiveWindowSize() with recvBuf and recvQueue = %d, want %d", got, segmentTreeCapacity-2)
	}
}

func testLowEntropyTrafficPattern(mode appctlpb.LowEntropyMode, rotation appctlpb.LowEntropyMaskRotation) *appctlpb.TrafficPattern {
	return &appctlpb.TrafficPattern{LowEntropy: &appctlpb.LowEntropyPattern{
		Mode:         mode.Enum(),
		MaskRotation: rotation.Enum(),
	}}
}

func collectSessionSegments(t *testing.T, s *Session, want int, write func() (int, error)) ([]*segment, int, error) {
	t.Helper()
	type writeResult struct {
		n   int
		err error
	}
	resultCh := make(chan writeResult, 1)
	go func() {
		n, err := write()
		resultCh <- writeResult{n: n, err: err}
	}()

	segments := make([]*segment, 0, want)
	deadline := time.NewTimer(time.Second)
	defer deadline.Stop()
	for len(segments) < want {
		if seg, ok := s.sendQueue.DeleteMin(); ok {
			segments = append(segments, seg)
			continue
		}
		select {
		case <-s.sendQueue.chanNotEmptyEvent:
		case <-deadline.C:
			t.Fatalf("timed out collecting session segments: got %d, want %d", len(segments), want)
		}
	}
	select {
	case result := <-resultCh:
		return segments, result.n, result.err
	case <-deadline.C:
		t.Fatal("timed out waiting for session write")
		return nil, 0, nil
	}
}

func testSessionSegment(protocol protocolType, sessionID uint32, transport common.TransportProtocol) *segment {
	return &segment{
		metadata: &sessionStruct{
			baseStruct: baseStruct{
				protocol: uint8(protocol),
			},
			sessionID: sessionID,
		},
		transport: transport,
	}
}

func testDataSegment(sessionID, seq uint32, payload []byte, transport common.TransportProtocol) *segment {
	return &segment{
		metadata: &dataAckStruct{
			baseStruct: baseStruct{
				protocol: uint8(dataClientToServer),
			},
			sessionID:  sessionID,
			seq:        seq,
			windowSize: uint16(segmentTreeCapacity),
			payloadLen: uint16(len(payload)),
		},
		payload:   append([]byte(nil), payload...),
		transport: transport,
	}
}

// newTestPacketSession returns an established client packet session that
// writes to receiverConn, plus the block cipher to decrypt its output.
func newTestPacketSession(t *testing.T) (*Session, net.PacketConn, cipher.BlockCipher) {
	t.Helper()
	block, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, []byte(t.Name()), true)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}
	receiverConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket() receiver failed: %v", err)
	}
	t.Cleanup(func() { receiverConn.Close() })
	senderConn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket() sender failed: %v", err)
	}
	t.Cleanup(func() { senderConn.Close() })
	sender := &PacketUnderlay{
		baseUnderlay: *newBaseUnderlay(true, 1400, nil),
		conn:         senderConn,
		serverAddr:   receiverConn.LocalAddr(),
		block:        block,
	}
	s := NewSession(1, true, 1400, nil, nil)
	s.conn = sender
	s.transportProtocol = common.PacketTransport
	s.remoteAddr = receiverConn.LocalAddr()
	s.forwardStateTo(sessionEstablished)
	return s, receiverConn, block.Clone()
}

func decryptDataAckForTest(t *testing.T, block cipher.BlockCipher, wire []byte) *dataAckStruct {
	t.Helper()
	decrypted, err := block.Decrypt(wire[:packetNonHeaderPosition])
	if err != nil {
		t.Fatalf("Decrypt(metadata) failed: %v", err)
	}
	das := &dataAckStruct{}
	if err := das.Unmarshal(decrypted); err != nil {
		t.Fatalf("Unmarshal(metadata) failed: %v", err)
	}
	return das
}

func TestPacketOutputDelay(t *testing.T) {
	// randomHeartbeatJitter() is uniform in [-baseJitter, +baseJitter] and adds
	// a long tail of up to 8*baseJitter with probability 1/8, so the deadline
	// of an idle session can be as late as sessionHeartbeatInterval+maxJitter.
	baseJitter := sessionHeartbeatJitterMs * time.Millisecond
	maxJitter := baseJitter + 8*sessionHeartbeatJitterMs*time.Millisecond
	tests := []struct {
		name    string
		setup   func(s *Session)
		minWant time.Duration
		maxWant time.Duration
	}{
		{
			name:    "idle waits for heartbeat",
			setup:   func(s *Session) {},
			minWant: sessionHeartbeatInterval - baseJitter - 100*time.Millisecond,
			maxWant: sessionHeartbeatInterval + maxJitter,
		},
		{
			name:    "pending ack",
			setup:   func(s *Session) { s.requestPacketAck() },
			minWant: 0,
			maxWant: packetAckDelay,
		},
		{
			name: "pending retransmission",
			setup: func(s *Session) {
				s.sendBuf.Insert(testDataSegment(1, 0, []byte("a"), common.PacketTransport))
				s.nextRetransmissionTime.Store(time.Now().Add(50 * time.Millisecond).UnixMicro())
			},
			minWant: 40 * time.Millisecond,
			maxWant: 50 * time.Millisecond,
		},
		{
			name: "overdue retransmission",
			setup: func(s *Session) {
				s.sendBuf.Insert(testDataSegment(1, 0, []byte("a"), common.PacketTransport))
				s.nextRetransmissionTime.Store(0)
			},
			minWant: minOutputInterval,
			maxWant: minOutputInterval,
		},
		{
			name: "stale retransmission time is ignored when sendBuf is empty",
			setup: func(s *Session) {
				s.nextRetransmissionTime.Store(0)
			},
			minWant: sessionHeartbeatInterval - baseJitter - 100*time.Millisecond,
			maxWant: sessionHeartbeatInterval + maxJitter,
		},
		{
			name: "opening client ignores ack and heartbeat",
			setup: func(s *Session) {
				s.state.Store(int32(sessionAttached))
				s.requestPacketAck()
				s.lastTXTime.Store(0)
			},
			minWant: sessionHeartbeatInterval,
			maxWant: sessionHeartbeatInterval,
		},
		{
			name: "opening client retransmits open request",
			setup: func(s *Session) {
				s.state.Store(int32(sessionAttached))
				s.sendBuf.Insert(testSessionSegment(openSessionRequest, 1, common.PacketTransport))
				s.nextRetransmissionTime.Store(time.Now().Add(20 * time.Millisecond).UnixMicro())
			},
			minWant: 10 * time.Millisecond,
			maxWant: 20 * time.Millisecond,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			s := NewSession(1, true, 1400, nil, nil)
			s.transportProtocol = common.PacketTransport
			s.forwardStateTo(sessionEstablished)
			test.setup(s)
			got := s.nextPacketOutputDelay()
			if got < test.minWant || got > test.maxWant {
				t.Fatalf("nextPacketOutputDelay() = %v, want in [%v, %v]", got, test.minWant, test.maxWant)
			}
		})
	}
}

// TestRandomHeartbeatJitter checks the bounds of the heartbeat jitter and the
// presence of its long tail. Every draw must stay in
// [-sessionHeartbeatJitterMs, +9*sessionHeartbeatJitterMs] milliseconds, and
// the long tail must show up in a sample of 1000 draws: the probability that a
// sample this large misses it is 0.875^1000, which is effectively zero.
func TestRandomHeartbeatJitter(t *testing.T) {
	const draws = 1000
	baseJitter := sessionHeartbeatJitterMs * time.Millisecond
	maxJitter := baseJitter + 8*sessionHeartbeatJitterMs*time.Millisecond

	tests := []struct {
		name  string
		check func(t *testing.T, jitters []time.Duration)
	}{
		{
			name: "all draws stay within the base jitter and the long tail",
			check: func(t *testing.T, jitters []time.Duration) {
				for i, got := range jitters {
					if got < -baseJitter || got > maxJitter {
						t.Fatalf("draw %d = %v, want in [%v, %v]", i, got, -baseJitter, maxJitter)
					}
				}
			},
		},
		{
			name: "long tail appears at least once",
			check: func(t *testing.T, jitters []time.Duration) {
				for _, got := range jitters {
					if got > baseJitter {
						return
					}
				}
				t.Fatalf("no draw exceeded %v in %d draws, the long tail is missing", baseJitter, len(jitters))
			},
		},
	}

	jitters := make([]time.Duration, 0, draws)
	for range draws {
		jitters = append(jitters, randomHeartbeatJitter())
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			test.check(t, jitters)
		})
	}
}

func TestRequestAckCoalesces(t *testing.T) {
	s := NewSession(1, true, 1400, nil, nil)
	s.transportProtocol = common.PacketTransport
	before := time.Now().UnixMicro()
	s.requestPacketAck()
	if !s.ackOnDataRecv.Load() {
		t.Fatal("ackOnDataRecv = false after requestAck()")
	}
	deadline := s.ackDeadline.Load()
	if deadline < before+packetAckDelay.Microseconds() || deadline > time.Now().UnixMicro()+packetAckDelay.Microseconds() {
		t.Fatalf("ackDeadline = %d, want about now + %v", deadline, packetAckDelay)
	}
	select {
	case <-s.outputWakeup:
	default:
		t.Fatal("requestAck() didn't wake up the output loop")
	}

	// A second request while the first is pending must not delay the ACK
	// or wake up the output loop again.
	time.Sleep(200 * time.Microsecond)
	s.requestPacketAck()
	if got := s.ackDeadline.Load(); got != deadline {
		t.Fatalf("ackDeadline changed from %d to %d by a pending request", deadline, got)
	}
	select {
	case <-s.outputWakeup:
		t.Fatal("pending requestAck() woke up the output loop again")
	default:
	}
}

func TestPacketRetransmissionDeadline(t *testing.T) {
	s, receiverConn, _ := newTestPacketSession(t)

	// Sending into an empty sendBuf schedules an early check.
	seg := testDataSegment(1, 0, []byte("first"), common.PacketTransport)
	if !s.sendQueue.Insert(seg) {
		t.Fatal("failed to queue segment")
	}
	s.runOutputOncePacket()
	readPacketForTest(t, receiverConn)
	if s.sendBuf.Len() != 1 {
		t.Fatalf("sendBuf length = %d, want 1", s.sendBuf.Len())
	}
	if got, want := s.nextRetransmissionTime.Load(), seg.txTime+retransmissionCheckDelay.Microseconds(); got != want {
		t.Fatalf("nextRetransmissionTime after first send = %d, want %d", got, want)
	}

	// After a retransmission the next check uses the new deadline,
	// not the expired one.
	seg.txTime = time.Now().Add(-time.Second).UnixMicro()
	seg.txTimeout = time.Nanosecond
	s.nextRetransmissionTime.Store(0)
	s.runOutputOncePacket()
	readPacketForTest(t, receiverConn)
	if seg.txCount != 2 {
		t.Fatalf("txCount = %d, want 2", seg.txCount)
	}
	if got, want := s.nextRetransmissionTime.Load(), seg.txTime+seg.txTimeout.Microseconds(); got != want {
		t.Fatalf("nextRetransmissionTime after retransmission = %d, want %d", got, want)
	}
	if s.nextRetransmissionTime.Load() <= time.Now().UnixMicro() {
		t.Fatal("nextRetransmissionTime after retransmission is not in the future")
	}

	// A far away deadline from a backed off segment doesn't delay the
	// check of a newly sent segment.
	far := time.Now().Add(maxBackOffDuration).UnixMicro()
	s.nextRetransmissionTime.Store(far)
	second := testDataSegment(1, 1, []byte("second"), common.PacketTransport)
	if !s.sendQueue.Insert(second) {
		t.Fatal("failed to queue second segment")
	}
	s.runOutputOncePacket()
	readPacketForTest(t, receiverConn)
	if s.sendBuf.Len() != 2 {
		t.Fatalf("sendBuf length = %d, want 2", s.sendBuf.Len())
	}
	if got, want := s.nextRetransmissionTime.Load(), second.txTime+second.txTimeout.Microseconds(); got != want {
		t.Fatalf("nextRetransmissionTime after second send = %d, want %d", got, want)
	}
}

// TestPacketOutputLoopEventDriven verifies that the packet output loop
// stays silent when idle, acknowledges received data promptly, and still
// sends heartbeats.
func TestPacketOutputLoopEventDriven(t *testing.T) {
	s, receiverConn, decryptBlock := newTestPacketSession(t)
	ctx, cancel := context.WithCancel(context.Background())
	loopDone := make(chan struct{})
	go func() {
		defer close(loopDone)
		s.runOutputLoop(ctx)
	}()
	defer func() {
		cancel()
		select {
		case <-loopDone:
		case <-time.After(time.Second):
			t.Error("runOutputLoop() didn't stop")
		}
	}()

	// Idle session doesn't transmit.
	expectNoPacketForTest(t, receiverConn)

	// Received data is acknowledged after a short delay.
	data := testDataSegment(1, 0, []byte("payload"), common.PacketTransport)
	data.metadata.(*dataAckStruct).baseStruct.protocol = uint8(dataServerToClient)
	start := time.Now()
	if err := s.input(data); err != nil {
		t.Fatalf("input() failed: %v", err)
	}
	ack := decryptDataAckForTest(t, decryptBlock, readPacketForTest(t, receiverConn))
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Errorf("ACK arrived after %v, want within 100ms", elapsed)
	}
	if ack.Protocol() != ackClientToServer || ack.unAckSeq != 1 {
		t.Fatalf("ACK = %v, want %v with unAckSeq 1", ack, ackClientToServer)
	}
	if s.ackOnDataRecv.Load() {
		t.Fatal("ackOnDataRecv is still set after the ACK is sent")
	}

	// Only one ACK is sent and the session returns to idle.
	expectNoPacketForTest(t, receiverConn)

	// Heartbeat is sent when the interval expires. The last transmit time is
	// pushed back far enough to exceed the largest possible jittered interval
	// (sessionHeartbeatInterval plus the long tail), so the heartbeat is due
	// whatever jitter this session drew.
	s.lastTXTime.Store(time.Now().Add(-(4 * sessionHeartbeatInterval)).UnixMicro())
	s.wakeOutput()
	heartbeat := decryptDataAckForTest(t, decryptBlock, readPacketForTest(t, receiverConn))
	if heartbeat.Protocol() != ackClientToServer {
		t.Fatalf("heartbeat protocol = %v, want %v", heartbeat.Protocol(), ackClientToServer)
	}
	expectNoPacketForTest(t, receiverConn)
}

// TestUnderlayCloseIsConcurrentAndIdempotent verifies that closing an underlay
// from many goroutines is safe: every call returns, no shutdown step runs
// twice, and a later call is a no-op.
func TestUnderlayCloseIsConcurrentAndIdempotent(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	underlay := &StreamUnderlay{
		baseUnderlay:       *newBaseUnderlay(false, 1400, nil),
		conn:               local,
		sessionCleanTicker: time.NewTicker(sessionCleanInterval),
	}
	underlay.baseUnderlay.rawConn = local
	defer underlay.sessionCleanTicker.Stop()

	for i := 1; i <= 4; i++ {
		session := NewSession(uint32(i), false, 1400, nil, nil)
		if err := underlay.AddSession(session, nil); err != nil {
			t.Fatalf("AddSession(%d) failed: %v", i, err)
		}
	}

	const goroutines = 8
	errs := make(chan error, goroutines)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- underlay.Close()
		}()
	}
	returned := make(chan struct{})
	go func() {
		wg.Wait()
		close(returned)
	}()
	select {
	case <-returned:
	case <-time.After(5 * time.Second):
		t.Fatal("concurrent Close() didn't return")
	}
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("Close() = %v, want nil", err)
		}
	}
	if err := underlay.Close(); err != nil {
		t.Errorf("Close() after close = %v, want nil", err)
	}
}

// TestStreamUnderlayCloseReleasesEventLoopRead verifies that closing the
// underlay releases the event loop from its pending read, and that the event
// loop can release the underlying connection again after the underlay already
// closed it.
func TestStreamUnderlayCloseReleasesEventLoopRead(t *testing.T) {
	local, remote := net.Pipe()
	defer remote.Close()
	underlay := &StreamUnderlay{
		baseUnderlay:       *newBaseUnderlay(true, 1400, nil),
		conn:               local,
		sessionCleanTicker: time.NewTicker(sessionCleanInterval),
	}
	underlay.baseUnderlay.rawConn = local
	defer underlay.sessionCleanTicker.Stop()

	loopDone := make(chan error, 1)
	go func() {
		loopDone <- underlay.RunEventLoop(context.Background())
	}()
	// Give the event loop a chance to block in the read of the connection.
	time.Sleep(100 * time.Millisecond)
	if err := underlay.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	select {
	case err := <-loopDone:
		if err != nil && !stderror.IsClosed(err) && !stderror.IsTimeout(err) {
			t.Fatalf("RunEventLoop() = %v, want nil or a connection close error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunEventLoop() didn't stop after Close()")
	}

	// The connection of the underlay is already released. Running the event
	// loop after that must not panic when it releases the connection again.
	if err := underlay.RunEventLoop(context.Background()); err != nil {
		t.Fatalf("RunEventLoop() after Close() = %v, want nil", err)
	}
	if err := underlay.Close(); err != nil {
		t.Errorf("Close() after RunEventLoop() = %v, want nil", err)
	}
}

// TestPacketUnderlayCloseReleasesEventLoopRead verifies the same for the packet
// underlay, whose pending read is released by an expired read deadline.
func TestPacketUnderlayCloseReleasesEventLoopRead(t *testing.T) {
	conn, err := net.ListenPacket("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ListenPacket() failed: %v", err)
	}
	underlay := &PacketUnderlay{
		baseUnderlay:       *newBaseUnderlay(false, 1400, nil),
		conn:               conn,
		sessionCleanTicker: time.NewTicker(sessionCleanInterval),
	}
	underlay.baseUnderlay.rawConn = conn
	defer underlay.sessionCleanTicker.Stop()

	loopDone := make(chan error, 1)
	go func() {
		loopDone <- underlay.RunEventLoop(context.Background())
	}()
	// Give the event loop a chance to block in the read of the connection.
	time.Sleep(100 * time.Millisecond)
	if err := underlay.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	select {
	case err := <-loopDone:
		if err != nil && !stderror.IsClosed(err) && !stderror.IsTimeout(err) {
			t.Fatalf("RunEventLoop() = %v, want nil or a connection close error", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("RunEventLoop() didn't stop after Close()")
	}

	if err := underlay.RunEventLoop(context.Background()); err != nil {
		t.Fatalf("RunEventLoop() after Close() = %v, want nil", err)
	}
}

// TestUnderlayCloseIsNotSlowedDownBySessionCount verifies that closing an
// underlay doesn't wait for the sessions one after another.
func TestUnderlayCloseIsNotSlowedDownBySessionCount(t *testing.T) {
	// A session doesn't wait for its close session request to be written
	// anymore, so closing one session is cheap. This measurement only guards
	// against a regression that makes a single session close slow again.
	single := newTestStalledSessions(t, 1)
	start := time.Now()
	if err := single.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	singleCost := time.Since(start)

	const sessionCount = 64
	underlay := newTestStalledSessions(t, sessionCount)
	if got := underlay.SessionCount(); got != sessionCount {
		t.Fatalf("SessionCount() = %d, want %d", got, sessionCount)
	}
	start = time.Now()
	if err := underlay.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	elapsed := time.Since(start)

	// Closing the sessions one after another would cost about sessionCount
	// times the cost of closing one session, which is far above this bound.
	if limit := 6*singleCost + time.Second; elapsed > limit {
		t.Fatalf("Close() with %d stalled sessions took %v, want less than %v (one session costs %v)", sessionCount, elapsed, limit, singleCost)
	}
	if limit := 3 * time.Second; elapsed > limit {
		t.Fatalf("Close() with %d stalled sessions took %v, want less than %v", sessionCount, elapsed, limit)
	}
	underlay.sessionMap.Range(func(_, value any) bool {
		session := value.(*Session)
		if !session.isState(sessionClosed) {
			t.Errorf("session %d is %v after the underlay Close(), want %v", session.id, sessionState(session.state.Load()), sessionClosed)
		}
		return true
	})
}

// newTestStalledSessions returns a server stream underlay with n attached
// sessions whose underlay connection is never drained by the peer. That is the
// worst case for the close path of the sessions.
func newTestStalledSessions(t *testing.T, n int) *StreamUnderlay {
	t.Helper()
	local, remote := net.Pipe()
	underlay := &StreamUnderlay{
		baseUnderlay:       *newBaseUnderlay(false, 1400, nil),
		conn:               local,
		sessionCleanTicker: time.NewTicker(sessionCleanInterval),
	}
	underlay.baseUnderlay.rawConn = local
	t.Cleanup(func() {
		underlay.Close()
		remote.Close()
		underlay.sessionCleanTicker.Stop()
	})
	for i := 0; i < n; i++ {
		session := NewSession(uint32(i+1), false, 1400, nil, nil)
		if err := underlay.AddSession(session, nil); err != nil {
			t.Fatalf("AddSession(%d) failed: %v", i, err)
		}
		// The session sent a segment before, so it is closed from the data
		// plane state that a real session reaches.
		session.nextSend.Store(1)
	}
	return underlay
}

// TestStalledStreamSessionDoesNotBlockOtherSessions verifies that a session
// whose application stopped reading only affects itself: it is closed once its
// unread buffer reaches maxUnreadSegments, and the other sessions of the same
// underlay keep receiving and sending.
func TestStalledStreamSessionDoesNotBlockOtherSessions(t *testing.T) {
	// The underlay writes to a pipe that is drained in the background, like a
	// peer that keeps reading.
	local, remote := net.Pipe()
	block, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, []byte(t.Name()), false)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}
	underlay := &StreamUnderlay{
		baseUnderlay:       *newBaseUnderlay(true, 1400, nil),
		conn:               local,
		block:              block,
		sessionCleanTicker: time.NewTicker(sessionCleanInterval),
	}
	underlay.baseUnderlay.rawConn = local
	t.Cleanup(func() {
		underlay.Close()
		remote.Close()
		underlay.sessionCleanTicker.Stop()
	})
	go func() {
		_, _ = io.Copy(io.Discard, remote)
	}()

	stalled := NewSession(1, true, 1400, nil, nil)
	healthy := NewSession(2, true, 1400, nil, nil)
	for _, session := range []*Session{stalled, healthy} {
		if err := underlay.AddSession(session, nil); err != nil {
			t.Fatalf("AddSession(%d) failed: %v", session.id, err)
		}
	}

	// The application of the stalled session never reads, so the segments
	// delivered to it pile up in its receive queue until the session reaches
	// its unread buffer limit and closes itself instead of buffering more.
	for seq := uint32(0); ; seq++ {
		seg := testServerToClientDataSegment(stalled.id, seq, []byte("stalled"), common.StreamTransport)
		if !deliverSegmentWithin(t, &underlay.baseUnderlay, stalled, seg, 5*time.Second) {
			t.Fatal("the segment of the stalled session was dropped before it reached the unread buffer limit")
		}
		if stalled.closeRequested.Load() {
			break
		}
	}
	select {
	case <-stalled.closedChan:
	case <-time.After(5 * time.Second):
		t.Fatal("the stalled session was not closed after it reached the unread buffer limit")
	}
	if got := stalled.unreadSegments(); got > maxUnreadSegments {
		t.Errorf("the stalled session buffered %d unread segments, limit is %d", got, maxUnreadSegments)
	}

	// Another session of the same underlay still receives data.
	if !deliverSegmentWithin(t, &underlay.baseUnderlay, healthy, testServerToClientDataSegment(healthy.id, 0, []byte("healthy"), common.StreamTransport), 5*time.Second) {
		t.Fatal("the segment of the healthy session was dropped")
	}
	type readResult struct {
		payload string
		err     error
	}
	readDone := make(chan readResult, 1)
	go func() {
		buf := make([]byte, 16)
		n, err := healthy.Read(buf)
		readDone <- readResult{payload: string(buf[:n]), err: err}
	}()
	select {
	case res := <-readDone:
		if res.err != nil || res.payload != "healthy" {
			t.Fatalf("Read() on the healthy session = (%q, %v), want (%q, nil)", res.payload, res.err, "healthy")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read() on the healthy session didn't return")
	}

	// ... and it can still send.
	payload := make([]byte, 2*MaxSessionOpenPayload)
	for i := range payload {
		payload[i] = byte(i)
	}
	type writeResult struct {
		n   int
		err error
	}
	writeDone := make(chan writeResult, 1)
	go func() {
		n, err := healthy.Write(payload)
		writeDone <- writeResult{n: n, err: err}
	}()
	select {
	case res := <-writeDone:
		if res.err != nil || res.n != len(payload) {
			t.Fatalf("Write() on the healthy session = (%d, %v), want (%d, nil)", res.n, res.err, len(payload))
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Write() on the healthy session didn't return")
	}
	if healthy.closeRequested.Load() {
		t.Fatal("the healthy session was closed while another session was stalled")
	}
}

// TestDeliverSegmentToSessionQueueFullSemantics verifies what happens when the
// receive buffer of a session is full. The packet transport is lossy and drops
// the segment. The stream transport is reliable and waits for room.
func TestDeliverSegmentToSessionQueueFullSemantics(t *testing.T) {
	underlay := newBaseUnderlay(true, 1400, nil)
	seg := testDataSegment(1, 1, []byte("a"), common.PacketTransport)

	packetSession := NewSession(1, true, 1400, nil, nil)
	packetSession.transportProtocol = common.PacketTransport
	for i := 0; i < segmentChanCapacity; i++ {
		packetSession.recvChan <- seg
	}
	start := time.Now()
	if underlay.deliverSegmentToSession(packetSession, seg) {
		t.Fatal("deliverSegmentToSession() = true when the receive buffer of a packet session is full, want false")
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("deliverSegmentToSession() blocked %v for a full packet session, want an immediate drop", elapsed)
	}
	if got := packetSession.droppedSegments.Load(); got != 1 {
		t.Fatalf("droppedSegments = %d, want 1", got)
	}

	streamSession := NewSession(2, true, 1400, nil, nil)
	streamSession.transportProtocol = common.StreamTransport
	for i := 0; i < segmentChanCapacity; i++ {
		streamSession.recvChan <- seg
	}
	done := make(chan bool, 1)
	go func() {
		done <- underlay.deliverSegmentToSession(streamSession, seg)
	}()
	select {
	case delivered := <-done:
		t.Fatalf("deliverSegmentToSession() = %v when the receive buffer of a stream session is full, want it to wait for room", delivered)
	case <-time.After(100 * time.Millisecond):
	}
	// Free one slot. The reliable transport delivers the segment instead of
	// dropping it.
	<-streamSession.recvChan
	select {
	case delivered := <-done:
		if !delivered {
			t.Fatal("deliverSegmentToSession() = false after the receive buffer of the stream session had room, want true")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("deliverSegmentToSession() didn't return after the receive buffer of the stream session had room")
	}
	if got := streamSession.droppedSegments.Load(); got != 0 {
		t.Fatalf("droppedSegments = %d for a stream session, want 0", got)
	}
}

// TestDeliverSegmentToSessionReturnsFalseAfterUnderlayClose verifies that a
// segment is not queued when the underlay is closed, and that a delivery
// waiting for room is released by the underlay close.
func TestDeliverSegmentToSessionReturnsFalseAfterUnderlayClose(t *testing.T) {
	underlay := newBaseUnderlay(false, 1400, nil)
	packetSession := NewSession(1, false, 1400, nil, nil)
	packetSession.transportProtocol = common.PacketTransport
	if err := underlay.AddSession(packetSession, nil); err != nil {
		t.Fatalf("AddSession() failed: %v", err)
	}
	seg := testDataSegment(1, 1, []byte("a"), common.PacketTransport)
	if err := underlay.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	if underlay.deliverSegmentToSession(packetSession, seg) {
		t.Fatal("deliverSegmentToSession() = true after the underlay was closed, want false")
	}

	blockedUnderlay := newBaseUnderlay(false, 1400, nil)
	streamSession := NewSession(2, false, 1400, nil, nil)
	streamSession.transportProtocol = common.StreamTransport
	if err := blockedUnderlay.AddSession(streamSession, nil); err != nil {
		t.Fatalf("AddSession() failed: %v", err)
	}
	for i := 0; i < segmentChanCapacity; i++ {
		streamSession.recvChan <- seg
	}
	done := make(chan bool, 1)
	go func() {
		done <- blockedUnderlay.deliverSegmentToSession(streamSession, seg)
	}()
	select {
	case delivered := <-done:
		t.Fatalf("deliverSegmentToSession() returned %v before the underlay was closed, want it to wait for room", delivered)
	case <-time.After(100 * time.Millisecond):
	}
	if err := blockedUnderlay.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	select {
	case delivered := <-done:
		if delivered {
			t.Fatal("deliverSegmentToSession() = true after the underlay was closed, want false")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("deliverSegmentToSession() didn't return after the underlay was closed")
	}
}

// TestExpiredReadDeadlineFailsRead verifies that a read deadline which is
// already in the past fails the read immediately, as net.Conn requires.
func TestExpiredReadDeadlineFailsRead(t *testing.T) {
	s := NewSession(1, true, 1400, nil, nil)
	s.transportProtocol = common.StreamTransport
	if err := s.SetReadDeadline(time.Now()); err != nil {
		t.Fatalf("SetReadDeadline() failed: %v", err)
	}

	buf := make([]byte, 16)
	start := time.Now()
	n, err, returned := readWithin(t, s, buf, time.Second)
	if !returned {
		t.Fatal("Read() with an expired deadline didn't return")
	}
	if n != 0 || !stderror.IsTimeout(err) {
		t.Fatalf("Read() = (%d, %v), want (0, a timeout)", n, err)
	}
	if elapsed := time.Since(start); elapsed > 100*time.Millisecond {
		t.Fatalf("Read() with an expired deadline returned after %v, want an immediate timeout", elapsed)
	}
}

// TestReadDeadlinePersistsAcrossReads verifies that a read deadline set by the
// application stays armed for every following Read. Clearing it after the first
// Read, as the session used to do, leaves the second Read blocked forever.
func TestReadDeadlinePersistsAcrossReads(t *testing.T) {
	s := NewSession(1, true, 1400, nil, nil)
	s.transportProtocol = common.StreamTransport
	if err := s.SetReadDeadline(time.Now().Add(50 * time.Millisecond)); err != nil {
		t.Fatalf("SetReadDeadline() failed: %v", err)
	}

	buf := make([]byte, 16)
	for i := 1; i <= 2; i++ {
		start := time.Now()
		n, err, returned := readWithin(t, s, buf, 5*time.Second)
		if !returned {
			t.Fatalf("Read() call %d didn't return with a read deadline that was already set", i)
		}
		if n != 0 || !stderror.IsTimeout(err) {
			t.Fatalf("Read() call %d = (%d, %v), want (0, a timeout)", i, n, err)
		}
		if elapsed := time.Since(start); elapsed > time.Second {
			t.Fatalf("Read() call %d returned after %v, want it bounded by the read deadline", i, elapsed)
		}
		if got := s.readDeadline.Load(); got == 0 {
			t.Fatalf("read deadline was cleared by Read() call %d", i)
		}
	}
}

// TestExpiredWriteDeadlineFailsWrite verifies that an expired write deadline
// fails the write instead of being silently ignored.
func TestExpiredWriteDeadlineFailsWrite(t *testing.T) {
	s := NewSession(1, true, 1400, nil, nil)
	s.transportProtocol = common.StreamTransport
	s.forwardStateTo(sessionEstablished)
	if err := s.SetWriteDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetWriteDeadline() failed: %v", err)
	}

	start := time.Now()
	n, err := s.Write([]byte("payload"))
	if n != 0 || !stderror.IsTimeout(err) {
		t.Fatalf("Write() = (%d, %v), want (0, a timeout)", n, err)
	}
	if elapsed := time.Since(start); elapsed > time.Second {
		t.Fatalf("Write() with an expired deadline returned after %v, want an immediate timeout", elapsed)
	}
}

// TestWriteKeepsApplicationDeadlines verifies that a data plane write doesn't
// overwrite or clear the deadlines that the application set, and doesn't arm an
// internal deadline once the handshake is not pending anymore.
func TestWriteKeepsApplicationDeadlines(t *testing.T) {
	s := NewSession(1, true, 1400, nil, nil)
	s.transportProtocol = common.PacketTransport
	s.forwardStateTo(sessionEstablished)
	readDeadline := time.Now().Add(time.Minute)
	writeDeadline := time.Now().Add(2 * time.Minute)
	if err := s.SetReadDeadline(readDeadline); err != nil {
		t.Fatalf("SetReadDeadline() failed: %v", err)
	}
	if err := s.SetWriteDeadline(writeDeadline); err != nil {
		t.Fatalf("SetWriteDeadline() failed: %v", err)
	}

	payload := []byte("data plane payload")
	_, n, err := collectSessionSegments(t, s, 1, func() (int, error) {
		return s.Write(payload)
	})
	if err != nil || n != len(payload) {
		t.Fatalf("Write() = (%d, %v), want (%d, nil)", n, err, len(payload))
	}

	if got := s.readDeadline.Load(); got != readDeadline.UnixMicro() {
		t.Errorf("read deadline = %d after Write(), want the application deadline %d", got, readDeadline.UnixMicro())
	}
	if got := s.writeDeadline.Load(); got != writeDeadline.UnixMicro() {
		t.Errorf("write deadline = %d after Write(), want the application deadline %d", got, writeDeadline.UnixMicro())
	}
	if got := s.internalDeadline.Load(); got != 0 {
		t.Errorf("internal deadline = %d after a data plane Write(), want 0", got)
	}
}

// TestHandshakeDeadlineIsSeparateFromApplicationDeadline verifies that the
// internal deadline which bounds the handshake of a client lives in its own
// field: it never overwrites an application deadline, the earlier of the two is
// used, and it is ignored once the handshake is done.
func TestHandshakeDeadlineIsSeparateFromApplicationDeadline(t *testing.T) {
	s := NewSession(1, true, 1400, nil, nil)
	s.transportProtocol = common.PacketTransport
	s.forwardStateTo(sessionAttached)
	s.handshakeStarted.Store(true)

	appRead := time.Now().Add(time.Minute)
	appWrite := time.Now().Add(2 * time.Minute)
	if err := s.SetReadDeadline(appRead); err != nil {
		t.Fatalf("SetReadDeadline() failed: %v", err)
	}
	if err := s.SetWriteDeadline(appWrite); err != nil {
		t.Fatalf("SetWriteDeadline() failed: %v", err)
	}

	payload := []byte("handshake data")
	if _, _, err := collectSessionSegments(t, s, 1, func() (int, error) {
		return s.writeChunk(payload)
	}); err != nil {
		t.Fatalf("writeChunk() failed: %v", err)
	}

	if got := s.readDeadline.Load(); got != appRead.UnixMicro() {
		t.Errorf("read deadline = %d, want the application deadline %d", got, appRead.UnixMicro())
	}
	if got := s.writeDeadline.Load(); got != appWrite.UnixMicro() {
		t.Errorf("write deadline = %d, want the application deadline %d", got, appWrite.UnixMicro())
	}
	internal := s.internalDeadline.Load()
	if internal == 0 {
		t.Fatal("writeChunk() didn't arm the internal handshake deadline")
	}

	// While the handshake is pending the internal deadline, which is nearer
	// than the application deadline, is the one that applies.
	if got := s.effectiveReadDeadline(); got != internal {
		t.Fatalf("effectiveReadDeadline() = %d, want the internal deadline %d", got, internal)
	}
	if got := s.effectiveWriteDeadline(); got != internal {
		t.Fatalf("effectiveWriteDeadline() = %d, want the internal deadline %d", got, internal)
	}

	// A nearer application deadline wins over the internal one.
	near := time.Now().Add(time.Second)
	if err := s.SetReadDeadline(near); err != nil {
		t.Fatalf("SetReadDeadline() failed: %v", err)
	}
	if got := s.effectiveReadDeadline(); got != near.UnixMicro() {
		t.Fatalf("effectiveReadDeadline() = %d, want the application deadline %d", got, near.UnixMicro())
	}

	// A completed handshake makes the internal deadline irrelevant.
	s.handshakeDone.Store(true)
	if got := s.effectiveReadDeadline(); got != near.UnixMicro() {
		t.Fatalf("effectiveReadDeadline() after the handshake = %d, want the application deadline %d", got, near.UnixMicro())
	}
	if got := s.effectiveWriteDeadline(); got != appWrite.UnixMicro() {
		t.Fatalf("effectiveWriteDeadline() after the handshake = %d, want the application deadline %d", got, appWrite.UnixMicro())
	}
}

// TestCloseReturnsWhenPeerDoesNotRead verifies that Close() marks the session
// closed and returns promptly even when the underlay connection can't drain,
// and that the close session request is still delivered once the peer reads.
func TestCloseReturnsWhenPeerDoesNotRead(t *testing.T) {
	password := cipher.HashPassword([]byte(t.Name()), []byte("user"))
	block, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, password, false)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}
	local, remote := net.Pipe()
	underlay := &StreamUnderlay{
		baseUnderlay:       *newBaseUnderlay(true, 1400, nil),
		conn:               local,
		block:              block.Clone(),
		sessionCleanTicker: time.NewTicker(sessionCleanInterval),
	}
	underlay.baseUnderlay.rawConn = local
	defer underlay.Close()
	defer remote.Close()

	// The session reaches the data plane, so Close() tries to tell the peer.
	session := NewSession(1, true, 1400, nil, nil)
	if err := underlay.AddSession(session, nil); err != nil {
		t.Fatalf("AddSession() failed: %v", err)
	}
	session.forwardStateTo(sessionEstablished)

	closeDone := make(chan error, 1)
	go func() {
		closeDone <- session.Close()
	}()
	select {
	case err := <-closeDone:
		if err != nil {
			t.Fatalf("Close() = %v, want nil", err)
		}
	case <-time.After(time.Second):
		t.Fatal("Close() didn't return within 1s while the peer wasn't reading")
	}

	select {
	case <-session.closedChan:
	default:
		t.Fatal("closedChan is not closed after Close() returned")
	}

	// A second Close() reports the close of the session, which is already done.
	if err := session.Close(); err != nil {
		t.Fatalf("second Close() = %v, want nil", err)
	}

	// The close session request is best effort: Close() doesn't wait for it,
	// but it is still written to the peer.
	buf := make([]byte, 4096)
	readDone := make(chan int, 1)
	go func() {
		n, _ := remote.Read(buf)
		readDone <- n
	}()
	select {
	case n := <-readDone:
		if n == 0 {
			t.Fatal("no close session request was written to the peer")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the close session request wasn't written to the peer")
	}
}

// TestRemoteWindowSizeIgnoresStaleUpdate verifies that a window update carried
// by a reordered or duplicated segment can't shrink the send window.
func TestRemoteWindowSizeIgnoresStaleUpdate(t *testing.T) {
	tests := []struct {
		name     string
		unAckSeq uint32
		window   uint16
		want     uint32
	}{
		{"first update", 10, 100, 100},
		{"stale update", 5, 1, 100},
		{"same unAckSeq with a larger window", 10, 50, 50},
		{"newer update", 11, 20, 20},
		{"newer update with a larger unAckSeq", 12, 4096, 4096},
	}
	s := NewSession(1, true, 1400, nil, nil)
	s.transportProtocol = common.PacketTransport
	for _, test := range tests {
		seg := testDataSegment(1, 0, []byte("a"), common.PacketTransport)
		das := seg.metadata.(*dataAckStruct)
		das.baseStruct.protocol = uint8(ackServerToClient)
		das.unAckSeq = test.unAckSeq
		das.windowSize = test.window
		if err := s.input(seg); err != nil {
			t.Fatalf("%s: input() failed: %v", test.name, err)
		}
		if got := s.remoteWindowSize.Load(); got != test.want {
			t.Fatalf("%s: remoteWindowSize = %d, want %d", test.name, got, test.want)
		}
	}
}

// TestReadRefreshesReceiveWindow verifies that the application side asks for a
// window update after it consumed enough of the receive window.
func TestReadRefreshesReceiveWindow(t *testing.T) {
	s := NewSession(1, true, 1400, nil, nil)
	s.transportProtocol = common.PacketTransport
	for i := range ackWindowUpdateThreshold {
		if !s.recvQueue.Insert(testServerToClientDataSegment(s.id, uint32(i), []byte("d"), common.PacketTransport)) {
			t.Fatalf("failed to queue segment %d", i)
		}
	}
	if s.ackOnDataRecv.Load() {
		t.Fatal("an ACK is pending before the application read the segments")
	}

	buf := make([]byte, ackWindowUpdateThreshold)
	if n, err := s.Read(buf); err != nil || n != len(buf) {
		t.Fatalf("Read() = (%d, %v), want (%d, nil)", n, err, len(buf))
	}
	if !s.ackOnDataRecv.Load() {
		t.Fatal("Read() didn't request a receive window update")
	}
}

// readWithin runs Read in a separate goroutine and reports whether it returned
// within the given limit. A regression that makes Read block forever fails the
// test instead of hanging the test binary.
func readWithin(t *testing.T, s *Session, b []byte, limit time.Duration) (n int, err error, returned bool) {
	t.Helper()
	type readResult struct {
		n   int
		err error
	}
	resultCh := make(chan readResult, 1)
	go func() {
		n, err := s.Read(b)
		resultCh <- readResult{n: n, err: err}
	}()
	select {
	case result := <-resultCh:
		return result.n, result.err, true
	case <-time.After(limit):
		return 0, nil, false
	}
}

// deliverSegmentWithin delivers seg to the session in a separate goroutine and
// reports whether it was queued. The test fails when the delivery doesn't
// return in time, so a wrong expectation can't hang the test binary.
func deliverSegmentWithin(t *testing.T, underlay *baseUnderlay, s *Session, seg *segment, timeout time.Duration) bool {
	t.Helper()
	done := make(chan bool, 1)
	go func() {
		done <- underlay.deliverSegmentToSession(s, seg)
	}()
	select {
	case delivered := <-done:
		return delivered
	case <-time.After(timeout):
		t.Fatalf("deliverSegmentToSession() to session %d didn't return in %v", s.id, timeout)
		return false
	}
}

// testServerToClientDataSegment returns a data segment in the server to client
// direction, which a client session accepts.
func testServerToClientDataSegment(sessionID, seq uint32, payload []byte, transport common.TransportProtocol) *segment {
	seg := testDataSegment(sessionID, seq, payload, transport)
	seg.metadata.(*dataAckStruct).baseStruct.protocol = uint8(dataServerToClient)
	return seg
}
