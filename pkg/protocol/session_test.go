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

	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/cipher"
	"github.com/enfein/mieru/v3/pkg/common"
	"github.com/enfein/mieru/v3/pkg/stderror"
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
		{appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_32, appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION, 2, 32764, 4},
		{appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_40, appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_ROTATE_RIGHT_7, 1, maxPDU, 0},
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
				wantEncodedLen, err := lowEntropyEncodedPayloadLen(len(seg.payload), test.mode)
				if err != nil {
					t.Fatalf("lowEntropyEncodedPayloadLen() failed: %v", err)
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
				wantEncodedLen, err := lowEntropyEncodedPayloadLen(len(seg.payload), test.mode)
				if err != nil {
					t.Fatalf("lowEntropyEncodedPayloadLen() failed: %v", err)
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
	if ss.Protocol() != openSessionRequest || ss.payloadLen != uint16(len(payload)) || !bytes.Equal(segments[0].payload, payload) {
		t.Fatalf("openSessionRequest segment = %v, want piggyback payload", segments[0])
	}
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
	if ss.Protocol() != openSessionRequest || ss.payloadLen != 0 || len(segments[0].payload) != 0 {
		t.Fatalf("openSessionRequest segment = %v, want empty payload", segments[0])
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
	block, err := cipher.BlockCipherFromPassword([]byte(t.Name()), true)
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
	tests := []struct {
		name    string
		setup   func(s *Session)
		minWant time.Duration
		maxWant time.Duration
	}{
		{
			name:    "idle waits for heartbeat",
			setup:   func(s *Session) {},
			minWant: sessionHeartbeatInterval - sessionHeartbeatJitterMs*time.Millisecond - 100*time.Millisecond,
			maxWant: sessionHeartbeatInterval + sessionHeartbeatJitterMs*time.Millisecond,
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
			minWant: sessionHeartbeatInterval - sessionHeartbeatJitterMs*time.Millisecond - 100*time.Millisecond,
			maxWant: sessionHeartbeatInterval + sessionHeartbeatJitterMs*time.Millisecond,
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
	case <-s.packetOutputWakeup:
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
	case <-s.packetOutputWakeup:
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

	// Heartbeat is sent when the interval expires.
	s.lastTXTime.Store(time.Now().Add(-2 * sessionHeartbeatInterval).UnixMicro())
	s.wakePacketOutput()
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
	// Each session of this underlay can't flush its close session request, so
	// closing one session waits for the graceful close timeout before it gives
	// up. That makes the cost of closing a single session observable.
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

// newTestStalledSessions returns a server stream underlay with n sessions whose
// output can't flush the close session request, so that closing each session
// waits for the graceful close timeout before it gives up.
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
		// The session sent a segment before, so the close session request has
		// a sequence number the peer can't have received yet.
		session.nextSend.Store(1)
	}
	return underlay
}

// TestStalledStreamSessionDoesNotBlockOtherSessions verifies that a session
// whose application stopped reading only blocks its own delivery. The other
// sessions of the same underlay keep receiving and sending.
func TestStalledStreamSessionDoesNotBlockOtherSessions(t *testing.T) {
	// The underlay writes to a pipe that is drained in the background, like a
	// peer that keeps reading.
	local, remote := net.Pipe()
	block, err := cipher.BlockCipherFromPassword([]byte(t.Name()), false)
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

	// The application of the stalled session never reads, so its receive queue
	// stays full.
	for i := 0; i < segmentTreeCapacity; i++ {
		if !stalled.recvQueue.Insert(testServerToClientDataSegment(stalled.id, uint32(i), nil, common.StreamTransport)) {
			t.Fatalf("failed to fill the receive queue of the stalled session at %d", i)
		}
	}

	// Fill the receive buffer of the stalled session. Its input loop consumes
	// one segment before it blocks, so the rest fills both receive channels.
	seg := testServerToClientDataSegment(stalled.id, segmentTreeCapacity, []byte("stalled"), common.StreamTransport)
	for i := 0; i < 1+2*segmentChanCapacity; i++ {
		if !deliverSegmentWithin(t, &underlay.baseUnderlay, stalled, seg, 5*time.Second) {
			t.Fatalf("segment %d of the stalled session was dropped, want it to be queued", i)
		}
	}

	// The next segment waits for room instead of being dropped, because the
	// stream transport is reliable.
	blocked := make(chan bool, 1)
	go func() {
		blocked <- underlay.deliverSegmentToSession(stalled, seg)
	}()
	select {
	case delivered := <-blocked:
		t.Fatalf("deliverSegmentToSession() = %v for the stalled session, want it to wait for room", delivered)
	case <-time.After(100 * time.Millisecond):
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
	if got := len(stalled.recvChan); got != segmentChanCapacity {
		t.Fatalf("the receive buffer of the stalled session holds %d segments, want %d", got, segmentChanCapacity)
	}

	// Closing the stalled session releases the blocked delivery. The segment is
	// either queued before the delivery loop stops or dropped, so only the
	// prompt return is checked here.
	if err := stalled.Close(); err != nil {
		t.Fatalf("stalled.Close() failed: %v", err)
	}
	select {
	case <-blocked:
	case <-time.After(5 * time.Second):
		t.Fatal("deliverSegmentToSession() didn't return after the stalled session was closed")
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

// TestExpiredReadDeadlineDoesNotFailRead verifies that a read deadline which is
// already in the past, as it is left by a previous write, is not turned into an
// immediate timeout.
func TestExpiredReadDeadlineDoesNotFailRead(t *testing.T) {
	s := NewSession(1, true, 1400, nil, nil)
	s.transportProtocol = common.StreamTransport
	if err := s.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() failed: %v", err)
	}

	// Data that arrived before the deadline expired is still readable.
	if !s.recvQueue.Insert(testServerToClientDataSegment(s.id, 0, []byte("payload"), common.StreamTransport)) {
		t.Fatal("failed to queue a segment")
	}
	buf := make([]byte, 16)
	n, err := s.Read(buf)
	if err != nil || n != len("payload") || string(buf[:n]) != "payload" {
		t.Fatalf("Read() = (%d, %v), want (%d, nil)", n, err, len("payload"))
	}

	// An expired deadline doesn't fail a read that has nothing to return yet.
	if err := s.SetReadDeadline(time.Now().Add(-time.Second)); err != nil {
		t.Fatalf("SetReadDeadline() failed: %v", err)
	}
	readDone := make(chan error, 1)
	go func() {
		_, err := s.Read(buf)
		readDone <- err
	}()
	select {
	case err := <-readDone:
		t.Fatalf("Read() = %v with an expired deadline and no data, want it to wait", err)
	case <-time.After(200 * time.Millisecond):
	}
	if err := s.Close(); err != nil {
		t.Fatalf("Close() failed: %v", err)
	}
	select {
	case err := <-readDone:
		if err != io.EOF {
			t.Fatalf("Read() after Close() = %v, want %v", err, io.EOF)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Read() didn't return after the session was closed")
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
