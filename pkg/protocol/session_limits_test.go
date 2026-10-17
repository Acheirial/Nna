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

// Tests for the resource bounds of a session and for the copies that run on
// it: the unread buffer limit and the write back pressure (B4), io.ReaderFrom
// and io.WriterTo (C2a), the send rate bound derived from the receive window
// that the peer advertised (C10), the pools of the send path (C5) and the
// allocation budget of one UDP data packet (D5).

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

// testCountingWriter counts the writes and the bytes it receives, and keeps a
// copy of them.
type testCountingWriter struct {
	writes atomic.Int64
	bytes  atomic.Int64

	// mu guards buf.
	mu  sync.Mutex
	buf bytes.Buffer
}

func (w *testCountingWriter) Write(b []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	n, err := w.buf.Write(b)
	w.writes.Add(1)
	w.bytes.Add(int64(n))
	return n, err
}

// copied returns a copy of the bytes written to the writer so far.
func (w *testCountingWriter) copied() []byte {
	w.mu.Lock()
	defer w.mu.Unlock()
	return append([]byte(nil), w.buf.Bytes()...)
}

// TestStreamUnreadBufferLimitClosesSession verifies that a stream session whose
// application stopped reading is closed once it buffered maxUnreadSegments
// segments, and that the close reports a recognizable reason.
func TestStreamUnreadBufferLimitClosesSession(t *testing.T) {
	s := NewSession(1, true, 1400, nil, nil)
	s.transportProtocol = common.StreamTransport
	// The test session is not attached to an underlay, so the close below has
	// no close session request to send and needs no connection.
	if s.isState(sessionAttached) {
		t.Fatal("the test session is attached, want an unattached session")
	}

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	errCh := make(chan error, 1)
	go func() {
		errCh <- s.runInputLoop(ctx)
	}()

	// The underlay feeds data segments, and the application of the session
	// never reads them.
	feedDone := make(chan struct{})
	go func() {
		defer close(feedDone)
		for seq := uint32(1); ; seq++ {
			seg := testServerToClientDataSegment(s.id, seq, []byte("x"), common.StreamTransport)
			select {
			case s.recvChan <- seg:
			case <-s.closedChan:
				return
			}
		}
	}()

	// The session closes itself and reports why.
	select {
	case err := <-errCh:
		if !errors.Is(err, errUnreadLimit) {
			t.Fatalf("runInputLoop() = %v, want an error that matches %v", err, errUnreadLimit)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("the session never reached the unread buffer limit")
	}
	select {
	case <-s.closedChan:
	default:
		t.Fatal("closedChan is not closed after the unread buffer limit was reached")
	}

	// The session stopped buffering at the limit, and the application observes
	// the close on the next write.
	if got := s.unreadSegments(); got != maxUnreadSegments {
		t.Errorf("unreadSegments() = %d, want %d", got, maxUnreadSegments)
	}
	if _, err := s.Write([]byte("x")); err == nil {
		t.Error("Write() on a session that hit the unread buffer limit = nil, want an error")
	}

	select {
	case <-feedDone:
	case <-time.After(5 * time.Second):
		t.Fatal("the feeder goroutine didn't stop after the session was closed")
	}
}

// TestStreamWriteBackpressureAtSendQueueLimit verifies that a full send queue
// blocks the application instead of letting a session buffer more data than its
// bound.
func TestStreamWriteBackpressureAtSendQueueLimit(t *testing.T) {
	s := NewSession(1, false, 1400, nil, nil)
	s.transportProtocol = common.StreamTransport
	s.forwardStateTo(sessionAttached)

	// Fill the send queue to its capacity, so that the next write has to wait
	// for room.
	for seq := uint32(1); seq <= segmentSendQueueTreeCapacity; seq++ {
		if !s.sendQueue.Insert(testDataSegment(s.id, seq, []byte("q"), common.StreamTransport)) {
			t.Fatalf("failed to fill the send queue at segment %d", seq)
		}
	}
	if got := s.sendQueue.Len(); got != segmentSendQueueTreeCapacity {
		t.Fatalf("send queue length = %d, want %d", got, segmentSendQueueTreeCapacity)
	}

	writeErr := make(chan error, 1)
	writeReturned := make(chan struct{})
	go func() {
		defer close(writeReturned)
		_, err := s.Write([]byte("data"))
		writeErr <- err
	}()

	select {
	case <-writeReturned:
		t.Fatal("Write() returned while the send queue was full, want it to wait for room")
	case <-time.After(50 * time.Millisecond):
	}

	// The output loop of a session drains the queue, which unblocks the writer.
	// The drained segments are released the way the output loop releases them.
	var sent [][]byte
	drained := make(chan struct{})
	go func() {
		defer close(drained)
		drain := func() {
			for {
				seg, ok := s.sendQueue.DeleteMin()
				if !ok {
					return
				}
				sent = append(sent, append([]byte(nil), seg.payload...))
				releaseSendSegment(seg)
			}
		}
		for {
			drain()
			select {
			case <-writeReturned:
				drain()
				return
			case <-s.sendQueue.chanNotEmptyEvent:
			}
		}
	}()

	select {
	case err := <-writeErr:
		if err != nil {
			t.Fatalf("Write() = %v, want nil", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("Write() didn't return after the send queue was drained")
	}
	select {
	case <-drained:
	case <-time.After(5 * time.Second):
		t.Fatal("the draining goroutine didn't stop")
	}
	if len(sent) == 0 || !bytes.Equal(sent[len(sent)-1], []byte("data")) {
		t.Fatalf("the drained segments end with %q, want the written data", sent[len(sent)-1])
	}
	if got := s.sendQueue.Len(); got != 0 {
		t.Errorf("send queue length after the drain = %d, want 0", got)
	}
	// The session is intentionally not closed: it is attached but has no
	// underlay connection, so a close session request has nowhere to go.
}

// TestSessionCopyUsesReaderFromAndWriterTo verifies that io.Copy and
// io.CopyBuffer take the ReadFrom and WriteTo paths of a session, and that the
// data of a copy is unchanged.
func TestSessionCopyUsesReaderFromAndWriterTo(t *testing.T) {
	var conn net.Conn = NewSession(1, false, 1400, nil, nil)
	if _, ok := conn.(io.ReaderFrom); !ok {
		t.Fatal("Session does not implement io.ReaderFrom")
	}
	if _, ok := conn.(io.WriterTo); !ok {
		t.Fatal("Session does not implement io.WriterTo")
	}

	t.Run("WriteTo", func(t *testing.T) {
		s := NewSession(1, false, 1400, nil, nil)
		s.transportProtocol = common.StreamTransport
		chunks := [][]byte{[]byte("first segment"), []byte("second segment"), []byte("third segment")}
		var want []byte
		for i, chunk := range chunks {
			if !s.recvQueue.Insert(testDataSegment(s.id, uint32(10+i), chunk, common.StreamTransport)) {
				t.Fatalf("failed to queue segment %d", i)
			}
			want = append(want, chunk...)
		}
		// A copy of a session ends when the session reports io.EOF, which a
		// closed session reports once the data it buffered has been read.
		if err := s.Close(); err != nil {
			t.Fatalf("Close() failed: %v", err)
		}

		canary := bytes.Repeat([]byte{0xaa}, 64*1024)
		relay := append([]byte(nil), canary...)
		w := &testCountingWriter{}
		n, err := io.CopyBuffer(w, s, relay)
		if err != nil {
			t.Fatalf("io.CopyBuffer() failed: %v", err)
		}
		if n != int64(len(want)) || w.bytes.Load() != int64(len(want)) {
			t.Fatalf("io.CopyBuffer() copied %d bytes and wrote %d, want %d", n, w.bytes.Load(), len(want))
		}
		if got := w.copied(); !bytes.Equal(got, want) {
			t.Fatalf("io.CopyBuffer() wrote %q, want %q", got, want)
		}
		if !bytes.Equal(relay, canary) {
			t.Fatal("io.CopyBuffer() used the relay buffer of the caller, so Session.WriteTo was not called")
		}
	})

	t.Run("ReadFrom", func(t *testing.T) {
		s := NewSession(1, false, 1400, nil, nil)
		s.transportProtocol = common.StreamTransport
		s.forwardStateTo(sessionAttached)
		data := bytes.Repeat([]byte("payload"), 8192)

		canary := bytes.Repeat([]byte{0xaa}, 64*1024)
		relay := append([]byte(nil), canary...)

		type copyResult struct {
			n   int64
			err error
		}
		resultCh := make(chan copyResult, 1)
		go func() {
			n, err := io.CopyBuffer(s, bytes.NewReader(data), relay)
			resultCh <- copyResult{n: n, err: err}
		}()

		// Drain the send queue the way the output loop of a session does. The
		// write path waits for room, so the copy only makes progress while the
		// queue is drained.
		var sent []byte
		for {
			for {
				seg, ok := s.sendQueue.DeleteMin()
				if !ok {
					break
				}
				sent = append(sent, seg.payload...)
				releaseSendSegment(seg)
			}
			select {
			case res := <-resultCh:
				if res.err != nil {
					t.Fatalf("io.CopyBuffer() failed: %v", res.err)
				}
				if res.n != int64(len(data)) {
					t.Fatalf("io.CopyBuffer() copied %d bytes, want %d", res.n, len(data))
				}
				if !bytes.Equal(sent, data) {
					t.Fatalf("the session sent %d bytes, want the %d bytes of the copy", len(sent), len(data))
				}
				if !bytes.Equal(relay, canary) {
					t.Fatal("io.CopyBuffer() used the relay buffer of the caller, so Session.ReadFrom was not called")
				}
				return
			case <-s.sendQueue.chanNotEmptyEvent:
			}
		}
	})
}

// TestStreamOutputRespectsRemoteWindow verifies that the stream output loop
// bounds a pass with the receive window that the peer advertised, and that a
// window which is exhausted or stale only slows the loop down.
func TestStreamOutputRespectsRemoteWindow(t *testing.T) {
	t.Run("send budget", func(t *testing.T) {
		tests := []struct {
			name   string
			window uint32
			want   int
		}{
			{"exhausted window uses the floor", 0, streamSendWindowFloor},
			{"window below the queue length", 3, 3},
			{"window above the queue length", segmentTreeCapacity, segmentTreeCapacity},
		}
		for _, test := range tests {
			t.Run(test.name, func(t *testing.T) {
				s := NewSession(1, true, 1400, nil, nil)
				s.remoteWindowSize.Store(test.window)
				if got := s.streamSendWindow(); got != test.want {
					t.Errorf("streamSendWindow() with a remote window of %d = %d, want %d", test.window, got, test.want)
				}
			})
		}
	})

	t.Run("exhausted window only slows the output loop down", func(t *testing.T) {
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
		// The peer reads everything the session writes.
		reader := &testCountingWriter{}
		go func() {
			_, _ = io.Copy(reader, remote)
		}()

		// The session is not attached to the underlay with AddSession, so no
		// output loop runs until this test starts one.
		s := NewSession(1, true, 1400, nil, nil)
		s.conn = underlay
		s.transportProtocol = common.StreamTransport
		s.forwardStateTo(sessionEstablished)
		// The peer advertised a window of two segments and never refreshed it.
		s.remoteWindowSize.Store(2)

		const want = 5
		for seq := uint32(1); seq <= want; seq++ {
			if !s.sendQueue.Insert(testDataSegment(s.id, seq, []byte("segment"), common.StreamTransport)) {
				t.Fatalf("failed to queue segment %d", seq)
			}
		}

		// One pass hands over the segments of the window and stops.
		s.runOutputOnceStream()
		if got := s.sendQueue.Len(); got != want-2 {
			t.Fatalf("send queue length after one pass with a window of 2 = %d, want %d", got, want-2)
		}
		if s.outputHasErr.Load() {
			t.Fatal("the output of the session failed")
		}

		// The output loop makes progress even though the window stays
		// exhausted: it wakes itself up until the send queue is drained.
		ctx, cancel := context.WithCancel(context.Background())
		defer cancel()
		go s.runOutputLoop(ctx)
		select {
		case <-s.sendQueue.chanEmptyEvent:
		case <-time.After(5 * time.Second):
			t.Fatalf("the session stopped with %d segments queued and an exhausted window", s.sendQueue.Len())
		}
		if s.outputHasErr.Load() {
			t.Fatal("the output of the session failed while it drained an exhausted window")
		}
		if got := reader.bytes.Load(); got == 0 {
			t.Fatal("the peer received no data while the window was exhausted")
		}
	})
}

// TestSendSegmentPoolReleasesReferences verifies the invariants that the pools
// of the send path rely on: a released segment holds no reference, a reused
// segment carries no state of its previous user, and a segment that the pool
// didn't create is left alone.
func TestSendSegmentPoolReleasesReferences(t *testing.T) {
	block, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, []byte(t.Name()), false)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}

	seg := acquireSendSegment(dataClientToServer, 7, common.PacketTransport)
	seg.payload = []byte("payload")
	seg.block = block
	seg.txCount = 3
	seg.txTime = 42
	seg.txTimeout = time.Second
	releaseSendSegment(seg)

	if seg.metadata != nil || seg.payload != nil || seg.block != nil {
		t.Errorf("a released segment still holds references: %+v", seg)
	}
	if seg.transport != 0 || seg.txCount != 0 || seg.txTime != 0 || seg.txTimeout != 0 || seg.ackCount != 0 {
		t.Errorf("a released segment still holds its state: %+v", seg)
	}

	// The acquired segment carries only its new protocol, session ID and
	// transport, whether the pool handed over the released object or a new one.
	reused := acquireSendSegment(dataServerToClient, 8, common.StreamTransport)
	reusedDas, ok := reused.metadata.(*dataAckStruct)
	if !ok {
		t.Fatalf("the metadata of an acquired segment is %T, want *dataAckStruct", reused.metadata)
	}
	if reusedDas.Protocol() != dataServerToClient || reusedDas.sessionID != 8 {
		t.Errorf("metadata of an acquired segment = %v, want protocol %v and session 8", reusedDas, dataServerToClient)
	}
	if reusedDas.seq != 0 || reusedDas.unAckSeq != 0 || reusedDas.windowSize != 0 || reusedDas.payloadLen != 0 ||
		reusedDas.fragment != 0 || reusedDas.prefixLen != 0 || reusedDas.suffixLen != 0 {
		t.Errorf("an acquired segment keeps the metadata of its previous user: %v", reusedDas)
	}
	if reused.payload != nil || reused.block != nil || reused.transport != common.StreamTransport {
		t.Errorf("an acquired segment keeps the state of its previous user: %+v", reused)
	}
	releaseSendSegment(reused)

	// A segment that the pool didn't create is not touched.
	sessionSeg := testSessionSegment(openSessionRequest, 1, common.StreamTransport)
	releaseSendSegment(sessionSeg)
	if sessionSeg.metadata == nil {
		t.Error("releaseSendSegment() cleared the metadata of a segment that the pool didn't create")
	}
	// Releasing nothing is allowed, so that a release point doesn't need a nil
	// check of its own.
	releaseSendSegment(nil)
}

// TestPooledSendSegmentsKeepTheirPayloadOnRetransmission verifies that the
// storage of a segment that left the send buffer can be reused by a new segment
// without corrupting the payloads that are still waiting for an ACK.
func TestPooledSendSegmentsKeepTheirPayloadOnRetransmission(t *testing.T) {
	s, receiverConn, block := newTestPacketSession(t)
	receiver := &PacketUnderlay{
		baseUnderlay: *newBaseUnderlay(true, 1400, nil),
		conn:         receiverConn,
		serverAddr:   s.LocalAddr(),
		block:        block,
	}

	// writeChunk() waits for the send queue to drain, which the output loop of
	// a session does; this test drives the output itself, and numbers the
	// segments from one on so that the wait of the first write returns at once.
	s.nextSend.Store(1)

	// want maps the sequence number of a segment in the send buffer to the
	// payload it must carry on the wire.
	want := map[uint32][]byte{}
	write := func(payload []byte) uint32 {
		t.Helper()
		n, err := s.writeChunk(payload)
		if err != nil || n != len(payload) {
			t.Fatalf("writeChunk(%q) = (%d, %v), want (%d, nil)", payload, n, err, len(payload))
		}
		seq := s.nextSend.Load() - 1
		want[seq] = append([]byte(nil), payload...)
		s.runOutputOncePacket()
		return seq
	}

	// readExpected reads datagrams until every wanted sequence number arrived.
	// A datagram that the test doesn't wait for, for example a retransmission
	// that the timer of a previous pass armed, is ignored.
	readExpected := func(seqs ...uint32) map[uint32][]byte {
		t.Helper()
		expected := map[uint32]bool{}
		for _, seq := range seqs {
			expected[seq] = true
		}
		got := map[uint32][]byte{}
		deadline := time.Now().Add(5 * time.Second)
		for len(got) < len(expected) {
			segCh := make(chan *segment, 1)
			go func() {
				seg, _, err := receiver.readOneSegment()
				if err != nil {
					seg = nil
				}
				segCh <- seg
			}()
			select {
			case seg := <-segCh:
				if seg == nil {
					t.Fatalf("%d of %d datagrams are missing", len(expected)-len(got), len(expected))
				}
				das, ok := seg.metadata.(*dataAckStruct)
				if !ok || !expected[das.seq] {
					continue
				}
				if _, seen := got[das.seq]; seen {
					continue
				}
				got[das.seq] = append([]byte(nil), seg.payload...)
			case <-time.After(time.Until(deadline)):
				t.Fatalf("%d of %d datagrams are missing", len(expected)-len(got), len(expected))
			}
		}
		return got
	}

	// Fill the send buffer with three sent segments.
	var seqs []uint32
	for _, payload := range [][]byte{[]byte("payload one"), []byte("payload two"), []byte("payload three")} {
		seqs = append(seqs, write(payload))
	}
	if s.sendBuf.Len() != len(seqs) {
		t.Fatalf("send buffer length = %d, want %d", s.sendBuf.Len(), len(seqs))
	}
	for seq, payload := range readExpected(seqs...) {
		if !bytes.Equal(payload, want[seq]) {
			t.Fatalf("segment %d carries %q, want %q", seq, payload, want[seq])
		}
	}

	// Every round acknowledges one segment, which hands its storage back to the
	// pool, writes a new segment that may reuse that storage, and then forces a
	// retransmission of everything that is still waiting for an ACK.
	for round := range 3 {
		oldest, err := s.sendBuf.MinSeq()
		if err != nil {
			t.Fatalf("round %d: the send buffer is empty: %v", round, err)
		}
		ack := testDataSegment(s.id, 0, nil, common.PacketTransport)
		ackDas := ack.metadata.(*dataAckStruct)
		ackDas.baseStruct.protocol = uint8(ackServerToClient)
		ackDas.unAckSeq = oldest + 1
		ackDas.windowSize = uint16(segmentTreeCapacity)
		if err := s.input(ack); err != nil {
			t.Fatalf("round %d: input(ACK of segment %d) failed: %v", round, oldest, err)
		}
		delete(want, oldest)

		reused := write([]byte(fmt.Sprintf("reused payload %d", round)))
		for seq, payload := range readExpected(reused) {
			if !bytes.Equal(payload, want[seq]) {
				t.Fatalf("round %d: segment %d carries %q, want %q", round, seq, payload, want[seq])
			}
		}

		var outstanding []uint32
		s.sendBuf.Ascend(func(iter *segment) bool {
			seq, _ := iter.Seq()
			outstanding = append(outstanding, seq)
			iter.txTime = 0
			return true
		})
		if len(outstanding) != len(want) {
			t.Fatalf("round %d: the send buffer holds %d segments, want %d", round, len(outstanding), len(want))
		}
		s.nextRetransmissionTime.Store(0)
		s.runOutputOncePacket()
		for seq, payload := range readExpected(outstanding...) {
			if !bytes.Equal(payload, want[seq]) {
				t.Fatalf("round %d: retransmitted segment %d carries %q, want %q", round, seq, payload, want[seq])
			}
		}
	}
}

// budgetTestAddr is the remote address that the discard connection of the
// allocation budget test reports.
var budgetTestAddr = &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 9}

// discardPacketConn is a net.PacketConn that drops every datagram. It keeps the
// allocation budget of the send path measurable without a socket, a receive
// buffer and a reader goroutine inside the measurement window.
type discardPacketConn struct{}

func (discardPacketConn) ReadFrom([]byte) (int, net.Addr, error) {
	return 0, nil, io.EOF
}

func (discardPacketConn) WriteTo(b []byte, _ net.Addr) (int, error) {
	return len(b), nil
}

func (discardPacketConn) Close() error {
	return nil
}

func (discardPacketConn) LocalAddr() net.Addr {
	return budgetTestAddr
}

func (discardPacketConn) SetDeadline(time.Time) error {
	return nil
}

func (discardPacketConn) SetReadDeadline(time.Time) error {
	return nil
}

func (discardPacketConn) SetWriteDeadline(time.Time) error {
	return nil
}

// TestPacketSendAllocationBudget verifies the allocation budget of the send
// path of one UDP data packet: framing the segment, queueing it, handing it to
// the underlay and returning its storage to the pool.
//
// The budget is deliberately loose, so that it is a regression guard and not a
// tripwire for an unrelated allocation elsewhere in the process. Tighten it
// once the first CI run shows the real number; the pooled segment acquisition
// below is already asserted on its own.
func TestPacketSendAllocationBudget(t *testing.T) {
	block, err := cipher.BlockCipherFromPassword(cipher.SuiteXChaCha20Poly1305, []byte(t.Name()), true)
	if err != nil {
		t.Fatalf("BlockCipherFromPassword() failed: %v", err)
	}
	underlay := &PacketUnderlay{
		baseUnderlay: *newBaseUnderlay(true, 1400, nil),
		conn:         discardPacketConn{},
		serverAddr:   budgetTestAddr,
		block:        block,
	}
	s := NewSession(1, true, 1400, nil, nil)
	s.conn = underlay
	s.transportProtocol = common.PacketTransport
	s.remoteAddr = budgetTestAddr
	s.forwardStateTo(sessionEstablished)
	// The first write of the test must not wait for the send queue to drain,
	// because the test drains it itself inside the measured function.
	s.nextSend.Store(1)

	payload := make([]byte, 128)
	for i := range payload {
		payload[i] = byte(i)
	}

	// AllocsPerRun() calls the measured function once to warm it up, in
	// addition to the runs it measures, so the pools of the send path are
	// already filled when the measurement starts.
	const runs = 100
	const maxAllocsPerPacket = 16

	allocs := testing.AllocsPerRun(runs, func() {
		n, err := s.writeChunk(payload)
		if err != nil || n != len(payload) {
			t.Fatalf("writeChunk() = (%d, %v), want (%d, nil)", n, err, len(payload))
		}
		seg, ok := s.sendQueue.DeleteMin()
		if !ok {
			t.Fatal("the written segment is not in the send queue")
		}
		if err := s.output(seg, s.remoteAddr); err != nil {
			t.Fatalf("output() failed: %v", err)
		}
		releaseSendSegment(seg)
	})
	if allocs > maxAllocsPerPacket {
		t.Errorf("the send path of one UDP data packet allocated %v times, want at most %d", allocs, maxAllocsPerPacket)
	}

	// Acquiring and releasing a segment must not allocate. A garbage
	// collection can flush the pool, which costs one allocation in the first
	// measured run, so the assertion allows less than one allocation per
	// segment on average.
	segmentAllocs := testing.AllocsPerRun(runs, func() {
		seg := acquireSendSegment(dataClientToServer, s.id, common.PacketTransport)
		releaseSendSegment(seg)
	})
	if segmentAllocs >= 1 {
		t.Errorf("acquiring a segment of the send path allocated %v times per segment, want less than 1", segmentAllocs)
	}
}
