// Copyright (C) 2023  mieru authors
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
// along with this program.  If not, see <https://www.gnu.org/licenses/>

package protocol

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/cipher"
	"github.com/enfein/mieru/v3/pkg/common"
	"github.com/enfein/mieru/v3/pkg/log"
	"github.com/enfein/mieru/v3/pkg/rng"
	"github.com/enfein/mieru/v3/pkg/stderror"
)

const (
	// Number of ready sessions before they are consumed by Accept().
	sessionChanCapacity = 64

	sessionCleanInterval = 5 * time.Second

	// droppedSegmentLogInterval is the number of dropped segments between two
	// debug log messages.
	droppedSegmentLogInterval = 100
)

var (
	readOneSegmentTimeout = time.Duration(60+rng.FixedIntVH(61)) * time.Second
)

// baseUnderlay contains a partial implementation of underlay.
type baseUnderlay struct {
	isClient bool
	mtu      int
	done     chan struct{} // if the underlay is closed

	// rawConn is the network connection that this underlay reads from and
	// writes to. The underlay releases it when it is closed, even if the event
	// loop hasn't started yet. The concrete underlay types set this field when
	// they are created.
	rawConn io.Closer

	sessionMap     sync.Map      // Map<sessionID, *Session>
	readySessions  chan *Session // sessions that completed handshake and ready for consume
	trafficPattern *appctlpb.TrafficPattern

	sendMutex  sync.Mutex // protect writing data to the connection
	closeMutex sync.Mutex // protect closing the connection

	inBytes  atomic.Int64
	outBytes atomic.Int64

	// ---- client fields ----
	scheduler *ScheduleController
}

var (
	_ Underlay = &baseUnderlay{}
)

func newBaseUnderlay(isClient bool, mtu int, trafficPattern *appctlpb.TrafficPattern) *baseUnderlay {
	return &baseUnderlay{
		isClient:       isClient,
		mtu:            mtu,
		done:           make(chan struct{}),
		readySessions:  make(chan *Session, sessionChanCapacity),
		trafficPattern: trafficPattern,
		scheduler:      &ScheduleController{},
	}
}

// Accept implements net.Listener interface.
func (b *baseUnderlay) Accept() (net.Conn, error) {
	select {
	case session := <-b.readySessions:
		return session, nil
	case <-b.done:
		return nil, io.ErrClosedPipe
	}
}

// Close implements net.Listener interface. The caller must hold closeMutex lock.
// Close is idempotent: the second and later calls return nil immediately.
func (b *baseUnderlay) Close() error {
	select {
	case <-b.done:
		return nil
	default:
	}

	// Release the underlying network connection first. The event loop may not
	// have started yet, so this is the only chance to release the socket file
	// descriptor. Closing the connection also unblocks the pending I/O of the
	// event loop and of the sessions. The event loop may close the connection
	// again when it stops, which is safe.
	if b.rawConn != nil {
		if err := b.rawConn.Close(); err != nil && !stderror.IsClosed(err) {
			log.Debugf("Failed to close the underlying connection: %v", err)
		}
	}

	// Close the sessions concurrently. Closing one session waits for the
	// session goroutines to stop, so closing the sessions one after another
	// makes the cost of Close() grow linearly with the number of sessions.
	sessions := make([]*Session, 0, b.SessionCount())
	b.sessionMap.Range(func(k, v any) bool {
		sessions = append(sessions, v.(*Session))
		return true
	})
	var wg sync.WaitGroup
	for _, s := range sessions {
		wg.Add(1)
		go func(s *Session) {
			defer wg.Done()
			s.Close()
			s.wg.Wait()
		}(s)
	}
	wg.Wait()

	close(b.done)
	return nil
}

// Addr implements net.Listener interface.
func (b *baseUnderlay) Addr() net.Addr {
	return common.NilNetAddr()
}

func (b *baseUnderlay) MTU() int {
	return b.mtu
}

func (b *baseUnderlay) TransportProtocol() common.TransportProtocol {
	return common.UnknownTransport
}

func (b *baseUnderlay) LocalAddr() net.Addr {
	return common.NilNetAddr()
}

func (b *baseUnderlay) RemoteAddr() net.Addr {
	return common.NilNetAddr()
}

func (b *baseUnderlay) AddSession(s *Session, remoteAddr net.Addr) error {
	if s == nil {
		return stderror.ErrNullPointer
	}
	if s.id == 0 {
		return fmt.Errorf("session ID can't be 0")
	}
	if s.isStateAfter(sessionAttached, true) {
		return fmt.Errorf("session %d is already attached to a underlay", s.id)
	}
	if b.isClient && !s.isClient {
		return fmt.Errorf("can't add a server session to a client underlay")
	}
	if !b.isClient && s.isClient {
		return fmt.Errorf("can't add a client session to a server underlay")
	}
	if _, loaded := b.sessionMap.LoadOrStore(s.id, s); loaded {
		return stderror.ErrAlreadyExist
	}
	s.conn = b
	s.remoteAddr = remoteAddr

	return nil
}

func (b *baseUnderlay) RemoveSession(s *Session) error {
	if s == nil {
		return stderror.ErrNullPointer
	}
	if s.isStateBefore(sessionAttached, false) {
		return fmt.Errorf("session %d is not attached to this underlay", s.id)
	}

	b.sessionMap.Delete(s.id)
	s.Close()
	s.wg.Wait()
	return nil
}

func (b *baseUnderlay) SessionCount() int {
	n := 0
	b.sessionMap.Range(func(k, v any) bool {
		n++
		return true
	})
	return n
}

func (b *baseUnderlay) InBytes() int64 {
	return b.inBytes.Load()
}

func (b *baseUnderlay) OutBytes() int64 {
	return b.outBytes.Load()
}

func (b *baseUnderlay) RunEventLoop(ctx context.Context) error {
	return stderror.ErrUnsupported
}

func (b *baseUnderlay) Scheduler() *ScheduleController {
	return b.scheduler
}

func (b *baseUnderlay) Done() chan struct{} {
	return b.done
}

// deliverSegmentToSession hands one segment to the given session.
//
// The segment is put into the session receive buffer, and it is moved to the
// input loop by the session delivery loop. The underlay event loop never runs
// the session input loop itself, so that one session with a slow consumer
// can't stop the underlay from serving the other sessions.
//
// The packet transport is lossy, so a segment is dropped when the session
// receive buffer is full, which means that the input loop of the session is
// too far behind. The peer retransmits the segment if it is not acknowledged.
// The stream transport is reliable, so the caller waits for room in the
// receive buffer instead.
//
// The return value is false when the segment is not queued, which happens when
// the session or the underlay is closed, and when a packet transport segment
// is dropped.
func (b *baseUnderlay) deliverSegmentToSession(s *Session, seg *segment) bool {
	if s == nil {
		return false
	}
	// Don't queue segments for a closed session or a closed underlay. This
	// check also makes the return value deterministic when the segment is
	// still buffered.
	select {
	case <-s.closedChan:
		return false
	case <-b.done:
		return false
	default:
	}
	if s.transportProtocol == common.PacketTransport {
		select {
		case s.recvChan <- seg:
			return true
		case <-s.closedChan:
			return false
		case <-b.done:
			return false
		default:
		}
		n := s.droppedSegments.Add(1)
		if n == 1 || n%droppedSegmentLogInterval == 0 {
			log.Debugf("Session %d dropped %d segments because the receive buffer is full", s.id, n)
		}
		return false
	}
	select {
	case s.recvChan <- seg:
		return true
	case <-s.closedChan:
		return false
	case <-b.done:
		return false
	}
}

// encodeLowEntropyEncryptedPayload encodes the ciphertext body with
// low entropy padding. The trailing AEAD tag is not changed.
func encodeLowEntropyEncryptedPayload(encryptedPayload []byte, das *dataAckStruct) ([]byte, error) {
	if das == nil {
		return nil, stderror.ErrNullPointer
	}
	extractedPayloadLen := int(das.extractedPayloadLen)
	expectedEncryptedLen := extractedPayloadLen + cipher.DefaultOverhead
	if len(encryptedPayload) != expectedEncryptedLen {
		return nil, fmt.Errorf("encrypted payload length is %d, want %d", len(encryptedPayload), expectedEncryptedLen)
	}
	encodedBody, err := encodeLowEntropyPayload(
		encryptedPayload[:extractedPayloadLen],
		appctlpb.LowEntropyMode(das.lowEntropyMode),
		das.lowEntropyMask,
		appctlpb.LowEntropyMaskRotation(das.lowEntropyMaskRotation),
	)
	if err != nil {
		return nil, err
	}
	if len(encodedBody) != int(das.payloadLen) {
		return nil, fmt.Errorf("encoded payload length is %d, want %d", len(encodedBody), das.payloadLen)
	}
	wirePayload := make([]byte, 0, len(encodedBody)+cipher.DefaultOverhead)
	wirePayload = append(wirePayload, encodedBody...)
	wirePayload = append(wirePayload, encryptedPayload[extractedPayloadLen:]...)
	return wirePayload, nil
}

// decodeLowEntropyEncryptedPayload removes low entropy padding from the
// encrypted payload body and appends the original AEAD tag unchanged.
func decodeLowEntropyEncryptedPayload(encryptedPayload []byte, das *dataAckStruct) ([]byte, error) {
	if das == nil {
		return nil, stderror.ErrNullPointer
	}
	if err := validateLowEntropyDataAckMetadata(das); err != nil {
		return nil, err
	}
	wirePayloadLen := int(das.payloadLen) + cipher.DefaultOverhead
	if len(encryptedPayload) != wirePayloadLen {
		return nil, fmt.Errorf("low entropy encrypted payload length is %d, want %d", len(encryptedPayload), wirePayloadLen)
	}

	decodedBody, err := decodeLowEntropyPayload(
		encryptedPayload[:das.payloadLen],
		int(das.extractedPayloadLen),
		appctlpb.LowEntropyMode(das.lowEntropyMode),
		das.lowEntropyMask,
		appctlpb.LowEntropyMaskRotation(das.lowEntropyMaskRotation),
	)
	if err != nil {
		return nil, err
	}
	reconstructed := make([]byte, 0, len(decodedBody)+cipher.DefaultOverhead)
	reconstructed = append(reconstructed, decodedBody...)
	reconstructed = append(reconstructed, encryptedPayload[das.payloadLen:]...)
	return reconstructed, nil
}

// prepareLowEntropyDataAckForSend verifies the stable per-segment metadata and
// generates the fresh half-mask used by this wire transmission.
func prepareLowEntropyDataAckForSend(das *dataAckStruct, plaintextPayloadLen int) error {
	if das == nil {
		return stderror.ErrNullPointer
	}
	if !isLowEntropyProtocol(das.Protocol()) {
		return fmt.Errorf("protocol %d is not low entropy data", das.Protocol())
	}
	if plaintextPayloadLen != int(das.extractedPayloadLen) {
		return fmt.Errorf("plaintext payload length is %d, want %d", plaintextPayloadLen, das.extractedPayloadLen)
	}
	mode := appctlpb.LowEntropyMode(das.lowEntropyMode)
	expectedPayloadLen, err := lowEntropyEncodedPayloadLen(plaintextPayloadLen, mode)
	if err != nil {
		return err
	}
	if das.payloadLen != expectedPayloadLen {
		return fmt.Errorf("low entropy payload length is %d, want %d", das.payloadLen, expectedPayloadLen)
	}
	rotation := appctlpb.LowEntropyMaskRotation(das.lowEntropyMaskRotation)
	if !isValidLowEntropyRotation(rotation) {
		return fmt.Errorf("invalid low entropy mask rotation %d", rotation)
	}
	das.lowEntropyMask, err = newLowEntropyHalfMask(mode)
	if err != nil {
		return err
	}
	return validateLowEntropyDataAckMetadata(das)
}
