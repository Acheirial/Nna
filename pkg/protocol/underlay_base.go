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
	"net/netip"
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

	// maxSessionsPerUnderlay is the maximum number of sessions that one
	// underlay serves at the same time.
	//
	// Every session owns flow control state and receive buffers, and the
	// underlay spends work on each session that stays in its registry, so an
	// unbounded registry lets an authenticated peer grow the memory and the
	// CPU cost of a shared underlay without limit. AddSession() returns an
	// error when the limit is reached, and the caller closes the session and
	// drops the message that created it, which is the behavior of a lost
	// datagram: the peer retries later.
	//
	// The limit is a last resort and not a tuning knob: a server serves all of
	// its UDP users from one underlay, so the limit is far above the session
	// count of a busy endpoint and a legitimate client never reaches it.
	maxSessionsPerUnderlay = 64 * 1024

	// removeSessionWaitTimeout bounds how long RemoveSession() waits for the
	// goroutines of the session that it removes.
	//
	// Removing a session closes it and then waits for its loops to stop.
	// Closing the session releases the loops, so the wait normally lasts only
	// as long as the loops need to notice the close. A loop that is blocked in
	// a transport call is bounded by the timeout of that call, for example by
	// streamWriteTimeout for a write to a peer that stopped reading and by
	// readOneSegmentTimeout for a read, so the goroutines of a session always
	// stop on their own.
	//
	// The wait is still bounded, because RemoveSession() runs in the event
	// loop of a stream underlay: one session whose goroutines are slow to stop
	// must not keep the event loop from serving the other sessions of the
	// connection. When the timeout expires, the session is already closed and
	// already removed from the session registry, so no participant of the
	// underlay can observe or use it any more. The only cost of giving up is
	// that the goroutines of the session release their resources when their
	// transport calls return instead of before the caller resumes, which is
	// why abandoning the wait is safe.
	//
	// The timeout is not a tuning knob: it only expires for a peer that
	// stopped making progress.
	removeSessionWaitTimeout = 5 * time.Second
)

// readOneSegmentTimeout returns the read deadline used for one metadata read.
// The value is randomized on every call so that the idle lifetime of an underlay
// can't be predicted from the host name and mieru version.
func readOneSegmentTimeout() time.Duration {
	return time.Duration(60+rng.Intn(61)) * time.Second
}

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

	// sessionCount is the number of sessions in sessionMap. AddSession() is
	// the only place that increases it and detachSession() is the only place
	// that decreases it, so the limit check of a new session doesn't iterate
	// over the map.
	sessionCount atomic.Int64

	// sessionsByAddr indexes the sessions of sessionMap by their remote
	// address, so that an underlay finds the sessions of an incoming message
	// without scanning the whole registry. One source address can own more
	// than one session, so the value is a list.
	//
	// sessionsByAddrLock protects both maps below. It is a RWMutex, because
	// the lookup runs on every packet of the data plane and the updates are
	// rare. A caller doesn't keep a reference to the lists of sessionsByAddr:
	// it uses sessionsByRemoteAddr(), which returns a snapshot.
	//
	// A session whose remote address is not a UDP address, for example the
	// session of a byte stream transport, can't be indexed. unindexedSessions
	// remembers those sessions, so that a lookup knows when the index is not
	// the complete answer.
	sessionsByAddrLock sync.RWMutex
	sessionsByAddr     map[netip.AddrPort][]*Session
	unindexedSessions  map[*Session]struct{}

	sendMutex  sync.Mutex // protect writing data to the connection
	closeMutex sync.Mutex // protect closing the connection

	// sessionWaitTimeout is the bound that RemoveSession() applies to the wait
	// for the goroutines of a removed session. It is a field rather than a
	// direct use of removeSessionWaitTimeout, so that a test can shrink it
	// instead of waiting for the production timeout.
	sessionWaitTimeout time.Duration

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
		isClient:           isClient,
		mtu:                mtu,
		done:               make(chan struct{}),
		readySessions:      make(chan *Session, sessionChanCapacity),
		trafficPattern:     trafficPattern,
		scheduler:          &ScheduleController{},
		sessionWaitTimeout: removeSessionWaitTimeout,
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
	// Reserve the slot before the session becomes visible, so that two
	// concurrent callers can't push the registry over the limit.
	if n := b.sessionCount.Add(1); n > maxSessionsPerUnderlay {
		b.sessionCount.Add(-1)
		return fmt.Errorf("underlay reached the limit of %d sessions", maxSessionsPerUnderlay)
	}
	if _, loaded := b.sessionMap.LoadOrStore(s.id, s); loaded {
		b.sessionCount.Add(-1)
		return stderror.ErrAlreadyExist
	}
	s.conn = b
	s.remoteAddr = remoteAddr
	b.indexSession(s)

	return nil
}

// detachSession removes the session from the session registry and from the
// address index. It doesn't close the session and it doesn't wait for the
// goroutines of the session, so a caller that runs in the event loop of an
// underlay doesn't block on the teardown of the session.
func (b *baseUnderlay) detachSession(s *Session) error {
	if s == nil {
		return stderror.ErrNullPointer
	}
	if s.isStateBefore(sessionAttached, false) {
		return fmt.Errorf("session %d is not attached to this underlay", s.id)
	}

	if _, loaded := b.sessionMap.LoadAndDelete(s.id); loaded {
		b.sessionCount.Add(-1)
	}
	b.unindexSession(s)
	return nil
}

// RemoveSession removes a session from the underlay connection.
//
// The session is closed and detached before the call returns, so it can't be
// used any more once it is removed. The wait for the goroutines of the session
// is bounded by sessionWaitTimeout, because the caller may run in the event
// loop of the underlay; see removeSessionWaitTimeout for why the caller can
// abandon the wait safely.
func (b *baseUnderlay) RemoveSession(s *Session) error {
	if err := b.detachSession(s); err != nil {
		return err
	}
	s.Close()
	if !b.waitSessionGoroutines(s) {
		// The session is closed and detached, so giving up the wait doesn't
		// leave it usable. Its goroutines stop within the timeout of the
		// transport call that blocks them.
		log.Debugf("Gave up waiting for the goroutines of %v after %v", s, b.sessionWaitTimeout)
	}
	return nil
}

// waitSessionGoroutines waits for the goroutines of a closed session to stop,
// for at most sessionWaitTimeout. It returns false when the wait gave up.
//
// The helper goroutine that waits for the session ends as soon as the last
// goroutine of the session stops, so giving up doesn't leak it: it only stops
// the caller from waiting.
func (b *baseUnderlay) waitSessionGoroutines(s *Session) bool {
	stopped := make(chan struct{})
	go func() {
		s.wg.Wait()
		close(stopped)
	}()
	timer := time.NewTimer(b.sessionWaitTimeout)
	defer timer.Stop()
	select {
	case <-stopped:
		return true
	case <-timer.C:
		return false
	}
}

// udpAddrPortKey converts a network address to the key type of the address
// index. The second return value is false when the address is not a UDP
// address, for example the address of a client session that is created before
// the first packet arrives, the address of a byte stream transport, and the
// address that a test or a mock creates.
//
// Both key producers, the attachment of a session and the lookup of a received
// packet, use this function, so they always agree on the key of an address.
func udpAddrPortKey(addr net.Addr) (netip.AddrPort, bool) {
	udpAddr, ok := addr.(*net.UDPAddr)
	if !ok || udpAddr == nil {
		return netip.AddrPort{}, false
	}
	ip, ok := netip.AddrFromSlice(udpAddr.IP)
	if !ok {
		return netip.AddrPort{}, false
	}
	// An IPv4 address is carried as 4 bytes or as a 16 byte IPv4 mapped
	// address, depending on the source of the address. Unmap() normalizes both
	// forms to the same value. The zone stays part of the key, because two
	// sessions of the same link local address in two zones are two different
	// endpoints.
	return netip.AddrPortFrom(ip.Unmap().WithZone(udpAddr.Zone), uint16(udpAddr.Port)), true
}

// indexSession records the session in the address index, so that
// sessionsByRemoteAddr() finds it. Repeated calls for one session are
// idempotent.
//
// The session is indexed under the remote address that its underlay reports,
// which is the address a packet of the peer carries. A session whose remote
// address is not a UDP address is recorded in unindexedSessions instead, which
// makes sessionsByRemoteAddr() report that the index is incomplete.
func (b *baseUnderlay) indexSession(s *Session) {
	key, ok := udpAddrPortKey(s.RemoteAddr())

	b.sessionsByAddrLock.Lock()
	defer b.sessionsByAddrLock.Unlock()

	if !ok {
		if b.unindexedSessions == nil {
			b.unindexedSessions = make(map[*Session]struct{})
		}
		b.unindexedSessions[s] = struct{}{}
		return
	}
	delete(b.unindexedSessions, s)
	for _, indexed := range b.sessionsByAddr[key] {
		if indexed == s {
			return
		}
	}
	if b.sessionsByAddr == nil {
		b.sessionsByAddr = make(map[netip.AddrPort][]*Session)
	}
	b.sessionsByAddr[key] = append(b.sessionsByAddr[key], s)
}

// unindexSession removes the session from the address index. It is the inverse
// of indexSession() and it is idempotent.
func (b *baseUnderlay) unindexSession(s *Session) {
	key, ok := udpAddrPortKey(s.RemoteAddr())

	b.sessionsByAddrLock.Lock()
	defer b.sessionsByAddrLock.Unlock()

	// The session is removed from the set of the unindexed sessions first:
	// when the remote address of the session became convertible after it was
	// indexed, for example when its underlay connection was installed, the
	// session can be in both structures.
	delete(b.unindexedSessions, s)
	if !ok {
		return
	}
	sessions := b.sessionsByAddr[key]
	for i, indexed := range sessions {
		if indexed != s {
			continue
		}
		sessions = append(sessions[:i], sessions[i+1:]...)
		break
	}
	if len(sessions) == 0 {
		delete(b.sessionsByAddr, key)
		return
	}
	b.sessionsByAddr[key] = sessions
}

// sessionsByRemoteAddr returns the sessions of this underlay whose remote
// address is addr, and whether the address index is the complete answer for
// addr.
//
// The returned slice is a snapshot, so the caller can decrypt with the
// sessions of the result without holding a lock. A session that is detached
// while a caller holds a snapshot stays usable: detaching doesn't close it.
//
// The index is incomplete, and the caller must scan the whole session
// registry, when addr is not a UDP address, and when a session of this
// underlay was attached with an address that can't be indexed. The lock is
// read only, so lookups of different packets never block each other.
//
// The index lock is released before this function returns, so the caller uses
// the sessions, takes their locks, and decrypts without holding it. That order
// keeps the index lock the outermost and shortest one: no session lock is ever
// held while the index is updated.
func (b *baseUnderlay) sessionsByRemoteAddr(addr net.Addr) ([]*Session, bool) {
	key, ok := udpAddrPortKey(addr)
	if !ok {
		return nil, false
	}

	b.sessionsByAddrLock.RLock()
	defer b.sessionsByAddrLock.RUnlock()

	if len(b.unindexedSessions) > 0 {
		// An address that the index can't describe is attached to this
		// underlay, so an address that is missing from the index can still
		// belong to a session.
		return nil, false
	}
	sessions := b.sessionsByAddr[key]
	if len(sessions) == 0 {
		return nil, true
	}
	snapshot := make([]*Session, len(sessions))
	copy(snapshot, sessions)
	return snapshot, true
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
// generates the fresh half-mask used by this wire transmission. The half-mask
// decides how many plaintext bytes each chunk carries, so it is generated
// first and the encoded payload length is then computed from its stride.
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
	rotation := appctlpb.LowEntropyMaskRotation(das.lowEntropyMaskRotation)
	mask, err := newLowEntropyHalfMask(mode)
	if err != nil {
		return err
	}
	das.lowEntropyMask = mask
	params, err := validateLowEntropyCodecParams(mode, mask, rotation)
	if err != nil {
		return err
	}
	payloadLen, err := lowEntropyEncodedPayloadLen(plaintextPayloadLen, params.sourceBytesPerChunk)
	if err != nil {
		return err
	}
	das.payloadLen = payloadLen
	return validateLowEntropyDataAckMetadata(das)
}
