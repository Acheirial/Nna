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
// along with this program.  If not, see <https://www.gnu.org/licenses/>.

package protocol

import (
	"context"
	"crypto/ecdh"
	crand "crypto/rand"
	"errors"
	"fmt"
	"io"
	"math"
	mrand "math/rand"
	"net"
	"slices"
	"sync"
	"sync/atomic"
	"time"

	apicommon "github.com/Acheirial/shadowlemon/v3/apis/common"
	"github.com/Acheirial/shadowlemon/v3/pkg/appctl/appctlpb"
	"github.com/Acheirial/shadowlemon/v3/pkg/cipher"
	"github.com/Acheirial/shadowlemon/v3/pkg/common"
	"github.com/Acheirial/shadowlemon/v3/pkg/congestion"
	"github.com/Acheirial/shadowlemon/v3/pkg/log"
	"github.com/Acheirial/shadowlemon/v3/pkg/mathext"
	"github.com/Acheirial/shadowlemon/v3/pkg/protocol/serveruser"
	"github.com/Acheirial/shadowlemon/v3/pkg/stderror"
	"github.com/Acheirial/shadowlemon/v3/pkg/version"
)

const (
	// Buffer some segments before blocking the underlay input loop.
	segmentChanCapacity = 256

	// Maximum number of segments in a queue or buffer.
	segmentTreeCapacity = 4096

	// Use a smaller number in sendQueue to produce earlier write backpressure.
	segmentSendQueueTreeCapacity = 1024

	minWindowSize = 16
	maxWindowSize = segmentTreeCapacity

	serverRespTimeout        = 10 * time.Second
	sessionHeartbeatInterval = 5 * time.Second

	// sessionHeartbeatJitterMs is the base heartbeat jitter in milliseconds.
	// randomHeartbeatJitter draws the delay of a heartbeat uniformly in
	// [-sessionHeartbeatJitterMs, +sessionHeartbeatJitterMs] and, with
	// probability 1/8, adds a long tail of up to 8*sessionHeartbeatJitterMs
	// more. An idle packet session therefore still refreshes its NAT binding
	// on time in the common case, but its heartbeat is no longer a periodic
	// beacon that an observer can use to identify the tunnel.
	sessionHeartbeatJitterMs = 1000

	// minOutputInterval is the minimum interval between two output loops.
	minOutputInterval = 1 * time.Millisecond

	// backPressureDelay is the polling interval used to add back pressure
	// while waiting for room in the receive queue.
	backPressureDelay = 100 * time.Microsecond

	// packetAckDelay is the maximum time the packet transport waits before it
	// acknowledges received data. Segments received within this window
	// share a single ACK, which bounds the ACK rate.
	packetAckDelay = 1 * time.Millisecond

	// retransmissionCheckDelay is the time to wait before the first
	// retransmission check after new segments are sent into an empty
	// send buffer.
	retransmissionCheckDelay = 10 * time.Millisecond

	// Number of ack to trigger early retransmission.
	earlyRetransmission = 3
	// Maximum number of early retransmission attempt.
	earlyRetransmissionLimit = 1
	// Send timeout back off multiplier.
	txTimeoutBackOff = 1.5
	// Maximum back off duration.
	maxBackOffDuration = 10 * time.Second

	// ackWindowUpdateThreshold is the number of segments the application must
	// read before the session proactively sends an ACK that carries the updated
	// receive window to the peer. A peer stops sending once the receive window
	// it was told about reaches zero, and then no further segment arrives to
	// trigger the delayed ACK, so the reading side has to refresh the window.
	// Updating it after half of the receive window has been consumed keeps the
	// extra ACK rate low while bounding how long the peer stays stalled.
	ackWindowUpdateThreshold = segmentTreeCapacity / 2

	// maxUnreadSegments is the hard limit of segments that a stream session
	// buffers for the application without the application reading them. The
	// receive trees of a session hold up to segmentTreeCapacity segments each,
	// so without this limit an application that stopped reading lets one
	// session hold ~128 MiB (4096 segments of up to 32 KiB) while the peer
	// keeps sending; the limit bounds that at ~16 MiB. The packet transport
	// doesn't need it, because the receive window a packet session advertises
	// stops the peer before its trees fill up.
	//
	// A session that reaches the limit is closed with errUnreadLimit. The
	// send path has its own bound: Write() blocks (back pressure) while the
	// send queue holds segmentSendQueueTreeCapacity segments.
	maxUnreadSegments = 512

	// streamSendWindowFloor is the smallest number of segments that one pass of
	// the stream output loop may send, whatever receive window the peer
	// advertised. The stream transport has no window update of its own, so a
	// stale window - in particular the zero that a peer with a full receive
	// buffer advertises - may slow a pass down to this many segments but must
	// never stop a session.
	streamSendWindowFloor = 1
)

// errUnreadLimit is the sentinel error that closes a session whose unread
// buffer reached maxUnreadSegments. It is recognizable with errors.Is, so a
// caller can tell a session that was closed for buffering too much unread data
// apart from any other failure.
var errUnreadLimit = errors.New("session unread buffer is full")

type sessionState int32

const (
	sessionInit        sessionState = 0
	sessionAttached    sessionState = 1
	sessionEstablished sessionState = 2
	sessionClosed      sessionState = 3
)

func (ss sessionState) String() string {
	switch ss {
	case sessionInit:
		return "INITIALIZED"
	case sessionAttached:
		return "ATTACHED"
	case sessionEstablished:
		return "ESTABLISHED"
	case sessionClosed:
		return "CLOSED"
	default:
		return "UNKNOWN"
	}
}

type Session struct {
	conn  Underlay                           // underlay connection
	block atomic.Pointer[cipher.BlockCipher] // cipher to decrypt data
	// sendBlock is the cipher that protects the data that this session sends
	// after a handshake installed the session keys. It is nil when no
	// handshake has completed yet, and the transport of the session falls back
	// to its static cipher in that case.
	sendBlock atomic.Pointer[cipher.BlockCipher]

	id                uint32                   // session ID number
	isClient          bool                     // if this session is owned by client
	mtu               int                      // Underlay maxinum transmission unit
	transportProtocol common.TransportProtocol // transport protocol of underlay connection
	remoteAddr        net.Addr                 // specify remote network address, used by UDP
	state             atomic.Int32             // session state
	status            statusCode               // session status

	trafficPattern *appctlpb.TrafficPattern

	ready          chan struct{} // indicate the session is ready to use
	closeRequested atomic.Bool   // the session is being closed or has been closed
	closedChan     chan struct{} // indicate the session is closed
	// readDeadline is the read deadline set by the application through
	// SetReadDeadline, in microseconds since Unix epoch. 0 means no deadline.
	readDeadline atomic.Int64
	// writeDeadline is the write deadline set by the application through
	// SetWriteDeadline, in microseconds since Unix epoch. 0 means no deadline.
	writeDeadline atomic.Int64
	// internalDeadline is the deadline the session arms for itself while the
	// handshake of a client session is pending, in microseconds since Unix
	// epoch. It bounds how long the client waits for the response of the
	// server. It never overwrites an application deadline and is ignored once
	// the handshake is done.
	internalDeadline atomic.Int64
	inputHasErr      atomic.Bool // input has error
	inputErr         chan error  // this channel is closed when input has error
	outputHasErr     atomic.Bool // output has error
	outputErr        chan error  // this channel is closed when output has error

	sendQueue *segmentTree  // segments waiting to send
	sendBuf   *segmentTree  // segments sent but not acknowledged
	recvBuf   *segmentTree  // segments received but acknowledge is not sent
	recvQueue *segmentTree  // segments waiting to be read by application
	recvChan  chan *segment // channel to receive segments from underlay

	// inputChan holds the segments that the session delivery loop moved from
	// recvChan, and that wait for the input loop to process them.
	inputChan       chan *segment
	droppedSegments atomic.Int64 // number of segments dropped by the underlay

	outputWakeup chan struct{} // channel to wake up the output loop

	nextSend               atomic.Uint32 // next sequence number to send a segment
	nextRecv               atomic.Uint32 // next sequence number to receive
	lastRXTime             atomic.Int64  // last timestamp when a segment is received, in microseconds since Unix epoch
	lastTXTime             atomic.Int64  // last timestamp when a segment is sent, in microseconds since Unix epoch
	heartbeatJitter        time.Duration // random jitter added to the heartbeat interval; long-tailed, see randomHeartbeatJitter
	nextRetransmissionTime atomic.Int64  // time that need to retransmit a segment in sendBuf, in microseconds since Unix epoch
	ackOnDataRecv          atomic.Bool   // whether ack should be sent due to receive of new data
	ackDeadline            atomic.Int64  // time to send the pending ack requested by ackOnDataRecv, in microseconds since Unix epoch
	unreadBuf              []byte        // payload removed from the recvQueue that haven't been read by application
	readSinceAck           int           // segments read by the application since the last receive window update, guarded by rLock

	rttStat            *congestion.RTTStats
	cubicSendAlgorithm *congestion.CubicSendAlgorithm
	remoteWindowSize   atomic.Uint32
	// remoteWindowUnAckSeq is the highest unAckSeq whose receive window has
	// been applied to remoteWindowSize. A window update carried by a reordered
	// or duplicated segment, whose unAckSeq is older than this one, must not
	// shrink the window.
	remoteWindowUnAckSeq      atomic.Uint32
	remoteWindowUnAckSeqValid atomic.Bool

	wg    sync.WaitGroup
	rLock sync.Mutex // serialize application read
	wLock sync.Mutex // serialize application write
	oLock sync.Mutex // serialize the output sequence

	// ---- client fields ----
	openSessionRequestSent atomic.Bool // whether open session request has been sent

	// ---- client handshake fields ----
	// handshakeStarted is true once the open session request that carries the
	// handshake request of this session has been queued.
	handshakeStarted atomic.Bool
	// handshakeDone is true once the handshake response has been verified and
	// the data plane ciphers have been installed. A client session must not
	// send data or acknowledge messages before that, because the server can't
	// decrypt them with a session key it doesn't know yet.
	handshakeDone atomic.Bool
	// handshakeMu guards the pending handshake state below.
	handshakeMu         sync.Mutex
	handshakeSuites     []cipher.Suite // cipher suite preference of this session, in order
	handshakePriv       *ecdh.PrivateKey
	handshakeClientSalt [handshakeSaltLen]byte
	handshakeTimer      *time.Timer

	// ---- server fields ----
	userName                  atomic.Pointer[string]            // user that owns this session
	userPolicy                atomic.Pointer[serveruser.Policy] // matched immutable policy snapshot
	pendingServerUserPolicies map[string]serveruser.Policy      // policy of all users; released after user identity is known
	clientUseLowEntropy       atomic.Bool                       // whether the server received low entropy data from client
}

var (
	// Session implements net.Conn interface.
	_ net.Conn = (*Session)(nil)

	// Session implements UserContext interface.
	_ apicommon.UserContext = (*Session)(nil)

	// Session implements io.ReaderFrom and io.WriterTo, so io.Copy and
	// io.CopyBuffer move data with the buffers of the session instead of
	// allocating their own relay buffer.
	_ io.ReaderFrom = (*Session)(nil)
	_ io.WriterTo   = (*Session)(nil)
)

// NewSession creates a new session.
func NewSession(id uint32, isClient bool, mtu int, users map[string]*appctlpb.User, trafficPattern *appctlpb.TrafficPattern) *Session {
	return newSessionWithServerUserPolicy(id, isClient, mtu, serveruser.Policy{}, serveruser.BuildPolicies(users), trafficPattern)
}

func newSessionWithServerUserPolicy(
	id uint32,
	isClient bool,
	mtu int,
	policy serveruser.Policy,
	pendingPolicies map[string]serveruser.Policy,
	trafficPattern *appctlpb.TrafficPattern,
) *Session {
	rttStat := congestion.NewRTTStats()
	rttStat.SetMaxAckDelay(packetAckDelay)
	// The RTO multiplier of the RTT stats stays at its default of 1.0. The
	// retransmission timeout of a segment is backed off by txTimeoutBackOff
	// once per transmission attempt, and letting RTO() apply the same
	// multiplier as well would apply it twice to the first transmission.
	s := &Session{
		conn:                      nil,
		block:                     atomic.Pointer[cipher.BlockCipher]{},
		id:                        id,
		isClient:                  isClient,
		mtu:                       mtu,
		status:                    statusOK,
		pendingServerUserPolicies: pendingPolicies,
		trafficPattern:            trafficPattern,
		ready:                     make(chan struct{}),
		closedChan:                make(chan struct{}),
		inputErr:                  make(chan error),
		outputErr:                 make(chan error),
		sendQueue:                 newSegmentTree(segmentSendQueueTreeCapacity),
		sendBuf:                   newSegmentTree(segmentTreeCapacity),
		recvBuf:                   newSegmentTree(segmentTreeCapacity),
		recvQueue:                 newSegmentTree(segmentTreeCapacity),
		recvChan:                  make(chan *segment, segmentChanCapacity),
		inputChan:                 make(chan *segment, segmentChanCapacity),
		outputWakeup:              make(chan struct{}, 1),
		rttStat:                   rttStat,
		cubicSendAlgorithm:        congestion.NewCubicSendAlgorithm(minWindowSize, maxWindowSize),
	}
	now := time.Now().UnixMicro()
	s.lastRXTime.Store(now)
	s.lastTXTime.Store(now)
	s.heartbeatJitter = randomHeartbeatJitter()
	s.remoteWindowSize.Store(minWindowSize)
	if policy.Name() != "" {
		s.userPolicy.Store(&policy)
	}
	return s
}

func (s *Session) String() string {
	if s.conn == nil {
		return fmt.Sprintf("Session{id=%v}", s.id)
	}
	return fmt.Sprintf("Session{id=%v, local=%v, remote=%v}", s.id, s.LocalAddr(), s.RemoteAddr())
}

// Read lets a user to read data from receive queue.
// Read is allowed even after the session has been closed.
//
// Read honors the read deadline set by SetReadDeadline. The deadline stays
// armed across calls: net.Conn semantics require a deadline to apply to every
// subsequent read until the application changes or clears it.
func (s *Session) Read(b []byte) (n int, err error) {
	s.rLock.Lock()
	defer s.rLock.Unlock()
	if len(b) == 0 {
		return 0, nil
	}

	if log.IsLevelEnabled(log.TraceLevel) {
		log.Tracef("%v trying to read %d bytes", s, len(b))
	}

	// Stop reading when deadline is reached. An expired deadline fails the
	// read right away, as net.Conn requires; ignoring it would leave a caller
	// that set a deadline once blocked here forever.
	timeC := deadlineChan(s.effectiveReadDeadline())

	for {
		// Read remaining data that application left last time.
		if len(s.unreadBuf) > 0 {
			copied := copy(b[n:], s.unreadBuf)
			n += copied
			if copied == len(s.unreadBuf) {
				s.unreadBuf = nil
			} else {
				s.unreadBuf = s.unreadBuf[copied:]
			}
			if n == len(b) || len(s.unreadBuf) > 0 {
				break
			}
		}

		if s.recvQueue.Len() > 0 {
			// Read segments from recv queue.
			seg, ok := s.recvQueue.DeleteMin()
			if !ok {
				continue
			}
			if s.isClient && seg.metadata.Protocol() == openSessionResponse && s.isState(sessionAttached) {
				s.forwardStateTo(sessionEstablished)
			}
			// Tell the peer that the receive window opened up. The window is
			// otherwise only advertised when a segment is received, and the
			// peer doesn't send anything once it believes the window is full.
			if s.transportProtocol == common.PacketTransport {
				s.readSinceAck++
				if s.readSinceAck >= ackWindowUpdateThreshold {
					s.readSinceAck = 0
					s.requestPacketAck()
				}
			}
			copied := copy(b[n:], seg.payload)
			n += copied
			if copied < len(seg.payload) {
				s.unreadBuf = seg.payload[copied:]
			}
			if n == len(b) {
				break
			}
		} else {
			if n > 0 {
				break
			}

			// recvQueue is empty and we haven't read anything.
			// Wait for incoming segments to fill the recvQueue.
			select {
			case <-s.closedChan:
				return 0, io.EOF
			case <-s.inputErr:
				return 0, io.ErrUnexpectedEOF
			case <-timeC:
				return 0, stderror.ErrTimeout
			case <-s.recvQueue.chanNotEmptyEvent:
				// New segments are ready to read.
			}
		}
	}

	if log.IsLevelEnabled(log.TraceLevel) {
		log.Tracef("%v read %d bytes", s, n)
	}
	return n, nil
}

// Write stores the data to send queue.
//
// Write honors the write deadline set by SetWriteDeadline. The deadline stays
// armed across calls, as net.Conn requires, and the session never overwrites
// it with an internal timeout.
func (s *Session) Write(b []byte) (n int, err error) {
	s.wLock.Lock()
	defer s.wLock.Unlock()

	if s.closeRequested.Load() {
		return 0, io.ErrClosedPipe
	}

	if s.isStateBefore(sessionAttached, false) {
		return 0, fmt.Errorf("%v is not ready for Write()", s)
	}
	if s.isStateAfter(sessionClosed, true) {
		return 0, io.ErrClosedPipe
	}

	// Before the first write, client needs to send open session request.
	// Open session request is sent only once. Underlay may retry if the packet is lost.
	// The handshake request is the payload prefix of the open session request,
	// and the application data piggybacks after it when it fits.
	if s.isClient && s.isState(sessionAttached) && !s.openSessionRequestSent.Swap(true) {
		s.oLock.Lock()
		handshake, err := s.buildHandshakeRequest()
		if err != nil {
			s.oLock.Unlock()
			return 0, fmt.Errorf("buildHandshakeRequest() failed: %w", err)
		}
		seg := &segment{
			metadata: &sessionStruct{
				baseStruct: baseStruct{
					protocol: uint8(openSessionRequest),
				},
				sessionID: s.id,
				seq:       s.nextSend.Load(),
			},
			transport: s.transportProtocol,
		}
		s.nextSend.Add(1)
		// Low entropy metadata doesn't fit in a session-control message.
		// Do not piggyback when low entropy is enabled.
		_, _, sendLowEntropy := s.lowEntropySendConfig()
		payload := handshake
		appDataLen := 0
		if !sendLowEntropy && len(handshake)+len(b) <= MaxSessionOpenPayload {
			appDataLen = len(b)
			payload = append(payload, b...)
		}
		seg.metadata.(*sessionStruct).payloadLen = uint16(len(payload))
		seg.payload = payload
		if log.IsLevelEnabled(log.TraceLevel) {
			log.Tracef("%v writing handshake request with %d bytes of application data", s, appDataLen)
		}
		if !s.sendQueue.Insert(seg) {
			s.oLock.Unlock()
			return 0, fmt.Errorf("insert %v to send queue failed", seg)
		} else {
			s.oLock.Unlock()
		}
		// The session is unusable when the handshake doesn't complete in time.
		s.handshakeStarted.Store(true)
		s.startHandshakeTimer()
		if appDataLen > 0 {
			return appDataLen, nil
		}
	}

	if log.IsLevelEnabled(log.TraceLevel) {
		log.Tracef("%v writing %d bytes", s, n)
	}
	for len(b) > 0 {
		sizeToSend := mathext.Min(len(b), maxPDU)
		if sent, err := s.writeChunk(b[:sizeToSend]); sent == 0 || err != nil {
			return n, err
		}
		b = b[sizeToSend:]
		n += sizeToSend
	}
	if log.IsLevelEnabled(log.TraceLevel) {
		log.Tracef("%v wrote %d bytes", s, n)
	}
	return n, nil
}

// copyBufferSize is the size of the buffer that ReadFrom and WriterTo move data
// with. It matches maxPDU, so one read of ReadFrom fills exactly one segment of
// the session and one read of WriteTo returns at most one segment of it.
//
// The buffers come from copyBufferPool instead of being owned by a session, so
// a session that never copies with io.Copy holds no buffer and a copy allocates
// nothing after the first one. The memory that copies hold is therefore bounded
// by the number of copies that run at the same time.
const copyBufferSize = maxPDU

// copyBufferPool recycles the copy buffers of ReadFrom and WriterTo. It stores
// a pointer to the slice header, because boxing a slice header itself would
// allocate one object per Put.
var copyBufferPool = sync.Pool{
	New: func() any {
		buf := make([]byte, copyBufferSize)
		return &buf
	},
}

// ReadFrom implements io.ReaderFrom.
//
// io.Copy and io.CopyBuffer use ReadFrom when a session is the destination of
// the copy, so the data is written to the session without the relay buffer that
// io.Copy would allocate. Nothing else changes: the data is written with Write,
// in the same order and under the same back pressure.
//
// The returned count is the number of bytes written to the session. A read
// error other than io.EOF, and a write error, are returned to the caller.
func (s *Session) ReadFrom(r io.Reader) (n int64, err error) {
	bufPtr := copyBufferPool.Get().(*[]byte)
	defer copyBufferPool.Put(bufPtr)
	buf := *bufPtr
	for {
		nr, rerr := r.Read(buf)
		if nr > 0 {
			wn, werr := s.Write(buf[:nr])
			n += int64(wn)
			if werr != nil {
				return n, werr
			}
			if wn != nr {
				return n, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return n, nil
			}
			return n, rerr
		}
	}
}

// WriteTo implements io.WriterTo.
//
// io.Copy and io.CopyBuffer use WriteTo when a session is the source of the
// copy. The data is read from the session with Read into one fixed buffer that
// every segment of the copy reuses, and written to w, so the copy allocates no
// buffer per segment.
//
// The returned count is the number of bytes written to w. The copy ends when
// Read reports io.EOF, which is what a closed session reports once the data it
// buffered has been read.
func (s *Session) WriteTo(w io.Writer) (n int64, err error) {
	bufPtr := copyBufferPool.Get().(*[]byte)
	defer copyBufferPool.Put(bufPtr)
	buf := *bufPtr
	for {
		nr, rerr := s.Read(buf)
		if nr > 0 {
			wn, werr := w.Write(buf[:nr])
			n += int64(wn)
			if werr != nil {
				return n, werr
			}
			if wn != nr {
				return n, io.ErrShortWrite
			}
		}
		if rerr != nil {
			if rerr == io.EOF {
				return n, nil
			}
			return n, rerr
		}
	}
}

// Close terminates the session.
func (s *Session) Close() error {
	return s.closeWithError(nil)
}

func (s *Session) LocalAddr() net.Addr {
	if s.conn != nil {
		return s.conn.LocalAddr()
	}
	return common.NilNetAddr()
}

func (s *Session) RemoteAddr() net.Addr {
	if !common.IsNilNetAddr(s.remoteAddr) {
		return s.remoteAddr
	}
	if s.conn != nil {
		return s.conn.RemoteAddr()
	}
	return common.NilNetAddr()
}

// SetDeadline implements net.Conn.
func (s *Session) SetDeadline(t time.Time) error {
	micros := t.UnixMicro()
	if t.IsZero() {
		micros = 0
	}
	s.readDeadline.Store(micros)
	s.writeDeadline.Store(micros)
	return nil
}

// SetReadDeadline implements net.Conn.
func (s *Session) SetReadDeadline(t time.Time) error {
	micros := t.UnixMicro()
	if t.IsZero() {
		micros = 0
	}
	s.readDeadline.Store(micros)
	return nil
}

// SetWriteDeadline implements net.Conn.
func (s *Session) SetWriteDeadline(t time.Time) error {
	micros := t.UnixMicro()
	if t.IsZero() {
		micros = 0
	}
	s.writeDeadline.Store(micros)
	return nil
}

// effectiveReadDeadline returns the deadline Read must honor, in microseconds
// since Unix epoch. It is the earlier of the application read deadline and the
// internal handshake deadline. The internal deadline is considered only while
// the handshake of a client session is pending, so it can never cut a data
// plane read short. A return value of 0 means no deadline.
func (s *Session) effectiveReadDeadline() int64 {
	deadline := s.readDeadline.Load()
	if !s.clientHandshakePending() {
		return deadline
	}
	internal := s.internalDeadline.Load()
	if internal == 0 {
		return deadline
	}
	if deadline == 0 || internal < deadline {
		return internal
	}
	return deadline
}

// effectiveWriteDeadline returns the deadline Write must honor, in
// microseconds since Unix epoch. It follows the same rule as
// effectiveReadDeadline, based on the application write deadline.
func (s *Session) effectiveWriteDeadline() int64 {
	deadline := s.writeDeadline.Load()
	if !s.clientHandshakePending() {
		return deadline
	}
	internal := s.internalDeadline.Load()
	if internal == 0 {
		return deadline
	}
	if deadline == 0 || internal < deadline {
		return internal
	}
	return deadline
}

// deadlineChan returns a channel that fires when the given deadline, in
// microseconds since Unix epoch, expires. A deadline of 0 returns a nil
// channel, which blocks forever.
//
// A deadline that is already in the past returns an already closed channel, so
// that the caller times out immediately. net.Conn requires that behavior;
// silently ignoring an expired deadline, as this code used to do, leaves a
// caller that asked to stop waiting blocked forever.
func deadlineChan(deadline int64) <-chan time.Time {
	if deadline == 0 {
		return nil
	}
	if d := time.Until(time.UnixMicro(deadline)); d > 0 {
		return time.After(d)
	}
	expired := make(chan time.Time)
	close(expired)
	return expired
}

// UserName returns the user that owns this session,
// only if this is a server session.
func (s *Session) UserName() string {
	if p := s.userName.Load(); p != nil {
		return *p
	}
	return ""
}

func (s *Session) isState(target sessionState) bool {
	return sessionState(s.state.Load()) == target
}

func (s *Session) isStateBefore(target sessionState, include bool) bool {
	state := sessionState(s.state.Load())
	if include {
		return state <= target
	} else {
		return state < target
	}
}

func (s *Session) isStateAfter(target sessionState, include bool) bool {
	state := sessionState(s.state.Load())
	if include {
		return state >= target
	} else {
		return state > target
	}
}

func (s *Session) forwardStateTo(next sessionState) {
	for {
		old := s.state.Load()
		if int32(next) <= old {
			return
		}
		if s.state.CompareAndSwap(old, int32(next)) {
			if log.IsLevelEnabled(log.TraceLevel) {
				log.Tracef("%v %v => %v", s, sessionState(old), next)
			}
			return
		}
	}
}

func (s *Session) isClientPacketSessionOpening() bool {
	return s.isClient && s.transportProtocol == common.PacketTransport && s.isState(sessionAttached)
}

func (s *Session) isClientPacketSessionOpenResponse(seg *segment) bool {
	return s.isClientPacketSessionOpening() && seg.Protocol() == openSessionResponse
}

// shouldDeferNextPacketData reports whether the next queued packet is data
// that must wait for the server to acknowledge session establishment. This
// can happen when open session request is sent by the client by not
// acknowledged by the server. In this state, the open session request remains
// eligible for transmission and retransmission.
func (s *Session) shouldDeferNextPacketData() bool {
	if !s.isClientPacketSessionOpening() {
		return false
	}
	deferData := false
	s.sendQueue.Ascend(func(iter *segment) bool {
		deferData = isDataProtocol(iter.Protocol())
		return false // Check the first segment in send queue.
	})
	return deferData
}

// setClientCipherSuites sets the cipher suite preference order of this client
// session. The underlay that owns the session sets it before the session is
// handed to the application.
func (s *Session) setClientCipherSuites(suites []cipher.Suite) {
	s.handshakeMu.Lock()
	defer s.handshakeMu.Unlock()
	if len(suites) == 0 {
		s.handshakeSuites = nil
		return
	}
	s.handshakeSuites = normalizeClientCipherSuites(suites)
}

// clientHandshakePending reports whether this client session must not send
// data before the handshake response is verified.
func (s *Session) clientHandshakePending() bool {
	return s.isClient && s.handshakeStarted.Load() && !s.handshakeDone.Load()
}

// shouldDeferUntilHandshake reports whether the given queued segment must wait
// for the handshake response of a client session. Data and acknowledge
// segments must wait, because the peer may have switched to a session key that
// the client doesn't know yet.
func (s *Session) shouldDeferUntilHandshake(seg *segment) bool {
	if seg == nil || !s.clientHandshakePending() {
		return false
	}
	protocol := seg.Protocol()
	return isDataProtocol(protocol) || isAckProtocol(protocol)
}

// shouldDeferNextStreamData reports whether the first segment in the send queue
// of a stream session must wait for the handshake response.
func (s *Session) shouldDeferNextStreamData() bool {
	if !s.clientHandshakePending() {
		return false
	}
	deferData := false
	s.sendQueue.Ascend(func(iter *segment) bool {
		deferData = s.shouldDeferUntilHandshake(iter)
		return false // Check the first segment in the send queue.
	})
	return deferData
}

// buildHandshakeRequest creates the handshake request of this session with a
// fresh ephemeral key pair. The private key and the client salt are retained
// until the handshake response is verified, so that both peers can derive the
// same session keys.
func (s *Session) buildHandshakeRequest() ([]byte, error) {
	s.handshakeMu.Lock()
	suites := s.handshakeSuites
	s.handshakeMu.Unlock()

	request, privateKey, err := newHandshakeRequest(suites)
	if err != nil {
		return nil, err
	}

	s.handshakeMu.Lock()
	s.handshakePriv = privateKey
	s.handshakeClientSalt = request.clientSalt
	s.handshakeSuites = request.suites
	s.handshakeMu.Unlock()
	return request.Marshal(), nil
}

// startHandshakeTimer closes this client session when the handshake response
// doesn't arrive in time.
func (s *Session) startHandshakeTimer() {
	s.handshakeMu.Lock()
	defer s.handshakeMu.Unlock()
	if s.handshakeTimer != nil || s.handshakeDone.Load() {
		return
	}
	s.handshakeTimer = time.AfterFunc(handshakeTimeout, func() {
		if s.handshakeDone.Load() {
			return
		}
		err := fmt.Errorf("%v handshake timed out after %v", s, handshakeTimeout)
		log.Errorf("%v", err)
		s.closeWithError(err)
	})
}

// stopHandshakeTimer stops the handshake timer of this session.
func (s *Session) stopHandshakeTimer() {
	s.handshakeMu.Lock()
	timer := s.handshakeTimer
	s.handshakeTimer = nil
	s.handshakeMu.Unlock()
	if timer != nil {
		timer.Stop()
	}
}

// installSessionCiphers installs the data plane ciphers of a completed
// handshake on this session. A client receives with the server to client key
// and sends with the client to server key, and a server does the opposite.
func (s *Session) installSessionCiphers(c2s, s2c cipher.BlockCipher, isClient bool) {
	if isClient {
		s.block.Store(&s2c)
		s.sendBlock.Store(&c2s)
	} else {
		s.block.Store(&c2s)
		s.sendBlock.Store(&s2c)
	}
}

// newSessionResponseSegment builds the segment that carries the handshake
// response of this session. block is the cipher that protects the response.
func (s *Session) newSessionResponseSegment(payload []byte, block cipher.BlockCipher) *segment {
	s.oLock.Lock()
	defer s.oLock.Unlock()
	seq := s.nextSend.Load()
	s.nextSend.Add(1)
	return &segment{
		metadata: &sessionStruct{
			baseStruct: baseStruct{
				protocol: uint8(openSessionResponse),
			},
			sessionID:  s.id,
			seq:        seq,
			payloadLen: uint16(len(payload)),
		},
		payload:   payload,
		transport: s.transportProtocol,
		block:     block,
	}
}

// acceptHandshake processes the handshake request that prefixes the payload of
// an open session request and builds the response. requestCipher must be the
// cipher that decrypted seg, and allowedSuites is the cipher suite set that
// the server allows.
//
// On success the handshake request prefix is removed from seg, the session
// data plane ciphers are installed on the session, and the response carries
// the negotiated version, the server ephemeral public key and the server salt.
//
// On failure no session key is installed and the caller must close the session.
// A request that is not a handshake of protocolVersion, and a peer whose
// version range doesn't contain protocolVersion, are not answered at all: the
// returned response is nil, so that a peer which doesn't speak this protocol
// can't tell a dropped request from a request that never arrived. A peer that
// speaks protocolVersion but shares no cipher suite is answered with
// handshakeStatusNoSuite. A failure never panics.
func (s *Session) acceptHandshake(seg *segment, requestCipher cipher.BlockCipher, allowedSuites []cipher.Suite, stateless bool) (*handshakeResponse, cipher.BlockCipher, cipher.BlockCipher, error) {
	if s.isClient {
		return nil, nil, nil, fmt.Errorf("%v is not a server session", s)
	}
	if requestCipher == nil {
		return nil, nil, nil, fmt.Errorf("%v handshake request cipher is not available", s)
	}
	if len(seg.payload) < handshakeRequestHeaderLen || seg.payload[0] != protocolVersion {
		// The payload of an open session request starts with the lowest
		// protocol version of the client, so a peer that speaks another
		// version, or that sends a payload which can't even hold a handshake
		// request, is dropped without an answer.
		log.Debugf("%v dropped open session request from %v: the payload doesn't carry protocol version %d", s, s.remoteAddr, protocolVersion)
		return nil, nil, nil, fmt.Errorf("the open session request doesn't carry protocol version %d", protocolVersion)
	}

	request, consumed, err := parseHandshakeRequest(seg.payload)
	if err != nil {
		// A request that can't be parsed is dropped without an answer as well:
		// a diagnostic response would let a peer tell a server that speaks this
		// protocol from an unrelated service, and would answer traffic that
		// never was a handshake of this protocol.
		log.Debugf("%v dropped open session request from %v: %v", s, s.remoteAddr, err)
		return nil, nil, nil, fmt.Errorf("parseHandshakeRequest() failed: %w", err)
	}
	// The version range of the client must contain the protocol version of this
	// build: the first byte of the request is only the lowest version the client
	// speaks, so a range that excludes protocolVersion is dropped here instead
	// of being answered.
	negotiatedVersion, ok := negotiateVersion(request.versionMin, request.versionMax)
	if !ok {
		log.Debugf("%v dropped open session request: the client protocol version range %d-%d doesn't contain the server protocol version %d", s, request.versionMin, request.versionMax, protocolVersion)
		return nil, nil, nil, fmt.Errorf("no common protocol version with the client")
	}
	// The suite that protects the data plane is chosen from the intersection of
	// the client and the server preference lists. The session keys are derived
	// from the negotiated suite, so the key length of the handshake envelope
	// doesn't bound the selection.
	suite, ok := negotiateSuite(request.suites, allowedSuites)
	if !ok {
		log.Debugf("%v rejected open session request: client cipher suites %v don't intersect the server cipher suites %v", s, request.suites, allowedSuites)
		return handshakeFailureResponse(handshakeStatusNoSuite), nil, nil, fmt.Errorf("no common cipher suite with the client")
	}

	privateKey, publicKey, err := cipher.GenerateEphemeralKey()
	if err != nil {
		return nil, nil, nil, fmt.Errorf("cipher.GenerateEphemeralKey() failed: %w", err)
	}
	response := &handshakeResponse{
		status:  handshakeStatusOK,
		version: negotiatedVersion,
		suite:   suite,
	}
	copy(response.ephPub[:], publicKey)
	if _, err := crand.Read(response.serverSalt[:]); err != nil {
		return nil, nil, nil, fmt.Errorf("generate server salt failed: %w", err)
	}
	c2s, s2c, err := deriveSessionKeys(requestCipher, suite, privateKey, request.ephPub[:], request.clientSalt[:], response.serverSalt[:], stateless)
	if err != nil {
		return nil, nil, nil, fmt.Errorf("deriveSessionKeys() failed: %w", err)
	}
	// The private key is only used to derive the session keys. crypto/ecdh
	// doesn't offer a way to erase it, so dropping the reference is best
	// effort.
	privateKey = nil

	// The handshake request prefix is not application data, but the
	// application data that the client piggybacked after it is.
	appData := make([]byte, len(seg.payload)-consumed)
	copy(appData, seg.payload[consumed:])
	seg.payload = appData
	seg.metadata.(*sessionStruct).payloadLen = uint16(len(appData))

	s.installSessionCiphers(c2s, s2c, false)
	s.handshakeDone.Store(true)
	return response, c2s, s2c, nil
}

// deriveClientHandshake verifies the handshake response carried by the payload
// of seg and derives the session data plane ciphers. responseCipher must be the
// cipher that decrypted seg. stateless is true for the packet transport, whose
// session ciphers protect one packet at a time.
//
// The derived ciphers are not published: a transport that owns a cipher chain
// must switch the chain of its connection to them and then call
// commitClientHandshake publishing the handshake, so that a segment which waited
// for the handshake response can't be protected by the static key of the
// handshake envelope.
//
// On success the payload of seg is consumed and the returned response carries
// the negotiated cipher suite. On failure the caller must close the session.
// A failure never panics.
func (s *Session) deriveClientHandshake(seg *segment, responseCipher cipher.BlockCipher, stateless bool) (c2s, s2c cipher.BlockCipher, _ *handshakeResponse, err error) {
	if !s.isClient {
		return nil, nil, nil, fmt.Errorf("%v is not a client session", s)
	}
	if responseCipher == nil {
		return nil, nil, nil, fmt.Errorf("%v handshake response cipher is not available", s)
	}

	response, err := parseHandshakeResponse(seg.payload)
	if err != nil {
		s.stopHandshakeTimer()
		return nil, nil, nil, fmt.Errorf("parseHandshakeResponse() failed: %w", err)
	}
	// The payload of a handshake response is never application data.
	seg.payload = nil
	seg.metadata.(*sessionStruct).payloadLen = 0

	s.handshakeMu.Lock()
	suites := s.handshakeSuites
	privateKey := s.handshakePriv
	clientSalt := s.handshakeClientSalt
	s.handshakeMu.Unlock()
	if privateKey == nil {
		return nil, nil, nil, fmt.Errorf("%v has no pending handshake", s)
	}

	if response.status != handshakeStatusOK {
		s.stopHandshakeTimer()
		return nil, nil, nil, fmt.Errorf("no common cipher suite with the server, the client offered %v", suites)
	}
	if !slices.Contains(suites, response.suite) {
		s.stopHandshakeTimer()
		return nil, nil, nil, fmt.Errorf("server selected cipher suite %v which the client didn't offer", response.suite)
	}

	c2s, s2c, err = deriveSessionKeys(responseCipher, response.suite, privateKey, response.ephPub[:], clientSalt[:], response.serverSalt[:], stateless)
	if err != nil {
		s.stopHandshakeTimer()
		return nil, nil, nil, fmt.Errorf("deriveSessionKeys() failed: %w", err)
	}

	return c2s, s2c, response, nil
}

// commitClientHandshake publishes the data plane ciphers of a client session
// that deriveClientHandshake derived: the ciphers are installed on the session
// and the handshake is marked as done.
//
// A transport that owns a cipher chain must switch the chain of its connection
// to c2s and s2c before it calls this method, so that a segment which waited for
// the handshake response is never protected by the static key of the handshake
// envelope.
func (s *Session) commitClientHandshake(c2s, s2c cipher.BlockCipher, suite cipher.Suite) {
	s.installSessionCiphers(c2s, s2c, true)
	s.handshakeDone.Store(true)
	s.stopHandshakeTimer()
	s.handshakeMu.Lock()
	s.handshakePriv = nil
	s.handshakeClientSalt = [handshakeSaltLen]byte{}
	s.handshakeMu.Unlock()
	log.Debugf("%v handshake completed with protocol %s and cipher suite %v", s, version.ProtocolIdentifier(), suite)
}

// completeClientHandshake verifies the handshake response carried by the payload
// of seg, derives the session data plane ciphers and publishes them. It serves a
// transport that routes every message with the cipher of its session, so the
// session ciphers take effect without any per-connection state to switch.
//
// On success the session keys are installed on the session and the payload of
// seg is consumed. On failure the caller must close the session. A failure never
// panics.
func (s *Session) completeClientHandshake(seg *segment, responseCipher cipher.BlockCipher, stateless bool) (cipher.BlockCipher, cipher.BlockCipher, error) {
	c2s, s2c, response, err := s.deriveClientHandshake(seg, responseCipher, stateless)
	if err != nil {
		return nil, nil, err
	}
	s.commitClientHandshake(c2s, s2c, response.suite)
	return c2s, s2c, nil
}

// lowEntropySendConfig snapshots the effective send decision for this
// session.
func (s *Session) lowEntropySendConfig() (appctlpb.LowEntropyMode, appctlpb.LowEntropyMaskRotation, bool) {
	mode, rotation, enabled := extractLowEntropyConfig(s.trafficPattern)
	if !enabled {
		return appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_OFF, appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION, false
	}
	if !s.isClient && !s.clientUseLowEntropy.Load() {
		return appctlpb.LowEntropyMode_LOW_ENTROPY_MODE_OFF, appctlpb.LowEntropyMaskRotation_LOW_ENTROPY_MASK_NO_ROTATION, false
	}
	return mode, rotation, true
}

// sendSegmentPool and sendMetadataPool recycle the storage of the segments that
// the send path of a session creates: the data fragments of writeChunk and the
// ACK or heartbeat segments of the packet output loop. A segment of the receive
// path is never pooled, because the application reads its payload out of the
// receive queue and the segment outlives the read there.
//
// Invariants of a pooled segment:
//   - it is owned by the session between acquireSendSegment and
//     releaseSendSegment, and it is referenced only by sendQueue, sendBuf or
//     the output loop that is sending it;
//   - it is released only where it was removed from sendQueue or sendBuf and
//     no other goroutine can reach it any more;
//   - it is released exactly once: releasing the same object twice would hand
//     one segment to two senders;
//   - its payload is allocated by the send path and is never handed to the
//     application, so a pooled segment can't alias a buffer of the caller;
//   - releaseSendSegment clears every reference of the segment, so a pooled
//     segment never keeps a payload, a cipher or a user policy alive.
//
// The metadata of a segment stays an interface. Turning it into a value field
// of segment would remove the interface indirection of every metadata access as
// well, but that reaches metadata.go, both underlays and every test that builds
// a segment, which is too wide for the win of the pooling alone.
var (
	sendSegmentPool  = sync.Pool{New: func() any { return new(segment) }}
	sendMetadataPool = sync.Pool{New: func() any { return new(dataAckStruct) }}
)

// acquireSendSegment returns a segment of the send path, together with a
// dataAckStruct metadata whose protocol, session ID and transport are set.
// Every other field of the segment and of the metadata is zero, as it is after
// releaseSendSegment.
func acquireSendSegment(protocol protocolType, sessionID uint32, transport common.TransportProtocol) *segment {
	seg := sendSegmentPool.Get().(*segment)
	das := sendMetadataPool.Get().(*dataAckStruct)
	*das = dataAckStruct{
		baseStruct: baseStruct{
			protocol: uint8(protocol),
		},
		sessionID: sessionID,
	}
	seg.metadata = das
	seg.transport = transport
	return seg
}

// releaseSendSegment returns a segment of the send path to the pool. It is a
// no-op for a segment that the pool didn't create, so it is safe to call on
// every segment that leaves sendQueue or sendBuf.
func releaseSendSegment(seg *segment) {
	if seg == nil {
		return
	}
	das, ok := seg.metadata.(*dataAckStruct)
	if !ok {
		return
	}
	seg.metadata = nil
	seg.payload = nil
	seg.block = nil
	seg.transport = 0
	seg.ackCount = 0
	seg.txCount = 0
	seg.txTime = 0
	seg.txTimeout = 0
	seg.serverUserPolicy = serveruser.Policy{}
	seg.serverUserAuthentication = serveruser.Authentication{}
	sendMetadataPool.Put(das)
	sendSegmentPool.Put(seg)
}

func (s *Session) writeChunk(b []byte) (n int, err error) {
	if len(b) > maxPDU {
		return 0, io.ErrShortWrite
	}
	lowEntropyMode, lowEntropyRotation, sendLowEntropy := s.lowEntropySendConfig()

	// Stop writing when deadline is reached. An expired deadline fails the
	// write right away instead of being ignored.
	timeC := deadlineChan(s.effectiveWriteDeadline())

	seqBeforeWrite, _ := s.sendQueue.MinSeq()

	// Determine number of fragments to write.
	nFragment := 1
	fragmentSize, err := maxFragmentSize(s.mtu, s.transportProtocol, lowEntropyMode)
	if err != nil {
		return 0, err
	}
	if len(b) > fragmentSize {
		nFragment = (len(b)-1)/fragmentSize + 1
	}
	// Wait for room in the send queue instead of polling for it. The output
	// loop signals the queue events when it drains segments, and the queue can
	// only drain while this writer waits for it.
	for s.sendQueue.Remaining() <= nFragment { // reserve one slot for Close()
		select {
		case <-s.closedChan:
			return 0, io.EOF
		case <-s.outputErr:
			return 0, io.ErrClosedPipe
		case <-timeC:
			return 0, stderror.ErrTimeout
		case <-s.sendQueue.chanEmptyEvent:
		}
	}

	s.oLock.Lock()
	ptr := b
	for i := nFragment - 1; i >= 0; i-- {
		select {
		case <-s.closedChan:
			s.oLock.Unlock()
			return 0, io.EOF
		case <-s.outputErr:
			s.oLock.Unlock()
			return 0, io.ErrClosedPipe
		case <-timeC:
			s.oLock.Unlock()
			return 0, stderror.ErrTimeout
		default:
		}
		var protocol protocolType
		if s.isClient {
			protocol = dataClientToServer
			if sendLowEntropy {
				protocol = dataClientToServerLowEntropy
			}
		} else {
			protocol = dataServerToClient
			if sendLowEntropy {
				protocol = dataServerToClientLowEntropy
			}
		}
		partLen := mathext.Min(fragmentSize, len(ptr))
		part := ptr[:partLen]
		payloadLen := uint16(partLen)
		if sendLowEntropy {
			payloadLen, err = lowEntropyNominalEncodedPayloadLen(partLen, lowEntropyMode)
			if err != nil {
				s.oLock.Unlock()
				return 0, err
			}
		}
		// The segment and its metadata come from the pools of the send path,
		// but the payload is a fresh copy of the data of the caller: a pooled
		// segment never adopts a buffer of the application, and the receive
		// path never reads this payload.
		seg := acquireSendSegment(protocol, s.id, s.transportProtocol)
		das := seg.metadata.(*dataAckStruct)
		das.seq = s.nextSend.Load()
		das.unAckSeq = s.nextRecv.Load()
		das.windowSize = uint16(s.receiveWindowSize())
		das.fragment = uint8(i)
		das.payloadLen = payloadLen
		if sendLowEntropy {
			das.lowEntropyMode = uint8(lowEntropyMode)
			das.extractedPayloadLen = uint16(partLen)
			das.lowEntropyMaskRotation = uint8(lowEntropyRotation)
		}
		seg.payload = make([]byte, partLen)
		copy(seg.payload, part)
		s.nextSend.Add(1)
		if !s.sendQueue.Insert(seg) {
			insertErr := fmt.Errorf("insert %v to send queue failed", seg)
			s.oLock.Unlock()
			// The segment never reached a queue, so this is where its storage
			// goes back to the pool.
			releaseSendSegment(seg)
			return 0, insertErr
		}
		ptr = ptr[partLen:]
	}
	s.oLock.Unlock()

	// To create back pressure, wait until the send queue is empty or its head
	// moved past the segments written here. The wait blocks on the send queue
	// events instead of polling for the queue state. The queue can only drain
	// while this writer waits for it, so it eventually becomes empty.
	//
	// The sendQueue.chanNotEmptyEvent must not be consumed, because it drives
	// the output loop.
	for {
		seqAfterWrite, err := s.sendQueue.MinSeq()
		if err != nil || int32(seqAfterWrite-seqBeforeWrite) > 0 {
			break
		}
		select {
		case <-s.closedChan:
			return 0, io.EOF
		case <-s.outputErr:
			return 0, io.ErrClosedPipe
		case <-timeC:
			return 0, stderror.ErrTimeout
		case <-s.sendQueue.chanEmptyEvent:
		}
	}

	if s.clientHandshakePending() {
		// Bound how long the client waits for the handshake response of the
		// server. This is an internal deadline: it lives in its own field, so
		// it never overwrites the deadline the application set, and Read
		// ignores it once the handshake is done.
		s.internalDeadline.Store(time.Now().Add(serverRespTimeout).UnixMicro())
	}
	return len(b), nil
}

// runDeliveryLoop moves the segments received from the underlay to the input
// queue of the session.
//
// Only this loop waits for the session to consume the receive buffer, so that
// a session with a slow consumer doesn't block the underlay event loop.
func (s *Session) runDeliveryLoop(ctx context.Context) {
	defer s.wg.Done()
	for {
		select {
		case <-ctx.Done():
			return
		case <-s.closedChan:
			return
		case seg := <-s.recvChan:
			select {
			case s.inputChan <- seg:
			case <-ctx.Done():
				return
			case <-s.closedChan:
				return
			}
		}
	}
}

func (s *Session) runInputLoop(ctx context.Context) error {
	// Move the segments received from the underlay to the input queue in a
	// separate goroutine, so that a session with a slow consumer only blocks
	// its own delivery loop instead of the underlay event loop.
	s.wg.Add(1)
	go s.runDeliveryLoop(ctx)

	for {
		select {
		case <-ctx.Done():
			return nil
		case <-s.closedChan:
			return nil
		case seg := <-s.inputChan:
			if err := s.input(seg); err != nil {
				err = fmt.Errorf("input() failed: %w", err)
				log.Debugf("%v %v", s, err)
				if s.inputHasErr.CompareAndSwap(false, true) {
					close(s.inputErr)
				}
				s.closeWithError(err)
				return err
			}
		}
	}
}

func (s *Session) runOutputLoop(ctx context.Context) error {
	switch s.transportProtocol {
	case common.StreamTransport:
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-s.closedChan:
				return nil
			case <-s.sendQueue.chanNotEmptyEvent:
				s.runOutputOnceStream()
			case <-s.outputWakeup:
				// A deferred segment became eligible, for example when the
				// handshake response of this session is verified.
				s.runOutputOnceStream()
			}
		}
	case common.PacketTransport:
		// The packet output loop is driven by events and a timer.
		// The timer is armed for the earliest of the retransmission,
		// delayed ACK and heartbeat deadlines.
		timer := time.NewTimer(s.nextPacketOutputDelay())
		defer timer.Stop()
		for {
			select {
			case <-ctx.Done():
				return nil
			case <-s.closedChan:
				return nil
			case <-timer.C:
			case <-s.sendQueue.chanNotEmptyEvent:
			case <-s.outputWakeup:
			}
			s.runOutputOncePacket()
			resetTimer(timer, s.nextPacketOutputDelay())
		}
	default:
		err := fmt.Errorf("unsupported transport protocol %v", s.transportProtocol)
		log.Debugf("%v %v", s, err)
		if s.outputHasErr.CompareAndSwap(false, true) {
			close(s.outputErr)
		}
		return s.closeWithError(err)
	}
}

func (s *Session) runOutputOnceStream() {
	if s.outputHasErr.Load() {
		// Can't run output.
		time.Sleep(minOutputInterval)
		return
	}

	// Bound how many segments this pass hands to the underlay by the receive
	// window that the peer advertised. Draining the send queue faster than the
	// peer reads pushes the data into the socket buffers of both sides, and the
	// peer can only advertise its window in the data segments it sends, so the
	// window is advisory. It therefore never stops the session: a pass sends at
	// least streamSendWindowFloor segments, and the loop wakes itself up while
	// the send queue is not drained, so the queue always empties whatever the
	// window says.
	window := s.streamSendWindow()
	sent := 0
	deferWindow := false

	s.oLock.Lock()
	for {
		if s.shouldDeferNextStreamData() {
			// The queued segments stay in the send queue and are sent when
			// the handshake response is verified and the output loop is woken
			// up. Peeking instead of re-inserting keeps the loop from
			// spinning on its own wake up event.
			s.oLock.Unlock()
			break
		}
		if sent >= window {
			// The window is exhausted. Send the rest of the queue in the next
			// pass, which the wake up below schedules.
			deferWindow = true
			s.oLock.Unlock()
			break
		}
		seg, ok := s.sendQueue.DeleteMin()
		if !ok {
			s.oLock.Unlock()
			break
		}
		sent++
		if err := s.output(seg, nil); err != nil {
			// The segment left the send queue and nothing else references it,
			// whether the write reached the peer or not.
			releaseSendSegment(seg)
			err = fmt.Errorf("output() failed: %w", err)
			log.Debugf("%v %v", s, err)
			if s.outputHasErr.CompareAndSwap(false, true) {
				close(s.outputErr)
			}
			s.oLock.Unlock() // s.oLock can be acquired by s.closeWithError().
			s.closeWithError(err)
			break
		}
		releaseSendSegment(seg)
	}
	if deferWindow {
		s.wakeOutput()
	}
}

func (s *Session) runOutputOncePacket() {
	if s.outputHasErr.Load() {
		// Can't run output.
		time.Sleep(minOutputInterval)
		return
	}

	var closeSessionReason error
	hasLoss := false
	hasTimeout := false
	totalTransmissionCount := 0

	if s.sendBuf.Len() > 0 && time.Now().UnixMicro() >= s.nextRetransmissionTime.Load() {
		// Resend segments in sendBuf.
		//
		// Iterate all the segments in sendBuf to update nextRetransmissionTime,
		// but only resend segments if needed.
		//
		// Retransmission is not limited by window.
		//
		// To avoid deadlock, session can't be closed inside Ascend().
		s.oLock.Lock()
		var nextTX int64 = math.MaxInt64
		s.sendBuf.Ascend(func(iter *segment) bool {
			if iter.txCount >= txCountLimit {
				err := fmt.Errorf("too many retransmission of %v", iter)
				log.Debugf("%v is unhealthy: %v", s, err)
				if s.outputHasErr.CompareAndSwap(false, true) {
					close(s.outputErr)
				}
				closeSessionReason = err
				return false
			}

			satisfyEarlyRetransmission := iter.ackCount >= earlyRetransmission && iter.txCount <= earlyRetransmissionLimit
			if satisfyEarlyRetransmission || time.Now().UnixMicro()-iter.txTime >= iter.txTimeout.Microseconds() {
				if satisfyEarlyRetransmission {
					hasLoss = true
				} else {
					hasTimeout = true
				}
				iter.ackCount = 0
				iter.txCount++
				iter.txTime = time.Now().UnixMicro()
				// txTimeoutBackOff is the only backoff multiplier: the RTO
				// multiplier of the RTT stats stays at 1.0, so the first
				// transmission is not backed off twice.
				iter.txTimeout = mathext.Min(s.rttStat.RTO()*time.Duration(math.Pow(txTimeoutBackOff, float64(iter.txCount))), maxBackOffDuration)
				if isDataAckProtocol(iter.metadata.Protocol()) {
					das, _ := toDataAckStruct(iter.metadata)
					das.unAckSeq = s.nextRecv.Load()
				}
				if err := s.output(iter, s.RemoteAddr()); err != nil {
					err = fmt.Errorf("output() failed: %w", err)
					log.Debugf("%v %v", s, err)
					if s.outputHasErr.CompareAndSwap(false, true) {
						close(s.outputErr)
					}
					closeSessionReason = err
					return false
				}
				totalTransmissionCount++
			}
			// Use the deadline after a possible retransmission, so the
			// next check is not scheduled in the past.
			nextTX = mathext.Min(nextTX, iter.txTime+iter.txTimeout.Microseconds())
			return true
		})
		if nextTX != math.MaxInt64 {
			s.nextRetransmissionTime.Store(nextTX)
		}
		s.oLock.Unlock()
		if closeSessionReason != nil {
			s.closeWithError(closeSessionReason)
		}
		if hasTimeout {
			s.cubicSendAlgorithm.OnTimeout()
		} else if hasLoss {
			s.cubicSendAlgorithm.OnLoss()
		}
	}

	// Send new segments in sendQueue. The send window is computed once and
	// reused by the loop, because reading it acquires both the lock of the
	// congestion algorithm and the lock of the window fields.
	sendWindow := s.sendWindowSize()
	skipSendNewSegment := sendWindow <= 0
	if s.sendQueue.Len() > 0 && !skipSendNewSegment {
		s.oLock.Lock()
		for {
			if s.sendBuf.Remaining() <= 1 {
				s.oLock.Unlock()
				break
			}
			if s.shouldDeferNextPacketData() {
				s.oLock.Unlock()
				break
			}

			seg, deleted := s.sendQueue.DeleteMinIf(func(iter *segment) bool {
				return totalTransmissionCount < sendWindow
			})
			if !deleted {
				s.oLock.Unlock()
				break
			}

			seg.txCount++
			seg.txTime = time.Now().UnixMicro()
			seg.txTimeout = mathext.Min(s.rttStat.RTO()*time.Duration(math.Pow(txTimeoutBackOff, float64(seg.txCount))), maxBackOffDuration)
			if isDataAckProtocol(seg.metadata.Protocol()) {
				das, _ := toDataAckStruct(seg.metadata)
				das.unAckSeq = s.nextRecv.Load()
			}
			// Make sure the segment is checked for retransmission no later
			// than its own deadline. When sendBuf is empty the stored
			// deadline is stale and the first check is scheduled early.
			deadline := seg.txTime + seg.txTimeout.Microseconds()
			if s.sendBuf.Len() == 0 {
				s.nextRetransmissionTime.Store(mathext.Min(deadline, seg.txTime+retransmissionCheckDelay.Microseconds()))
			} else if s.nextRetransmissionTime.Load() > deadline {
				s.nextRetransmissionTime.Store(deadline)
			}
			if !s.sendBuf.Insert(seg) {
				s.oLock.Unlock()
				err := fmt.Errorf("output() failed: insert %v to send buffer failed", seg)
				log.Debugf("%v %v", s, err)
				if s.outputHasErr.CompareAndSwap(false, true) {
					close(s.outputErr)
				}
				s.closeWithError(err)
				break
			}
			if err := s.output(seg, s.RemoteAddr()); err != nil {
				s.oLock.Unlock()
				err = fmt.Errorf("output() failed: %w", err)
				log.Debugf("%v %v", s, err)
				if s.outputHasErr.CompareAndSwap(false, true) {
					close(s.outputErr)
				}
				s.closeWithError(err)
				break
			} else {
				totalTransmissionCount++
			}
		}
	}

	// Send ACK or heartbeat if needed.
	// ACK is not limited by window.
	now := time.Now().UnixMicro()
	ackDue := s.ackOnDataRecv.Load() && now >= s.ackDeadline.Load()
	jitteredInterval := sessionHeartbeatInterval + s.heartbeatJitter
	exceedHeartbeatInterval := now-s.lastTXTime.Load() > jitteredInterval.Microseconds()
	if !s.isClientPacketSessionOpening() && (ackDue || exceedHeartbeatInterval) {
		// Clear the request before reading nextRecv, so that a segment
		// received concurrently either is covered by this ACK or
		// requests a new one.
		s.ackOnDataRecv.Store(false)
		// The ACK goes straight to the underlay, which copies it into its own
		// send buffer, so its storage can return to the pool right after the
		// write. The segment is never queued.
		ackProtocol := ackServerToClient
		if s.isClient {
			ackProtocol = ackClientToServer
		}
		s.oLock.Lock()
		ackSeg := acquireSendSegment(ackProtocol, s.id, s.transportProtocol)
		das := ackSeg.metadata.(*dataAckStruct)
		das.seq = uint32(mathext.Max(0, int(s.nextSend.Load())-1))
		das.unAckSeq = s.nextRecv.Load()
		das.windowSize = uint16(s.receiveWindowSize())
		err := s.output(ackSeg, s.RemoteAddr())
		s.oLock.Unlock()
		releaseSendSegment(ackSeg)
		if err != nil {
			err = fmt.Errorf("output() failed: %w", err)
			log.Debugf("%v %v", s, err)
			if s.outputHasErr.CompareAndSwap(false, true) {
				close(s.outputErr)
			}
			s.closeWithError(err)
		}
		s.heartbeatJitter = randomHeartbeatJitter()
	}
}

// nextPacketOutputDelay returns how long the packet output loop can sleep
// before it must run again.
func (s *Session) nextPacketOutputDelay() time.Duration {
	now := time.Now().UnixMicro()
	var next int64 = math.MaxInt64
	if s.sendBuf.Len() > 0 {
		next = mathext.Min(next, s.nextRetransmissionTime.Load())
	}
	if !s.isClientPacketSessionOpening() {
		if s.ackOnDataRecv.Load() {
			next = mathext.Min(next, s.ackDeadline.Load())
		}
		jitteredInterval := sessionHeartbeatInterval + s.heartbeatJitter
		next = mathext.Min(next, s.lastTXTime.Load()+jitteredInterval.Microseconds())
	}
	if next == math.MaxInt64 {
		// Nothing is scheduled. Keep the session alive.
		return sessionHeartbeatInterval
	}

	delay := time.Duration(next-now) * time.Microsecond
	if delay <= 0 {
		return minOutputInterval
	}
	return delay
}

// wakeOutput wakes up the packet output loop without blocking.
func (s *Session) wakeOutput() {
	select {
	case s.outputWakeup <- struct{}{}:
	default:
	}
}

// requestPacketAck asks the packet output loop to acknowledge received data.
// The ACK is delayed by up to packetAckDelay to combine multiple requests.
func (s *Session) requestPacketAck() {
	if s.ackOnDataRecv.Load() {
		// An ACK is already pending.
		return
	}
	s.ackDeadline.Store(time.Now().UnixMicro() + packetAckDelay.Microseconds())
	s.ackOnDataRecv.Store(true)
	s.wakeOutput()
}

// resetTimer stops, drains and re-arms the timer. The caller must be the
// only receiver of the timer channel.
func resetTimer(timer *time.Timer, d time.Duration) {
	if !timer.Stop() {
		select {
		case <-timer.C:
		default:
		}
	}
	timer.Reset(d)
}

// input reads incoming packets from network and assemble
// them in the receive buffer and receive queue.
func (s *Session) input(seg *segment) error {
	protocol := seg.Protocol()
	if s.isClient {
		if protocol != openSessionResponse && protocol != dataServerToClient && protocol != dataServerToClientLowEntropy && protocol != ackServerToClient && protocol != closeSessionRequest && protocol != closeSessionResponse {
			return stderror.ErrInvalidArgument
		}
	} else {
		if protocol != openSessionRequest && protocol != dataClientToServer && protocol != dataClientToServerLowEntropy && protocol != ackClientToServer && protocol != closeSessionRequest && protocol != closeSessionResponse {
			return stderror.ErrInvalidArgument
		}
	}

	if seg.block != nil {
		// Validate cipher block user name is consistent.
		// A session keeps the first cipher block it received. In particular,
		// the data plane cipher that a handshake installed must not be
		// replaced by the static key that protected the handshake envelope.
		if current := s.block.Load(); current != nil {
			prevUserName := (*current).BlockContext().UserName
			nextUserName := seg.block.BlockContext().UserName
			// The user name of a cipher block is authenticated by the AEAD tag
			// that decrypted the segment, so a peer can't choose it: these
			// checks only catch a defect of the local code. They close the
			// session instead of crashing the whole process, because a session
			// is the smallest unit a transport can dispose of.
			if prevUserName == "" {
				return fmt.Errorf("%v cipher block user name is not set", s)
			}
			if nextUserName == "" {
				return fmt.Errorf("%v cipher block user name is not set", seg)
			}
			if prevUserName != nextUserName {
				return fmt.Errorf("%v cipher block user name %q is different from %v cipher block user name %q", s, prevUserName, seg, nextUserName)
			}
		} else {
			s.block.Store(&seg.block)
		}
		if !s.isClient {
			policy := seg.serverUserPolicy
			if policy.Name() == "" && s.pendingServerUserPolicies != nil {
				policy = s.pendingServerUserPolicies[seg.block.BlockContext().UserName]
			}
			s.pendingServerUserPolicies = nil
			if current := s.userPolicy.Load(); current != nil {
				if current.Name() != seg.block.BlockContext().UserName {
					return fmt.Errorf("%v user policy name %q differs from cipher user name %q", s, current.Name(), seg.block.BlockContext().UserName)
				}
				if policy.Name() != "" && current.Name() != policy.Name() {
					return fmt.Errorf("%v retained user policy name %q differs from segment user policy name %q", s, current.Name(), policy.Name())
				}
			} else if policy.Name() != "" {
				if policy.Name() != seg.block.BlockContext().UserName {
					return fmt.Errorf("%v user policy name %q differs from cipher user name %q", s, policy.Name(), seg.block.BlockContext().UserName)
				}
				s.userPolicy.Store(&policy)
			}
		}
		if s.UserName() == "" && seg.block.BlockContext().UserName != "" {
			userName := seg.block.BlockContext().UserName
			s.userName.Store(&userName)
		}
	}

	s.lastRXTime.Store(time.Now().UnixMicro())
	if !s.isClient && protocol == dataClientToServerLowEntropy {
		s.clientUseLowEntropy.Store(true)
	}
	if protocol == openSessionRequest || protocol == openSessionResponse || isDataProtocol(protocol) {
		if err := s.inputData(seg); err != nil {
			return err
		}
		if s.isClientPacketSessionOpenResponse(seg) {
			s.forwardStateTo(sessionEstablished)
			s.wakeOutput()
		}
		return nil
	} else if isAckProtocol(protocol) {
		return s.inputAck(seg)
	} else if protocol == closeSessionRequest || protocol == closeSessionResponse {
		return s.inputClose(seg)
	}
	return nil
}

func (s *Session) inputData(seg *segment) error {
	switch s.transportProtocol {
	case common.StreamTransport:
		// A segment of the peer carries its receive window, and that is the
		// only place where a stream session can learn it: the transport has no
		// window message of its own. The output loop uses the window to pace
		// what it sends.
		if das, ok := seg.metadata.(*dataAckStruct); ok {
			s.updateRemoteWindowSize(das)
		}
		// Close the session instead of buffering without bound when the
		// application of this session stopped reading. The receive queue of
		// the stream transport would otherwise grow to its capacity, because
		// nothing else tells the peer to slow down.
		if unread := s.unreadSegments(); unread >= maxUnreadSegments {
			return fmt.Errorf("%v holds %d unread segments, limit is %d: %w", s, unread, maxUnreadSegments, errUnreadLimit)
		}
		// Deliver the segment directly to recvQueue.
		if s.waitForRecvQueueSpace() {
			if !s.recvQueue.Insert(seg) {
				return fmt.Errorf("inputData() failed: insert %v to receive queue failed", seg)
			}
		}
	case common.PacketTransport:
		// Delete all previous acknowledged segments from sendBuf.
		das, ok := seg.metadata.(*dataAckStruct)
		if ok {
			unAckSeq := das.unAckSeq
			for {
				seg2, deleted := s.sendBuf.DeleteMinIf(func(iter *segment) bool {
					seq, _ := iter.Seq()
					return int32(seq-unAckSeq) < 0
				})
				if !deleted {
					break
				}
				// Karn's algorithm: only a segment that was transmitted once
				// gives an unambiguous RTT sample, because a retransmission
				// overwrites the time it was sent.
				if seg2.txCount == 1 {
					s.rttStat.UpdateRTT(time.Duration(time.Now().UnixMicro()-seg2.txTime) * time.Microsecond)
				}
				s.cubicSendAlgorithm.OnAck(s.rttStat.SmoothedRTT())
				// The send buffer released the segment, and nothing else
				// references it, so its storage goes back to the pool.
				releaseSendSegment(seg2)
			}
			s.updateRemoteWindowSize(das)
		}
		if s.sendQueue.Len() > 0 {
			s.wakeOutput()
		}

		// Deliver the segment to recvBuf.
		s.requestPacketAck()
		if s.receiveWindowSize() <= 0 {
			if log.IsLevelEnabled(log.TraceLevel) {
				log.Tracef("%v dropped %v because the receive window size is 0", s, seg)
			}
			return nil
		}
		if !s.recvBuf.Insert(seg) {
			if log.IsLevelEnabled(log.TraceLevel) {
				log.Tracef("%v dropped %v because insert to receive buffer failed", s, seg)
			}
			return nil
		}

		// Move segments from recvBuf to recvQueue.
		if s.waitForRecvQueueSpace() {
			if err := s.moveRecvBufToRecvQueue(); err != nil {
				return fmt.Errorf("inputData() failed: %w", err)
			}
		}
		// Make sure the segments moved to recvQueue are acknowledged,
		// even if an ACK was sent while they were being processed.
		s.requestPacketAck()
	default:
		return fmt.Errorf("unsupported transport protocol %v", s.transportProtocol)
	}
	return nil
}

func (s *Session) inputAck(seg *segment) error {
	switch s.transportProtocol {
	case common.StreamTransport:
		// Do nothing when receive ACK from TCP protocol.
		return nil
	case common.PacketTransport:
		// Delete all previous acknowledged segments from sendBuf.
		das := seg.metadata.(*dataAckStruct)
		unAckSeq := das.unAckSeq
		for {
			seg2, deleted := s.sendBuf.DeleteMinIf(func(iter *segment) bool {
				seq, _ := iter.Seq()
				return int32(seq-unAckSeq) < 0
			})
			if !deleted {
				break
			}
			// Karn's algorithm: only a segment that was transmitted once gives
			// an unambiguous RTT sample, because a retransmission overwrites
			// the time it was sent.
			if seg2.txCount == 1 {
				s.rttStat.UpdateRTT(time.Duration(time.Now().UnixMicro()-seg2.txTime) * time.Microsecond)
			}
			s.cubicSendAlgorithm.OnAck(s.rttStat.SmoothedRTT())
			// The send buffer released the segment, and nothing else
			// references it, so its storage goes back to the pool.
			releaseSendSegment(seg2)
		}
		s.updateRemoteWindowSize(das)

		// Update acknowledge count.
		s.sendBuf.Ascend(func(iter *segment) bool {
			seq, _ := iter.Seq()
			if int32(seq-unAckSeq) > 0 {
				return false
			}
			if seq == unAckSeq {
				iter.ackCount++
			}
			return true
		})
		if s.sendQueue.Len() > 0 {
			s.wakeOutput()
		}
		return nil
	default:
		return fmt.Errorf("unsupported transport protocol %v", s.transportProtocol)
	}
}

func (s *Session) inputClose(seg *segment) error {
	s.oLock.Lock()
	if seg.metadata.Protocol() == closeSessionRequest {
		// Send close session response.
		seg2 := &segment{
			metadata: &sessionStruct{
				baseStruct: baseStruct{
					protocol: uint8(closeSessionResponse),
				},
				sessionID:  s.id,
				seq:        s.nextSend.Load(),
				statusCode: uint8(statusOK),
				payloadLen: 0,
			},
			transport: s.transportProtocol,
		}
		s.nextSend.Add(1)
		// The response will not retry if it is not delivered.
		if err := s.output(seg2, s.RemoteAddr()); err != nil {
			s.oLock.Unlock()
			return fmt.Errorf("output() failed: %v", err)
		}
		// Immediately shutdown event loop.
		log.Debugf("Remote requested to shut down %v", s)
		s.oLock.Unlock()
		s.Close()
	} else if seg.metadata.Protocol() == closeSessionResponse {
		// Immediately shutdown event loop.
		log.Debugf("Remote received the request from %v to shut down", s)
		s.oLock.Unlock()
		s.Close()
	}
	return nil
}

func (s *Session) output(seg *segment, remoteAddr net.Addr) error {
	switch s.transportProtocol {
	case common.StreamTransport:
		if err := s.conn.(*StreamUnderlay).writeOneSegment(seg); err != nil {
			return fmt.Errorf("TCPUnderlay.writeOneSegment() failed: %v", err)
		}
	case common.PacketTransport:
		err := s.conn.(*PacketUnderlay).writeOneSegment(seg, remoteAddr)
		if err != nil {
			if !stderror.IsNotReady(err) {
				return fmt.Errorf("UDPUnderlay.writeOneSegment() failed: %v", err)
			}
			if log.IsLevelEnabled(log.TraceLevel) {
				log.Tracef("UDPUnderlay.writeOneSegment() failed: %v. Will retry later.", err)
			}
			return nil
		}
	default:
		return fmt.Errorf("unsupported transport protocol %v", s.transportProtocol)
	}
	s.lastTXTime.Store(time.Now().UnixMicro())
	return nil
}

// closeWithError closes this session. A session that reached the data plane
// also tells the peer that it is gone, see sendCloseSessionRequest.
func (s *Session) closeWithError(err error) error {
	return s.closeSession(err, true)
}

// dropWithError closes this session without writing anything to the peer. It is
// used when the first message of a peer is not a handshake of protocolVersion:
// such a peer is not answered at all, so the session is torn down in silence
// and the peer can't tell a dropped message from a message that never arrived.
func (s *Session) dropWithError(err error) error {
	return s.closeSession(err, false)
}

// closeSession performs the teardown shared by closeWithError and
// dropWithError. A close session request is sent to the peer only when
// notifyPeer is true and the session reached the data plane.
func (s *Session) closeSession(err error, notifyPeer bool) error {
	if !s.closeRequested.CompareAndSwap(false, true) {
		// This function has been called before.
		return nil
	}

	if err == nil {
		log.Debugf("Closing %v", s)
	} else {
		log.Debugf("Closing %v with error %v", s, err)
	}

	// The close session request is only useful for a session that reached the
	// data plane. A client whose handshake is still pending doesn't send one,
	// because the server may have already switched to session keys that this
	// client can't use yet. The peer cleans the session up when the transport
	// is closed or the session is idle. The decision is taken before the state
	// is advanced below.
	sendCloseRequest := notifyPeer && (s.isState(sessionAttached) || s.isState(sessionEstablished)) && !s.clientHandshakePending()

	// Mark the session closed and release everything that waits on it before
	// doing any I/O. A previous implementation sent the close session request
	// first and closed closedChan last, so a second Close() returned nil while
	// the session was still open, and a peer that had stopped reading could
	// block Close() forever.
	//
	// Don't clear receive buf and queue, because read is allowed after
	// the session is closed.
	s.forwardStateTo(sessionClosed)
	close(s.closedChan)
	// Return the storage of the segments of the send path to the pool, but only
	// when the output lock is free right now. An output loop holds that lock
	// while it writes to the underlay, and a write can block until the write
	// deadline of the transport expires, so waiting for the lock would make
	// Close() as slow as a stuck peer. A skipped drain costs nothing but the
	// reuse of the storage, which the garbage collector reclaims with the
	// session.
	//
	// The segments are removed from the queues before they are released, while
	// the output loops are excluded: a released segment has a nil metadata, so
	// a pass that still walks the tree of a queue must never see one.
	if s.oLock.TryLock() {
		var drained []*segment
		s.sendQueue.Ascend(func(seg *segment) bool {
			drained = append(drained, seg)
			return true
		})
		s.sendBuf.Ascend(func(seg *segment) bool {
			drained = append(drained, seg)
			return true
		})
		s.sendQueue.DeleteAll()
		s.sendBuf.DeleteAll()
		s.oLock.Unlock()
		for _, seg := range drained {
			releaseSendSegment(seg)
		}
	}

	if !sendCloseRequest {
		log.Debugf("Closed %v", s)
		return nil
	}

	// Send closeSessionRequest, but don't wait for closeSessionResponse,
	// because the underlay connection may be already broken.
	seg := &segment{
		metadata: &sessionStruct{
			baseStruct: baseStruct{
				protocol: uint8(closeSessionRequest),
			},
			sessionID:  s.id,
			seq:        s.nextSend.Load(),
			statusCode: uint8(s.status),
		},
		transport: s.transportProtocol,
	}
	s.nextSend.Add(1)

	// The request is best effort: the session doesn't wait for the peer to
	// receive it, and it is sent from its own goroutine because writing to a
	// peer that stopped reading can block until the connection is closed.
	go s.sendCloseSessionRequest(seg)

	log.Debugf("Closed %v", s)
	return nil
}

// sendCloseSessionRequest sends the close session request of a session that has
// already been marked as closed. It is best effort and runs in its own
// goroutine, so a peer that stopped reading can't block Close().
func (s *Session) sendCloseSessionRequest(seg *segment) {
	s.oLock.Lock()
	defer s.oLock.Unlock()
	if err := s.output(seg, s.RemoteAddr()); err != nil {
		log.Debugf("%v failed to send the close session request: %v", s, err)
	}
}

// updateRemoteWindowSize applies the receive window that the peer advertised in
// das to this session.
//
// A reordered or duplicated segment can carry an older window than the one
// already applied, and applying it would shrink the window and stall the
// session even though the peer has room. Only an update whose unAckSeq is not
// older than the newest applied one is accepted.
func (s *Session) updateRemoteWindowSize(das *dataAckStruct) {
	if s.remoteWindowUnAckSeqValid.Load() && int32(das.unAckSeq-s.remoteWindowUnAckSeq.Load()) < 0 {
		if log.IsLevelEnabled(log.TraceLevel) {
			log.Tracef("%v ignoring stale remote window %d from unAckSeq %d, newest is %d", s, das.windowSize, das.unAckSeq, s.remoteWindowUnAckSeq.Load())
		}
		return
	}
	s.remoteWindowUnAckSeq.Store(das.unAckSeq)
	s.remoteWindowUnAckSeqValid.Store(true)
	s.remoteWindowSize.Store(uint32(das.windowSize))
}

// sendWindowSize determines how many more packets this session can send.
func (s *Session) sendWindowSize() int {
	return mathext.Max(0, mathext.Min(int(s.cubicSendAlgorithm.CongestionWindowSize())-s.sendBuf.Len(), int(s.remoteWindowSize.Load())))
}

// receiveWindowSize determines how many more packets this session can receive.
func (s *Session) receiveWindowSize() int {
	return mathext.Max(0, segmentTreeCapacity-s.recvBuf.Len()-s.recvQueue.Len())
}

// streamSendWindow determines how many segments the stream output loop may send
// in one pass. It is the receive window that the peer advertised, never less
// than streamSendWindowFloor, because a stale window must not be able to stop
// the session.
func (s *Session) streamSendWindow() int {
	return mathext.Max(streamSendWindowFloor, int(s.remoteWindowSize.Load()))
}

// unreadSegments returns the number of segments that this session holds for the
// application without the application having read them.
func (s *Session) unreadSegments() int {
	return s.recvBuf.Len() + s.recvQueue.Len()
}

// waitForRecvQueueSpace returns true when the recv queue has empty space.
// It returns false when the session is closed.
func (s *Session) waitForRecvQueueSpace() bool {
	for {
		select {
		case <-s.closedChan:
			return false
		default:
		}
		if s.recvQueue.Remaining() > 0 {
			return true
		}
		select {
		case <-s.closedChan:
			return false
		case <-time.After(backPressureDelay):
		}
	}
}

func (s *Session) moveRecvBufToRecvQueue() error {
	for {
		if s.recvQueue.Remaining() <= 0 {
			return nil
		}

		nextRecv := s.nextRecv.Load()
		seg, deleted := s.recvBuf.DeleteMinIf(func(iter *segment) bool {
			seq, _ := iter.Seq()
			return int32(seq-nextRecv) <= 0
		})
		if seg == nil || !deleted {
			return nil
		}
		seq, _ := seg.Seq()
		if int32(seq-nextRecv) < 0 {
			continue // ignore this segment
		}
		if !s.recvQueue.Insert(seg) {
			// Can't move to recvQueue, try insert back to recvBuf.
			if !s.recvBuf.Insert(seg) {
				return fmt.Errorf("insert %v from receive queue back to receive buffer failed", seg)
			}
			return nil
		}
		s.nextRecv.Add(1)

		// Update remote window size.
		das, ok := seg.metadata.(*dataAckStruct)
		if ok {
			s.updateRemoteWindowSize(das)
		}
	}
}

// randomHeartbeatJitter returns the random delay added to
// sessionHeartbeatInterval. Most values stay within the base jitter so that a
// NAT binding is still refreshed on time, but one draw in eight adds up to
// 8 seconds more, so the heartbeat of an idle session is not a periodic beacon
// that an observer can use to identify the tunnel.
func randomHeartbeatJitter() time.Duration {
	jitterMs := mrand.Intn(2*sessionHeartbeatJitterMs+1) - sessionHeartbeatJitterMs
	if mrand.Intn(8) == 0 {
		jitterMs += mrand.Intn(8*sessionHeartbeatJitterMs) + 1
	}
	return time.Duration(jitterMs) * time.Millisecond
}
