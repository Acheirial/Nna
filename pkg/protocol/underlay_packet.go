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
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"sync"
	"time"

	apicommon "github.com/Acheirial/shadowlemon/v3/apis/common"
	"github.com/Acheirial/shadowlemon/v3/pkg/appctl/appctlpb"
	"github.com/Acheirial/shadowlemon/v3/pkg/cipher"
	"github.com/Acheirial/shadowlemon/v3/pkg/common"
	"github.com/Acheirial/shadowlemon/v3/pkg/log"
	"github.com/Acheirial/shadowlemon/v3/pkg/mathext"
	"github.com/Acheirial/shadowlemon/v3/pkg/protocol/serveruser"
	"github.com/Acheirial/shadowlemon/v3/pkg/replay"
	"github.com/Acheirial/shadowlemon/v3/pkg/stderror"
)

const (
	packetOverhead          = cipher.DefaultNonceSize + MetadataLength + cipher.DefaultOverhead*2
	packetNonHeaderPosition = cipher.DefaultNonceSize + MetadataLength + cipher.DefaultOverhead

	// packetIPUDPHeaderMax is the largest number of bytes that the IP header
	// and the UDP header add to the payload of a datagram: 40 bytes of IPv6
	// header, the longer of the two IP header versions, plus 8 bytes of UDP
	// header.
	//
	// The MTU of a packet underlay is the MTU of layer 3: the largest IP
	// packet that the network path accepts without fragmenting it. Deducting
	// this constant once, where the MTU enters the packet underlay, turns the
	// MTU into the payload budget that every other budget of the packet data
	// plane is computed from (the fragment size of a session and the padding
	// of a datagram), so an endpoint that is configured with an MTU of 1400
	// never makes the kernel fragment its datagrams.
	packetIPUDPHeaderMax = 48

	// packetTransientReadErrorBackoff is the delay before a packet underlay
	// reads its socket again after a read error that describes a datagram
	// instead of the socket (see isTransientPacketReadError).
	//
	// A socket reports the fate of a datagram it has sent on one of its later
	// reads, and it reports it again on every read until the peer or the route
	// comes back. The delay keeps a persistent error from spinning the event
	// loop at full speed, and it is short enough that a datagram which arrives
	// during the delay waits at most this long.
	packetTransientReadErrorBackoff = 10 * time.Millisecond

	idleSessionTimeout = time.Minute

	// readySessionTimeout is the time that a new session waits for room in the
	// accept queue of the underlay.
	//
	// The handover happens in the event loop, so waiting without a limit lets
	// an application that doesn't consume Accept() stop the underlay from
	// reading packets, which stops the service of every other session of the
	// endpoint. A handover that times out closes the session instead, which is
	// the behavior of a lost datagram: the peer retries later.
	readySessionTimeout = 100 * time.Millisecond

	// sessionReaperQueueCapacity is the number of detached sessions that wait
	// for the background removal of the underlay. The queue is bounded, so a
	// burst of sessions can't make the underlay allocate without a limit.
	sessionReaperQueueCapacity = 64

	// sessionReaperStopTimeout is the time that Close() waits for the reaper
	// goroutine to remove the sessions that the cleanup detached. The wait is
	// bounded, because the teardown of a session that ignores the close of its
	// underlay must not hang the caller.
	sessionReaperStopTimeout = 5 * time.Second
)

var packetReplayCache = replay.NewCache(64*1024, cipher.KeyRefreshInterval*3)

// packetUnderlayMTU returns the payload budget of a packet underlay that serves
// a network path with the given layer 3 MTU.
//
// The IP and UDP headers are deducted here, at the single point where the MTU
// of an endpoint enters the packet data plane, so that every budget that is
// derived from the MTU (the fragment size of a session, the padding of a
// datagram) is a payload budget and no combination of them can exceed the MTU
// of the path. An MTU that has no room for the headers leaves no budget at all;
// the data plane then sends the smallest datagrams it can instead of failing,
// and the configuration layer refuses an MTU below 1280.
func packetUnderlayMTU(l3MTU int) int {
	return l3MTU - packetIPUDPHeaderMax
}

type PacketUnderlay struct {
	// ---- common fields ----
	baseUnderlay
	conn net.PacketConn

	sessionCleanTicker *time.Ticker

	// rxBuf is the datagram buffer of the event loop. Only the goroutine that
	// runs RunEventLoop touches it, it keeps len == cap, and it grows to the
	// largest datagram seen so far, so every read reuses it, including the
	// reads that time out.
	//
	// The buffer holds wire bytes only: the metadata and the payload of a
	// datagram are decrypted into fresh allocations, so reusing the buffer
	// never extends the lifetime of a decrypted datagram.
	rxBuf []byte

	// sendBufPool hands out the buffers of one outbound datagram. A datagram
	// takes one buffer for the whole of its assembly, so two sessions of the
	// underlay assemble and encrypt their datagrams at the same time; only the
	// write of a datagram on the socket is ordered by sendMutex. See
	// packetSendBuf for what a buffer holds and why the assembly doesn't need
	// the mutex.
	sendBufPool sync.Pool

	// ---- client fields ----
	serverAddr net.Addr
	block      cipher.BlockCipher
	// cipherSuites is the cipher suite preference order of the client.
	cipherSuites []cipher.Suite

	// ---- server fields ----
	serverUsers *serveruser.Registry

	// readySessionTimeoutOverride replaces readySessionTimeout when it is not
	// zero. A test sets it to a short value, so that it can exercise the
	// timeout of the accept queue handover without waiting for the production
	// timeout.
	readySessionTimeoutOverride time.Duration

	// The session reaper runs the blocking part of the session removal, which
	// is Session.Close() and the wait for the goroutines of the session,
	// outside the event loop. reaperMu protects the fields below, which are
	// set up when the cleanup detaches the first session of the underlay.
	//
	// reaperQueue is bounded by sessionReaperQueueCapacity. reaperDone is
	// closed when the reaper goroutine stops, which lets Close() wait for the
	// removal of the sessions that the cleanup already detached.
	reaperMu    sync.Mutex
	reaperQueue chan *Session
	reaperDone  chan struct{}
}

var _ Underlay = &PacketUnderlay{}

// packetSendBuf holds the reusable buffers of one outbound datagram of a packet
// underlay.
//
// wire holds the encrypted wire bytes of the datagram. After the assembly it
// has len == cap, and the datagram is handed to the connection as a slice of it
// with a full slice expression, so its capacity is exactly its length and
// Encrypt() keeps rejecting a destination that is too short.
//
// plain is empty and holds the plaintext metadata and the payload that the
// padding strategy inspects. padding and padding2 are empty and hold the
// padding bytes of the datagram: a data or ack datagram carries a middle
// padding and an end padding at the same time, and both are needed while the
// wire bytes are assembled.
//
// The connection write is synchronous and copies the bytes, so none of these
// buffers is referenced after writeOneSegment returns. A buffer is held for the
// assembly of a single datagram and never by two senders at the same time,
// which is what lets the assembly and the encryption of a datagram run outside
// the send mutex of the underlay: every datagram of the packet transport
// carries a nonce of its own, so the order in which the sessions encrypt their
// datagrams is irrelevant.
type packetSendBuf struct {
	wire    []byte
	plain   []byte
	padding []byte
	// padding2 is the second padding of a data or ack datagram.
	padding2 []byte
}

// acquireSendBuf takes the buffers of one outbound datagram from the pool of
// the underlay. The caller must return them with releaseSendBuf after the
// datagram is on the wire.
func (u *PacketUnderlay) acquireSendBuf() *packetSendBuf {
	if v := u.sendBufPool.Get(); v != nil {
		return v.(*packetSendBuf)
	}
	return &packetSendBuf{}
}

// releaseSendBuf returns the buffers of an outbound datagram to the pool of the
// underlay. A released buffer is reused by the next datagram of the underlay.
func (u *PacketUnderlay) releaseSendBuf(buf *packetSendBuf) {
	if buf != nil {
		u.sendBufPool.Put(buf)
	}
}

// NewPacketUnderlay connects to the remote address "addr" on the network
// with packet encryption.
// "block" is the block encryption algorithm to encrypt packets.
//
// mtu is the MTU of layer 3 of the network path, i.e. the largest IP packet
// that the path accepts without fragmenting it. The IP and the UDP header of a
// datagram are deducted from it (see packetIPUDPHeaderMax), so the payload
// budget that the underlay hands to its sessions is mtu - 48 and a datagram is
// never larger than the MTU of the path.
//
// This function is only used by proxy client.
func NewPacketUnderlay(
	ctx context.Context,
	packetDialer apicommon.PacketDialer,
	resolver apicommon.DNSResolver,
	network string,
	addr string,
	mtu int,
	block cipher.BlockCipher,
	trafficPattern *appctlpb.TrafficPattern,
) (*PacketUnderlay, error) {
	switch network {
	case "udp", "udp4", "udp6":
	default:
		return nil, fmt.Errorf("network %s is not supported by packet underlay", network)
	}
	if !block.IsStateless() {
		return nil, fmt.Errorf("packet underlay block cipher must be stateless")
	}
	udpAddrs, err := apicommon.ResolveUDPAddrs(ctx, resolver, network, addr)
	if err != nil {
		return nil, fmt.Errorf("ResolveUDPAddrs() failed: %w", err)
	}

	// Try each resolved address in order and use the first one that the packet
	// dialer accepts, so that a client is able to fall back from an unreachable
	// IP address family to the next candidate.
	var conn net.PacketConn
	var remoteUDPAddr *net.UDPAddr
	var listenErrs []error
	for _, candidate := range udpAddrs {
		c, err := packetDialer.ListenPacket(ctx, network, "", candidate.String())
		if err != nil {
			log.Debugf("ListenPacket() to %v failed: %v", candidate, err)
			listenErrs = append(listenErrs, fmt.Errorf("%v: %w", candidate, err))
			continue
		}
		conn = c
		remoteUDPAddr = candidate
		break
	}
	if conn == nil {
		if len(listenErrs) == 0 {
			return nil, fmt.Errorf("no UDP address is resolved from %s", addr)
		}
		return nil, fmt.Errorf("ListenPacket() failed: %w", errors.Join(listenErrs...))
	}
	u := &PacketUnderlay{
		baseUnderlay:       *newBaseUnderlay(true, packetUnderlayMTU(mtu), trafficPattern),
		conn:               conn,
		sessionCleanTicker: time.NewTicker(sessionCleanInterval),
		serverAddr:         remoteUDPAddr,
		block:              block,
	}

	// The block cipher expires after this time.
	u.scheduler.SetRemainingTime(cipher.KeyRefreshInterval / 2)
	return u, nil
}

func (u *PacketUnderlay) String() string {
	if u.conn == nil {
		return "PacketUnderlay{}"
	}
	if u.isClient {
		return fmt.Sprintf("PacketUnderlay{local=%v, remote=%v, mtu=%v}", u.LocalAddr(), u.RemoteAddr(), u.mtu)
	} else {
		return fmt.Sprintf("PacketUnderlay{local=%v, mtu=%v}", u.LocalAddr(), u.mtu)
	}
}

func (u *PacketUnderlay) Close() error {
	u.closeMutex.Lock()
	defer u.closeMutex.Unlock()
	select {
	case <-u.done:
		return nil
	default:
	}

	log.Debugf("Closing %v", u)
	u.sessionCleanTicker.Stop()
	// Unblock any pending I/O before closing sessions.
	u.conn.SetReadDeadline(time.Now())
	u.baseUnderlay.Close()
	// The reaper removes the sessions that the cleanup detached from the
	// registry, which are not in the registry anymore when the base underlay
	// closes the sessions that are still there. Wait for it for a bounded
	// time, so that Close() usually doesn't return while a session goroutine
	// of this underlay still runs. The base underlay closed u.done above, so
	// the reaper stops as soon as its queue is empty.
	_, reaperDone := u.sessionReaper()
	select {
	case <-reaperDone:
	case <-time.After(sessionReaperStopTimeout):
		log.Debugf("%v session reaper is still running after %v", u, sessionReaperStopTimeout)
	}
	return nil
}

func (u *PacketUnderlay) TransportProtocol() common.TransportProtocol {
	return common.PacketTransport
}

func (u *PacketUnderlay) LocalAddr() net.Addr {
	return u.conn.LocalAddr()
}

func (u *PacketUnderlay) RemoteAddr() net.Addr {
	if u.isClient && u.serverAddr != nil {
		return u.serverAddr
	}
	return common.NilNetAddr()
}

func (u *PacketUnderlay) AddSession(s *Session, remoteAddr net.Addr) error {
	if err := u.baseUnderlay.AddSession(s, remoteAddr); err != nil {
		return err
	}
	s.conn = u // override base underlay
	// A session that is created before the connection of the underlay exists,
	// which is what the mux does for a client, carries no remote address of
	// its own. Its remote address is the address of the peer of the underlay,
	// which is known once the connection is installed, so index the session
	// again here. The index of the session is what lets a received packet find
	// its session without scanning the whole registry.
	u.baseUnderlay.indexSession(s)
	s.transportProtocol = u.TransportProtocol()
	if u.isClient {
		s.setClientCipherSuites(u.cipherSuites)
	}
	s.forwardStateTo(sessionAttached)
	close(s.ready)
	log.Debugf("Adding session %d to %v", s.id, u)

	s.wg.Add(2)
	go func() {
		if err := s.runInputLoop(context.Background()); err != nil && !stderror.IsEOF(err) && !stderror.IsClosed(err) {
			log.Debugf("%v runInputLoop(): %v", s, err)
		}
		s.wg.Done()
	}()
	go func() {
		if err := s.runOutputLoop(context.Background()); err != nil && !stderror.IsEOF(err) && !stderror.IsClosed(err) {
			log.Debugf("%v runOutputLoop(): %v", s, err)
		}
		s.wg.Done()
	}()
	return nil
}

// sessionUserName returns the user name that owns the session, or an empty
// string if the owner is not known yet.
func sessionUserName(s *Session) string {
	if b := s.block.Load(); b != nil {
		if userName := (*b).BlockContext().UserName; userName != "" {
			return userName
		}
	}
	if userName := s.UserName(); userName != "" {
		return userName
	}
	if policy := s.userPolicy.Load(); policy != nil {
		return policy.Name()
	}
	return ""
}

// segmentUserName returns the user name authenticated by the cipher that
// decrypted the segment. It is empty if the cipher is not available, which is
// the case for segments received by a client.
func segmentUserName(seg *segment) string {
	if seg.block == nil {
		return ""
	}
	return seg.block.BlockContext().UserName
}

// mayDeliverToSession reports whether seg is allowed to be delivered to s.
// A server underlay only accepts a segment when the user name authenticated by
// the cipher that decrypted the segment matches the user that owns the session,
// so a session ID used by one user can't be used to inject segments of another
// user. A client underlay holds a single user and its sessions are created
// locally, so the check is not applicable.
func (u *PacketUnderlay) mayDeliverToSession(s *Session, seg *segment) bool {
	if u.isClient {
		return true
	}
	segUser := segmentUserName(seg)
	return segUser != "" && segUser == sessionUserName(s)
}

// RunEventLoop reads datagrams and dispatches the segments they carry, until
// the socket of the underlay can't be read anymore or the underlay is closed.
//
// The errors of this loop are classified, because the socket of a packet
// underlay is the listener of its endpoint: returning makes the mux rebuild the
// listener (see acceptUnderlayLoop), so only a socket level failure may end the
// loop.
//   - A datagram level failure, which is a segment that failed to parse, a
//     segment that carries the session ID of a session that this underlay
//     doesn't serve, a segment of a user that doesn't own the session, and a
//     write that fails for the peer that sent the datagram, is logged and
//     dropped. The sender of a datagram is not authenticated yet, so no failure
//     that a peer can cause may interrupt the service of the other peers of the
//     endpoint.
//   - A session level failure is reported by the session itself; the event loop
//     only drops the segment, and the session is closed by the session, by its
//     peer or by the session cleanup.
//   - A socket level failure of ReadFrom ends the loop. readOneSegment
//     classifies the errors of ReadFrom and only reports the ones that leave
//     the socket unreadable: an error that describes the fate of a datagram is
//     retried there after packetTransientReadErrorBackoff.
//   - The close of the underlay and the end of ctx end the loop without an
//     error.
func (u *PacketUnderlay) RunEventLoop(ctx context.Context) error {
	if u.conn == nil {
		return stderror.ErrNullPointer
	}
	defer u.conn.Close()

	for {
		select {
		case <-ctx.Done():
			u.cleanSessions()
			return nil
		case <-u.done:
			u.cleanSessions()
			return nil
		case <-u.sessionCleanTicker.C:
			u.cleanSessions()
		default:
		}
		seg, addr, err := u.readOneSegment()
		if err != nil {
			// If the underlay is closing, return gracefully.
			select {
			case <-u.done:
				u.cleanSessions()
				return nil
			default:
			}
			// A socket level failure: the event loop can't read the socket
			// anymore, and the listener of the endpoint has to be rebuilt.
			// readOneSegment() reports an error only when it left the socket
			// unreadable: a read error that describes a datagram instead of
			// the socket is retried there, and every other failure of this
			// loop is handled below without leaving the loop.
			return fmt.Errorf("readOneSegment() failed: %w", err)
		} else if seg == nil && addr == nil {
			// Timeout reading the segment, will try again later.
			continue
		}
		if log.IsLevelEnabled(log.TraceLevel) {
			log.Tracef("%v received %v from peer %v", u, seg, addr)
		}
		if isSessionProtocol(seg.metadata.Protocol()) {
			switch seg.metadata.Protocol() {
			case openSessionRequest:
				if err := u.onOpenSessionRequest(seg, addr); err != nil {
					log.Debugf("%v dropped openSessionRequest from peer %v: %v", u, addr, err)
					continue
				}
			case openSessionResponse:
				if err := u.onOpenSessionResponse(seg); err != nil {
					log.Debugf("%v dropped openSessionResponse from peer %v: %v", u, addr, err)
					continue
				}
			case closeSessionRequest, closeSessionResponse:
				if err := u.onCloseSession(seg); err != nil {
					log.Debugf("%v dropped close session message from peer %v: %v", u, addr, err)
					continue
				}
			default:
				log.Debugf("%v dropped unrecognized session protocol %d from peer %v", u, seg.metadata.Protocol(), addr)
				continue
			}
		} else if isDataAckProtocol(seg.metadata.Protocol()) {
			das, _ := toDataAckStruct(seg.metadata)
			session, ok := u.sessionMap.Load(das.sessionID)
			if !ok {
				log.Debugf("Session %d is not registered to %v", das.sessionID, u)
				if u.isClient || seg.block != nil {
					// Request the peer to close the session.
					// Client uses u.block so it is safe when seg.block is nil.
					closeReq := &segment{
						metadata: &sessionStruct{
							baseStruct: baseStruct{
								protocol: uint8(closeSessionRequest),
							},
							sessionID:  das.sessionID,
							seq:        das.unAckSeq,
							statusCode: 0,
							payloadLen: 0,
						},
						transport: u.TransportProtocol(),
						block:     seg.block,
					}
					if err := u.writeOneSegment(closeReq, addr); err != nil {
						// The request failed for the peer that sent the
						// datagram, which is a datagram level failure: the
						// answer of one unknown session must not end the
						// service of the other peers of the endpoint.
						log.Debugf("%v failed to request the close of session %d from peer %v: %v", u, das.sessionID, addr, err)
					}
				}
				continue
			}
			s := session.(*Session)
			if !u.mayDeliverToSession(s, seg) {
				log.Debugf("%v dropped segment of session ID %d from peer %v, the session is owned by user %q but the segment is from user %q", u, das.sessionID, addr, sessionUserName(s), segmentUserName(seg))
				continue
			}
			u.deliverSegmentToSession(s, seg)
		} else {
			log.Debugf("Ignore unknown protocol %d", seg.metadata.Protocol())
		}
	}
}

func (u *PacketUnderlay) onOpenSessionRequest(seg *segment, remoteAddr net.Addr) error {
	if u.isClient {
		return stderror.ErrInvalidOperation
	}

	// Create a new session.
	sessionID := seg.metadata.(*sessionStruct).sessionID
	if sessionID == 0 {
		// 0 is reserved and can't be used.
		return fmt.Errorf("reserved session ID %d is used", sessionID)
	}
	if v, found := u.sessionMap.Load(sessionID); found {
		owner := v.(*Session)
		if !u.mayDeliverToSession(owner, seg) {
			// Another user sends the session ID that is already in use. Reject
			// it here, so it can't be routed to the existing session.
			log.Debugf("%v dropped openSessionRequest for session ID %d from user %q, the session is owned by user %q", u, sessionID, segmentUserName(seg), sessionUserName(owner))
			return nil
		}
		log.Debugf("%v received openSessionRequest, but session ID %d is already used", u, sessionID)
		return nil
	}
	if segmentUserName(seg) == "" {
		return fmt.Errorf("openSessionRequest for session ID %d doesn't carry an authenticated user name", sessionID)
	}
	session := newSessionWithServerUserPolicy(sessionID, false, u.MTU(), seg.serverUserPolicy, nil, u.trafficPattern)
	if err := u.AddSession(session, remoteAddr); err != nil {
		return err
	}

	// Complete the handshake before the session becomes visible to the
	// application. The response is protected by the cipher that decrypted the
	// request, at the same time slot.
	response, _, _, handshakeErr := session.acceptHandshake(seg, seg.block, u.allowedCipherSuites(), true)
	if handshakeErr != nil {
		// A request of a peer that doesn't speak protocolVersion is dropped
		// without any answer: the session is torn down in silence, so that such
		// a peer can't tell the datagram from one that never arrived. A
		// datagram is independent of the other datagrams, so the underlay keeps
		// listening. A peer that speaks protocolVersion but no common cipher
		// suite is answered with a diagnostic response.
		//
		// The rejected session is closed before its diagnostic response is
		// written, so that no observer can find a rejected session that is
		// registered and still open, whatever the order in which this routine
		// is scheduled against its observers. A datagram is independent of the
		// session send queue and of the cipher chain of the connection, so
		// closing first doesn't change the framing of the response; the
		// response is written outside the send queue of the session because
		// closing the session clears the queue. The request is never delivered
		// as session data, so an unauthenticated handshake can't reach the
		// application.
		log.Errorf("%v rejected session %d: %v", u, sessionID, handshakeErr)
		if response == nil {
			session.dropWithError(handshakeErr)
			return nil
		}
		session.closeWithError(handshakeErr)
		respSeg := session.newSessionResponseSegment(response.Marshal(), seg.block)
		if err := u.writeOneSegment(respSeg, remoteAddr); err != nil {
			log.Debugf("%v failed to send the handshake response of session %d: %v", u, sessionID, err)
		}
		return nil
	}
	// A successful response travels through the send queue of the session, so
	// that a lost datagram is retransmitted.
	if response != nil {
		respSeg := session.newSessionResponseSegment(response.Marshal(), seg.block)
		session.oLock.Lock()
		inserted := session.sendQueue.Insert(respSeg)
		session.oLock.Unlock()
		if !inserted {
			err := fmt.Errorf("failed to queue the handshake response of session %d", sessionID)
			session.closeWithError(err)
			return err
		}
	}
	session.forwardStateTo(sessionEstablished)

	if !u.deliverSegmentToSession(session, seg) {
		return fmt.Errorf("failed to deliver open session request for session %d", sessionID)
	}
	if err := u.enqueueReadySession(session); err != nil {
		return err
	}
	u.commitServerUserAuthentication(seg)
	return nil
}

// enqueueReadySession hands one session to the queue that Accept() reads from.
// It is called by the event loop, so it never waits for the application for
// more than readySessionTimeout.
//
// A session that is not consumed in time is closed with an error: the
// application is too far behind to serve it, and the event loop must keep
// reading packets for the other sessions of the endpoint. The peer observes a
// closed session, which is the same observable behavior as a lost datagram.
func (u *PacketUnderlay) enqueueReadySession(session *Session) error {
	timeout := u.readySessionTimeoutOverride
	if timeout <= 0 {
		timeout = readySessionTimeout
	}
	timer := time.NewTimer(timeout)
	defer timer.Stop()
	select {
	case u.readySessions <- session:
		return nil
	case <-u.done:
		// The underlay is closing: its cleanup removes the session.
		return io.ErrClosedPipe
	case <-timer.C:
		err := fmt.Errorf("session %d is not consumed by the application after %v", session.id, timeout)
		log.Debugf("%v %v", u, err)
		session.closeWithError(err)
		return err
	}
}

// allowedCipherSuites returns the cipher suite set that the server allows.
func (u *PacketUnderlay) allowedCipherSuites() []cipher.Suite {
	if u.serverUsers == nil {
		return cipher.AllSuites()
	}
	return u.serverUsers.AllowedCipherSuites()
}

// commitServerUserAuthentication is the single UDP cache-recording point. The
// open-session handler invokes it only after new-session parsing and dispatch
// succeed.
func (u *PacketUnderlay) commitServerUserAuthentication(seg *segment) {
	if seg == nil || !seg.serverUserAuthentication.Valid() {
		return
	}
	seg.serverUserAuthentication.Record()
}

func (u *PacketUnderlay) onOpenSessionResponse(seg *segment) error {
	if !u.isClient {
		return stderror.ErrInvalidOperation
	}

	sessionID := seg.metadata.(*sessionStruct).sessionID
	session, found := u.sessionMap.Load(sessionID)
	if !found {
		return fmt.Errorf("session ID %d is not found", sessionID)
	}
	if !u.deliverSegmentToSession(session.(*Session), seg) && log.IsLevelEnabled(log.TraceLevel) {
		log.Tracef("%v ignored openSessionResponse segment for closed session %d", u, sessionID)
	}
	return nil
}

func (u *PacketUnderlay) onCloseSession(seg *segment) error {
	ss := seg.metadata.(*sessionStruct)
	sessionID := ss.sessionID
	session, found := u.sessionMap.Load(sessionID)
	if !found {
		if log.IsLevelEnabled(log.TraceLevel) {
			log.Tracef("%v received close session request or response, but session ID %d is not found", u, sessionID)
		}
		return nil
	}
	s := session.(*Session)
	if !u.mayDeliverToSession(s, seg) {
		log.Debugf("%v dropped close session request or response of session ID %d from peer, the session is owned by user %q but the segment is from user %q", u, sessionID, sessionUserName(s), segmentUserName(seg))
		return nil
	}
	if !u.deliverSegmentToSession(s, seg) && log.IsLevelEnabled(log.TraceLevel) {
		log.Tracef("%v ignored closeSessionRequest or closeSessionResponse segment for closed session %d", u, sessionID)
	}
	return nil
}

func (u *PacketUnderlay) readOneSegment() (*segment, net.Addr, error) {
	for {
		select {
		case <-u.done:
			return nil, nil, io.ErrClosedPipe
		default:
		}

		// Peer may select a different MTU.
		// Use the largest possible value here to avoid error.
		if cap(u.rxBuf) < 1500 {
			u.rxBuf = make([]byte, 1500)
		}
		b := u.rxBuf[:1500]
		common.SetReadTimeout(u.conn, readOneSegmentTimeout())
		n, addr, err := u.conn.ReadFrom(b)
		if err != nil {
			if stderror.IsTimeout(err) {
				// No UDP packet received. Caller will retry.
				return nil, nil, nil
			}
			select {
			case <-u.done:
				return nil, nil, io.ErrClosedPipe
			default:
			}
			if isTransientPacketReadError(err) {
				// The error describes the fate of a datagram instead of this
				// socket, so the socket can still serve the sessions of the
				// underlay: wait for the backoff and read again. Closing the
				// underlay releases the wait.
				log.Debugf("%v: %v, retry the read after %v", u, err, packetTransientReadErrorBackoff)
				select {
				case <-u.done:
					return nil, nil, io.ErrClosedPipe
				case <-time.After(packetTransientReadErrorBackoff):
				}
				continue
			}
			return nil, nil, fmt.Errorf("ReadFrom() failed: %w", err)
		}
		if u.isClient && addr.String() != u.serverAddr.String() {
			if log.IsLevelEnabled(log.TraceLevel) {
				log.Tracef("%v received unsolicited packet from %v", u, addr)
			}
			continue
		}
		if n < packetNonHeaderPosition {
			if log.IsLevelEnabled(log.TraceLevel) {
				log.Tracef("%v received packet from %v with only %d bytes, which is too short", u, addr, n)
			}
			continue
		}
		b = b[:n]
		u.inBytes.Add(int64(n))

		// Read encrypted metadata.
		encryptedMeta := b[:packetNonHeaderPosition]

		// Replay protection of the packet. Seen() is a read only lookup, which
		// is safe on a packet that is not authenticated yet: the signature is
		// recorded only after the packet passed all the checks below, so a
		// forged or truncated packet never enters the cache.
		//
		// The signature spans the entire 24 byte wire nonce, not just the first
		// 16 bytes: a noncePattern can pin those leading bytes to a constant,
		// which would leave almost no entropy in the signed input and make the
		// signature collide across packets.
		//
		// The tag is the source address of the packet, which exempts an exact
		// retransmission from the same source from the replay detection. The
		// domain separates the two directions of the traffic.
		replayDomain := replay.DomainPacketServerToClient
		if !u.isClient {
			replayDomain = replay.DomainPacketClientToServer
		}
		replayTag, _ := udpAddrPortKey(addr)
		isNewSessionReplay := packetReplayCache.Seen(replayDomain, encryptedMeta[:cipher.DefaultNonceSize], replayTag)
		nonce := encryptedMeta[:cipher.DefaultNonceSize]

		// Decrypt metadata.
		var decryptedMeta []byte
		var blockCipher cipher.BlockCipher
		var matchedPolicy serveruser.Policy
		var authentication serveruser.Authentication
		if u.isClient {
			// A handshake response is protected by the static key, and the
			// data of an established session is protected by its session key.
			decryptedMeta, err = u.block.Decrypt(encryptedMeta)
			if err != nil {
				var decrypted bool
				decryptedMeta, blockCipher, matchedPolicy, decrypted = u.tryDecryptExistingSession(encryptedMeta, addr)
				if !decrypted {
					blockCipher = nil
					if log.IsLevelEnabled(log.TraceLevel) {
						log.Tracef("%v Decrypt() failed with packet from %v", u, addr)
					}
					continue
				}
			}
		} else {
			var decrypted bool
			var err error
			// Try existing sessions.
			decryptedMeta, blockCipher, matchedPolicy, decrypted = u.tryDecryptExistingSession(encryptedMeta, addr)

			if !decrypted {
				// Existing-session lookup intentionally remains first and scans
				// the session registry. Source-IP candidates are consulted only
				// after that direct path fails.
				source := serveruser.SourceFromAddr(addr)
				blockCipher, decryptedMeta, authentication, err = u.serverTryDecryptMetadataForNewSession(encryptedMeta, source)
				if err == nil {
					decrypted = true
					matchedPolicy = authentication.Policy()
				}
			}
			if !decrypted {
				if isNewSessionReplay {
					log.Debugf("found possible replay attack in %v from %v", u, addr)
				} else if log.IsLevelEnabled(log.TraceLevel) {
					log.Tracef("%v TryDecrypt() failed with packet from %v", u, addr)
				}
				continue
			} else {
				if blockCipher == nil {
					panic("PacketUnderlay readOneSegment(): block cipher is nil after decryption is successful")
				}
				if isNewSessionReplay {
					log.Debugf("found possible replay attack with payload decrypted in %v from %v", u, addr)
					continue
				}
			}
		}
		if len(decryptedMeta) != MetadataLength {
			log.Debugf("decrypted metadata size %d is unexpected", len(decryptedMeta))
			continue
		}

		// Read payload and construct segment.
		var seg *segment
		p := decryptedMeta[0]
		if isSessionProtocol(protocolType(p)) {
			ss := &sessionStruct{}
			if err := ss.Unmarshal(decryptedMeta); err != nil {
				log.Debugf("%v Unmarshal() to sessionStruct failed: %v", u, err)
				continue
			}
			seg, err = u.parseSessionSegment(ss, nonce, b[packetNonHeaderPosition:], blockCipher)
			if err != nil {
				log.Debugf("%v parseSessionSegment() failed: %v", u, err)
				continue
			}
			if blockCipher != nil {
				seg.block = blockCipher
				seg.serverUserPolicy = matchedPolicy
			}
			if authentication.Valid() {
				if err := validateServerSegmentDirection(seg); err != nil {
					log.Debugf("%v dropped invalid new session from %v: %v", u, addr, err)
					continue
				}
				if seg.metadata.Protocol() == openSessionRequest {
					if err := validateNewServerSessionSegment(seg); err != nil {
						log.Debugf("%v dropped invalid new session from %v: %v", u, addr, err)
						continue
					}
					seg.serverUserAuthentication = authentication
				}
			}
			// A client has to install the session keys before any data packet
			// of the new session is processed, so the handshake completes here
			// and not in the input loop of the session.
			if u.isClient && seg.metadata.Protocol() == openSessionResponse {
				if err := u.completeClientHandshake(seg, u.block); err != nil {
					log.Errorf("%v dropped open session response from %v: %v", u, addr, err)
					continue
				}
			}
			packetReplayCache.Record(replayDomain, encryptedMeta[:cipher.DefaultNonceSize], replayTag)
			return seg, addr, nil
		} else if isDataAckProtocol(protocolType(p)) {
			das := &dataAckStruct{}
			if err := das.Unmarshal(decryptedMeta); err != nil {
				log.Debugf("%v Unmarshal() to dataAckStruct failed: %v", u, err)
				continue
			}
			seg, err = u.parseDataAckSegment(das, nonce, b[packetNonHeaderPosition:], blockCipher)
			if err != nil {
				log.Debugf("%v parseDataAckSegment() failed: %v", u, err)
				continue
			}
			if blockCipher != nil {
				seg.block = blockCipher
				seg.serverUserPolicy = matchedPolicy
			}
			if authentication.Valid() {
				if err := validateServerSegmentDirection(seg); err != nil {
					log.Debugf("%v dropped invalid new session from %v: %v", u, addr, err)
					continue
				}
			}
			packetReplayCache.Record(replayDomain, encryptedMeta[:cipher.DefaultNonceSize], replayTag)
			return seg, addr, nil
		} else {
			log.Debugf("%v unable to handle unknown protocol %d", u, p)
			continue
		}
	}
}

// isTransientPacketReadError reports whether an error returned by the read of a
// packet socket describes the fate of a datagram instead of the socket.
//
// A packet socket reports the fate of a datagram that it sent on one of its
// later reads, and it reports the same error again on every read until the peer
// or the route comes back: a UDP socket returns the ICMP error of a datagram
// that the peer refused, and it returns the error of a route that went away.
// The socket stays readable, so the caller treats such an error as a datagram
// level failure and reads again after packetTransientReadErrorBackoff instead
// of ending the service of the endpoint.
//
// A closed socket is not transient, and an error that this function doesn't
// recognize is not transient either: an unknown error may be the one that left
// the socket unreadable, and the caller of the loop is the one that rebuilds
// the listener.
func isTransientPacketReadError(err error) bool {
	if err == nil || stderror.IsClosed(err) || errors.Is(err, net.ErrClosed) {
		return false
	}
	if stderror.IsConnRefused(err) {
		return true
	}
	msg := strings.ToLower(err.Error())
	return strings.Contains(msg, "network is unreachable") || strings.Contains(msg, "no route to host")
}

func (u *PacketUnderlay) parseSessionSegment(ss *sessionStruct, nonce, remaining []byte, blockCipher cipher.BlockCipher) (*segment, error) {
	var decryptedPayload []byte
	var err error

	if ss.payloadLen > 0 {
		if len(remaining) < int(ss.payloadLen)+cipher.DefaultOverhead {
			return nil, fmt.Errorf("payload: received incomplete packet")
		}
		if blockCipher == nil {
			if u.isClient {
				blockCipher = u.block
			} else {
				panic("PacketUnderlay readSessionSegment(): block is nil")
			}
		}
		encryptedPayload := remaining[:ss.payloadLen+cipher.DefaultOverhead]
		decryptedPayload, err = blockCipher.DecryptPayloadWithNonce(encryptedPayload, nonce)
		if err != nil {
			return nil, fmt.Errorf("DecryptPayloadWithNonce() failed: %w", err)
		}
		if int(ss.payloadLen)+cipher.DefaultOverhead+int(ss.suffixLen) != len(remaining) {
			return nil, fmt.Errorf("padding: size not match")
		}
	} else {
		if int(ss.suffixLen) != len(remaining) {
			return nil, fmt.Errorf("padding: size not match")
		}
	}

	return &segment{
		metadata:  ss,
		payload:   decryptedPayload,
		transport: common.PacketTransport,
	}, nil
}

func (u *PacketUnderlay) parseDataAckSegment(das *dataAckStruct, nonce, remaining []byte, blockCipher cipher.BlockCipher) (*segment, error) {
	var decryptedPayload []byte
	var err error

	if isLowEntropyProtocol(das.Protocol()) {
		if err := validateLowEntropyDataAckMetadata(das); err != nil {
			return nil, err
		}
	}
	if das.prefixLen > 0 {
		if int(das.prefixLen) > len(remaining) {
			return nil, fmt.Errorf("padding: prefix length %d exceeds remaining packet size %d", das.prefixLen, len(remaining))
		}
		remaining = remaining[das.prefixLen:]
	}
	if das.payloadLen > 0 {
		wirePayloadLen := int(das.payloadLen) + cipher.DefaultOverhead
		if len(remaining) < wirePayloadLen {
			return nil, fmt.Errorf("payload: received incomplete packet")
		}
		if len(remaining) != wirePayloadLen+int(das.suffixLen) {
			return nil, fmt.Errorf("padding: size not match")
		}
		if blockCipher == nil {
			if u.isClient {
				blockCipher = u.block
			} else {
				panic("PacketUnderlay readDataAckSegment(): block is nil")
			}
		}
		encryptedPayload := remaining[:wirePayloadLen]
		if isLowEntropyProtocol(das.Protocol()) {
			encryptedPayload, err = decodeLowEntropyEncryptedPayload(encryptedPayload, das)
			if err != nil {
				return nil, fmt.Errorf("decode low entropy payload failed: %w", err)
			}
		}
		decryptedPayload, err = blockCipher.DecryptPayloadWithNonce(encryptedPayload, nonce)
		if err != nil {
			return nil, fmt.Errorf("DecryptPayloadWithNonce() failed: %w", err)
		}
	} else {
		if int(das.suffixLen) != len(remaining) {
			return nil, fmt.Errorf("padding: size not match")
		}
	}

	return &segment{
		metadata:  das,
		payload:   decryptedPayload,
		transport: common.PacketTransport,
	}, nil
}

func (u *PacketUnderlay) writeOneSegment(seg *segment, addr net.Addr) error {
	if seg == nil {
		return stderror.ErrNullPointer
	}
	if u.isClient && addr.String() != u.serverAddr.String() {
		return fmt.Errorf("can't write to %v, server address is %v", addr, u.serverAddr)
	}

	// One buffer holds the buffers of this datagram for the whole of its
	// assembly, and it is returned after the datagram is on the wire, on the
	// error paths as well.
	buf := u.acquireSendBuf()
	defer u.releaseSendBuf(buf)

	// Choosing the cipher, assembling the datagram and encrypting it run
	// outside sendMutex.
	//
	// Nothing of these steps is shared with another sender: the session
	// registry and the cipher slots of a session are read under their own
	// synchronization, the fields of the underlay that the steps read are
	// immutable, and the buffers of the datagram belong to the one sender that
	// took them from the pool. Two senders may encrypt with the cipher of the
	// same session at the same time, and that is safe as well: a datagram of
	// the packet transport carries a nonce of its own, so the order in which
	// the datagrams are encrypted doesn't change any of them, and the lock
	// inside the cipher only serializes the generation of the nonces.
	// Only the write of the datagram, and the accounting of its bytes, take
	// sendMutex (see writeDatagram).
	var blockCipher cipher.BlockCipher
	if u.isClient {
		if u.block == nil {
			panic(fmt.Sprintf("%v cipher block is not ready", u))
		} else {
			blockCipher = u.clientSendBlockCipher(seg)
		}
	} else {
		if seg.block != nil {
			blockCipher = seg.block
		} else {
			sessionID, err := seg.SessionID()
			if err != nil {
				return fmt.Errorf("%v SessionID() failed: %v", seg, err)
			}
			session, ok := u.sessionMap.Load(sessionID)
			if !ok {
				return fmt.Errorf("session %d not found", sessionID)
			}
			s := session.(*Session)
			// A session that completed a handshake sends with its server to
			// client session key, and every earlier message uses the cipher
			// that decrypted it.
			if block := s.sendBlock.Load(); block != nil {
				blockCipher = *block
			} else if block := s.block.Load(); block != nil {
				blockCipher = *block
			} else {
				// stderror.ErrNotReady is needed to trigger stderror.ShouldRetry.
				return fmt.Errorf("%v cipher block is not ready, please try again later: %w", s, stderror.ErrNotReady)
			}
		}
	}

	if blockCipher == nil {
		panic(fmt.Sprintf("%v cipher block is not ready", u))
	}

	if ss, ok := toSessionStruct(seg.metadata); ok {
		maxPaddingSize := maxPaddingSizeWithTrafficPattern(u.mtu, u.TransportProtocol(), int(ss.payloadLen), 0, u.trafficPattern, endPadding)
		// The padding strategy depends on the bit distribution of the
		// plaintext data to protect. The metadata is marshaled again below
		// with the final suffix length.
		//
		// metaBuf is a stack array and buf.plain is the reusable buffer of this
		// datagram: both hold plaintext that is consumed while the datagram is
		// assembled, and neither of them is shared with another sender.
		var metaBuf [MetadataLength]byte
		ss.marshalTo(metaBuf[:])
		if cap(buf.plain) < MetadataLength+len(seg.payload) {
			buf.plain = make([]byte, 0, MetadataLength+len(seg.payload))
		}
		existingData := append(buf.plain[:0], metaBuf[:]...)
		existingData = append(existingData, seg.payload...)
		padding, err := newPaddingInto(buf.padding[:0],
			buildRecommendedPaddingOpts(maxPaddingSize, existingData),
		)
		if err != nil {
			return fmt.Errorf("newPaddingInto() failed: %w", err)
		}
		// Keep the grown buffer for the next datagram; the padding itself is
		// copied into the wire buffer below.
		buf.padding = padding[:0]
		ss.suffixLen = uint8(len(padding))
		if log.IsLevelEnabled(log.TraceLevel) {
			log.Tracef("%v is sending %v", u, seg)
		}

		ss.marshalTo(metaBuf[:])
		plaintextMetadata := metaBuf[:]
		encryptedMetadataLen := len(plaintextMetadata) + blockCipher.NonceSize() + blockCipher.Overhead()
		encryptedPayloadLen := 0
		if len(seg.payload) > 0 {
			encryptedPayloadLen = len(seg.payload) + blockCipher.Overhead()
		}
		wireLen := encryptedMetadataLen + encryptedPayloadLen + len(padding)
		if cap(buf.wire) < wireLen {
			buf.wire = make([]byte, wireLen)
		}
		// The slice is capped at the exact datagram length, so Encrypt() still
		// rejects a wireLen that is too short instead of writing into the
		// larger buffer of an earlier datagram.
		dataToSend := buf.wire[:wireLen:wireLen]
		if err := blockCipher.Encrypt(dataToSend[:0], plaintextMetadata); err != nil {
			return fmt.Errorf("Encrypt() failed: %w", err)
		}
		nonce := dataToSend[:blockCipher.NonceSize()]
		offset := encryptedMetadataLen
		if len(seg.payload) > 0 {
			// The payload must not reuse the metadata nonce, so encrypt it
			// with a nonce derived from the message nonce.
			if err := blockCipher.EncryptPayloadWithNonce(dataToSend[offset:offset], nonce, seg.payload); err != nil {
				return fmt.Errorf("EncryptPayloadWithNonce() failed: %w", err)
			}
			offset += encryptedPayloadLen
		}
		copy(dataToSend[offset:], padding)
		if err := u.writeDatagram(dataToSend, addr); err != nil {
			return fmt.Errorf("WriteTo() failed: %w", err)
		}
	} else if das, ok := toDataAckStruct(seg.metadata); ok {
		lowEntropy := isLowEntropyProtocol(das.Protocol())
		if lowEntropy {
			if err := prepareLowEntropyDataAckForSend(das, len(seg.payload)); err != nil {
				return fmt.Errorf("prepare low entropy payload failed: %w", err)
			}
		}
		maxMiddlePaddingSize := maxPaddingSizeWithTrafficPattern(u.mtu, u.TransportProtocol(), int(das.payloadLen), 0, u.trafficPattern, middlePadding)
		padding1, err := newPaddingInto(buf.padding[:0], paddingOpts{
			maxLen: maxMiddlePaddingSize,
			ascii: &asciiPaddingOpts{
				minConsecutiveASCIILen: mathext.Min(maxMiddlePaddingSize, recommendedConsecutiveASCIILen),
			},
		})
		if err != nil {
			return fmt.Errorf("newPaddingInto() failed: %w", err)
		}
		// Keep the grown buffer for the next datagram.
		buf.padding = padding1[:0]
		maxEndPaddingSize := maxPaddingSizeWithTrafficPattern(u.mtu, u.TransportProtocol(), int(das.payloadLen), len(padding1), u.trafficPattern, endPadding)
		// The end padding has a buffer of its own, because it is generated
		// while the middle padding is still needed: both of them are copied
		// into the wire buffer below, after the last one is generated.
		padding2, err := newPaddingInto(buf.padding2[:0], paddingOpts{
			maxLen: maxEndPaddingSize,
			ascii: &asciiPaddingOpts{
				minConsecutiveASCIILen: mathext.Min(maxEndPaddingSize, recommendedConsecutiveASCIILen),
			},
		})
		if err != nil {
			return fmt.Errorf("newPaddingInto() failed: %w", err)
		}
		// Keep the grown buffer for the next datagram.
		buf.padding2 = padding2[:0]
		das.prefixLen = uint8(len(padding1))
		das.suffixLen = uint8(len(padding2))
		if log.IsLevelEnabled(log.TraceLevel) {
			log.Tracef("%v is sending %v", u, seg)
		}

		var metaBuf [MetadataLength]byte
		das.marshalTo(metaBuf[:])
		plaintextMetadata := metaBuf[:]
		encryptedMetadataLen := len(plaintextMetadata) + blockCipher.NonceSize() + blockCipher.Overhead()
		wirePayloadLen := 0
		if len(seg.payload) > 0 {
			wirePayloadLen = len(seg.payload) + blockCipher.Overhead()
			if lowEntropy {
				wirePayloadLen = int(das.payloadLen) + blockCipher.Overhead()
			}
		}
		wireLen := encryptedMetadataLen + len(padding1) + wirePayloadLen + len(padding2)
		if cap(buf.wire) < wireLen {
			buf.wire = make([]byte, wireLen)
		}
		// The slice is capped at the exact datagram length, so Encrypt() still
		// rejects a wireLen that is too short instead of writing into the
		// larger buffer of an earlier datagram.
		dataToSend := buf.wire[:wireLen:wireLen]
		if err := blockCipher.Encrypt(dataToSend[:0], plaintextMetadata); err != nil {
			return fmt.Errorf("Encrypt() failed: %w", err)
		}
		nonce := dataToSend[:blockCipher.NonceSize()]
		offset := encryptedMetadataLen
		offset += copy(dataToSend[offset:], padding1)
		if len(seg.payload) > 0 {
			// The payload must not reuse the metadata nonce, so encrypt it
			// with a nonce derived from the message nonce.
			if err := blockCipher.EncryptPayloadWithNonce(dataToSend[offset:offset], nonce, seg.payload); err != nil {
				return fmt.Errorf("EncryptPayloadWithNonce() failed: %w", err)
			}
			if lowEntropy {
				encryptedPayloadLen := len(seg.payload) + blockCipher.Overhead()
				encryptedPayload, err := encodeLowEntropyEncryptedPayload(dataToSend[offset:offset+encryptedPayloadLen], das)
				if err != nil {
					return fmt.Errorf("encode low entropy payload failed: %w", err)
				}
				copy(dataToSend[offset:], encryptedPayload)
			}
			offset += wirePayloadLen
		}
		copy(dataToSend[offset:], padding2)
		if lowEntropy && len(dataToSend) > u.mtu {
			return fmt.Errorf("low entropy datagram length %d exceeds MTU %d", len(dataToSend), u.mtu)
		}
		if err := u.writeDatagram(dataToSend, addr); err != nil {
			return fmt.Errorf("WriteTo() failed: %w", err)
		}
	} else {
		return stderror.ErrInvalidArgument
	}
	return nil
}

// writeDatagram writes one assembled datagram on the socket of the underlay
// and adds its length to the outbound byte count.
//
// sendMutex covers the write and the count, so the datagrams of the sessions of
// the underlay reach the socket one after another. The buffer of the datagram
// is not part of the shared state: the write of a packet connection copies the
// datagram into the socket before it returns, so the buffer of a datagram can
// be returned to the pool, and reused by the next datagram, as soon as this
// method returns.
func (u *PacketUnderlay) writeDatagram(b []byte, addr net.Addr) error {
	u.sendMutex.Lock()
	defer u.sendMutex.Unlock()
	if _, err := u.conn.WriteTo(b, addr); err != nil {
		return err
	}
	u.outBytes.Add(int64(len(b)))
	return nil
}

// completeClientHandshake completes the handshake of a client session with the
// open session response carried by seg. handshakeCipher is the cipher that
// decrypted seg. A packet underlay serves many sessions, so a failing
// handshake closes the session of the response only.
func (u *PacketUnderlay) completeClientHandshake(seg *segment, handshakeCipher cipher.BlockCipher) error {
	ss, ok := toSessionStruct(seg.metadata)
	if !ok {
		return fmt.Errorf("handshake response metadata is not a session struct")
	}
	value, found := u.sessionMap.Load(ss.sessionID)
	if !found {
		return fmt.Errorf("session %d of the handshake response is not found", ss.sessionID)
	}
	s := value.(*Session)
	if !s.handshakeStarted.Load() || s.handshakeDone.Load() {
		// A spurious or retransmitted response. Its payload is never
		// application data.
		seg.payload = nil
		ss.payloadLen = 0
		return nil
	}
	if handshakeCipher == nil {
		return fmt.Errorf("handshake response cipher is not available")
	}
	if _, _, err := s.completeClientHandshake(seg, handshakeCipher, true); err != nil {
		err = fmt.Errorf("%v handshake failed: %w", s, err)
		s.closeWithError(err)
		return err
	}
	return nil
}

// clientSendBlockCipher returns the cipher that protects a message that the
// client sends. A session that completed a handshake uses its session key, and
// every other message uses the static cipher of the underlay.
func (u *PacketUnderlay) clientSendBlockCipher(seg *segment) cipher.BlockCipher {
	if seg != nil && seg.block != nil {
		return seg.block
	}
	if seg != nil {
		if sessionID, err := seg.SessionID(); err == nil {
			if value, found := u.sessionMap.Load(sessionID); found {
				if block := value.(*Session).sendBlock.Load(); block != nil {
					return *block
				}
			}
		}
	}
	return u.block
}

// serverTryDecryptMetadataForNewSession attempts to decrypt metadata for an
// unknown session using the source cache before the full user registry.
func (u *PacketUnderlay) serverTryDecryptMetadataForNewSession(encryptedMeta []byte, source serveruser.Source) (cipher.BlockCipher, []byte, serveruser.Authentication, error) {
	if u.serverUsers == nil {
		return nil, nil, serveruser.Authentication{}, fmt.Errorf("server user registry is nil")
	}
	matchedBlock, decryptedMetadata, authentication, err := u.serverUsers.Discover(encryptedMeta, source, false)
	if err != nil {
		return nil, nil, serveruser.Authentication{}, err
	}

	if u.trafficPattern != nil {
		matchedBlock.SetNoncePattern(u.trafficPattern.GetNonce())
	}
	return matchedBlock, decryptedMetadata, authentication, nil
}

// tryDecryptSession attempts to decrypt the metadata of a segment with the
// cipher of one session. It reports true when the segment is decrypted.
//
// The address of the session must match the address that the packet came from
// before the cipher is used, so that a packet never reaches the cipher of a
// session of another source. The match is required even when the caller found
// the session with the address index, and both checks use the same comparison
// function.
func (u *PacketUnderlay) tryDecryptSession(session *Session, encryptedMeta []byte, addr net.Addr) (decryptedMeta []byte, blockCipher cipher.BlockCipher, matchedPolicy serveruser.Policy, decrypted bool) {
	sessionBlock := session.block.Load()
	if sessionBlock == nil || !isSamePacketAddr(session.RemoteAddr(), addr) {
		return
	}
	plaintext, err := (*sessionBlock).Decrypt(encryptedMeta)
	if err != nil {
		return
	}
	decryptedMeta = plaintext
	blockCipher = *sessionBlock
	if policy := session.userPolicy.Load(); policy != nil {
		matchedPolicy = *policy
	}
	decrypted = true
	return
}

// tryDecryptExistingSession tries to decrypt the metadata of an incoming
// segment with the cipher of a session that this underlay already serves.
//
// The candidates come from the address index, so the number of the ciphers
// that are tried grows with the number of the sessions of the source address
// and not with the number of the sessions of the underlay. The lookup of a
// packet that arrives from an address that owns no session tries no cipher at
// all.
//
// The index is used only when it can answer the question completely. When the
// index is not complete, which is the case when the address of the packet or
// the address of an attached session can't be converted to a netip.AddrPort
// (the session of a byte stream transport, the session that a test attached
// with a mock address), the whole session registry is scanned instead. The
// fallback keeps the behavior of the transports and of the tests that never
// populate the index, and the address comparison of the scan keeps the cipher
// of a session out of the packets of another source.
func (u *PacketUnderlay) tryDecryptExistingSession(encryptedMeta []byte, addr net.Addr) (decryptedMeta []byte, blockCipher cipher.BlockCipher, matchedPolicy serveruser.Policy, decrypted bool) {
	candidates, complete := u.sessionsByRemoteAddr(addr)
	if complete {
		for _, session := range candidates {
			decryptedMeta, blockCipher, matchedPolicy, decrypted = u.tryDecryptSession(session, encryptedMeta, addr)
			if decrypted {
				return
			}
		}
		return
	}
	u.sessionMap.Range(func(_, value any) bool {
		decryptedMeta, blockCipher, matchedPolicy, decrypted = u.tryDecryptSession(value.(*Session), encryptedMeta, addr)
		return !decrypted
	})
	return
}

// cleanSessions detaches the closed sessions and the sessions that didn't
// receive any segment within idleSessionTimeout from the session registry and
// from the address index, and hands them to the reaper goroutine.
//
// The event loop only detaches a session and marks it closed. Both steps are
// bounded: detaching takes the lock of the index, and marking a session closed
// takes the output lock of the session, sends the close session request on a
// best effort basis and wakes up the loops of the session, but it never waits
// for the peer. The blocking part of the removal, which closes the session and
// waits for its goroutines, runs in the reaper goroutine. The cleanup of a
// burst of sessions therefore never stops the underlay from serving the
// sessions that stay.
//
// The ordering matters: a session is detached before it is handed to the
// reaper, so a segment that arrives while the session is removed can't be
// routed to it, and a caller that holds a snapshot of the index sees a session
// that is still safe to decrypt with.
func (u *PacketUnderlay) cleanSessions() {
	u.sessionMap.Range(func(k, v any) bool {
		session := v.(*Session)
		closed := false
		select {
		case <-session.closedChan:
			closed = true
		default:
		}
		idle := time.Now().UnixMicro()-session.lastRXTime.Load() > idleSessionTimeout.Microseconds()
		if !closed && !idle {
			return true
		}
		if !closed {
			log.Debugf("Found idle %v", session)
		} else {
			log.Debugf("Found closed %v", session)
		}
		if err := u.baseUnderlay.detachSession(session); err != nil {
			log.Debugf("%v detachSession() of %v failed: %v", u, session, err)
			return true
		}
		if !closed {
			// An idle session is closed with an error instead of a graceful
			// close, because nothing waits for the peer of a session that
			// receives nothing anymore. The close session request is still
			// sent, so the peer releases the session as well.
			session.closeWithError(fmt.Errorf("session is idle for %v", idleSessionTimeout))
		}
		u.reapSession(session)
		return true
	})
}

// sessionReaper returns the queue of the reaper goroutine and the channel that
// the goroutine closes when it stops. The goroutine is created on the first
// call, because an underlay that never removes a session doesn't need it.
func (u *PacketUnderlay) sessionReaper() (chan *Session, chan struct{}) {
	u.reaperMu.Lock()
	defer u.reaperMu.Unlock()
	if u.reaperQueue == nil {
		u.reaperQueue = make(chan *Session, sessionReaperQueueCapacity)
		u.reaperDone = make(chan struct{})
		go u.runSessionReaper(u.reaperQueue, u.reaperDone)
	}
	return u.reaperQueue, u.reaperDone
}

// reapSession hands a detached session to the reaper goroutine. The caller
// must have detached the session from the registry and from the index first.
//
// The handover never blocks the event loop. A full queue is the only case in
// which the removal runs in the caller: skipping the handover would leave the
// goroutines of the session running forever, and the queue is only full while
// the teardown of a burst of sessions is slower than the cleanup.
func (u *PacketUnderlay) reapSession(session *Session) {
	queue, _ := u.sessionReaper()
	select {
	case queue <- session:
	default:
		log.Debugf("%v session reaper queue is full, removing %v in the event loop", u, session)
		u.removeSessionBlocking(session)
	}
}

// runSessionReaper removes the sessions of the queue. One goroutine serves the
// whole underlay, so the removals are serialized: a burst of sessions doesn't
// start a goroutine per session, and the memory of the teardown stays bounded.
// The goroutine stops when the underlay is closed and its queue is empty.
func (u *PacketUnderlay) runSessionReaper(queue chan *Session, done chan struct{}) {
	defer close(done)
	for {
		select {
		case session := <-queue:
			u.removeSessionBlocking(session)
		case <-u.done:
			for {
				select {
				case session := <-queue:
					u.removeSessionBlocking(session)
				default:
					return
				}
			}
		}
	}
}

// removeSessionBlocking runs the part of RemoveSession() that waits: it closes
// the session and waits for the goroutines of the session. It must not be
// called by the event loop, except when the queue of the reaper is full.
func (u *PacketUnderlay) removeSessionBlocking(session *Session) {
	if err := session.Close(); err != nil {
		log.Debugf("%v Close() of %v failed: %v", u, session, err)
	}
	session.wg.Wait()
}

// isSamePacketAddr compares UDP endpoints. If input type is not *net.UDPAddr,
// use string comparison to check if they are the same address.
func isSamePacketAddr(a, b net.Addr) bool {
	aUDP, aOK := a.(*net.UDPAddr)
	bUDP, bOK := b.(*net.UDPAddr)
	if aOK && bOK {
		if aUDP == nil || bUDP == nil {
			return aUDP == bUDP
		}
		return aUDP.Port == bUDP.Port && aUDP.Zone == bUDP.Zone && aUDP.IP.Equal(bUDP.IP)
	}
	return a.String() == b.String()
}
