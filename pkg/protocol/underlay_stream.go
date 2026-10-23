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
	"math"
	mrand "math/rand"
	"net"
	"time"

	apicommon "github.com/Acheirial/shadowlemon/v3/apis/common"
	"github.com/Acheirial/shadowlemon/v3/pkg/appctl/appctlpb"
	"github.com/Acheirial/shadowlemon/v3/pkg/cipher"
	"github.com/Acheirial/shadowlemon/v3/pkg/common"
	"github.com/Acheirial/shadowlemon/v3/pkg/log"
	"github.com/Acheirial/shadowlemon/v3/pkg/mathext"
	"github.com/Acheirial/shadowlemon/v3/pkg/protocol/serveruser"
	"github.com/Acheirial/shadowlemon/v3/pkg/replay"
	"github.com/Acheirial/shadowlemon/v3/pkg/rng"
	"github.com/Acheirial/shadowlemon/v3/pkg/stderror"
)

var streamReplayCache = replay.NewCache(64*1024, cipher.KeyRefreshInterval*3)

// idleStreamSessionTimeout is the idle period after which the event loop
// reclaims a stream session that received no segment since. It is measured
// from the last received segment, like the idle timeout of the packet
// transport, but it is far longer, because the two transports differ in what
// keeps a session fresh:
//
//   - the packet data plane sends a heartbeat, so an idle session of a live
//     peer keeps updating its receive time and the short timeout only catches
//     a peer that is gone;
//   - the stream data plane is silent when the application is silent: TCP
//     carries the connection, and neither peer sends anything until the
//     application does. A tunnel that the user leaves open is therefore quiet
//     for minutes or hours without being dead.
//
// The reclaim only releases the state of a peer that disappeared without
// closing the connection, so the timeout is set well above the silence of a
// normal tunnel.
const idleStreamSessionTimeout = 30 * time.Minute

// streamWriteTimeout bounds a single write to the connection of a stream
// underlay.
//
// The stream transport is reliable, so a peer that reads its socket drains the
// data quickly and a write completes at the speed of the link. A peer that
// stops reading is a different matter: its socket receive buffer fills up and
// then every write blocks until the peer reads or the connection breaks. The
// block is expensive, because the write happens while the sendMutex of the
// underlay is held and it is the output loop of a session that performs it:
//
//   - Session.Close() and RemoveSession() wait for the output loop, and the
//     stream transport removes a session inside the event loop of the
//     connection;
//   - the output loop holds the output lock of the session while it writes, so
//     the close session request of that session waits behind the blocked write
//     as well;
//   - a write that never returns therefore hangs Close(), the session cleanup
//     and the whole event loop of the connection, which serves the other
//     sessions of that connection too.
//
// The deadline converts the block into a timeout error, and the output loop
// treats it as a broken session, like any other write error. The value is far
// above the time a live peer needs to accept a segment, so a slow but reading
// peer is never cut off: only a peer that makes no progress for the whole
// timeout fails. The deadline is armed again before every write, so a write
// never inherits an expired deadline and a peer that drains slowly doesn't
// accumulate the timeout over a sequence of writes.
const streamWriteTimeout = 30 * time.Second

type StreamUnderlay struct {
	baseUnderlay
	conn net.Conn

	send cipher.BlockCipher
	recv cipher.BlockCipher

	// recvNoncePending is true when the next inbound message starts with the
	// wire format nonce. The first message of a cipher chain carries the nonce,
	// so it is set when the receive cipher is replaced by a session key in the
	// middle of a connection.
	recvNoncePending bool

	// sendNoncePending mirrors recvNoncePending on the sender side: it is true when
	// the next outbound message starts with the wire format nonce. It is set
	// together with recvNoncePending when the send cipher is replaced by a session
	// key in the middle of a connection, because the first message of the new
	// cipher chain carries the nonce and its framing is therefore NonceSize bytes
	// longer than the framing of the following messages.
	sendNoncePending bool

	// chainSwitched is true once the handshake of the first session replaced
	// the cipher chain of this connection with the session keys. A connection
	// switches its chain at most once, so a second openSessionRequest received
	// after the switch is dropped instead of rekeying the connection and
	// breaking the session that already runs on it. Only the event loop
	// goroutine reads and writes this field.
	chainSwitched bool

	sessionCleanTicker *time.Ticker

	// Receive buffers of the event loop. Only the goroutine that runs
	// RunEventLoop touches them. Each field keeps len == cap, so a buffer is
	// reused by reslicing it to the size of the current message, and it grows
	// to the largest message seen so far.
	//
	// The buffers hold wire bytes only: the metadata and the payload of a
	// message are decrypted into fresh allocations, so reusing a buffer never
	// extends the lifetime of a decrypted message.
	rxMetaBuf    []byte // encrypted metadata, and the wire nonce on the first read
	rxPayloadBuf []byte // message body: prefix padding, encrypted payload and suffix padding

	// Send buffers of the data plane. sendMutex protects both of them, and the
	// connection write is synchronous and copies the bytes, so neither buffer
	// is referenced after writeOneSegment returns.
	//
	// txBuf has len == cap and holds the encrypted wire bytes of one outbound
	// message. The message is sliced out of it with a full slice expression, so
	// its capacity is exactly its length and Encrypt() keeps rejecting a
	// destination that is too short.
	//
	// txScratch is empty and holds the plaintext metadata and payload that the
	// padding strategy inspects.
	txBuf     []byte
	txScratch []byte

	// padScratch is empty and holds the padding of one message. Generating the
	// padding into a reusable buffer keeps the send path from allocating a
	// buffer per message. Like txBuf and txScratch it is only used while
	// sendMutex is held, and the padding is copied into txBuf before the next
	// message rewrites the buffer.
	padScratch []byte

	// ---- client fields ----
	block cipher.BlockCipher
	// cipherSuites is the cipher suite preference order of the client.
	cipherSuites []cipher.Suite

	// ---- server fields ----
	serverUsers      *serveruser.Registry
	serverUserSource serveruser.Source
	serverUserPolicy serveruser.Policy
}

var _ Underlay = &StreamUnderlay{}

// NewStreamUnderlay connects to the remote address "addr" on the network
// with packet encryption.
// "block" is the block encryption algorithm to encrypt packets.
//
// This function is only used by proxy client.
func NewStreamUnderlay(
	ctx context.Context,
	dialer apicommon.Dialer,
	resolver apicommon.DNSResolver,
	dnsConfig *apicommon.ClientDNSConfig,
	network string,
	addr string,
	mtu int,
	block cipher.BlockCipher,
	trafficPattern *appctlpb.TrafficPattern,
) (*StreamUnderlay, error) {
	switch network {
	case "tcp", "tcp4", "tcp6":
	default:
		return nil, fmt.Errorf("network %s is not supported by stream underlay", network)
	}
	if block.IsStateless() {
		return nil, fmt.Errorf("stream underlay block cipher must be stateful")
	}
	remotes := []string{addr}
	if dnsConfig == nil || (!dnsConfig.BypassDialerDNS) {
		remoteTCPAddrs, err := apicommon.ResolveTCPAddrs(ctx, resolver, network, addr)
		if err != nil {
			return nil, fmt.Errorf("ResolveTCPAddrs() failed: %w", err)
		}
		// Try every resolved address in order and keep the first established
		// connection, so a broken address family doesn't prevent the working one
		// from being used.
		remotes = make([]string, 0, len(remoteTCPAddrs))
		for _, remoteTCPAddr := range remoteTCPAddrs {
			remotes = append(remotes, remoteTCPAddr.String())
		}
	}

	var conn net.Conn
	var err error
	var dialErrs []error
	for _, remote := range remotes {
		conn, err = dialer.DialContext(ctx, network, remote)
		if err == nil {
			break
		}
		dialErrs = append(dialErrs, err)
	}
	if err != nil {
		return nil, fmt.Errorf("DialContext() failed: %w", errors.Join(dialErrs...))
	}
	t := &StreamUnderlay{
		baseUnderlay:       *newBaseUnderlay(true, mtu, trafficPattern),
		conn:               conn,
		block:              block,
		sessionCleanTicker: time.NewTicker(sessionCleanInterval),
	}
	return t, nil
}

func (t *StreamUnderlay) String() string {
	if t.conn == nil {
		return "StreamUnderlay{}"
	}
	return fmt.Sprintf("StreamUnderlay{local=%v, remote=%v, mtu=%v}", t.conn.LocalAddr(), t.conn.RemoteAddr(), t.mtu)
}

func (t *StreamUnderlay) Close() error {
	t.closeMutex.Lock()
	defer t.closeMutex.Unlock()
	select {
	case <-t.done:
		return nil
	default:
	}

	log.Debugf("Closing %v", t)
	t.sessionCleanTicker.Stop()
	// Unblock any pending I/O before closing sessions.
	t.conn.SetDeadline(time.Now())
	t.baseUnderlay.Close()
	return nil
}

func (t *StreamUnderlay) Addr() net.Addr {
	return t.LocalAddr()
}

func (t *StreamUnderlay) TransportProtocol() common.TransportProtocol {
	return common.StreamTransport
}

func (t *StreamUnderlay) LocalAddr() net.Addr {
	if t.conn == nil {
		return common.NilNetAddr()
	}
	return t.conn.LocalAddr()
}

func (t *StreamUnderlay) RemoteAddr() net.Addr {
	if t.conn == nil {
		return common.NilNetAddr()
	}
	return t.conn.RemoteAddr()
}

func (t *StreamUnderlay) AddSession(s *Session, remoteAddr net.Addr) error {
	if err := t.baseUnderlay.AddSession(s, remoteAddr); err != nil {
		return err
	}
	s.conn = t // override base underlay
	s.transportProtocol = t.TransportProtocol()
	if t.isClient {
		// The cipher suite preference of the client protects the handshake
		// request of this session.
		s.setClientCipherSuites(t.cipherSuites)
	}
	s.forwardStateTo(sessionAttached)
	close(s.ready)
	log.Debugf("Adding session %d to %v", s.id, t)

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

func (t *StreamUnderlay) RunEventLoop(ctx context.Context) error {
	if t.conn == nil {
		return stderror.ErrNullPointer
	}
	defer t.conn.Close()

	for {
		select {
		case <-ctx.Done():
			t.cleanSessions()
			return nil
		case <-t.done:
			t.cleanSessions()
			return nil
		case <-t.sessionCleanTicker.C:
			t.cleanSessions()
		default:
		}
		seg, err := t.readOneSegment()
		if err != nil {
			// If the underlay is closing, return gracefully.
			select {
			case <-t.done:
				t.cleanSessions()
				return nil
			default:
			}
			errType := stderror.GetErrorType(err)
			if errType == stderror.NO_ERROR {
				panic(fmt.Sprintf("%v error type is NO_ERROR while error is not nil", t))
			}
			if errType == stderror.UNKNOWN_ERROR {
				panic(fmt.Sprintf("%v got unexpected error type UNKNOWN_ERROR", t))
			}
			if errType == stderror.CRYPTO_ERROR || errType == stderror.REPLAY_ERROR {
				t.drainAfterError()
			}
			return fmt.Errorf("readOneSegment() failed: %w", err)
		} else if seg == nil {
			// Timeout reading the segment, will try again later.
			continue
		}
		if log.IsLevelEnabled(log.TraceLevel) {
			log.Tracef("%v received %v", t, seg)
		}
		if seg.serverUserAuthentication.Valid() {
			if err := validateServerSegmentDirection(seg); err != nil {
				return stderror.WrapErrorWithType(err, stderror.PROTOCOL_ERROR)
			}
			// Only openSessionRequest may create a new server session. Other
			// protocols, such as the closeSessionRequest sent by a client that
			// closes before its first write, are handled by the dispatch below.
			if seg.metadata.Protocol() == openSessionRequest {
				if err := validateNewServerSessionSegment(seg); err != nil {
					return stderror.WrapErrorWithType(err, stderror.PROTOCOL_ERROR)
				}
			}
		}
		if isSessionProtocol(seg.metadata.Protocol()) {
			switch seg.metadata.Protocol() {
			case openSessionRequest:
				if err := t.onOpenSessionRequest(seg); err != nil {
					return fmt.Errorf("onOpenSessionRequest() failed: %w", err)
				}
				t.commitServerUserAuthentication(seg)
			case openSessionResponse:
				if err := t.onOpenSessionResponse(seg); err != nil {
					return fmt.Errorf("onOpenSessionResponse() failed: %w", err)
				}
			case closeSessionRequest, closeSessionResponse:
				if err := t.onCloseSession(seg); err != nil {
					return fmt.Errorf("onCloseSession() failed: %w", err)
				}
			default:
				return fmt.Errorf("protocol %d is a session protocol but not recognized by stream underlay", seg.metadata.Protocol())
			}
		} else if isDataAckProtocol(seg.metadata.Protocol()) {
			das, _ := toDataAckStruct(seg.metadata)
			session, ok := t.sessionMap.Load(das.sessionID)
			if !ok {
				log.Debugf("Session %d is not registered to %v", das.sessionID, t)
				// Request the peer to close the session.
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
					transport: t.TransportProtocol(),
				}
				if err := t.writeOneSegment(closeReq); err != nil {
					return fmt.Errorf("writeOneSegment() failed: %w", err)
				}
				continue
			}
			t.deliverSegmentToSession(session.(*Session), seg)
		} else {
			log.Debugf("Ignore unknown protocol %d", seg.metadata.Protocol())
		}
	}
}

func (t *StreamUnderlay) onOpenSessionRequest(seg *segment) error {
	if t.isClient {
		return stderror.ErrInvalidOperation
	}

	// The handshake of the first session replaced the cipher chain of this
	// connection with the session keys, and a chain can be switched only once.
	// A second openSessionRequest can only reach this point when the peer
	// protects it with the session keys, which a peer that follows the
	// protocol never does: a new session travels on a new connection. The
	// request is dropped, because answering it would rekey the connection
	// under the session that is already running on it and break a healthy
	// connection of an established user.
	if t.chainSwitched {
		log.Debugf("%v ignores openSessionRequest %d received after the cipher chain switched", t, seg.metadata.(*sessionStruct).sessionID)
		return nil
	}

	// Create a new session.
	sessionID := seg.metadata.(*sessionStruct).sessionID
	if sessionID == 0 {
		// 0 is reserved and can't be used.
		return fmt.Errorf("reserved session ID %d is used", sessionID)
	}
	_, found := t.sessionMap.Load(sessionID)
	if found {
		log.Debugf("%v received openSessionRequest, but session ID %d is already used", t, sessionID)
		return nil
	}
	policy := t.serverUserPolicy
	if seg.serverUserAuthentication.Valid() {
		policy = seg.serverUserAuthentication.Policy()
	}
	session := newSessionWithServerUserPolicy(sessionID, false, t.MTU(), policy, nil, t.trafficPattern)
	if err := t.AddSession(session, nil); err != nil {
		return err
	}

	// Complete the handshake before the session becomes visible to the
	// application. The response is protected by the cipher that decrypted the
	// request, at the same time slot, and the connection switches to the
	// session keys after the response has been written.
	response, c2s, s2c, handshakeErr := session.acceptHandshake(seg, seg.block, t.allowedCipherSuites(), false)
	if response != nil {
		respSeg := session.newSessionResponseSegment(response.Marshal(), seg.block)
		if err := t.writeOneSegment(respSeg); err != nil {
			session.closeWithError(err)
			return fmt.Errorf("writeOneSegment() for the handshake response failed: %w", err)
		}
	}
	if handshakeErr != nil {
		// A request of a peer that doesn't speak protocolVersion is dropped
		// without any answer: the session is torn down in silence and the
		// connection is closed, because a connection whose first request is not
		// a handshake of this protocol has nothing left to carry. A peer that
		// speaks protocolVersion but no common cipher suite is told why the
		// handshake failed by the response, and only its session is closed
		// here. The request is never delivered as session data in either case,
		// so an unauthenticated handshake can't reach the application.
		//
		// The response is written before the session is closed, unlike in the
		// packet transport: the response has to be the first message of the
		// static cipher chain of this connection, because a client reads its
		// first message together with the nonce that starts that chain.
		log.Errorf("%v rejected session %d: %v", t, sessionID, handshakeErr)
		if response == nil {
			session.dropWithError(handshakeErr)
			return t.Close()
		}
		session.closeWithError(handshakeErr)
		return nil
	}
	// Switch the cipher chain of this connection. The fields are published under
	// sendMutex because the output loops of the sessions read them while they
	// write, and because maybeInitSendBlockCipher reads the receive field.
	t.sendMutex.Lock()
	t.send = s2c
	t.sendNoncePending = true
	t.recv = c2s
	t.recvNoncePending = true
	t.sendMutex.Unlock()
	t.chainSwitched = true
	session.forwardStateTo(sessionEstablished)

	if !t.deliverSegmentToSession(session, seg) {
		return fmt.Errorf("failed to deliver open session request for session %d", sessionID)
	}
	select {
	case t.readySessions <- session:
	case <-t.done:
		return io.ErrClosedPipe
	}
	return nil
}

// allowedCipherSuites returns the cipher suite set that the server allows.
func (t *StreamUnderlay) allowedCipherSuites() []cipher.Suite {
	if t.serverUsers == nil {
		return cipher.AllSuites()
	}
	return t.serverUsers.AllowedCipherSuites()
}

// completeClientHandshake completes the handshake of a client session with the
// response carried by seg, and switches the cipher chain of this connection to
// the session keys.
func (t *StreamUnderlay) completeClientHandshake(seg *segment) error {
	ss, ok := toSessionStruct(seg.metadata)
	if !ok {
		return fmt.Errorf("handshake response metadata is not a session struct")
	}
	value, found := t.sessionMap.Load(ss.sessionID)
	if !found {
		// The dispatch of the response reports an unknown session.
		return nil
	}
	s := value.(*Session)
	if !s.handshakeStarted.Load() || s.handshakeDone.Load() {
		// A spurious or retransmitted response. Its payload is never
		// application data.
		seg.payload = nil
		ss.payloadLen = 0
		return nil
	}
	// The response cipher is the static cipher of this connection, which is
	// still installed while the response is verified and derived.
	c2s, s2c, response, err := s.deriveClientHandshake(seg, t.recv, false)
	if err != nil {
		return err
	}
	// Switch the cipher chain of this connection before the handshake is
	// published: publishing it releases the data segments that waited for the
	// handshake response, and those must be protected by the session key rather
	// than by the static key of the handshake envelope. The fields are published
	// under sendMutex because the output loops of the sessions read them while
	// they write, and because maybeInitSendBlockCipher reads the receive field.
	t.sendMutex.Lock()
	t.send = c2s
	t.sendNoncePending = true
	t.recv = s2c
	t.recvNoncePending = true
	t.sendMutex.Unlock()
	s.commitClientHandshake(c2s, s2c, response.suite)
	// Data segments that waited for the handshake response can be sent now.
	s.wakeOutput()
	return nil
}

// commitServerUserAuthentication is the single TCP cache-recording point. The
// caller invokes it only after the first segment has passed authentication,
// replay, metadata, payload, padding, role, session-ID, and dispatch checks.
func (t *StreamUnderlay) commitServerUserAuthentication(seg *segment) {
	if seg == nil || !seg.serverUserAuthentication.Valid() {
		return
	}
	t.serverUserPolicy = seg.serverUserAuthentication.Policy()
	seg.serverUserAuthentication.Record()
}

func (t *StreamUnderlay) onOpenSessionResponse(seg *segment) error {
	if !t.isClient {
		return stderror.ErrInvalidOperation
	}

	sessionID := seg.metadata.(*sessionStruct).sessionID
	session, found := t.sessionMap.Load(sessionID)
	if !found {
		return fmt.Errorf("session ID %d is not found", sessionID)
	}
	if !t.deliverSegmentToSession(session.(*Session), seg) && log.IsLevelEnabled(log.TraceLevel) {
		log.Tracef("%v ignored openSessionResponse segment for closed session %d", t, sessionID)
	}
	return nil
}

func (t *StreamUnderlay) onCloseSession(seg *segment) error {
	ss := seg.metadata.(*sessionStruct)
	sessionID := ss.sessionID
	session, found := t.sessionMap.Load(sessionID)
	if !found {
		if log.IsLevelEnabled(log.TraceLevel) {
			log.Tracef("%v received close session request or response, but session ID %d is not found", t, sessionID)
		}
		return nil
	}
	s := session.(*Session)
	if !t.deliverSegmentToSession(s, seg) && log.IsLevelEnabled(log.TraceLevel) {
		log.Tracef("%v ignored closeSessionRequest or closeSessionResponse segment for closed session %d", t, sessionID)
	}
	return nil
}

func (t *StreamUnderlay) readOneSegment() (*segment, error) {
	var firstRead bool
	var err error

	// Every read of this connection refreshes the read deadline, and the event
	// loop is the only reader, so the deadline doesn't need to be cleared when
	// this function returns: the next call sets it again before it blocks.
	// Keeping one SetReadDeadline() per read instead of two keeps the timeout
	// semantics of the read loop unchanged.
	common.SetReadTimeout(t.conn, readOneSegmentTimeout())

	// Read encrypted metadata.
	readLen := MetadataLength + cipher.DefaultOverhead
	if t.recv == nil || t.recvNoncePending {
		// The first message of a cipher chain carries the nonce.
		firstRead = true
		readLen += cipher.DefaultNonceSize
	}
	if cap(t.rxMetaBuf) < readLen {
		t.rxMetaBuf = make([]byte, readLen)
	}
	encryptedMeta := t.rxMetaBuf[:readLen]
	if n, err := io.ReadFull(t.conn, encryptedMeta); err != nil {
		if stderror.IsTimeout(err) && n == 0 && !errors.Is(err, net.ErrClosed) {
			// Retry read deadlines, but don't retry when underlay is closed.
			return nil, nil
		}
		err = fmt.Errorf("metadata: read %d bytes from StreamUnderlay failed: %w", readLen, err)
		return nil, stderror.WrapErrorWithType(err, stderror.NETWORK_ERROR)
	}
	t.inBytes.Add(int64(len(encryptedMeta)))

	// Replay protection of the message that starts an inbound cipher chain.
	// The signature spans the entire 24 byte wire nonce, not just the first 16
	// bytes: a noncePattern can pin those leading bytes to a constant, which
	// would leave almost no entropy in the signed input and make the signature
	// collide across messages. The lookup is read-only: the signature is
	// recorded after the message has passed the authentication and the framing
	// checks below, so a forged or truncated message can't enter the cache.
	isNewSessionReplay := false
	if firstRead && streamReplayCache.Seen(replay.DomainStream, encryptedMeta[:cipher.DefaultNonceSize], replay.Tag{}) {
		isNewSessionReplay = true
	}

	// Decrypt metadata.
	var decryptedMeta []byte
	var authentication serveruser.Authentication
	if t.recv == nil && t.isClient {
		t.recv = t.block.Clone()
	}
	if t.recv == nil {
		decryptedMeta, authentication, err = t.serverInitRecvBlockCipherAndDecryptMetadata(encryptedMeta)
		if err != nil {
			if isNewSessionReplay {
				err = fmt.Errorf("found possible replay attack in %v", t)
				return nil, stderror.WrapErrorWithType(err, stderror.REPLAY_ERROR)
			} else {
				err = fmt.Errorf("%w", err)
				return nil, stderror.WrapErrorWithType(err, stderror.CRYPTO_ERROR)
			}
		} else if isNewSessionReplay {
			err = fmt.Errorf("found possible replay attack with payload decrypted in %v", t)
			return nil, stderror.WrapErrorWithType(err, stderror.REPLAY_ERROR)
		}
	} else {
		decryptedMeta, err = t.recv.Decrypt(encryptedMeta)
		if err != nil {
			err = fmt.Errorf("Decrypt() failed: %w", err)
			return nil, stderror.WrapErrorWithType(err, stderror.CRYPTO_ERROR)
		}
	}
	if len(decryptedMeta) != MetadataLength {
		err = fmt.Errorf("decrypted metadata size %d is unexpected", len(decryptedMeta))
		return nil, stderror.WrapErrorWithType(err, stderror.PROTOCOL_ERROR)
	}
	if t.recv != nil {
		t.recvNoncePending = false
	}

	// Read payload and construct segment.
	p := decryptedMeta[0]
	var seg *segment
	if isSessionProtocol(protocolType(p)) {
		ss := &sessionStruct{}
		if err := ss.Unmarshal(decryptedMeta); err != nil {
			err = fmt.Errorf("Unmarshal() to sessionStruct failed: %w", err)
			return nil, stderror.WrapErrorWithType(err, stderror.PROTOCOL_ERROR)
		}
		seg, err = t.readSessionSegment(ss)
	} else if isDataAckProtocol(protocolType(p)) {
		das := &dataAckStruct{}
		if err := das.Unmarshal(decryptedMeta); err != nil {
			err = fmt.Errorf("Unmarshal() to dataAckStruct failed: %w", err)
			return nil, stderror.WrapErrorWithType(err, stderror.PROTOCOL_ERROR)
		}
		seg, err = t.readDataAckSegment(das)
	} else {
		err = fmt.Errorf("unable to handle unknown protocol %d", p)
		return nil, stderror.WrapErrorWithType(err, stderror.PROTOCOL_ERROR)
	}
	if err != nil {
		return nil, err
	}
	if authentication.Valid() {
		seg.serverUserPolicy = authentication.Policy()
		seg.serverUserAuthentication = authentication
	}
	// A client must switch the cipher chain of the connection to the session
	// keys before the next message is read, because the first message of the
	// new chain carries its nonce and therefore has a different framing.
	if t.isClient && seg.metadata.Protocol() == openSessionResponse {
		if err := t.completeClientHandshake(seg); err != nil {
			return nil, stderror.WrapErrorWithType(err, stderror.PROTOCOL_ERROR)
		}
	}
	if firstRead {
		// Record the signature that Seen() looked up before the decryption.
		// Only the first message of a cipher chain can be replayed: the nonce
		// of every later message is derived from the state of the chain, so a
		// copy of such a message fails authentication instead of being
		// accepted twice. Recording here, after the metadata, the payload and
		// the padding of the message are all consistent, keeps a message that
		// failed a check out of the cache.
		streamReplayCache.Record(replay.DomainStream, encryptedMeta[:cipher.DefaultNonceSize], replay.Tag{})
	}
	return seg, nil
}

// readMessageBody reads the part of the current message that follows the
// metadata in a single read. The caller knows the total size of that part from
// the decrypted metadata, so it slices the padding regions and the encrypted
// payload out of the returned buffer, and the padding never costs a read of its
// own. One message therefore costs at most two reads of the connection: the
// metadata read of readOneSegment() and this one.
//
// The returned slice belongs to the receive buffer of the event loop, which
// holds wire bytes only: the payload is decrypted into a fresh allocation, so
// the next message can reuse the buffer.
func (t *StreamUnderlay) readMessageBody(bodyLen int) ([]byte, error) {
	if bodyLen == 0 {
		return nil, nil
	}
	if cap(t.rxPayloadBuf) < bodyLen {
		t.rxPayloadBuf = make([]byte, bodyLen)
	}
	body := t.rxPayloadBuf[:bodyLen]
	if _, err := io.ReadFull(t.conn, body); err != nil {
		err = fmt.Errorf("message body: read %d bytes from StreamUnderlay failed: %w", bodyLen, err)
		return nil, stderror.WrapErrorWithType(err, stderror.NETWORK_ERROR)
	}
	t.inBytes.Add(int64(bodyLen))
	return body, nil
}

func (t *StreamUnderlay) readSessionSegment(ss *sessionStruct) (*segment, error) {
	// A session message is the encrypted payload followed by the suffix
	// padding; it has no prefix padding.
	wirePayloadLen := 0
	if ss.payloadLen > 0 {
		wirePayloadLen = int(ss.payloadLen) + cipher.DefaultOverhead
	}
	body, err := t.readMessageBody(wirePayloadLen + int(ss.suffixLen))
	if err != nil {
		return nil, err
	}

	var decryptedPayload []byte
	if ss.payloadLen > 0 {
		decryptedPayload, err = t.recv.Decrypt(body[:wirePayloadLen])
		if err != nil {
			err = fmt.Errorf("Decrypt() failed: %w", err)
			return nil, stderror.WrapErrorWithType(err, stderror.CRYPTO_ERROR)
		}
	}

	return &segment{
		metadata:  ss,
		payload:   decryptedPayload,
		transport: common.StreamTransport,
		block:     t.recv,
	}, nil
}

func (t *StreamUnderlay) readDataAckSegment(das *dataAckStruct) (*segment, error) {
	// A data or ack message is the prefix padding, the encrypted payload and
	// the suffix padding. The metadata carries the length of all three parts,
	// so they are read with one call and sliced out of the buffer, and the
	// padding of either side is discarded in place.
	prefixLen := int(das.prefixLen)
	wirePayloadLen := 0
	if das.payloadLen > 0 {
		wirePayloadLen = int(das.payloadLen) + cipher.DefaultOverhead
	}
	body, err := t.readMessageBody(prefixLen + wirePayloadLen + int(das.suffixLen))
	if err != nil {
		return nil, err
	}

	var decryptedPayload []byte
	if das.payloadLen > 0 {
		encryptedPayload := body[prefixLen : prefixLen+wirePayloadLen]
		if isLowEntropyProtocol(das.Protocol()) {
			encryptedPayload, err = decodeLowEntropyEncryptedPayload(encryptedPayload, das)
			if err != nil {
				err = fmt.Errorf("decode low entropy payload failed: %w", err)
				return nil, stderror.WrapErrorWithType(err, stderror.PROTOCOL_ERROR)
			}
		}
		decryptedPayload, err = t.recv.Decrypt(encryptedPayload)
		if err != nil {
			err = fmt.Errorf("Decrypt() failed: %w", err)
			return nil, stderror.WrapErrorWithType(err, stderror.CRYPTO_ERROR)
		}
	}

	return &segment{
		metadata:  das,
		payload:   decryptedPayload,
		transport: common.StreamTransport,
		block:     t.recv,
	}, nil
}

func (t *StreamUnderlay) writeOneSegment(seg *segment) error {
	if seg == nil {
		return stderror.ErrNullPointer
	}

	t.sendMutex.Lock()
	defer t.sendMutex.Unlock()

	// firstWrite covers the first message of the connection and the first
	// message after the send cipher was replaced by a session key, which both
	// start a new cipher chain and therefore carry the wire format nonce. The
	// pending flag is consumed here, so a retry never adds the nonce twice.
	firstWrite := t.send == nil || t.sendNoncePending
	t.sendNoncePending = false
	if err := t.maybeInitSendBlockCipher(); err != nil {
		return fmt.Errorf("maybeInitSendBlockCipher() failed: %w", err)
	}

	if ss, ok := toSessionStruct(seg.metadata); ok {
		maxPaddingSize := maxPaddingSizeWithTrafficPattern(t.mtu, t.TransportProtocol(), int(ss.payloadLen), 0, t.trafficPattern, endPadding)
		// The padding strategy depends on the bit distribution of the
		// plaintext data to protect. The metadata is marshaled again below
		// with the final suffix length.
		//
		// metaBuf is a stack array and txScratch is the reusable buffer of this
		// underlay: both hold plaintext that is consumed inside this function,
		// while sendMutex is held.
		var metaBuf [MetadataLength]byte
		ss.marshalTo(metaBuf[:])
		if cap(t.txScratch) < MetadataLength+len(seg.payload) {
			t.txScratch = make([]byte, 0, MetadataLength+len(seg.payload))
		}
		existingData := append(t.txScratch[:0], metaBuf[:]...)
		existingData = append(existingData, seg.payload...)
		padding, err := newPaddingInto(t.padScratch[:0],
			buildRecommendedPaddingOpts(maxPaddingSize, existingData),
		)
		if err != nil {
			return fmt.Errorf("newPaddingInto() failed: %w", err)
		}
		// Keep the grown buffer for the next message; the padding itself is
		// copied into the wire buffer below.
		t.padScratch = padding[:0]
		ss.suffixLen = uint8(len(padding))
		if log.IsLevelEnabled(log.TraceLevel) {
			log.Tracef("%v is sending %v", t, seg)
		}

		ss.marshalTo(metaBuf[:])
		plaintextMetadata := metaBuf[:]
		encryptedMetadataLen := len(plaintextMetadata) + t.send.Overhead()
		if firstWrite {
			encryptedMetadataLen += t.send.NonceSize()
		}
		encryptedPayloadLen := 0
		if len(seg.payload) > 0 {
			encryptedPayloadLen = len(seg.payload) + t.send.Overhead()
		}
		wireLen := encryptedMetadataLen + encryptedPayloadLen + len(padding)
		if cap(t.txBuf) < wireLen {
			t.txBuf = make([]byte, wireLen)
		}
		// The slice is capped at the exact message length, so Encrypt() still
		// rejects a wireLen that is too short instead of writing into the
		// larger buffer of an earlier message.
		dataToSend := t.txBuf[:wireLen:wireLen]
		if err := t.send.Encrypt(dataToSend[:0], plaintextMetadata); err != nil {
			return fmt.Errorf("Encrypt() failed: %w", err)
		}
		offset := encryptedMetadataLen
		if len(seg.payload) > 0 {
			if err := t.send.Encrypt(dataToSend[offset:offset], seg.payload); err != nil {
				return fmt.Errorf("Encrypt() failed: %w", err)
			}
			offset += encryptedPayloadLen
		}
		copy(dataToSend[offset:], padding)
		if err := t.writeWithPossibleFragment(dataToSend); err != nil {
			return err
		}
		t.outBytes.Add(int64(len(dataToSend)))
	} else if das, ok := toDataAckStruct(seg.metadata); ok {
		lowEntropy := isLowEntropyProtocol(das.Protocol())
		if lowEntropy {
			if err := prepareLowEntropyDataAckForSend(das, len(seg.payload)); err != nil {
				return fmt.Errorf("prepare low entropy payload failed: %w", err)
			}
		}
		maxMiddlePaddingSize := maxPaddingSizeWithTrafficPattern(t.mtu, t.TransportProtocol(), int(das.payloadLen), 0, t.trafficPattern, middlePadding)
		padding1, err := newPaddingInto(t.padScratch[:0], paddingOpts{
			maxLen: maxMiddlePaddingSize,
			ascii: &asciiPaddingOpts{
				minConsecutiveASCIILen: mathext.Min(maxMiddlePaddingSize, recommendedConsecutiveASCIILen),
			},
		})
		if err != nil {
			return fmt.Errorf("newPaddingInto() failed: %w", err)
		}
		maxEndPaddingSize := maxPaddingSizeWithTrafficPattern(t.mtu, t.TransportProtocol(), int(das.payloadLen), len(padding1), t.trafficPattern, endPadding)
		// The end padding is appended after the middle padding in the same
		// scratch buffer, so the two regions never overwrite each other, and
		// padding2 is sliced back to the end padding before it is used.
		padding2WithPrefix, err := newPaddingInto(padding1, paddingOpts{
			maxLen: maxEndPaddingSize,
			ascii: &asciiPaddingOpts{
				minConsecutiveASCIILen: mathext.Min(maxEndPaddingSize, recommendedConsecutiveASCIILen),
			},
		})
		if err != nil {
			return fmt.Errorf("newPaddingInto() failed: %w", err)
		}
		t.padScratch = padding2WithPrefix[:0]
		padding2 := padding2WithPrefix[len(padding1):]
		das.prefixLen = uint8(len(padding1))
		das.suffixLen = uint8(len(padding2))
		if log.IsLevelEnabled(log.TraceLevel) {
			log.Tracef("%v is sending %v", t, seg)
		}

		var metaBuf [MetadataLength]byte
		das.marshalTo(metaBuf[:])
		plaintextMetadata := metaBuf[:]
		encryptedMetadataLen := len(plaintextMetadata) + t.send.Overhead()
		if firstWrite {
			encryptedMetadataLen += t.send.NonceSize()
		}
		wirePayloadLen := 0
		if len(seg.payload) > 0 {
			wirePayloadLen = len(seg.payload) + t.send.Overhead()
			if lowEntropy {
				wirePayloadLen = int(das.payloadLen) + t.send.Overhead()
			}
		}
		wireLen := encryptedMetadataLen + len(padding1) + wirePayloadLen + len(padding2)
		if cap(t.txBuf) < wireLen {
			t.txBuf = make([]byte, wireLen)
		}
		// The slice is capped at the exact message length, so Encrypt() still
		// rejects a wireLen that is too short instead of writing into the
		// larger buffer of an earlier message.
		dataToSend := t.txBuf[:wireLen:wireLen]
		if err := t.send.Encrypt(dataToSend[:0], plaintextMetadata); err != nil {
			return fmt.Errorf("Encrypt() failed: %w", err)
		}
		offset := encryptedMetadataLen
		offset += copy(dataToSend[offset:], padding1)
		if len(seg.payload) > 0 {
			if err := t.send.Encrypt(dataToSend[offset:offset], seg.payload); err != nil {
				return fmt.Errorf("Encrypt() failed: %w", err)
			}
			if lowEntropy {
				encryptedPayloadLen := len(seg.payload) + t.send.Overhead()
				encryptedPayload, err := encodeLowEntropyEncryptedPayload(dataToSend[offset:offset+encryptedPayloadLen], das)
				if err != nil {
					return fmt.Errorf("encode low entropy payload failed: %w", err)
				}
				copy(dataToSend[offset:], encryptedPayload)
			}
			offset += wirePayloadLen
		}
		copy(dataToSend[offset:], padding2)
		if err := t.writeWithPossibleFragment(dataToSend); err != nil {
			return err
		}
		t.outBytes.Add(int64(len(dataToSend)))
	} else {
		return stderror.ErrInvalidArgument
	}
	return nil
}

// serverInitRecvBlockCipherAndDecryptMetadata performs stateless discovery
// against one current generation and then initializes t.recv from the mutable
// winning clone. The returned authentication is temporary and must be recorded
// only after the complete first segment is validated and dispatched.
func (t *StreamUnderlay) serverInitRecvBlockCipherAndDecryptMetadata(encryptedMeta []byte) ([]byte, serveruser.Authentication, error) {
	if t.recv != nil {
		return nil, serveruser.Authentication{}, fmt.Errorf("recv cipher is already set")
	}
	if t.serverUsers == nil {
		return nil, serveruser.Authentication{}, fmt.Errorf("server user registry is nil")
	}
	block, _, authentication, err := t.serverUsers.Discover(encryptedMeta, t.serverUserSource, true)
	if err != nil {
		return nil, serveruser.Authentication{}, err
	}

	// Re-decrypt with implicit nonce mode enabled to capture TCP nonce state.
	t.recv = block
	if t.trafficPattern != nil {
		t.recv.SetNoncePattern(t.trafficPattern.GetNonce())
	}
	t.recv.SetImplicitNonceMode(true)
	decryptedMeta, err := t.recv.Decrypt(encryptedMeta)
	if err != nil {
		t.recv = nil
		return nil, serveruser.Authentication{}, fmt.Errorf("stateful Decrypt() failed: %w", err)
	}
	return decryptedMeta, authentication, nil
}

func (t *StreamUnderlay) maybeInitSendBlockCipher() error {
	if t.send != nil {
		return nil
	}
	if t.isClient {
		t.send = t.block.Clone()
	} else {
		if t.recv != nil {
			t.send = t.recv.Clone()
			t.send.SetImplicitNonceMode(false) // clear implicit nonce
			t.send.SetImplicitNonceMode(true)
		} else {
			return fmt.Errorf("recv cipher is nil")
		}
	}
	return nil
}

// writeWithPossibleFragment writes data to the stream network connection
// with or without fragmentation depending on the traffic pattern.
func (t *StreamUnderlay) writeWithPossibleFragment(dataToSend []byte) error {
	if t.trafficPattern == nil || t.trafficPattern.GetTcpFragment() == nil || !t.trafficPattern.GetTcpFragment().GetEnable() {
		return t.writeToConn(dataToSend)
	}

	remaining := dataToSend
	for len(remaining) > 0 {
		minLenToSend := int(math.Sqrt(float64(len(dataToSend)))) + 1
		maxLenToSend := mathext.Max(minLenToSend, len(dataToSend)/2)
		lenToSend := mrand.Intn(maxLenToSend-minLenToSend+1) + minLenToSend
		if lenToSend > len(remaining) {
			lenToSend = len(remaining)
		}
		if err := t.writeToConn(remaining[:lenToSend]); err != nil {
			return err
		}
		if t.trafficPattern.GetTcpFragment().GetMaxSleepMs() > 0 {
			sleepMs := mrand.Intn(int(t.trafficPattern.GetTcpFragment().GetMaxSleepMs()) + 1)
			time.Sleep(time.Duration(sleepMs) * time.Millisecond)
		}
		remaining = remaining[lenToSend:]
	}
	return nil
}

// writeToConn writes one chunk of an outbound message to the connection of the
// underlay.
//
// Every write is bounded by streamWriteTimeout. The deadline is armed before
// the write and the next write arms it again, so an expired deadline is never
// left behind for the write that follows it. See streamWriteTimeout for why a
// write must not block forever.
//
// A timeout is distinguishable from a connection error. Both are reported as
// network errors, because both make the session unusable, but a timeout also
// carries stderror.ErrTimeout in its error chain: stderror.IsTimeout() reports
// true for a peer that stopped reading and false for a peer that closed the
// connection.
func (t *StreamUnderlay) writeToConn(data []byte) error {
	if err := t.conn.SetWriteDeadline(time.Now().Add(streamWriteTimeout)); err != nil {
		err = fmt.Errorf("SetWriteDeadline() failed: %w", err)
		return stderror.WrapErrorWithType(err, stderror.NETWORK_ERROR)
	}
	if _, err := t.conn.Write(data); err != nil {
		if stderror.IsTimeout(err) {
			err = fmt.Errorf("Write() timed out after %v: %w", streamWriteTimeout, errors.Join(err, stderror.ErrTimeout))
		} else {
			err = fmt.Errorf("Write() failed: %w", err)
		}
		return stderror.WrapErrorWithType(err, stderror.NETWORK_ERROR)
	}
	return nil
}

// drainAfterError continues to read some data from the stream network connection
// after an error happened to confuse possible attacks.
func (t *StreamUnderlay) drainAfterError() {
	// Set read deadline to avoid being blocked forever. The timeout is drawn
	// per connection instead of adding a host-stable component: a connection
	// that stays silent for a whole minute is itself a fingerprint, and
	// draining only needs to absorb what a prober writes in reply.
	timeoutMillis := rng.IntRange(500, 5000) // Maximum 5 seconds.
	t.conn.SetReadDeadline(time.Now().Add(time.Duration(timeoutMillis) * time.Millisecond))

	// Determine the read buffer size.
	bufSizeType := mrand.Intn(4)
	bufSize := 1 << (12 + bufSizeType) // 4, 8, 16, 32 KB
	buf := make([]byte, bufSize)

	// Determine the number of bytes to read.
	// Minimum 0 bytes, maximum bufSize bytes.
	minRead := rng.IntRange(0, bufSize)

	if minRead > 0 {
		n, err := io.ReadAtLeast(t.conn, buf, minRead)
		if err != nil {
			log.Debugf("%v read after stream error failed to complete: %v", t, err)
		} else {
			log.Debugf("%v read at least %d bytes after stream error", t, n)
		}
	}
}

func (t *StreamUnderlay) cleanSessions() {
	// now is read once, so every session is compared against the same instant
	// and a cleanup run can't remove a session that received a segment while
	// the map is being scanned.
	now := time.Now().UnixMicro()
	t.sessionMap.Range(func(k, v any) bool {
		session := v.(*Session)
		select {
		case <-session.closedChan:
			log.Debugf("Found closed %v", session)
			if err := t.RemoveSession(session); err != nil {
				log.Debugf("%v RemoveSession() failed: %v", t, err)
			}
		default:
			// Reclaim a session whose peer disappeared without closing the
			// connection, so that a stream connection doesn't keep the state
			// of a dead session forever. See idleStreamSessionTimeout for why
			// the timeout is far longer than the one of the packet transport.
			// The session is removed by the event loop, which is the only
			// caller of this method.
			if now-session.lastRXTime.Load() > idleStreamSessionTimeout.Microseconds() {
				log.Debugf("Found idle %v", session)
				if err := t.RemoveSession(session); err != nil {
					log.Debugf("%v RemoveSession() failed: %v", t, err)
				}
			}
		}
		return true
	})
}
