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
	"time"

	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/cipher"
	"github.com/enfein/mieru/v3/pkg/common"
	"github.com/enfein/mieru/v3/pkg/log"
	"github.com/enfein/mieru/v3/pkg/mathext"
	"github.com/enfein/mieru/v3/pkg/protocol/serveruser"
	"github.com/enfein/mieru/v3/pkg/replay"
	"github.com/enfein/mieru/v3/pkg/stderror"
)

const (
	packetOverhead          = cipher.DefaultNonceSize + MetadataLength + cipher.DefaultOverhead*2
	packetNonHeaderPosition = cipher.DefaultNonceSize + MetadataLength + cipher.DefaultOverhead

	idleSessionTimeout = time.Minute
)

var packetReplayCache = replay.NewCache(64*1024, cipher.KeyRefreshInterval*3)

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

	// Send buffers of the data plane. sendMutex protects both of them, and the
	// connection write is synchronous and copies the bytes, so neither buffer
	// is referenced after writeOneSegment returns.
	//
	// txBuf has len == cap and holds the encrypted wire bytes of one outbound
	// datagram. The datagram is sliced out of it with a full slice expression,
	// so its capacity is exactly its length and Encrypt() keeps rejecting a
	// destination that is too short.
	//
	// txScratch is empty and holds the plaintext metadata and payload that the
	// padding strategy inspects.
	txBuf     []byte
	txScratch []byte

	// ---- client fields ----
	serverAddr net.Addr
	block      cipher.BlockCipher
	// cipherSuites is the cipher suite preference order of the client.
	cipherSuites []cipher.Suite

	// ---- server fields ----
	serverUsers *serveruser.Registry
}

var _ Underlay = &PacketUnderlay{}

// NewPacketUnderlay connects to the remote address "addr" on the network
// with packet encryption.
// "block" is the block encryption algorithm to encrypt packets.
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
		baseUnderlay:       *newBaseUnderlay(true, mtu, trafficPattern),
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
						return fmt.Errorf("writeOneSegment() failed: %w", err)
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
		session.closeWithError(handshakeErr)
		if response != nil {
			respSeg := session.newSessionResponseSegment(response.Marshal(), seg.block)
			if err := u.writeOneSegment(respSeg, remoteAddr); err != nil {
				log.Debugf("%v failed to send the handshake response of session %d: %v", u, sessionID, err)
			}
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
	select {
	case u.readySessions <- session:
	case <-u.done:
		return io.ErrClosedPipe
	}
	u.commitServerUserAuthentication(seg)
	return nil
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
		common.SetReadTimeout(u.conn, readOneSegmentTimeout)
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
		isNewSessionReplay := false
		if packetReplayCache.IsDuplicate(encryptedMeta[:cipher.DefaultOverhead], addr.String()) {
			isNewSessionReplay = true
		}
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
			return seg, addr, nil
		} else {
			log.Debugf("%v unable to handle unknown protocol %d", u, p)
			continue
		}
	}
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

	u.sendMutex.Lock()
	defer u.sendMutex.Unlock()

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
		// metaBuf is a stack array and txScratch is the reusable buffer of this
		// underlay: both hold plaintext that is consumed inside this function,
		// while sendMutex is held.
		var metaBuf [MetadataLength]byte
		ss.marshalTo(metaBuf[:])
		if cap(u.txScratch) < MetadataLength+len(seg.payload) {
			u.txScratch = make([]byte, 0, MetadataLength+len(seg.payload))
		}
		existingData := append(u.txScratch[:0], metaBuf[:]...)
		existingData = append(existingData, seg.payload...)
		padding := newPadding(
			buildRecommendedPaddingOpts(maxPaddingSize, existingData, blockCipher.BlockContext().UserName),
		)
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
		if cap(u.txBuf) < wireLen {
			u.txBuf = make([]byte, wireLen)
		}
		// The slice is capped at the exact message length, so Encrypt() still
		// rejects a wireLen that is too short instead of writing into the
		// larger buffer of an earlier message.
		dataToSend := u.txBuf[:wireLen:wireLen]
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
		if _, err := u.conn.WriteTo(dataToSend, addr); err != nil {
			return fmt.Errorf("WriteTo() failed: %w", err)
		}
		u.outBytes.Add(int64(len(dataToSend)))
	} else if das, ok := toDataAckStruct(seg.metadata); ok {
		lowEntropy := isLowEntropyProtocol(das.Protocol())
		if lowEntropy {
			if err := prepareLowEntropyDataAckForSend(das, len(seg.payload)); err != nil {
				return fmt.Errorf("prepare low entropy payload failed: %w", err)
			}
		}
		maxMiddlePaddingSize := maxPaddingSizeWithTrafficPattern(u.mtu, u.TransportProtocol(), int(das.payloadLen), 0, u.trafficPattern, middlePadding)
		padding1 := newPadding(paddingOpts{
			maxLen: maxMiddlePaddingSize,
			ascii: &asciiPaddingOpts{
				minConsecutiveASCIILen: mathext.Min(maxMiddlePaddingSize, recommendedConsecutiveASCIILen),
			},
		})
		maxEndPaddingSize := maxPaddingSizeWithTrafficPattern(u.mtu, u.TransportProtocol(), int(das.payloadLen), len(padding1), u.trafficPattern, endPadding)
		padding2 := newPadding(paddingOpts{
			maxLen: maxEndPaddingSize,
			ascii: &asciiPaddingOpts{
				minConsecutiveASCIILen: mathext.Min(maxEndPaddingSize, recommendedConsecutiveASCIILen),
			},
		})
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
		if cap(u.txBuf) < wireLen {
			u.txBuf = make([]byte, wireLen)
		}
		// The slice is capped at the exact message length, so Encrypt() still
		// rejects a wireLen that is too short instead of writing into the
		// larger buffer of an earlier message.
		dataToSend := u.txBuf[:wireLen:wireLen]
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
		if _, err := u.conn.WriteTo(dataToSend, addr); err != nil {
			return fmt.Errorf("WriteTo() failed: %w", err)
		}
		u.outBytes.Add(int64(len(dataToSend)))
	} else {
		return stderror.ErrInvalidArgument
	}
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

func (u *PacketUnderlay) tryDecryptExistingSession(encryptedMeta []byte, addr net.Addr) (decryptedMeta []byte, blockCipher cipher.BlockCipher, matchedPolicy serveruser.Policy, decrypted bool) {
	u.sessionMap.Range(func(_, value any) bool {
		session := value.(*Session)
		sessionBlock := session.block.Load()
		if sessionBlock != nil && isSamePacketAddr(session.RemoteAddr(), addr) {
			plaintext, err := (*sessionBlock).Decrypt(encryptedMeta)
			if err == nil {
				decryptedMeta = plaintext
				blockCipher = *sessionBlock
				if policy := session.userPolicy.Load(); policy != nil {
					matchedPolicy = *policy
				}
				decrypted = true
				return false
			}
		}
		return true
	})
	return
}

func (u *PacketUnderlay) cleanSessions() {
	u.sessionMap.Range(func(k, v any) bool {
		session := v.(*Session)
		select {
		case <-session.closedChan:
			log.Debugf("Found closed %v", session)
			if err := u.RemoveSession(session); err != nil {
				log.Debugf("%v RemoveSession() failed: %v", u, err)
			}
		default:
		}
		if time.Now().UnixMicro()-session.lastRXTime.Load() > idleSessionTimeout.Microseconds() {
			log.Debugf("Found idle %v", session)
			if err := u.RemoveSession(session); err != nil {
				log.Debugf("%v RemoveSession() failed: %v", u, err)
			}
		}
		return true
	})
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
