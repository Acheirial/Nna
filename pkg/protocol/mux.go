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
	"errors"
	"fmt"
	"io"
	"math"
	mrand "math/rand"
	"net"
	"net/netip"
	"reflect"
	"sync"
	"sync/atomic"
	"time"

	apicommon "github.com/Acheirial/shadowlemon/v3/apis/common"
	"github.com/Acheirial/shadowlemon/v3/apis/trafficpattern"
	"github.com/Acheirial/shadowlemon/v3/pkg/appctl/appctlpb"
	"github.com/Acheirial/shadowlemon/v3/pkg/cipher"
	"github.com/Acheirial/shadowlemon/v3/pkg/common"
	"github.com/Acheirial/shadowlemon/v3/pkg/log"
	"github.com/Acheirial/shadowlemon/v3/pkg/mathext"
	"github.com/Acheirial/shadowlemon/v3/pkg/protocol/serveruser"
	"github.com/Acheirial/shadowlemon/v3/pkg/sockopts"
	"github.com/Acheirial/shadowlemon/v3/pkg/stderror"
)

const (
	underlayCleanInterval      = 5 * time.Second
	minUnderlayCapacityReclaim = 16
)

// Backoff of the rebuild of the listener of a packet endpoint.
//
// The socket of a packet endpoint is the listener of the endpoint itself, so an
// endpoint whose socket died serves nobody: the listener is rebuilt instead of
// letting the endpoint stay offline until the process restarts. The rebuild
// runs after a growing delay, because the reason a rebuild fails is usually a
// condition that lasts (a port that another process holds, a network interface
// that is down), and a tight retry loop would burn the CPU of the server.
const (
	// packetUnderlayRebuildBackoffInitial is the delay before the second
	// listener of a packet endpoint.
	packetUnderlayRebuildBackoffInitial = 1 * time.Second

	// packetUnderlayRebuildBackoffMax caps the delay between two rebuild
	// attempts. It also serves as the time that a rebuilt endpoint has to
	// serve for the backoff of a previous failure to be forgiven.
	packetUnderlayRebuildBackoffMax = 30 * time.Second
)

// Limits of the mux underlay list and of the server accept path.
const (
	// maxUnderlays is the maximum number of underlays a single mux keeps at the
	// same time. The underlays of a server are established by peers that are not
	// authenticated yet, so this bounds how many sockets, goroutines and buffers
	// such peers can make the server allocate. Reaching the limit rejects new
	// underlays only: it never touches an existing underlay or the sessions
	// running on it.
	maxUnderlays = 4096

	// serverUnderlayTTL is how long a server stream underlay without any session
	// stays open. It is well above the largest single read timeout of a stream
	// underlay (readOneSegmentTimeout is at most 121s), so a peer that is
	// temporarily quiet during the handshake is not dropped, while a connection
	// that never establishes a session is reclaimed in a bounded time.
	serverUnderlayTTL = 3 * time.Minute

	// acceptBurst is the size of the token bucket of one source IP address in
	// the server TCP accept path: how many underlays a source IP address can
	// open back to back. It covers a client that starts many sessions at once,
	// and it covers several clients that share the same NAT address. The
	// integration test opens more than a thousand underlays from 127.0.0.1 in a
	// few seconds with multiplexing enabled, so the burst is well above that:
	// the bound of the number of underlays is maxUnderlays, and this limiter
	// only keeps a single source address from draining that bound instantly.
	acceptBurst = 2048

	// acceptRefillPerSecond is the token refill rate of one source IP address.
	// It bounds the sustained rate at which an unauthenticated peer can make the
	// server allocate and handshake new TCP underlays. It is calibrated the same
	// way as acceptBurst: it has to stay above the churn of a legitimate client,
	// or a busy client is disconnected.
	acceptRefillPerSecond = 512

	// acceptBucketIdleTimeout is how long a source IP address keeps its token
	// bucket after its last new underlay.
	acceptBucketIdleTimeout = 10 * time.Minute

	// acceptMaxSourceBuckets is the hard upper bound of the number of source IP
	// buckets tracked at the same time, so that a flood from many source
	// addresses can't grow the token bucket map without bound.
	acceptMaxSourceBuckets = 4096

	// maxMultiplexFactor is the largest client multiplexing factor. The
	// configuration layer maps MULTIPLEXING_OFF to 0, MULTIPLEXING_LOW to 1,
	// MULTIPLEXING_MIDDLE to 2 and MULTIPLEXING_HIGH to 3, so no valid
	// configuration is clamped. Larger factors are refused because
	// baseUnderlayTrafficVolumeLimit is shifted left by the factor to compute
	// the underlay traffic volume limit, and a shift of 64 or more overflows to
	// a zero limit that never disables scheduling.
	maxMultiplexFactor = 3

	// baseUnderlayTrafficVolumeLimit is the number of bytes that disables
	// scheduling new sessions to a client underlay, for a multiplexing factor
	// of 0. It is 512 MiB, so the limit is 1 GiB for a multiplexing factor of 1.
	baseUnderlayTrafficVolumeLimit int64 = 512 * 1024 * 1024
)

// Mux manages the sessions and underlays.
type Mux struct {
	// ---- common fields ----
	isClient              bool
	endpoints             []UnderlayProperties
	underlays             []Underlay
	dialer                apicommon.Dialer
	packetDialer          apicommon.PacketDialer
	resolver              apicommon.DNSResolver
	clientDNSConfig       *apicommon.ClientDNSConfig
	streamListenerFactory apicommon.StreamListenerFactory
	packetListenerFactory apicommon.PacketListenerFactory
	trafficPattern        *trafficpattern.Config
	chAccept              chan net.Conn
	acceptErr             *muxAcceptErr
	used                  bool
	done                  chan struct{}
	closeDone             chan struct{}
	maintenanceDone       chan struct{}
	ctx                   context.Context    // mux master context
	ctxCancelFunc         context.CancelFunc // function to cancel master context when mux is closed
	mu                    sync.Mutex
	serverUnderlayLoopWG  sync.WaitGroup
	cleaner               *time.Ticker

	// maxUnderlayCount and silentUnderlayTTL are the runtime values of the
	// maxUnderlays and serverUnderlayTTL constants. They are struct fields so
	// that a test can lower them before the mux is used.
	maxUnderlayCount  int
	silentUnderlayTTL time.Duration

	// packetRebuildBackoffInitial and packetRebuildBackoffMax are the runtime
	// values of the packetUnderlayRebuildBackoff* constants. They are struct
	// fields so that a test can lower them before the mux is used.
	packetRebuildBackoffInitial time.Duration
	packetRebuildBackoffMax     time.Duration

	// acceptLimiter limits how fast a single source IP address can make the
	// server establish new TCP underlays. Only the server accept path uses it.
	acceptLimiter *sourceRateLimiter

	// ---- client only fields ----
	username        string
	password        []byte
	multiplexFactor int
	// cipherSuites is the cipher suite preference order of the client. It is
	// stored as a pointer to a slice so that a reader can snapshot it without
	// taking the mux lock.
	cipherSuites atomic.Pointer[[]cipher.Suite]

	// ---- server only fields ----
	serverUsers serveruser.Registry
}

var _ net.Listener = &Mux{}

// NewMux creates a new ShadowLemon multiplex controller.
func NewMux(isClinet bool) *Mux {
	if isClinet {
		log.Infof("Initializing client multiplexer")
	} else {
		log.Infof("Initializing server multiplexer")
	}
	mux := &Mux{
		isClient:              isClinet,
		underlays:             make([]Underlay, 0),
		dialer:                &net.Dialer{Timeout: 10 * time.Second, Control: sockopts.DefaultDialerControl()},
		packetDialer:          common.UDPDialer{Control: sockopts.DefaultDialerControl()},
		resolver:              &net.Resolver{},
		clientDNSConfig:       &apicommon.ClientDNSConfig{},
		streamListenerFactory: &net.ListenConfig{Control: sockopts.DefaultListenerControl()},
		packetListenerFactory: &net.ListenConfig{Control: sockopts.DefaultListenerControl()},
		chAccept:              make(chan net.Conn, sessionChanCapacity),
		acceptErr:             newMuxAcceptErr(),
		done:                  make(chan struct{}),
		closeDone:             make(chan struct{}),
		maintenanceDone:       make(chan struct{}),
		cleaner:               time.NewTicker(underlayCleanInterval),
		maxUnderlayCount:      maxUnderlays,
		silentUnderlayTTL:     serverUnderlayTTL,

		packetRebuildBackoffInitial: packetUnderlayRebuildBackoffInitial,
		packetRebuildBackoffMax:     packetUnderlayRebuildBackoffMax,
		acceptLimiter:               newSourceRateLimiter(acceptBurst, acceptRefillPerSecond),
	}
	mux.ctx, mux.ctxCancelFunc = context.WithCancel(context.Background())

	// Run maintenance tasks in the background.
	go func() {
		defer close(mux.maintenanceDone)
		for {
			select {
			case <-mux.cleaner.C:
				mux.mu.Lock()
				if isClinet {
					mux.cleanUnderlay(true)
				} else {
					mux.cleanUnderlay(false)
				}
				mux.mu.Unlock()
				// Drop the token buckets of source addresses that stopped
				// opening new underlays, so the limiter memory stays bounded.
				mux.acceptLimiter.clean(time.Now())
			case <-mux.done:
				mux.cleaner.Stop()
				return
			}
		}
	}()
	return mux
}

// SetEndpoints updates the endpoints that mux is listening to.
// If mux is started and new endpoints are added, mux also starts
// to listen to those new endpoints. In that case, old endpoints
// are not impacted.
// Listener failures are logged. Use UpdateEndpoints to receive the errors.
func (m *Mux) SetEndpoints(endpoints []UnderlayProperties) *Mux {
	if err := m.UpdateEndpoints(endpoints); err != nil {
		log.Errorf("Update mux endpoints failed: %v", err)
	}
	return m
}

// UpdateEndpoints updates the configured endpoints before startup or on a client.
// On a running server, it adds listeners while retaining all existing endpoints.
// It returns listener errors without stopping the mux. Successful additions remain
// active even if another endpoint fails; failed endpoints can be retried.
func (m *Mux) UpdateEndpoints(endpoints []UnderlayProperties) error {
	m.mu.Lock()
	defer m.mu.Unlock()
	select {
	case <-m.done:
		return io.ErrClosedPipe
	default:
	}
	if m.isClient || !m.used {
		m.endpoints = endpoints
		return nil
	}
	new := m.newEndpoints(m.endpoints, endpoints)
	var wg sync.WaitGroup
	results := make([]*muxAcceptErr, len(new))
	for i, p := range new {
		results[i] = newMuxAcceptErr()
		wg.Add(1)
		go m.acceptUnderlayLoop(m.ctx, p, &wg, results[i])
	}
	wg.Wait()
	var errs []error
	for i, result := range results {
		if err := result.get(); err != nil {
			errs = append(errs, err)
		} else {
			m.endpoints = append(m.endpoints, new[i])
		}
	}
	log.Infof("Mux now has %d endpoints", len(m.endpoints))
	return errors.Join(errs...)
}

// SetDialer updates the dialer used by the mux.
func (m *Mux) SetDialer(dialer apicommon.Dialer) *Mux {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.dialer = dialer
	log.Infof("Mux dialer has been updated")
	return m
}

// SetPacketDialer updates the packet dialer used by the mux.
func (m *Mux) SetPacketDialer(packetDialer apicommon.PacketDialer) *Mux {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.packetDialer = packetDialer
	log.Infof("Mux packet dialer has been updated")
	return m
}

// SetResolver updates the DNS resolver used by the mux.
func (m *Mux) SetResolver(resolver apicommon.DNSResolver) *Mux {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.resolver = resolver
	log.Infof("Mux DNS resolver has been updated")
	return m
}

// SetClientDNSConfig updates the client DNS configuration used by the mux.
func (m *Mux) SetClientDNSConfig(clientDNSConfig *apicommon.ClientDNSConfig) *Mux {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.clientDNSConfig = clientDNSConfig
	log.Infof("Mux client DNS configuration has been updated")
	return m
}

// SetStreamListenerFactory updates the stream oriented network listener factory used by the mux.
func (m *Mux) SetStreamListenerFactory(listenerFactory apicommon.StreamListenerFactory) *Mux {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.streamListenerFactory = listenerFactory
	log.Infof("Mux stream listener factory has been updated")
	return m
}

// SetPacketListenerFactory updates the packet oriented network listener factory used by the mux.
func (m *Mux) SetPacketListenerFactory(listenerFactory apicommon.PacketListenerFactory) *Mux {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.packetListenerFactory = listenerFactory
	log.Infof("Mux packet listener factory has been updated")
	return m
}

// SetTrafficPattern updates the traffic pattern configuration used by the mux.
func (m *Mux) SetTrafficPattern(trafficPattern *trafficpattern.Config) *Mux {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.trafficPattern = trafficPattern
	log.Infof("Mux traffic pattern has been updated")
	return m
}

// SetClientUserNamePassword panics if the mux is already started.
func (m *Mux) SetClientUserNamePassword(username string, password []byte) *Mux {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.isClient {
		panic("Can't set client password in server mux")
	}
	if m.used {
		panic("Can't set client password after mux is used")
	}
	m.username = username
	m.password = password
	return m
}

// SetClientMultiplexFactor sets how aggressively the client reuses an existing
// underlay instead of creating a new one. The supported range is
// [0, maxMultiplexFactor]: 0 disables multiplexing and larger values make reuse
// more likely. A value outside the range is clamped, because a larger factor
// would overflow the traffic volume limit computed by cleanUnderlay.
//
// This method panics if the mux is already started.
func (m *Mux) SetClientMultiplexFactor(n int) *Mux {
	m.mu.Lock()
	defer m.mu.Unlock()
	if !m.isClient {
		panic("Can't set multiplex factor in server mux")
	}
	if m.used {
		panic("Can't set multiplex factor after mux is used")
	}
	factor := mathext.Min(mathext.Max(n, 0), maxMultiplexFactor)
	if factor != n {
		log.Warnf("Multiplexing factor %d is out of the supported range [0, %d], using %d", n, maxMultiplexFactor, factor)
	}
	m.multiplexFactor = factor
	log.Infof("Mux multiplexing factor is set to %d", m.multiplexFactor)
	return m
}

// SetServerUsers builds and atomically updates the registered users.
func (m *Mux) SetServerUsers(users map[string]*appctlpb.User) *Mux {
	if m.isClient {
		panic("Can't set server users in client mux")
	}
	m.serverUsers.SetUsers(users)
	return m
}

// SetCipherSuites sets the cipher suite preference order of the client.
// The first entry of the list protects the handshake request, and the server
// picks the final suite from the intersection of this list and the suites it
// allows. A candidate also has to fit the handshake envelope: a suite whose
// key is longer than the key of the first entry can't be derived from the
// envelope and is skipped.
//
// Duplicates and unknown suites are dropped, the order is preserved, and an
// empty list selects SuiteXChaCha20Poly1305. This method panics if the mux is
// a server mux.
func (m *Mux) SetCipherSuites(suites []cipher.Suite) {
	if !m.isClient {
		panic("Can't set client cipher suites in server mux")
	}
	normalized := normalizeClientCipherSuites(suites)
	m.cipherSuites.Store(&normalized)
	log.Infof("Mux cipher suite preference is set to %v", normalized)
}

// SetAllowedCipherSuites sets the cipher suite set that the server allows.
// Duplicates and unknown suites are dropped, the order is preserved, and an
// empty list allows all the supported cipher suites. The server picks the
// final suite from the intersection of this set and the suites the client
// offers, in the order of this set.
//
// This method panics if the mux is a client mux.
func (m *Mux) SetAllowedCipherSuites(suites []cipher.Suite) {
	if m.isClient {
		panic("Can't set allowed cipher suites in client mux")
	}
	normalized := normalizeAllowedCipherSuites(suites)
	// The discovery material of every user and the handshake negotiation of
	// every server underlay read the allowed suites from the user registry.
	m.serverUsers.SetAllowedCipherSuites(normalized)
	log.Infof("Mux allowed cipher suites are set to %v", normalized)
}

// clientCipherSuites returns a snapshot of the cipher suite preference of the
// client.
func (m *Mux) clientCipherSuites() []cipher.Suite {
	if p := m.cipherSuites.Load(); p != nil && len(*p) > 0 {
		return *p
	}
	return normalizeClientCipherSuites(nil)
}

// SetServerUserHintIsMandatory atomically sets whether the user hint is
// mandatory.
func (m *Mux) SetServerUserHintIsMandatory(userHintIsMandatory bool) *Mux {
	if m.isClient {
		panic("Can't set server user hint is mandatory in client mux")
	}
	m.serverUsers.SetHintMandatory(userHintIsMandatory)
	log.Infof("Mux user hint is mandatory is set to %v", userHintIsMandatory)
	return m
}

func (m *Mux) Accept() (net.Conn, error) {
	select {
	case <-m.acceptErr.done:
		return nil, io.ErrClosedPipe
	case conn := <-m.chAccept:
		return conn, nil
	case <-m.done:
		return nil, io.EOF
	}
}

func (m *Mux) Close() error {
	m.mu.Lock()
	select {
	case <-m.done:
		closeDone := m.closeDone
		m.mu.Unlock()
		<-closeDone
		return nil
	default:
	}

	if m.isClient {
		log.Infof("Closing client multiplexer")
	} else {
		log.Infof("Closing server multiplexer")
	}
	// Signal shutdown while holding mu. Server underlay event loops are
	// registered under the same lock, so no writer can be added after this
	// point.
	close(m.done)
	m.ctxCancelFunc()
	for _, underlay := range m.underlays {
		underlay.Close()
	}
	m.underlays = make([]Underlay, 0)
	m.mu.Unlock()

	// Wait for the maintenance loop and all underlay event loops to stop.
	<-m.maintenanceDone
	m.serverUnderlayLoopWG.Wait()
	close(m.closeDone)
	return nil
}

// Addr is not supported by Mux.
func (m *Mux) Addr() net.Addr {
	return common.NilNetAddr()
}

// Start listens on all the server addresses for incoming connections.
// Call this method in client results in an error.
// Mux is automatically closed when accept underlay fails.
func (m *Mux) Start() error {
	if m.isClient {
		return stderror.ErrInvalidOperation
	}
	if !m.serverUsers.HasUsers() {
		return fmt.Errorf("no user found")
	}
	if len(m.endpoints) == 0 {
		return fmt.Errorf("no server listening endpoint found")
	}
	for _, p := range m.endpoints {
		if common.IsNilNetAddr(p.LocalAddr()) {
			return fmt.Errorf("endpoint local address is not set")
		}
	}

	m.mu.Lock()
	m.used = true
	var wg sync.WaitGroup
	for _, p := range m.endpoints {
		wg.Add(1)
		go m.acceptUnderlayLoop(m.ctx, p, &wg, m.acceptErr)
	}
	wg.Wait()
	acceptErr := m.acceptErr.get()
	m.mu.Unlock()
	if acceptErr != nil {
		if err := m.Close(); err != nil {
			log.Warnf("mux Close() failed: %v", err)
		}
		return fmt.Errorf("mux server listener failed: %w", acceptErr)
	}
	return nil
}

// DialContext returns a network connection for the client to consume.
// The connection may be a session established from an existing underlay.
func (m *Mux) DialContext(ctx context.Context) (net.Conn, error) {
	if !m.isClient {
		return nil, stderror.ErrInvalidOperation
	}
	if len(m.password) == 0 {
		return nil, fmt.Errorf("client password is not set")
	}
	if len(m.endpoints) == 0 {
		return nil, fmt.Errorf("no server listening endpoint found")
	}
	for _, p := range m.endpoints {
		if common.IsNilNetAddr(p.RemoteAddr()) {
			return nil, fmt.Errorf("endpoint remote address is not set")
		}
	}

	var err error
	m.mu.Lock()
	m.used = true
	m.cleanUnderlay(true)
	underlay := m.maybePickExistingUnderlay() // try to find a underlay for the session
	m.mu.Unlock()
	if underlay == nil {
		underlay, err = m.newUnderlay(ctx)
		if err != nil {
			return nil, err
		}
		log.Debugf("Created new underlay %v", underlay)
	} else {
		log.Debugf("Reusing existing underlay %v", underlay)
	}

	if ok := underlay.Scheduler().IncPending(); !ok {
		// This underlay can't be used. Create a new one.
		underlay, err = m.newUnderlay(ctx)
		if err != nil {
			return nil, err
		}
		log.Debugf("Created yet another new underlay %v", underlay)
		underlay.Scheduler().IncPending()
	}
	defer func() {
		underlay.Scheduler().DecPending()
	}()
	var trafficPattern *appctlpb.TrafficPattern
	if m.trafficPattern != nil {
		trafficPattern = m.trafficPattern.Effective()
	}
	session := NewSession(mrand.Uint32(), true, underlay.MTU(), nil, trafficPattern)
	if err := underlay.AddSession(session, nil); err != nil {
		return nil, fmt.Errorf("AddSession() failed: %v", err)
	}
	return session, nil
}

func (m *Mux) newEndpoints(old, new []UnderlayProperties) []UnderlayProperties {
	newEndpoints := []UnderlayProperties{}

	for _, n := range new {
		found := false
		for _, o := range old {
			if reflect.DeepEqual(n, o) {
				found = true
				break
			}
		}
		if !found {
			newEndpoints = append(newEndpoints, n)
		}
	}

	return newEndpoints
}

func (m *Mux) acceptUnderlayLoop(ctx context.Context, properties UnderlayProperties, wg *sync.WaitGroup, acceptErr *muxAcceptErr) {
	laddr := properties.LocalAddr().String()
	if laddr == "" {
		err := fmt.Errorf("underlay local address is empty")
		log.Errorf("%v", err)
		acceptErr.set(err)
		wg.Done()
		return
	}

	network := properties.LocalAddr().Network()
	switch network {
	case "tcp", "tcp4", "tcp6":
		tcpAddr, err := apicommon.ResolveTCPAddr(ctx, m.resolver, "tcp", laddr)
		if err != nil {
			err = fmt.Errorf("resolve TCP address %q failed: %w", laddr, err)
			log.Errorf("%v", err)
			acceptErr.set(err)
			wg.Done()
			return
		}
		rawListener, err := m.streamListenerFactory.Listen(ctx, tcpAddr.Network(), tcpAddr.String())
		if err != nil {
			err = fmt.Errorf("listen %s %s failed: %w", tcpAddr.Network(), tcpAddr.String(), err)
			log.Errorf("%v", err)
			acceptErr.set(err)
			wg.Done()
			return
		}
		wg.Done()
		log.Infof("Mux is listening to endpoint %s %s", network, laddr)

		// Close the rawListener if the master context is canceled.
		// This can break the forever loop below.
		go func(ctx context.Context, l net.Listener) {
			<-ctx.Done()
			log.Infof("Closing TCPListener %v", rawListener.Addr())
			rawListener.Close()
		}(ctx, rawListener)

		for {
			// A new underlay should be established.
			underlay, err := m.acceptTCPUnderlay(rawListener, properties)
			if err != nil {
				log.Debugf("%v", err)
				break
			}
			log.Debugf("Created new server underlay %v", underlay)
			m.mu.Lock()
			select {
			case <-m.done:
				m.mu.Unlock()
				underlay.Close()
				return
			default:
			}
			m.cleanUnderlay(false)
			if len(m.underlays) >= m.maxUnderlayCount {
				limit := m.maxUnderlayCount
				m.mu.Unlock()
				log.Debugf("Mux has reached the limit of %d underlays, rejecting new server underlay from %v", limit, underlay.RemoteAddr())
				underlay.Close()
				continue
			}
			// A server stream underlay serves a single session. Disable
			// scheduling after silentUnderlayTTL, so a connection that never
			// establishes a session becomes idle and cleanUnderlay closes it.
			underlay.Scheduler().SetRemainingTime(m.silentUnderlayTTL)
			m.underlays = append(m.underlays, underlay)
			m.startServerUnderlayEventLoop(ctx, underlay)
			m.mu.Unlock()

			// Accept sessions from the underlay.
			go func(ctx context.Context, underlay Underlay) {
				for {
					conn, err := underlay.Accept()
					if err != nil {
						if !stderror.IsEOF(err) && !stderror.IsClosed(err) {
							log.Debugf("%v Accept(): %v", underlay, err)
						}
						break
					}
					select {
					case m.chAccept <- conn:
					case <-ctx.Done():
						return
					}
				}
			}(ctx, underlay)
		}
	case "udp", "udp4", "udp6":
		udpAddr, err := apicommon.ResolveUDPAddr(ctx, m.resolver, "udp", laddr)
		if err != nil {
			err = fmt.Errorf("resolve UDP address %q failed: %w", laddr, err)
			log.Errorf("%v", err)
			acceptErr.set(err)
			wg.Done()
			return
		}
		// The listener of a packet endpoint is the endpoint itself, so this
		// loop never gives the endpoint up. When the event loop of the
		// underlay returns, which only a failure of the listener socket does,
		// the dead underlay leaves the mux and the listener is rebuilt after a
		// growing backoff. A failed rebuild keeps the loop running as well,
		// because the condition that prevented the rebuild (a port that
		// another process holds, the underlay limit of the mux) can go away
		// while the server runs, and an endpoint that stays offline until the
		// process restarts serves nobody.
		//
		// Only the first listen reports a failure to the caller: Start() and
		// UpdateEndpoints() have to know whether the endpoint was usable at
		// all, while a rebuild failure of an endpoint that already served is a
		// temporary condition that the endpoint retries on its own.
		bound := false
		attempt := 0
		for {
			conn, err := m.packetListenerFactory.ListenPacket(ctx, udpAddr.Network(), udpAddr.String())
			if err != nil {
				err = fmt.Errorf("listen %s %s failed: %w", udpAddr.Network(), udpAddr.String(), err)
				if !bound {
					log.Errorf("%v", err)
					acceptErr.set(err)
					wg.Done()
					return
				}
				log.Errorf("Failed to rebuild the packet endpoint %s %s: %v", network, laddr, err)
				if !m.waitPacketUnderlayRebuild(ctx, attempt) {
					return
				}
				attempt++
				continue
			}
			if !bound {
				bound = true
				wg.Done()
				log.Infof("Mux is listening to endpoint %s %s", network, laddr)
			}

			var trafficPattern *appctlpb.TrafficPattern
			if m.trafficPattern != nil {
				trafficPattern = m.trafficPattern.Effective()
			}
			underlay := &PacketUnderlay{
				// The MTU of the endpoint is the MTU of layer 3, so the IP and
				// UDP headers are deducted once, here: every budget below
				// (fragment size, padding) is a payload budget.
				baseUnderlay:       *newBaseUnderlay(false, packetUnderlayMTU(properties.MTU()), trafficPattern),
				conn:               conn,
				sessionCleanTicker: time.NewTicker(sessionCleanInterval),
				serverUsers:        &m.serverUsers,
			}
			setUnderlayRawConn(underlay)
			log.Infof("Created new server underlay %v", underlay)

			m.mu.Lock()
			select {
			case <-m.done:
				m.mu.Unlock()
				underlay.Close()
				return
			default:
			}
			m.cleanUnderlay(false)
			if len(m.underlays) >= m.maxUnderlayCount {
				limit := m.maxUnderlayCount
				m.mu.Unlock()
				log.Errorf("Mux has reached the limit of %d underlays, can't start the server underlay on %s", limit, laddr)
				underlay.Close()
				if !m.waitPacketUnderlayRebuild(ctx, attempt) {
					return
				}
				attempt++
				continue
			}
			// Unlike a stream underlay, a packet underlay is the listener of the
			// endpoint itself, not a connection of a single peer. It is registered
			// without a TTL and must not be reclaimed while the mux is running.
			m.underlays = append(m.underlays, underlay)
			// The event loop runs in its own goroutine and this loop observes
			// its end, which is what makes the endpoint rebuild itself.
			eventLoopDone := m.startServerUnderlayEventLoop(ctx, underlay)
			m.mu.Unlock()
			started := time.Now()

			// Accept sessions from the underlay.
			go func(ctx context.Context, underlay Underlay) {
				for {
					conn, err := underlay.Accept()
					if err != nil {
						if !stderror.IsEOF(err) && !stderror.IsClosed(err) {
							log.Debugf("%v Accept(): %v", underlay, err)
						}
						break
					}
					select {
					case m.chAccept <- conn:
					case <-ctx.Done():
						return
					}
				}
			}(ctx, underlay)

			// Wait for the event loop to return. It returns when the endpoint
			// is closed, which ends this loop below, or when the socket of the
			// underlay failed, which is the case that rebuilds the endpoint.
			<-eventLoopDone

			// The event loop closed the dead underlay. Drop it from the mux
			// now, so that the rebuild can't run into the underlay limit on
			// behalf of an underlay that serves no session anymore.
			m.mu.Lock()
			m.cleanUnderlay(false)
			m.mu.Unlock()

			select {
			case <-ctx.Done():
				return
			case <-m.done:
				return
			default:
			}

			// The endpoint served for long enough: forgive its backoff and
			// rebuild the listener right away.
			if time.Since(started) >= m.packetRebuildBackoffMax {
				attempt = 0
			}
			log.Infof("Rebuilding the packet endpoint %s %s after the socket of its underlay failed", network, laddr)
			if !m.waitPacketUnderlayRebuild(ctx, attempt) {
				return
			}
			attempt++
		}
	default:
		err := fmt.Errorf("unsupported underlay network type %q", network)
		log.Errorf("%v", err)
		acceptErr.set(err)
		wg.Done()
	}
}

// acceptTCPUnderlay accepts one TCP connection and turns it into a server
// underlay. Connections of a source IP address that opens underlays faster than
// the accept rate limit are closed without being wrapped, so that an
// unauthenticated peer can't make the server run handshakes at an arbitrary
// rate.
func (m *Mux) acceptTCPUnderlay(rawListener net.Listener, properties UnderlayProperties) (Underlay, error) {
	for {
		rawConn, err := rawListener.Accept()
		if err != nil {
			return nil, fmt.Errorf("Accept() underlay failed: %w", err)
		}
		if !m.acceptLimiter.allow(underlaySourceAddr(rawConn.RemoteAddr())) {
			if m.acceptLimiter.shouldLogRefusal(time.Now()) {
				log.Warnf("Rejecting new server underlays: a source address exceeded the accept rate limit of %d underlays per second (last refused peer %v)", acceptRefillPerSecond, rawConn.RemoteAddr())
			}
			rawConn.Close()
			continue
		}
		var trafficPattern *appctlpb.TrafficPattern
		if m.trafficPattern != nil {
			trafficPattern = m.trafficPattern.Effective()
		}
		return m.serverWrapTCPConn(rawConn, properties.MTU(), trafficPattern), nil
	}
}

func (m *Mux) serverWrapTCPConn(rawConn net.Conn, mtu int, trafficPattern *appctlpb.TrafficPattern) Underlay {
	var source serveruser.Source
	if rawConn != nil {
		source = serveruser.SourceFromAddr(rawConn.RemoteAddr())
	}
	underlay := &StreamUnderlay{
		baseUnderlay:       *newBaseUnderlay(false, mtu, trafficPattern),
		conn:               rawConn,
		sessionCleanTicker: time.NewTicker(sessionCleanInterval),
		serverUsers:        &m.serverUsers,
		serverUserSource:   source,
	}
	setUnderlayRawConn(underlay)
	return underlay
}

// setUnderlayRawConn makes the base underlay of the given underlay own the
// underlying network connection. The underlay releases the connection when it
// is closed, even if the event loop hasn't started yet, so that the socket
// file descriptor is never leaked. The event loop also closes the connection
// when it stops, which is harmless because a connection can be closed more
// than once.
func setUnderlayRawConn(underlay Underlay) {
	switch u := underlay.(type) {
	case *StreamUnderlay:
		if u.conn != nil {
			u.baseUnderlay.rawConn = u.conn
		}
	case *PacketUnderlay:
		if u.conn != nil {
			u.baseUnderlay.rawConn = u.conn
		}
	}
}

// newUnderlay returns a new underlay.
// This method MUST be called when NOT holding the mu lock.
func (m *Mux) newUnderlay(ctx context.Context) (Underlay, error) {
	var underlay Underlay
	var trafficPattern *appctlpb.TrafficPattern
	// The first suite of the client preference list protects the handshake
	// request, so the static cipher of a new underlay is built from it.
	cipherSuites := m.clientCipherSuites()

	m.mu.Lock()
	if len(m.underlays) >= m.maxUnderlayCount {
		limit := m.maxUnderlayCount
		m.mu.Unlock()
		return nil, fmt.Errorf("mux has reached the limit of %d underlays", limit)
	}
	i := mrand.Intn(len(m.endpoints))
	p := m.endpoints[i]
	if m.trafficPattern != nil {
		trafficPattern = m.trafficPattern.Effective()
	}
	m.mu.Unlock()

	switch p.TransportProtocol() {
	case common.StreamTransport:
		block, err := cipher.BlockCipherFromPassword(cipherSuites[0], m.password, false)
		if err != nil {
			return nil, fmt.Errorf("cipher.BlockCipherFromPassword() failed: %v", err)
		}
		block.SetBlockContext(cipher.BlockContext{
			UserName: m.username,
			// The client writes the keyed user hint of protocol v3, so that
			// the server can filter candidate users without leaking which user
			// names are registered to an observer of the first packet.
			Pepper: cipher.HintPepper(m.username, string(m.password)),
		})
		if trafficPattern != nil {
			block.SetNoncePattern(trafficPattern.GetNonce())
		}
		streamUnderlay, err := NewStreamUnderlay(ctx, m.dialer, m.resolver, m.clientDNSConfig, p.RemoteAddr().Network(), p.RemoteAddr().String(), p.MTU(), block, trafficPattern)
		if err != nil {
			return nil, fmt.Errorf("NewTCPUnderlay() failed: %v", err)
		}
		streamUnderlay.cipherSuites = cipherSuites
		underlay = streamUnderlay
	case common.PacketTransport:
		block, err := cipher.BlockCipherFromPassword(cipherSuites[0], m.password, true)
		if err != nil {
			return nil, fmt.Errorf("cipher.BlockCipherFromPassword() failed: %v", err)
		}
		block.SetBlockContext(cipher.BlockContext{
			UserName: m.username,
			// The client writes the keyed user hint of protocol v3, so that
			// the server can filter candidate users without leaking which user
			// names are registered to an observer of the first packet.
			Pepper: cipher.HintPepper(m.username, string(m.password)),
		})
		if trafficPattern != nil {
			block.SetNoncePattern(trafficPattern.GetNonce())
		}
		packetUnderlay, err := NewPacketUnderlay(ctx, m.packetDialer, m.resolver, p.RemoteAddr().Network(), p.RemoteAddr().String(), p.MTU(), block, trafficPattern)
		if err != nil {
			return nil, fmt.Errorf("NewUDPUnderlay() failed: %v", err)
		}
		packetUnderlay.cipherSuites = cipherSuites
		underlay = packetUnderlay
	default:
		return nil, fmt.Errorf("unsupport transport protocol %v", p.TransportProtocol())
	}

	setUnderlayRawConn(underlay)
	m.mu.Lock()
	m.underlays = append(m.underlays, underlay)
	m.mu.Unlock()
	go func() {
		// This is a long running loop, detach from client dial context.
		err := underlay.RunEventLoop(context.Background())
		if err != nil && !stderror.IsEOF(err) && !stderror.IsClosed(err) {
			log.Debugf("%v RunEventLoop(): %v", underlay, err)
		}
		underlay.Close()
	}()
	return underlay, nil
}

// startServerUnderlayEventLoop registers and starts a server underlay event
// loop. The caller must hold m.mu and must verify that m.done is still open
// first. This keeps WaitGroup.Add ordered before the shutdown Wait.
//
// The returned channel is closed when the event loop has returned and the
// underlay is closed, which lets a caller that has to reconstruct the underlay
// observe the death of this one. A caller that doesn't need that can ignore the
// channel.
func (m *Mux) startServerUnderlayEventLoop(ctx context.Context, underlay Underlay) <-chan struct{} {
	eventLoopDone := make(chan struct{})
	m.serverUnderlayLoopWG.Add(1)
	go func() {
		defer m.serverUnderlayLoopWG.Done()
		err := underlay.RunEventLoop(ctx)
		if err != nil && !stderror.IsEOF(err) && !stderror.IsClosed(err) {
			log.Debugf("%v RunEventLoop(): %v", underlay, err)
		}
		underlay.Close()
		close(eventLoopDone)
	}()
	return eventLoopDone
}

// packetUnderlayRebuildBackoff returns the delay before the next attempt to
// rebuild the listener of a packet endpoint. attempt is the number of
// consecutive attempts that the endpoint already made, initial is the delay of
// the first attempt and max caps the delay of the later ones.
//
// The delay doubles with every attempt up to max, and it is randomized in
// [d/2, d]. The jitter keeps the endpoints of a server that lost a network
// interface from rebuilding their listeners in lockstep, in the same way the
// retransmission timers of the sessions are jittered.
func packetUnderlayRebuildBackoff(attempt int, initial, max time.Duration) time.Duration {
	delay := initial
	for i := 0; i < attempt && delay < max; i++ {
		delay *= 2
	}
	if delay > max || delay <= 0 {
		delay = max
	}
	if delay <= 0 {
		return 0
	}
	return delay/2 + time.Duration(mrand.Int63n(int64(delay/2)+1))
}

// waitPacketUnderlayRebuild waits for the rebuild backoff of the given attempt
// and reports whether the mux should continue. It reports false when the mux or
// the caller context is done, so that the endpoint gives up instead of
// rebuilding a listener of a mux that is shutting down.
func (m *Mux) waitPacketUnderlayRebuild(ctx context.Context, attempt int) bool {
	delay := packetUnderlayRebuildBackoff(attempt, m.packetRebuildBackoffInitial, m.packetRebuildBackoffMax)
	if delay <= 0 {
		return true
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return false
	case <-m.done:
		return false
	case <-timer.C:
		return true
	}
}

// maybePickExistingUnderlay returns either an existing underlay that
// can be used by a session, or nil. In the later case a new underlay
// should be created.
//
// A stream underlay is never reused: its cipher chain is replaced by the
// session keys when the handshake of its session completes, so a second
// session can't run the handshake on the same connection. A packet underlay
// multiplexes sessions, because every datagram carries the session key of its
// session.
// This method MUST be called only when holding the mu lock.
func (m *Mux) maybePickExistingUnderlay() Underlay {
	active := make([]Underlay, 0)
	for _, underlay := range m.underlays {
		select {
		case <-underlay.Done():
		default:
			if underlay.TransportProtocol() == common.StreamTransport {
				continue
			}
			if !underlay.Scheduler().IsDisabled() {
				active = append(active, underlay)
			}
		}
	}

	if m.multiplexFactor > 0 {
		reuseUnderlayFactor := len(active) * m.multiplexFactor
		n := mrand.Intn(reuseUnderlayFactor + 1)
		if n < reuseUnderlayFactor {
			return active[n/m.multiplexFactor]
		}
	}
	return nil
}

// cleanUnderlay removes closed underlays.
// This method MUST be called only when holding the mu lock.
func (m *Mux) cleanUnderlay(alsoDisableIdleOrOverloadUnderlay bool) {
	disable := 0
	close := 0
	n := 0
	for _, underlay := range m.underlays {
		select {
		case <-underlay.Done():
		default:
			// Close an underlay that has no session and that is done for good:
			// either its scheduling has been disabled for the idle interval, or
			// it is a server underlay that outlived serverUnderlayTTL without
			// establishing any session.
			if underlay.SessionCount() == 0 && m.underlayFinished(underlay) {
				underlay.Close()
				close++
			} else {
				m.underlays[n] = underlay
				n++
			}

			if alsoDisableIdleOrOverloadUnderlay {
				// Try disable scheduling in idle underlay.
				if underlay.SessionCount() == 0 {
					if underlay.Scheduler().TryDisableIdle() {
						disable++
					}
				}

				// Disable scheduling in overloaded underlay.
				trafficVolumeLimit := m.trafficVolumeLimit()
				if underlay.Scheduler().DisableTime().IsZero() && (underlay.InBytes() > trafficVolumeLimit || underlay.OutBytes() > trafficVolumeLimit) {
					underlay.Scheduler().SetRemainingTime(0)
					disable++
				}
			}
		}
	}

	for i := n; i < len(m.underlays); i++ {
		m.underlays[i] = nil
	}
	m.underlays = m.underlays[:n]

	// Reclaim the backing array only when the slice capacity is large and most slots are empty.
	if cap(m.underlays) > minUnderlayCapacityReclaim && len(m.underlays)*4 <= cap(m.underlays) {
		reclaimed := make([]Underlay, len(m.underlays))
		copy(reclaimed, m.underlays)
		m.underlays = reclaimed
	}

	if close > 0 {
		log.Debugf("Mux cleaned %d underlays", close)
	}
	if disable > 0 {
		log.Debugf("Mux disabled scheduling from %d underlays", disable)
	}
}

// underlayFinished reports whether an underlay without any session is done for
// good, and can therefore be closed by the maintenance loop.
//
// A client underlay is only closed after its scheduling has been disabled for
// the idle interval. A server stream underlay is accepted with a limited
// lifetime: its scheduler is disabled after serverUnderlayTTL, so a connection
// that never established a session, or whose session already ended, is
// reclaimed instead of being held open forever.
func (m *Mux) underlayFinished(underlay Underlay) bool {
	if underlay.Scheduler().Idle() {
		return true
	}
	return !m.isClient && underlay.Scheduler().IsDisabled()
}

// trafficVolumeLimit returns the number of bytes after which scheduling new
// sessions to a client underlay is disabled. SetClientMultiplexFactor clamps
// the multiplexing factor to [0, maxMultiplexFactor], so the shifted limit is
// always a positive number of bytes and is never zero.
func (m *Mux) trafficVolumeLimit() int64 {
	return baseUnderlayTrafficVolumeLimit << uint(m.multiplexFactor)
}

type muxAcceptErr struct {
	done chan struct{}
	once sync.Once
	mu   sync.Mutex
	err  error
}

func newMuxAcceptErr() *muxAcceptErr {
	return &muxAcceptErr{
		done: make(chan struct{}),
	}
}

func (e *muxAcceptErr) set(err error) {
	e.once.Do(func() {
		e.mu.Lock()
		e.err = err
		e.mu.Unlock()
		close(e.done)
	})
}

func (e *muxAcceptErr) get() error {
	e.mu.Lock()
	defer e.mu.Unlock()
	return e.err
}

// sourceBucket is the token bucket of a single source IP address.
type sourceBucket struct {
	tokens   float64
	lastSeen time.Time
}

// sourceRateLimiter limits how fast a single source IP address can make the
// server establish new TCP underlays. It keeps one token bucket per source IP
// address: burst is how many underlays a source can open back to back, and
// perSecond is the sustained rate. A rate limit is the cheapest way to bound
// this: every accepted connection makes the server allocate an underlay and run
// a handshake for a peer that is not authenticated yet.
//
// The map size is bounded by acceptMaxSourceBuckets and the buckets of idle
// sources are dropped, so a flood from many source addresses can't grow the
// limiter without bound either.
type sourceRateLimiter struct {
	burst     float64
	perSecond float64
	mu        sync.Mutex
	buckets   map[netip.Addr]*sourceBucket
	// lastRefusalLog is the time of the last refusal that was logged. The
	// limiter refuses every connection of a flooding source, so the refusal is
	// logged at most once per second instead of once per connection.
	lastRefusalLog time.Time
}

// shouldLogRefusal reports whether a refused connection should be logged now.
// It bounds the log rate of a flood to one line per second.
func (l *sourceRateLimiter) shouldLogRefusal(now time.Time) bool {
	if l == nil {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	if !l.lastRefusalLog.IsZero() && now.Sub(l.lastRefusalLog) < time.Second {
		return false
	}
	l.lastRefusalLog = now
	return true
}

// newSourceRateLimiter creates a limiter with the given bucket size and refill
// rate. A refill rate of 0 disables refilling.
func newSourceRateLimiter(burst, perSecond float64) *sourceRateLimiter {
	return &sourceRateLimiter{
		burst:     burst,
		perSecond: perSecond,
		buckets:   make(map[netip.Addr]*sourceBucket),
	}
}

// allow takes one token of the given source address and reports whether the
// token was available. An address that carries no IP address is always allowed,
// because it can't be attributed to a source.
func (l *sourceRateLimiter) allow(addr netip.Addr) bool {
	if l == nil || !addr.IsValid() {
		return true
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	now := time.Now()
	b, ok := l.buckets[addr]
	if !ok {
		if len(l.buckets) >= acceptMaxSourceBuckets {
			l.evictLocked(now)
		}
		b = &sourceBucket{tokens: l.burst, lastSeen: now}
		l.buckets[addr] = b
	} else {
		if elapsed := now.Sub(b.lastSeen).Seconds(); elapsed > 0 {
			b.tokens = math.Min(l.burst, b.tokens+elapsed*l.perSecond)
		}
		b.lastSeen = now
	}
	if b.tokens < 1 {
		return false
	}
	b.tokens--
	return true
}

// clean drops the token buckets of the source addresses that are idle for at
// least acceptBucketIdleTimeout.
func (l *sourceRateLimiter) clean(now time.Time) {
	if l == nil {
		return
	}
	l.mu.Lock()
	defer l.mu.Unlock()
	l.evictLocked(now)
}

// evictLocked drops the buckets of the idle source addresses. If the map is
// still full afterwards, the least recently seen bucket is dropped as well, so
// the number of buckets never exceeds acceptMaxSourceBuckets.
func (l *sourceRateLimiter) evictLocked(now time.Time) {
	for addr, b := range l.buckets {
		if now.Sub(b.lastSeen) >= acceptBucketIdleTimeout {
			delete(l.buckets, addr)
		}
	}
	if len(l.buckets) < acceptMaxSourceBuckets {
		return
	}
	var oldestAddr netip.Addr
	var oldestSeen time.Time
	for addr, b := range l.buckets {
		if !oldestSeen.IsZero() && !b.lastSeen.Before(oldestSeen) {
			continue
		}
		oldestAddr, oldestSeen = addr, b.lastSeen
	}
	delete(l.buckets, oldestAddr)
}

// underlaySourceAddr returns the source IP address of addr without the port and
// without an IPv4-mapped IPv6 prefix. It returns an invalid address when addr
// carries no IP address.
func underlaySourceAddr(addr net.Addr) netip.Addr {
	var ip net.IP
	switch addr := addr.(type) {
	case *net.TCPAddr:
		if addr == nil {
			return netip.Addr{}
		}
		ip = addr.IP
	case *net.UDPAddr:
		if addr == nil {
			return netip.Addr{}
		}
		ip = addr.IP
	default:
		return netip.Addr{}
	}
	parsed, ok := netip.AddrFromSlice(ip)
	if !ok || !parsed.IsValid() {
		return netip.Addr{}
	}
	return parsed.Unmap()
}
