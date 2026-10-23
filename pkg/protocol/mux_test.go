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
	"bytes"
	"context"
	"io"
	"math"
	mrand "math/rand"
	"net"
	"net/netip"
	"reflect"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/Acheirial/shadowlemon/v3/pkg/appctl/appctlpb"
	"github.com/Acheirial/shadowlemon/v3/pkg/cipher"
	"github.com/Acheirial/shadowlemon/v3/pkg/common"
	"github.com/Acheirial/shadowlemon/v3/pkg/log"
	"github.com/Acheirial/shadowlemon/v3/pkg/stderror"
	"github.com/Acheirial/shadowlemon/v3/pkg/testtool"
	"google.golang.org/protobuf/proto"
)

var users = map[string]*appctlpb.User{
	"xiaochitang": {
		Name:     proto.String("xiaochitang"),
		Password: proto.String("kuiranbudong"),
	},
}

func TestUpdateEndpointsListenerFailure(t *testing.T) {
	for _, network := range []string{"tcp", "udp"} {
		t.Run(network, func(t *testing.T) {
			var occupied io.Closer
			var occupiedAddr net.Addr
			if network == "tcp" {
				listener, err := net.Listen(network, "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				occupied, occupiedAddr = listener, listener.Addr()
			} else {
				conn, err := net.ListenPacket(network, "127.0.0.1:0")
				if err != nil {
					t.Fatal(err)
				}
				occupied, occupiedAddr = conn, conn.LocalAddr()
			}
			t.Cleanup(func() { occupied.Close() })
			properties := func(ip string) UnderlayProperties {
				if network == "tcp" {
					return NewUnderlayProperties(1400, common.StreamTransport, &net.TCPAddr{IP: net.ParseIP(ip)}, nil)
				}
				return NewUnderlayProperties(1400, common.PacketTransport, &net.UDPAddr{IP: net.ParseIP(ip)}, nil)
			}
			original := properties("127.0.0.1")
			added := properties("0.0.0.0")
			blocked := NewUnderlayProperties(1400, original.TransportProtocol(), occupiedAddr, nil)
			mux := NewMux(false).SetServerUsers(users).SetEndpoints([]UnderlayProperties{original})
			t.Cleanup(func() { mux.Close() })
			if err := mux.Start(); err != nil {
				t.Fatal(err)
			}

			for i := 0; i < 2; i++ {
				if err := mux.UpdateEndpoints([]UnderlayProperties{added, blocked}); err == nil {
					t.Fatal("UpdateEndpoints() succeeded with an occupied port")
				}
				if want := []UnderlayProperties{original, added}; !reflect.DeepEqual(mux.endpoints, want) {
					t.Fatalf("endpoints = %v, want %v", mux.endpoints, want)
				}
				if err := mux.acceptErr.get(); err != nil {
					t.Fatalf("reload failure reached Accept(): %v", err)
				}
			}

			if err := occupied.Close(); err != nil {
				t.Fatal(err)
			}
			if err := mux.UpdateEndpoints([]UnderlayProperties{added, blocked}); err != nil {
				t.Fatalf("retry after releasing the port failed: %v", err)
			}
			if err := mux.UpdateEndpoints([]UnderlayProperties{original, added, blocked}); err != nil {
				t.Fatalf("reloading existing listeners failed: %v", err)
			}
			if want := []UnderlayProperties{original, added, blocked}; !reflect.DeepEqual(mux.endpoints, want) {
				t.Fatalf("endpoints = %v, want %v", mux.endpoints, want)
			}
		})
	}
}

func runClient(t *testing.T, properties UnderlayProperties, username, password []byte, concurrent int) {
	clientMux := NewMux(true).
		SetClientUserNamePassword(string(username), cipher.HashPassword(password, username)).
		SetClientMultiplexFactor(2).
		SetEndpoints([]UnderlayProperties{properties})

	dialCtx, cancelFunc := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancelFunc()

	var wg sync.WaitGroup
	for i := 0; i < concurrent; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			conn, err := clientMux.DialContext(dialCtx)
			if err != nil {
				t.Errorf("DialContext() failed: %v", err)
				return
			}
			defer conn.Close()
			for i := 0; i < 100; i++ {
				payloadSize := mrand.Intn(maxPDU) + 1
				payload := testRot13Payload(t, testtool.TestHelperGenRot13Input(payloadSize))
				if _, err := conn.Write(payload); err != nil {
					t.Errorf("Write() failed: %v", err)
				}
				resp := make([]byte, payloadSize)
				if _, err := io.ReadFull(conn, resp); err != nil {
					t.Errorf("io.ReadFull() failed: %v", err)
				}
				rot13, err := testtool.TestHelperRot13(resp)
				if err != nil {
					t.Errorf("TestHelperRot13() failed: %v", err)
				}
				if !bytes.Equal(payload, rot13) {
					t.Errorf("Received unexpected response")
				}
			}
		}()
	}
	wg.Wait()

	if err := clientMux.Close(); err != nil {
		t.Errorf("Close client mux failed: %v", err)
	}
}

func TestIPv4TCPUnderlay(t *testing.T) {
	log.SetOutputToTest(t)
	log.SetLevel("DEBUG")
	port, err := common.UnusedTCPPort()
	if err != nil {
		t.Fatalf("common.UnusedTCPPort() failed: %v", err)
	}
	serverProperties := NewUnderlayProperties(1400, common.StreamTransport, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}, nil)
	serverMux := NewMux(false).
		SetServerUsers(users).
		SetEndpoints([]UnderlayProperties{serverProperties})
	testServer := testtool.NewTestHelperServer()

	if err := serverMux.Start(); err != nil {
		t.Fatalf("[%s] Start() failed: %v", time.Now().Format(testtool.TimeLayout), err)
	}
	// Every listener is bound when Start() returns and the underlay accept
	// loops are running, so the client can dial right away. The test helper
	// server consumes the sessions as soon as it is scheduled.
	go func() {
		if err := testServer.Serve(serverMux); err != nil {
			t.Errorf("[%s] Serve() failed: %v", time.Now().Format(testtool.TimeLayout), err)
		}
	}()
	defer testServer.Close()

	clientProperties := NewUnderlayProperties(1400, common.StreamTransport, nil, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	runClient(t, clientProperties, []byte("xiaochitang"), []byte("kuiranbudong"), 4)
	if err := serverMux.Close(); err != nil {
		t.Errorf("Server mux close failed: %v", err)
	}
}

func TestIPv6TCPUnderlay(t *testing.T) {
	log.SetOutputToTest(t)
	log.SetLevel("DEBUG")
	port, err := common.UnusedTCPPort()
	if err != nil {
		t.Fatalf("common.UnusedTCPPort() failed: %v", err)
	}
	serverProperties := NewUnderlayProperties(1400, common.StreamTransport, &net.TCPAddr{IP: net.ParseIP("::1"), Port: port}, nil)
	serverMux := NewMux(false).
		SetServerUsers(users).
		SetEndpoints([]UnderlayProperties{serverProperties})
	testServer := testtool.NewTestHelperServer()

	if err := serverMux.Start(); err != nil {
		t.Fatalf("[%s] Start() failed: %v", time.Now().Format(testtool.TimeLayout), err)
	}
	// Every listener is bound when Start() returns and the underlay accept
	// loops are running, so the client can dial right away. The test helper
	// server consumes the sessions as soon as it is scheduled.
	go func() {
		if err := testServer.Serve(serverMux); err != nil {
			t.Errorf("[%s] Serve() failed: %v", time.Now().Format(testtool.TimeLayout), err)
		}
	}()
	defer testServer.Close()

	clientProperties := NewUnderlayProperties(1400, common.StreamTransport, nil, &net.TCPAddr{IP: net.ParseIP("::1"), Port: port})
	runClient(t, clientProperties, []byte("xiaochitang"), []byte("kuiranbudong"), 4)
	if err := serverMux.Close(); err != nil {
		t.Errorf("Server mux close failed: %v", err)
	}
}

func TestIPv4UDPUnderlay(t *testing.T) {
	log.SetOutputToTest(t)
	log.SetLevel("DEBUG")
	port, err := common.UnusedUDPPort()
	if err != nil {
		t.Fatalf("common.UnusedUDPPort() failed: %v", err)
	}
	serverProperties := NewUnderlayProperties(1400, common.PacketTransport, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}, nil)
	serverMux := NewMux(false).
		SetServerUsers(users).
		SetEndpoints([]UnderlayProperties{serverProperties})
	testServer := testtool.NewTestHelperServer()

	if err := serverMux.Start(); err != nil {
		t.Fatalf("[%s] Start() failed: %v", time.Now().Format(testtool.TimeLayout), err)
	}
	// Every listener is bound when Start() returns and the underlay accept
	// loops are running, so the client can dial right away. The test helper
	// server consumes the sessions as soon as it is scheduled.
	go func() {
		if err := testServer.Serve(serverMux); err != nil {
			t.Errorf("[%s] Serve() failed: %v", time.Now().Format(testtool.TimeLayout), err)
		}
	}()
	defer testServer.Close()

	clientProperties := NewUnderlayProperties(1400, common.PacketTransport, nil, &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	runClient(t, clientProperties, []byte("xiaochitang"), []byte("kuiranbudong"), 4)
	if err := serverMux.Close(); err != nil {
		t.Errorf("Server mux close failed: %v", err)
	}
}

func TestIPv6UDPUnderlay(t *testing.T) {
	log.SetOutputToTest(t)
	log.SetLevel("DEBUG")
	port, err := common.UnusedUDPPort()
	if err != nil {
		t.Fatalf("common.UnusedUDPPort() failed: %v", err)
	}
	serverProperties := NewUnderlayProperties(1400, common.PacketTransport, &net.UDPAddr{IP: net.ParseIP("::1"), Port: port}, nil)
	serverMux := NewMux(false).
		SetServerUsers(users).
		SetEndpoints([]UnderlayProperties{serverProperties})
	testServer := testtool.NewTestHelperServer()

	if err := serverMux.Start(); err != nil {
		t.Fatalf("[%s] Start() failed: %v", time.Now().Format(testtool.TimeLayout), err)
	}
	// Every listener is bound when Start() returns and the underlay accept
	// loops are running, so the client can dial right away. The test helper
	// server consumes the sessions as soon as it is scheduled.
	go func() {
		if err := testServer.Serve(serverMux); err != nil {
			t.Errorf("[%s] Serve() failed: %v", time.Now().Format(testtool.TimeLayout), err)
		}
	}()
	defer testServer.Close()

	clientProperties := NewUnderlayProperties(1400, common.PacketTransport, nil, &net.UDPAddr{IP: net.ParseIP("::1"), Port: port})
	runClient(t, clientProperties, []byte("xiaochitang"), []byte("kuiranbudong"), 4)
	if err := serverMux.Close(); err != nil {
		t.Errorf("Server mux close failed: %v", err)
	}
}

func TestMuxStartReturnsListenerError(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	defer listener.Close()
	tcpAddr, ok := listener.Addr().(*net.TCPAddr)
	if !ok {
		t.Fatalf("listener address type is %T, want *net.TCPAddr", listener.Addr())
	}

	serverProperties := NewUnderlayProperties(1400, common.StreamTransport, tcpAddr, nil)
	serverMux := NewMux(false).
		SetServerUsers(users).
		SetEndpoints([]UnderlayProperties{serverProperties})

	err = serverMux.Start()
	if err == nil {
		t.Fatal("Start() succeeded with occupied server port")
	}
	for _, want := range []string{"mux server listener failed", listener.Addr().String()} {
		if !strings.Contains(err.Error(), want) {
			t.Fatalf("Start() error = %q, want error string contains %q", err.Error(), want)
		}
	}
}

func TestNewEndpointsReturnsOnlyAdditions(t *testing.T) {
	cases := []struct {
		old []UnderlayProperties
		new []UnderlayProperties
		res []UnderlayProperties
	}{
		{
			nil,
			nil,
			[]UnderlayProperties{},
		},
		{
			nil,
			[]UnderlayProperties{
				NewUnderlayProperties(1400, common.StreamTransport, common.NilNetAddr(), common.NilNetAddr()),
			},
			[]UnderlayProperties{
				NewUnderlayProperties(1400, common.StreamTransport, common.NilNetAddr(), common.NilNetAddr()),
			},
		},
		{
			[]UnderlayProperties{
				NewUnderlayProperties(1400, common.StreamTransport, common.NilNetAddr(), common.NilNetAddr()),
			},
			nil,
			[]UnderlayProperties{},
		},
		{
			[]UnderlayProperties{
				NewUnderlayProperties(1400, common.StreamTransport, common.NilNetAddr(), common.NilNetAddr()),
				NewUnderlayProperties(1400, common.StreamTransport, common.NilNetAddr(), common.NilNetAddr()),
			},
			[]UnderlayProperties{
				NewUnderlayProperties(1400, common.StreamTransport, common.NilNetAddr(), common.NilNetAddr()),
				NewUnderlayProperties(1400, common.PacketTransport, common.NilNetAddr(), common.NilNetAddr()),
			},
			[]UnderlayProperties{
				NewUnderlayProperties(1400, common.PacketTransport, common.NilNetAddr(), common.NilNetAddr()),
			},
		},
	}

	mux := NewMux(false)
	for _, tc := range cases {
		ep := mux.newEndpoints(tc.old, tc.new)
		if !reflect.DeepEqual(ep, tc.res) {
			t.Errorf("newEndpoints(): got %v, want %v", ep, tc.res)
		}
	}
}

// TestMuxCloseIsIdempotentUnderConcurrency verifies that the mux can be closed
// from many goroutines: every call returns, no shutdown step runs twice, all
// underlays stop, and a later call is a no-op.
func TestMuxCloseIsIdempotentUnderConcurrency(t *testing.T) {
	tcpPort, err := common.UnusedTCPPort()
	if err != nil {
		t.Fatalf("common.UnusedTCPPort() failed: %v", err)
	}
	udpPort, err := common.UnusedUDPPort()
	if err != nil {
		t.Fatalf("common.UnusedUDPPort() failed: %v", err)
	}
	tcpAddr := &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: tcpPort}
	udpAddr := &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: udpPort}
	mux := NewMux(false).
		SetServerUsers(users).
		SetEndpoints([]UnderlayProperties{
			NewUnderlayProperties(1400, common.StreamTransport, tcpAddr, nil),
			NewUnderlayProperties(1400, common.PacketTransport, udpAddr, nil),
		})
	t.Cleanup(func() { mux.Close() })
	if err := mux.Start(); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	// The mux creates a stream underlay for a new connection. Keep the
	// connection open so the underlay is still alive when the mux is closed.
	rawConn, err := net.Dial("tcp", tcpAddr.String())
	if err != nil {
		t.Fatalf("net.Dial() failed: %v", err)
	}
	t.Cleanup(func() { rawConn.Close() })

	// Wait until both endpoints have a running underlay.
	var underlays []Underlay
	waitForCondition(t, 5*time.Second, "the mux to start an underlay for both endpoints", func() bool {
		mux.mu.Lock()
		defer mux.mu.Unlock()
		if len(mux.underlays) < 2 {
			return false
		}
		underlays = append([]Underlay(nil), mux.underlays...)
		return true
	})

	const goroutines = 8
	errs := make(chan error, goroutines)
	var wg sync.WaitGroup
	for i := 0; i < goroutines; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs <- mux.Close()
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
		t.Fatal("concurrent Mux.Close() didn't return")
	}
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("Mux.Close() = %v, want nil", err)
		}
	}
	if err := mux.Close(); err != nil {
		t.Errorf("Mux.Close() after close = %v, want nil", err)
	}
	for _, underlay := range underlays {
		select {
		case <-underlay.Done():
		default:
			t.Errorf("%v is not closed after Mux.Close()", underlay)
		}
	}
	if _, err := mux.Accept(); err == nil {
		t.Error("Accept() succeeded after the mux was closed")
	}
}

// waitForCondition polls cond until it returns true, or fails the test when the
// deadline expires. Between two attempts the loop yields the processor instead
// of sleeping, so the outcome doesn't depend on a fixed sleep that may be too
// short on a slow machine.
func waitForCondition(t *testing.T, timeout time.Duration, what string, cond func() bool) {
	t.Helper()
	deadline := time.Now().Add(timeout)
	for {
		if cond() {
			return
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out after %v waiting for %s", timeout, what)
		}
		runtime.Gosched()
	}
}

// exchangePayload writes one payload through conn and verifies the rotate-13
// response of the test helper server.
func exchangePayload(t *testing.T, conn net.Conn) {
	t.Helper()
	payload := testRot13Payload(t, testtool.TestHelperGenRot13Input(64))
	if _, err := conn.Write(payload); err != nil {
		t.Fatalf("Write() failed: %v", err)
	}
	reply := make([]byte, len(payload))
	if _, err := io.ReadFull(conn, reply); err != nil {
		t.Fatalf("io.ReadFull() failed: %v", err)
	}
	rot13, err := testtool.TestHelperRot13(reply)
	if err != nil {
		t.Fatalf("TestHelperRot13() failed: %v", err)
	}
	if !bytes.Equal(payload, rot13) {
		t.Fatal("received an unexpected response")
	}
}

// TestSourceRateLimiter verifies the token bucket that limits how fast a single
// source IP address can open TCP underlays.
func TestSourceRateLimiter(t *testing.T) {
	const burst = 2
	limiter := newSourceRateLimiter(burst, 0)
	source := netip.MustParseAddr("192.0.2.10")
	other := netip.MustParseAddr("192.0.2.11")

	for i := range burst {
		if !limiter.allow(source) {
			t.Fatalf("allow() %d = false, want true", i)
		}
	}
	if limiter.allow(source) {
		t.Error("allow() = true after the bucket of the source is empty")
	}
	if !limiter.allow(other) {
		t.Error("allow() = false for another source address, want true")
	}
	if !limiter.allow(netip.Addr{}) {
		t.Error("allow() = false for an address without an IP address, want true")
	}

	// The bucket of a source that stopped opening underlays is dropped.
	limiter.clean(time.Now().Add(acceptBucketIdleTimeout))
	if !limiter.allow(source) {
		t.Error("allow() = false after the idle bucket of the source was dropped, want true")
	}

	// Tokens are refilled at the configured rate, up to the bucket size.
	refilling := newSourceRateLimiter(burst, 5)
	refilling.mu.Lock()
	refilling.buckets[source] = &sourceBucket{lastSeen: time.Now().Add(-time.Second)}
	refilling.mu.Unlock()
	for i := range burst {
		if !refilling.allow(source) {
			t.Fatalf("allow() %d = false after one second of refill, want true", i)
		}
	}
	if refilling.allow(source) {
		t.Error("allow() = true with more tokens than the bucket size")
	}

	// The number of buckets stays bounded even when every source address is new.
	counted := newSourceRateLimiter(1, 1)
	for i := range acceptMaxSourceBuckets + 16 {
		counted.allow(netip.AddrFrom4([4]byte{10, byte(i >> 8), byte(i), 1}))
	}
	if n := len(counted.buckets); n > acceptMaxSourceBuckets {
		t.Errorf("the limiter keeps %d buckets, want at most %d", n, acceptMaxSourceBuckets)
	}
}

// TestServerRejectsUnderlayOverSourceRate verifies that a source IP address
// that opens TCP underlays faster than the accept rate limit gets its new
// connections closed, while the accepted connections are kept.
func TestServerRejectsUnderlayOverSourceRate(t *testing.T) {
	log.SetOutputToTest(t)
	port, err := common.UnusedTCPPort()
	if err != nil {
		t.Fatalf("common.UnusedTCPPort() failed: %v", err)
	}
	serverProperties := NewUnderlayProperties(1400, common.StreamTransport, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}, nil)
	serverMux := NewMux(false).
		SetServerUsers(users).
		SetEndpoints([]UnderlayProperties{serverProperties})
	// A bucket of 2 tokens without refill makes the number of accepted
	// connections independent of the speed of the test.
	const acceptLimit = 2
	serverMux.acceptLimiter = newSourceRateLimiter(acceptLimit, 0)
	t.Cleanup(func() { serverMux.Close() })
	if err := serverMux.Start(); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	rawConns := make([]net.Conn, 0, acceptLimit+1)
	for i := range acceptLimit + 1 {
		conn, err := net.Dial("tcp", serverProperties.LocalAddr().String())
		if err != nil {
			t.Fatalf("net.Dial() %d failed: %v", i, err)
		}
		rawConns = append(rawConns, conn)
	}
	t.Cleanup(func() {
		for _, conn := range rawConns {
			conn.Close()
		}
	})

	// The server keeps the accepted connections, which wait for a handshake,
	// and closes the connection that the rate limiter rejected.
	closed := make(chan net.Conn, len(rawConns))
	for _, conn := range rawConns {
		go func(conn net.Conn) {
			buf := make([]byte, 1)
			for {
				conn.SetReadDeadline(time.Now().Add(100 * time.Millisecond))
				n, err := conn.Read(buf)
				if err == nil || n > 0 {
					return
				}
				if stderror.IsTimeout(err) {
					continue
				}
				closed <- conn
				return
			}
		}(conn)
	}
	waitForCondition(t, 5*time.Second, "the server to close the rejected connection", func() bool {
		return len(closed) >= 1
	})
	serverMux.mu.Lock()
	registered := len(serverMux.underlays)
	serverMux.mu.Unlock()
	if registered != acceptLimit {
		t.Fatalf("server mux has %d underlays, want %d", registered, acceptLimit)
	}
	if n := len(closed); n != 1 {
		t.Errorf("the server closed %d connections, want 1", n)
	}
}

// TestServerUnderlayLimitKeepsExistingSessions verifies that the concurrent
// underlay limit refuses new connections while a session that is already
// established keeps working.
func TestServerUnderlayLimitKeepsExistingSessions(t *testing.T) {
	log.SetOutputToTest(t)
	port, err := common.UnusedTCPPort()
	if err != nil {
		t.Fatalf("common.UnusedTCPPort() failed: %v", err)
	}
	serverProperties := NewUnderlayProperties(1400, common.StreamTransport, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}, nil)
	serverMux := NewMux(false).
		SetServerUsers(users).
		SetEndpoints([]UnderlayProperties{serverProperties})
	// Room for the underlay of the session and for two connections that never
	// establish a session.
	const underlayLimit = 3
	serverMux.maxUnderlayCount = underlayLimit
	// Keep the accept rate limiter out of the way; this test exercises the
	// underlay limit only.
	serverMux.acceptLimiter = newSourceRateLimiter(acceptBurst, acceptRefillPerSecond)
	testServer := testtool.NewTestHelperServer()
	defer testServer.Close()
	t.Cleanup(func() { serverMux.Close() })
	if err := serverMux.Start(); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}
	go func() {
		if err := testServer.Serve(serverMux); err != nil {
			t.Errorf("Serve() failed: %v", err)
		}
	}()

	clientProperties := NewUnderlayProperties(1400, common.StreamTransport, nil, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port})
	clientMux := NewMux(true).
		SetClientUserNamePassword("xiaochitang", cipher.HashPassword([]byte("kuiranbudong"), []byte("xiaochitang"))).
		SetEndpoints([]UnderlayProperties{clientProperties})
	t.Cleanup(func() { clientMux.Close() })
	dialCtx, cancelFunc := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancelFunc()
	conn, err := clientMux.DialContext(dialCtx)
	if err != nil {
		t.Fatalf("DialContext() failed: %v", err)
	}
	t.Cleanup(func() { conn.Close() })
	exchangePayload(t, conn)

	// Fill the remaining underlay slots with connections that never start a
	// session.
	blockers := make([]net.Conn, 0, underlayLimit-1)
	for i := range underlayLimit - 1 {
		blocker, err := net.Dial("tcp", serverProperties.LocalAddr().String())
		if err != nil {
			t.Fatalf("net.Dial() %d failed: %v", i, err)
		}
		blockers = append(blockers, blocker)
	}
	t.Cleanup(func() {
		for _, blocker := range blockers {
			blocker.Close()
		}
	})
	waitForCondition(t, 5*time.Second, "the server to reach the underlay limit", func() bool {
		serverMux.mu.Lock()
		defer serverMux.mu.Unlock()
		return len(serverMux.underlays) >= underlayLimit
	})

	// A connection over the limit is refused.
	overLimit, err := net.Dial("tcp", serverProperties.LocalAddr().String())
	if err != nil {
		t.Fatalf("net.Dial() failed: %v", err)
	}
	t.Cleanup(func() { overLimit.Close() })
	overLimit.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := overLimit.Read(make([]byte, 1)); err == nil || stderror.IsTimeout(err) {
		t.Fatalf("the server didn't close the connection over the underlay limit: %v", err)
	}
	serverMux.mu.Lock()
	registered := len(serverMux.underlays)
	serverMux.mu.Unlock()
	if registered != underlayLimit {
		t.Fatalf("server mux has %d underlays, want %d", registered, underlayLimit)
	}

	// The session that was established before the limit was reached still works.
	exchangePayload(t, conn)

	// Closing the server before the test returns stops the test helper server
	// while the test is still running.
	if err := serverMux.Close(); err != nil {
		t.Errorf("Server mux close failed: %v", err)
	}
}

// TestMultiplexFactorIsClamped verifies that the multiplexing factor stays in
// the supported range, so that the traffic volume limit of a client underlay
// can't overflow to a zero limit that never disables scheduling.
func TestMultiplexFactorIsClamped(t *testing.T) {
	log.SetOutputToTest(t)
	cases := []struct {
		name string
		in   int
		want int
	}{
		{"negative", -1, 0},
		{"off", 0, 0},
		{"low", 1, 1},
		{"middle", 2, 2},
		{"high", 3, 3},
		{"above high", 4, maxMultiplexFactor},
		{"shift overflow", 64, maxMultiplexFactor},
		{"max int", math.MaxInt, maxMultiplexFactor},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			mux := NewMux(true).SetClientMultiplexFactor(tc.in)
			if mux.multiplexFactor != tc.want {
				t.Errorf("multiplexing factor = %d, want %d", mux.multiplexFactor, tc.want)
			}
			want := baseUnderlayTrafficVolumeLimit << uint(tc.want)
			if limit := mux.trafficVolumeLimit(); limit != want || limit <= 0 {
				t.Errorf("traffic volume limit = %d, want %d and a positive number of bytes", limit, want)
			}
			if err := mux.Close(); err != nil {
				t.Errorf("Close() failed: %v", err)
			}
		})
	}
}

// TestServerStreamUnderlaySilentTTL verifies that a server stream underlay
// without any session is reclaimed after its TTL, so a connection that never
// establishes a session can't be held open forever.
func TestServerStreamUnderlaySilentTTL(t *testing.T) {
	log.SetOutputToTest(t)
	port, err := common.UnusedTCPPort()
	if err != nil {
		t.Fatalf("common.UnusedTCPPort() failed: %v", err)
	}
	serverProperties := NewUnderlayProperties(1400, common.StreamTransport, &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}, nil)
	serverMux := NewMux(false).
		SetServerUsers(users).
		SetEndpoints([]UnderlayProperties{serverProperties})
	serverMux.silentUnderlayTTL = 20 * time.Millisecond
	t.Cleanup(func() { serverMux.Close() })
	if err := serverMux.Start(); err != nil {
		t.Fatalf("Start() failed: %v", err)
	}

	rawConn, err := net.Dial("tcp", serverProperties.LocalAddr().String())
	if err != nil {
		t.Fatalf("net.Dial() failed: %v", err)
	}
	t.Cleanup(func() { rawConn.Close() })

	var underlay Underlay
	waitForCondition(t, 5*time.Second, "the server to accept the connection", func() bool {
		serverMux.mu.Lock()
		defer serverMux.mu.Unlock()
		if len(serverMux.underlays) != 1 {
			return false
		}
		underlay = serverMux.underlays[0]
		return true
	})

	// The TTL of the underlay disables its scheduler, which makes the idle
	// underlay cleanup reachable for a server underlay.
	waitForCondition(t, 5*time.Second, "the silent connection TTL to pass", func() bool {
		return underlay.Scheduler().IsDisabled()
	})

	// cleanUnderlay() is what the mux maintenance loop runs to reclaim the
	// underlays that are finished.
	serverMux.mu.Lock()
	serverMux.cleanUnderlay(false)
	remaining := len(serverMux.underlays)
	serverMux.mu.Unlock()
	if remaining != 0 {
		t.Fatalf("server mux has %d underlays after the silent connection TTL, want 0", remaining)
	}
	select {
	case <-underlay.Done():
	default:
		t.Fatal("the silent underlay is not closed")
	}

	// The peer observes the connection that was closed by the server.
	rawConn.SetReadDeadline(time.Now().Add(5 * time.Second))
	if _, err := rawConn.Read(make([]byte, 1)); err == nil || stderror.IsTimeout(err) {
		t.Fatalf("the silent connection is still open: %v", err)
	}
}
