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
	mrand "math/rand"
	"net"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/cipher"
	"github.com/enfein/mieru/v3/pkg/common"
	"github.com/enfein/mieru/v3/pkg/log"
	"github.com/enfein/mieru/v3/pkg/testtool"
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
				payload := testtool.TestHelperGenRot13Input(payloadSize)
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
	time.Sleep(100 * time.Millisecond)
	go func() {
		if err := testServer.Serve(serverMux); err != nil {
			t.Errorf("[%s] Serve() failed: %v", time.Now().Format(testtool.TimeLayout), err)
		}
	}()
	defer testServer.Close()
	time.Sleep(100 * time.Millisecond)

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
	time.Sleep(100 * time.Millisecond)
	go func() {
		if err := testServer.Serve(serverMux); err != nil {
			t.Errorf("[%s] Serve() failed: %v", time.Now().Format(testtool.TimeLayout), err)
		}
	}()
	defer testServer.Close()
	time.Sleep(100 * time.Millisecond)

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
	time.Sleep(100 * time.Millisecond)
	go func() {
		if err := testServer.Serve(serverMux); err != nil {
			t.Errorf("[%s] Serve() failed: %v", time.Now().Format(testtool.TimeLayout), err)
		}
	}()
	defer testServer.Close()
	time.Sleep(100 * time.Millisecond)

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
	time.Sleep(100 * time.Millisecond)
	go func() {
		if err := testServer.Serve(serverMux); err != nil {
			t.Errorf("[%s] Serve() failed: %v", time.Now().Format(testtool.TimeLayout), err)
		}
	}()
	defer testServer.Close()
	time.Sleep(100 * time.Millisecond)

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
	deadline := time.Now().Add(5 * time.Second)
	for {
		mux.mu.Lock()
		if len(mux.underlays) >= 2 {
			underlays = append([]Underlay(nil), mux.underlays...)
		}
		mux.mu.Unlock()
		if len(underlays) >= 2 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the mux didn't start an underlay for both endpoints")
		}
		time.Sleep(time.Millisecond)
	}

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
