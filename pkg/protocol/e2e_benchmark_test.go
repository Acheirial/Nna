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

package protocol

import (
	"context"
	"fmt"
	"io"
	"net"
	"sync"
	"testing"
	"time"

	"github.com/enfein/mieru/v3/pkg/cipher"
	"github.com/enfein/mieru/v3/pkg/common"
)

const (
	// e2eBenchmarkPayloadSize is the application payload of one measured
	// message. It fits into a single segment of e2eBenchmarkMTU.
	e2eBenchmarkPayloadSize = 1024

	// e2eBenchmarkMTU is the MTU of the benchmark endpoints.
	e2eBenchmarkMTU = 1400

	// e2eBenchmarkSessions is the number of concurrent sessions of the
	// multi-session benchmark.
	e2eBenchmarkSessions = 8

	// e2eBenchmarkMultiplexFactor lets several client sessions share one
	// packet underlay, the way a real client multiplexes UDP sessions.
	e2eBenchmarkMultiplexFactor = 2

	// e2eBenchmarkDialTimeout bounds the setup of one session.
	e2eBenchmarkDialTimeout = 10 * time.Second

	// e2eBenchmarkReadTimeout bounds the wait for an echoed message. It is far
	// above the round trip time of a loopback transport, so it only turns a
	// pathological data plane loss into a benchmark failure instead of a hang.
	e2eBenchmarkReadTimeout = 30 * time.Second
)

// newE2EBenchmarkClient starts a server mux that serves one user and the client
// mux that talks to it over loopback, and returns the client mux.
//
// Every session of the server mux is served concurrently: the application data
// of a session is echoed back to the peer when echo is true and discarded
// otherwise.
func newE2EBenchmarkClient(b *testing.B, transport common.TransportProtocol, echo bool) *Mux {
	b.Helper()

	userName := "e2e-benchmark-user"
	credential := cipher.HashPassword([]byte("e2e-benchmark-password"), []byte(userName))

	var serverAddr net.Addr
	switch transport {
	case common.StreamTransport:
		port, err := common.UnusedTCPPort()
		if err != nil {
			b.Fatalf("common.UnusedTCPPort() failed: %v", err)
		}
		serverAddr = &net.TCPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
	case common.PacketTransport:
		port, err := common.UnusedUDPPort()
		if err != nil {
			b.Fatalf("common.UnusedUDPPort() failed: %v", err)
		}
		serverAddr = &net.UDPAddr{IP: net.ParseIP("127.0.0.1"), Port: port}
	default:
		b.Fatalf("transport %v is not supported by the end to end benchmark", transport)
	}

	serverMux := NewMux(false).SetServerUsers(userMap(makeTestUser(userName, credential)))
	serverMux.SetEndpoints([]UnderlayProperties{NewUnderlayProperties(e2eBenchmarkMTU, transport, serverAddr, nil)})
	if err := serverMux.Start(); err != nil {
		b.Fatalf("serverMux.Start() failed: %v", err)
	}
	b.Cleanup(func() {
		if err := serverMux.Close(); err != nil {
			b.Errorf("serverMux.Close() failed: %v", err)
		}
	})
	go func() {
		for {
			conn, err := serverMux.Accept()
			if err != nil {
				return
			}
			go e2eBenchmarkServe(conn, echo)
		}
	}()

	clientMux := NewMux(true).
		SetClientUserNamePassword(userName, credential).
		SetClientMultiplexFactor(e2eBenchmarkMultiplexFactor).
		SetEndpoints([]UnderlayProperties{NewUnderlayProperties(e2eBenchmarkMTU, transport, nil, serverAddr)})
	b.Cleanup(func() {
		if err := clientMux.Close(); err != nil {
			b.Errorf("clientMux.Close() failed: %v", err)
		}
	})
	return clientMux
}

// e2eBenchmarkServe serves the application data of one server session.
func e2eBenchmarkServe(conn net.Conn, echo bool) {
	defer conn.Close()
	if echo {
		_, _ = io.Copy(conn, conn)
		return
	}
	_, _ = io.Copy(io.Discard, conn)
}

// dialBenchmarkSession creates one client session. The handshake of the session
// starts with its first write.
func dialBenchmarkSession(b *testing.B, clientMux *Mux) *Session {
	b.Helper()

	ctx, cancel := context.WithTimeout(context.Background(), e2eBenchmarkDialTimeout)
	defer cancel()
	conn, err := clientMux.DialContext(ctx)
	if err != nil {
		b.Fatalf("clientMux.DialContext() failed: %v", err)
	}
	session, ok := conn.(*Session)
	if !ok {
		b.Fatalf("DialContext() returned %T, want *Session", conn)
	}
	return session
}

// e2eBenchmarkMessage returns a deterministic payload of the given size with a
// uniform byte distribution, so that the padding strategy sees realistic data.
func e2eBenchmarkMessage(size int) []byte {
	payload := make([]byte, size)
	for i := range payload {
		payload[i] = byte(i%256 + i/256)
	}
	return payload
}

// e2eBenchmarkWrite writes one message. The write waits for the peer to
// acknowledge the earlier messages when the send window is exhausted, so the
// measured rate is the rate of the whole data path and not only the rate at
// which the application can enqueue data.
func e2eBenchmarkWrite(b *testing.B, session *Session, payload []byte) {
	if _, err := session.Write(payload); err != nil {
		b.Fatalf("Session.Write() failed: %v", err)
	}
}

// e2eBenchmarkRoundTrip writes one message and reads its echo.
func e2eBenchmarkRoundTrip(b *testing.B, session *Session, payload, reply []byte) {
	if _, err := session.Write(payload); err != nil {
		b.Fatalf("Session.Write() failed: %v", err)
	}
	// The deadline applies to every read until it is changed, so it is
	// refreshed for each echo.
	if err := session.SetReadDeadline(time.Now().Add(e2eBenchmarkReadTimeout)); err != nil {
		b.Fatalf("Session.SetReadDeadline() failed: %v", err)
	}
	if _, err := io.ReadFull(session, reply); err != nil {
		b.Fatalf("Session.Read() failed: %v", err)
	}
}

// e2eBenchmarkConcurrentRoundTrip is the goroutine safe form of
// e2eBenchmarkRoundTrip, which reports the error instead of failing the
// benchmark: testing.TB.FailNow must be called from the goroutine that runs the
// benchmark.
func e2eBenchmarkConcurrentRoundTrip(session *Session, payload, reply []byte) error {
	if _, err := session.Write(payload); err != nil {
		return fmt.Errorf("Session.Write() failed: %w", err)
	}
	if err := session.SetReadDeadline(time.Now().Add(e2eBenchmarkReadTimeout)); err != nil {
		return fmt.Errorf("Session.SetReadDeadline() failed: %w", err)
	}
	if _, err := io.ReadFull(session, reply); err != nil {
		return fmt.Errorf("Session.Read() failed: %w", err)
	}
	return nil
}

// BenchmarkE2EStreamUnidirectional measures the TCP data path of one session
// with the payload sizes of interest: segment assembly, encryption, socket
// write, socket read, decryption, and delivery to the peer session.
//
// ns/op is the cost of one Write() of the application payload in the steady
// state and MB/s is the achieved unidirectional throughput.
func BenchmarkE2EStreamUnidirectional(b *testing.B) {
	clientMux := newE2EBenchmarkClient(b, common.StreamTransport, false)
	for _, size := range []int{256, e2eBenchmarkPayloadSize} {
		b.Run(fmt.Sprintf("payload=%d", size), func(b *testing.B) {
			session := dialBenchmarkSession(b, clientMux)
			payload := e2eBenchmarkMessage(size)
			// The first write of a session carries the handshake request, so it
			// is not measured.
			e2eBenchmarkWrite(b, session, payload)

			b.SetBytes(int64(len(payload)))
			b.ReportAllocs()
			for b.Loop() {
				e2eBenchmarkWrite(b, session, payload)
			}
		})
	}
}

// BenchmarkE2EUDPBidirectional measures the UDP data path of one session with a
// full round trip: segment assembly, encryption, datagram write, datagram read,
// decryption, delivery, the echo of the peer and the acknowledgement of it.
//
// ns/op is the cost of one round trip and MB/s is the achieved throughput of
// one direction.
func BenchmarkE2EUDPBidirectional(b *testing.B) {
	clientMux := newE2EBenchmarkClient(b, common.PacketTransport, true)
	session := dialBenchmarkSession(b, clientMux)
	payload := e2eBenchmarkMessage(e2eBenchmarkPayloadSize)
	reply := make([]byte, len(payload))
	// The first round trip of a session carries and completes the handshake, so
	// it is not measured.
	e2eBenchmarkRoundTrip(b, session, payload, reply)

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	for b.Loop() {
		e2eBenchmarkRoundTrip(b, session, payload, reply)
	}
}

// BenchmarkE2EUDPConcurrentSessions measures the UDP data path of
// e2eBenchmarkSessions sessions that run round trips at the same time. The
// sessions share the send loop and the receive loop of the server underlay, and
// several of them share one client underlay, so the measurement includes the
// contention of the data plane buffers.
//
// ns/op is the cost of one round trip of one session and MB/s is the aggregate
// throughput of all the sessions.
func BenchmarkE2EUDPConcurrentSessions(b *testing.B) {
	clientMux := newE2EBenchmarkClient(b, common.PacketTransport, true)
	sessions := make([]*Session, e2eBenchmarkSessions)
	for i := range sessions {
		sessions[i] = dialBenchmarkSession(b, clientMux)
		// The first round trip of a session carries and completes the
		// handshake, so it is not measured.
		e2eBenchmarkRoundTrip(b, sessions[i], e2eBenchmarkMessage(e2eBenchmarkPayloadSize), make([]byte, e2eBenchmarkPayloadSize))
	}
	payload := e2eBenchmarkMessage(e2eBenchmarkPayloadSize)

	b.SetBytes(int64(len(payload)))
	b.ReportAllocs()
	b.ResetTimer()

	var wg sync.WaitGroup
	var errMutex sync.Mutex
	var firstErr error
	// testing.B.Loop() drives a single goroutine, so the iterations of this
	// benchmark are split between the session goroutines by hand.
	for i := range sessions {
		iterations := b.N / len(sessions)
		if i < b.N%len(sessions) {
			iterations++
		}
		wg.Add(1)
		go func(session *Session, iterations int) {
			defer wg.Done()
			reply := make([]byte, len(payload))
			for range iterations {
				if err := e2eBenchmarkConcurrentRoundTrip(session, payload, reply); err != nil {
					errMutex.Lock()
					if firstErr == nil {
						firstErr = err
					}
					errMutex.Unlock()
					return
				}
			}
		}(sessions[i], iterations)
	}
	wg.Wait()

	b.StopTimer()
	if firstErr != nil {
		b.Fatalf("concurrent round trip failed: %v", firstErr)
	}
}
