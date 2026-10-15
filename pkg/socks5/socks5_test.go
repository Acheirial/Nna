package socks5

import (
	"bytes"
	"encoding/binary"
	"errors"
	"io"
	"net"
	"os"
	"testing"
	"time"

	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/pkg/stderror"
	"github.com/enfein/mieru/v3/pkg/testtool"
)

func TestNewRejectsUnsupportedUDPAssociateMode(t *testing.T) {
	_, err := New(&Config{UDPAssociateMode: UDPAssociateMode(99)})
	if err == nil {
		t.Fatal("New() error = nil, want error")
	}
}

func TestSocks5Connect(t *testing.T) {
	// Create a local listener as the destination target.
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	defer l.Close()
	go func() {
		conn, err := l.Accept()
		if err != nil {
			t.Errorf("Accept() failed: %v", err)
			return
		}
		defer conn.Close()

		buf := make([]byte, 4)
		if _, err := io.ReadFull(conn, buf); err != nil {
			t.Errorf("io.ReadFull() failed: %v", err)
			return
		}

		want := []byte("ping")
		if !bytes.Equal(buf, want) {
			t.Errorf("got %v, want %v", buf, want)
			return
		}
		if _, err := conn.Write([]byte("pong")); err != nil {
			t.Errorf("Write() failed: %v", err)
		}
	}()
	lAddr := l.Addr().(*net.TCPAddr)

	// Create a socks server.
	conf := &Config{
		AllowLoopbackDestination: true,
	}
	serv, err := New(conf)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	conn := servePipe(t, serv)

	req := bytes.NewBuffer(nil)
	req.Write([]byte{constant.Socks5Version, 1, constant.Socks5NoAuth})
	req.Write([]byte{constant.Socks5Version, constant.Socks5ConnectCmd, 0, constant.Socks5IPv4Address, 127, 0, 0, 1})
	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(lAddr.Port))
	req.Write(port)
	req.Write([]byte("ping"))

	// Send all the bytes.
	if _, err := conn.Write(req.Bytes()); err != nil {
		t.Fatalf("Write() failed: %v", err)
	}

	// Verify response from socks server.
	want := []byte{
		constant.Socks5Version, constant.Socks5NoAuth,
		constant.Socks5Version, 0, 0, constant.Socks5IPv4Address,
		127, 0, 0, 1,
		0, 0,
		'p', 'o', 'n', 'g',
	}
	out := make([]byte, len(want))
	conn.SetDeadline(time.Now().Add(time.Second))
	if _, err := io.ReadFull(conn, out); err != nil {
		t.Fatalf("io.ReadFull() failed: %v", err)
	}

	// Ignore the port number before compare the result.
	out[10] = 0
	out[11] = 0

	if !bytes.Equal(out, want) {
		t.Fatalf("got %v, want %v", out, want)
	}
}

func TestSocks5UDPAssociation(t *testing.T) {
	// Waiting for the UDP association is bounded by these timeouts. There is no
	// assertion that a step completes within a fixed amount of time, because
	// the machine that runs the test may be heavily loaded.
	const (
		associationTimeout = 10 * time.Second
		udpRequestTimeout  = 5 * time.Second
		udpRequestAttempts = 3
	)
	isTimeout := func(err error) bool {
		if errors.Is(err, os.ErrDeadlineExceeded) {
			return true
		}
		var netErr net.Error
		return errors.As(err, &netErr) && netErr.Timeout()
	}

	// Create a local listener as the destination target. It echoes every
	// datagram it receives, so a retried request is answered as well.
	l, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("net.ListenUDP() failed: %v", err)
	}
	udpListenPort := l.LocalAddr().(*net.UDPAddr).Port
	echoDone := make(chan struct{})
	t.Cleanup(func() {
		l.Close()
		// Wait for the echo goroutine to return, so that it doesn't report an
		// error after the test is completed.
		<-echoDone
	})
	go func() {
		defer close(echoDone)
		buf := make([]byte, 1024)
		for {
			n, addr, err := l.ReadFromUDP(buf)
			if err != nil {
				// This is expected after the listener is closed.
				if !stderror.IsClosed(err) {
					t.Errorf("ReadFromUDP() failed: %v", err)
				}
				return
			}
			if !bytes.Equal(buf[:n], []byte("ping")) {
				t.Errorf("got %v, want %v", buf[:n], []byte("ping"))
				return
			}
			if _, err := l.WriteToUDP([]byte("pong"), addr); err != nil {
				// This is expected after the listener is closed.
				if !stderror.IsClosed(err) {
					t.Errorf("WriteToUDP() failed: %v", err)
				}
				return
			}
		}
	}()

	// Create a socks server.
	conf := &Config{
		AllowLoopbackDestination: true,
	}
	serv, err := New(conf)
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}

	conn := servePipe(t, serv)

	req := bytes.NewBuffer(nil)
	req.Write([]byte{constant.Socks5Version, 1, constant.Socks5NoAuth})
	req.Write([]byte{constant.Socks5Version, constant.Socks5UDPAssociateCmd, 0, constant.Socks5IPv4Address, 127, 0, 0, 1, 0, 0})

	// Send initial UDP association request. The write deadline is refreshed
	// because servePipe() sets a short one when it creates the connection.
	if err := conn.SetWriteDeadline(time.Now().Add(associationTimeout)); err != nil {
		t.Fatalf("SetWriteDeadline() failed: %v", err)
	}
	if _, err := conn.Write(req.Bytes()); err != nil {
		t.Fatalf("Write() failed: %v", err)
	}

	// Verify response from socks server. The socks server creates the UDP
	// listener of the association before it replies, which can take a while on
	// a loaded machine.
	want := []byte{
		constant.Socks5Version, constant.Socks5NoAuth,
		constant.Socks5Version, 0, 0, constant.Socks5IPv4Address,
		0, 0, 0, 0,
		0, 0,
	}
	out := make([]byte, len(want))
	if err := conn.SetReadDeadline(time.Now().Add(associationTimeout)); err != nil {
		t.Fatalf("SetReadDeadline() failed: %v", err)
	}
	if _, err := io.ReadFull(conn, out); err != nil {
		t.Fatalf("io.ReadFull() failed: %v", err)
	}

	// Ignore the port number before compare the result.
	t.Logf("socks5 server created UDP listener on port %d", int(out[10])<<8+int(out[11]))
	out[10] = 0
	out[11] = 0

	if !bytes.Equal(out, want) {
		t.Fatalf("got %v, want %v", out, want)
	}

	// Send subsequent UDP association request. The request is sent before the
	// association is guaranteed to be established, and a UDP datagram can be
	// dropped, so sending is retried with a bound instead of relying on a fixed
	// delay before the first request.
	wrappedConn := apicommon.NewPacketOverStreamTunnel(conn)
	req.Reset()
	req.Write([]byte{0, 0, 0, 1, 127, 0, 0, 1})
	req.WriteByte(byte(udpListenPort >> 8))
	req.WriteByte(byte(udpListenPort))
	req.Write([]byte("ping"))

	// Verify UDP response.
	want = append([]byte{0, 0, 0, 1, 127, 0, 0, 1, byte(udpListenPort >> 8), byte(udpListenPort)}, []byte("pong")...)
	out = make([]byte, len(want))
	var readErr error
	for attempt := 0; attempt < udpRequestAttempts; attempt++ {
		if err := wrappedConn.SetWriteDeadline(time.Now().Add(udpRequestTimeout)); err != nil {
			t.Fatalf("SetWriteDeadline() failed: %v", err)
		}
		if _, err := wrappedConn.Write(req.Bytes()); err != nil {
			t.Fatalf("Write() failed: %v", err)
		}
		if err := wrappedConn.SetReadDeadline(time.Now().Add(udpRequestTimeout)); err != nil {
			t.Fatalf("SetReadDeadline() failed: %v", err)
		}
		_, readErr = io.ReadFull(wrappedConn, out)
		if readErr == nil {
			break
		}
		if !isTimeout(readErr) {
			t.Fatalf("io.ReadFull() failed: %v", readErr)
		}
		t.Logf("UDP associate response is not received in attempt %d: %v", attempt+1, readErr)
	}
	if readErr != nil {
		t.Fatalf("UDP associate response is not received after %d attempts: %v", udpRequestAttempts, readErr)
	}
	if !bytes.Equal(out, want) {
		t.Fatalf("got %v, want %v", out, want)
	}
}

// servePipe buffers pipelined authentication, requests, and payloads while the
// server writes its replies before reading the next part of the request.
func servePipe(t *testing.T, serv *Server) net.Conn {
	t.Helper()
	clientConn, serverConn := testtool.BufPipe()
	done := make(chan error, 1)
	go func() {
		done <- serv.ServeConn(serverConn)
	}()
	t.Cleanup(func() {
		clientConn.Close()
		serverConn.Close()
		select {
		case err := <-done:
			if err != nil && !stderror.IsEOF(err) && !stderror.IsClosed(err) {
				t.Errorf("ServeConn() failed: %v", err)
			}
		case <-time.After(time.Second):
			t.Error("socks5 server did not stop")
		}
	})
	if err := clientConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() failed: %v", err)
	}
	return clientConn
}
