// Copyright (C) 2022  mieru authors
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

package socks5

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/pkg/testtool"
)

// TestCopyBufferPool verifies that getCopyBuffer() always returns a buffer of
// the expected size, that putCopyBuffer() restores it, and that a buffer which
// doesn't belong to the pool is not stored.
func TestCopyBufferPool(t *testing.T) {
	p := getCopyBuffer()
	if got := len(*p); got != copyBufferSize {
		t.Errorf("len(*getCopyBuffer()) = %d, want %d", got, copyBufferSize)
	}
	putCopyBuffer(p)

	// A buffer that was resliced by a caller is restored to its full size.
	p = getCopyBuffer()
	*p = (*p)[:10]
	putCopyBuffer(p)
	p = getCopyBuffer()
	if got := len(*p); got != copyBufferSize {
		t.Errorf("len(*getCopyBuffer()) = %d, want %d", got, copyBufferSize)
	}
	putCopyBuffer(p)

	// A buffer which is not owned by the pool is ignored.
	small := []byte{1, 2, 3}
	putCopyBuffer(&small)
	putCopyBuffer(nil)
}

// TestBidiCopySocks5RelaysPayload verifies that the pooled copy buffers don't
// change the data relayed between the user connection and the proxy tunnel, and
// that the socks5 response of the proxy server is still consumed instead of
// being forwarded to the user. The payload is larger than one copy buffer, and
// the test is repeated so that the buffers are taken from the pool.
func TestBidiCopySocks5RelaysPayload(t *testing.T) {
	const pendingReq = "CONNECT request"
	for attempt := range 3 {
		t.Run(fmt.Sprintf("attempt %d", attempt), func(t *testing.T) {
			userConn, userPeer := testtool.BufPipe()
			defer userConn.Close()
			defer userPeer.Close()
			proxyConn, proxyPeer := testtool.BufPipe()
			defer proxyConn.Close()
			defer proxyPeer.Close()

			toServer := bytes.Repeat([]byte{byte('a' + attempt)}, copyBufferSize+100)
			toClient := bytes.Repeat([]byte{byte('A' + attempt)}, copyBufferSize+200)

			for _, conn := range []net.Conn{userPeer, proxyPeer} {
				if err := conn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
					t.Fatalf("SetDeadline() failed: %v", err)
				}
			}

			done := make(chan error, 1)
			go func() {
				done <- BidiCopySocks5(userConn, proxyConn, []byte(pendingReq))
			}()

			// The socks5 response of the proxy server is consumed by
			// BidiCopySocks5() and must not be forwarded to the user.
			var resp bytes.Buffer
			if err := model.WriteSocks5Response(&resp, constant.Socks5ReplySuccess, zeroBindAddr()); err != nil {
				t.Fatalf("WriteSocks5Response() failed: %v", err)
			}
			if _, err := proxyPeer.Write(append(resp.Bytes(), toClient...)); err != nil {
				t.Fatalf("write to the tunnel failed: %v", err)
			}
			if _, err := userPeer.Write(toServer); err != nil {
				t.Fatalf("write to the user connection failed: %v", err)
			}

			// The pending request is prepended to the first payload sent to
			// the tunnel, and the rest is copied.
			want := append([]byte(pendingReq), toServer...)
			got := make([]byte, len(want))
			if _, err := io.ReadFull(proxyPeer, got); err != nil {
				t.Fatalf("read the tunnel payload failed: %v", err)
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("the tunnel received %d bytes, want %d bytes of the user payload.", len(got), len(want))
			}

			// The socks5 response is removed from the tunnel payload.
			got = make([]byte, len(toClient))
			if _, err := io.ReadFull(userPeer, got); err != nil {
				t.Fatalf("read the user payload failed: %v", err)
			}
			if !bytes.Equal(got, toClient) {
				t.Fatalf("the user received %d bytes, want %d bytes of the tunnel payload.", len(got), len(toClient))
			}

			// Closing the tunnel stops both copy directions.
			proxyPeer.Close()
			select {
			case <-done:
			case <-time.After(5 * time.Second):
				t.Fatalf("BidiCopySocks5() did not stop")
			}
		})
	}
}

// TestBidiCopyUDPRelaysDatagram verifies that the pooled copy buffers don't
// change the datagrams relayed between the UDP endpoint of the user and the
// proxy tunnel.
func TestBidiCopyUDPRelaysDatagram(t *testing.T) {
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("net.ListenUDP() failed: %v", err)
	}
	remoteAddr, ok := udpConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("udpConn.LocalAddr() = %v, want *net.UDPAddr", udpConn.LocalAddr())
	}
	clientConn, err := net.DialUDP("udp4", nil, remoteAddr)
	if err != nil {
		t.Fatalf("net.DialUDP() failed: %v", err)
	}
	defer clientConn.Close()
	if err := clientConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() failed: %v", err)
	}

	tunnelConn, tunnelPeer := testtool.BufPipe()
	defer tunnelPeer.Close()
	if err := tunnelPeer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() failed: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- BidiCopyUDP(udpConn, apicommon.NewPacketOverStreamTunnel(tunnelConn))
	}()

	// user -> tunnel
	toTunnel := bytes.Repeat([]byte("udp-payload-"), 100)
	if _, err := clientConn.Write(toTunnel); err != nil {
		t.Fatalf("write to the UDP endpoint failed: %v", err)
	}
	frame := make([]byte, 4+len(toTunnel))
	if _, err := io.ReadFull(tunnelPeer, frame); err != nil {
		t.Fatalf("read the tunnel packet failed: %v", err)
	}
	if frame[0] != 0x00 || frame[len(frame)-1] != 0xff {
		t.Fatalf("the tunnel packet is not delimited by 0x00 and 0xff.")
	}
	if got := int(binary.BigEndian.Uint16(frame[1:3])); got != len(toTunnel) {
		t.Fatalf("the tunnel packet length is %d, want %d.", got, len(toTunnel))
	}
	if !bytes.Equal(frame[3:3+len(toTunnel)], toTunnel) {
		t.Fatalf("the tunnel received a different payload.")
	}

	// tunnel -> user
	toUDP := bytes.Repeat([]byte("reply-payload"), 100)
	reply := make([]byte, 4+len(toUDP))
	reply[0] = 0x00
	binary.BigEndian.PutUint16(reply[1:3], uint16(len(toUDP)))
	copy(reply[3:], toUDP)
	reply[len(reply)-1] = 0xff
	if _, err := tunnelPeer.Write(reply); err != nil {
		t.Fatalf("write to the tunnel failed: %v", err)
	}
	got := make([]byte, copyBufferSize)
	n, err := clientConn.Read(got)
	if err != nil {
		t.Fatalf("read from the UDP endpoint failed: %v", err)
	}
	if !bytes.Equal(got[:n], toUDP) {
		t.Fatalf("the UDP endpoint received %d bytes, want %d bytes of the tunnel payload.", n, len(toUDP))
	}

	// Closing the tunnel stops both copy directions.
	tunnelPeer.Close()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatalf("BidiCopyUDP() did not stop")
	}
}
