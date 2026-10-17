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

// udpTestRelay is a BidiCopyUDP() relay under test: the UDP endpoint of the
// user and the peer of the tunnel which is connected to the relay.
type udpTestRelay struct {
	t          *testing.T
	clientConn *net.UDPConn
	tunnelPeer net.Conn
	done       chan error
}

// startUDPRelay starts a BidiCopyUDP() relay between a UDP endpoint and a
// buffered pipe which plays the role of the tunnel.
func startUDPRelay(t *testing.T) *udpTestRelay {
	t.Helper()
	udpConn, err := net.ListenUDP("udp4", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
	if err != nil {
		t.Fatalf("net.ListenUDP() failed: %v", err)
	}
	t.Cleanup(func() { udpConn.Close() })
	remoteAddr, ok := udpConn.LocalAddr().(*net.UDPAddr)
	if !ok {
		t.Fatalf("udpConn.LocalAddr() = %v, want *net.UDPAddr", udpConn.LocalAddr())
	}
	clientConn, err := net.DialUDP("udp4", nil, remoteAddr)
	if err != nil {
		t.Fatalf("net.DialUDP() failed: %v", err)
	}
	t.Cleanup(func() { clientConn.Close() })
	if err := clientConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() failed: %v", err)
	}

	tunnelConn, tunnelPeer := testtool.BufPipe()
	t.Cleanup(func() { tunnelPeer.Close() })
	if err := tunnelPeer.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() failed: %v", err)
	}

	r := &udpTestRelay{
		t:          t,
		clientConn: clientConn,
		tunnelPeer: tunnelPeer,
		done:       make(chan error, 1),
	}
	go func() {
		r.done <- BidiCopyUDP(udpConn, apicommon.NewPacketOverStreamTunnel(tunnelConn))
	}()
	return r
}

// readTunnelPacket reads the next packet of the tunnel and returns its content.
func (r *udpTestRelay) readTunnelPacket() []byte {
	r.t.Helper()
	header := make([]byte, 3)
	if _, err := io.ReadFull(r.tunnelPeer, header); err != nil {
		r.t.Fatalf("read the tunnel packet header failed: %v", err)
	}
	if header[0] != 0x00 {
		r.t.Fatalf("the tunnel packet prefix is 0x%x, want 0x00", header[0])
	}
	length := int(binary.BigEndian.Uint16(header[1:3]))
	body := make([]byte, length+1)
	if _, err := io.ReadFull(r.tunnelPeer, body); err != nil {
		r.t.Fatalf("read the tunnel packet body failed: %v", err)
	}
	if body[length] != 0xff {
		r.t.Fatalf("the tunnel packet suffix is 0x%x, want 0xff", body[length])
	}
	return body[:length]
}

// writeTunnelPacket writes one packet to the tunnel.
func (r *udpTestRelay) writeTunnelPacket(payload []byte) {
	r.t.Helper()
	packet := make([]byte, 4+len(payload))
	packet[0] = 0x00
	binary.BigEndian.PutUint16(packet[1:3], uint16(len(payload)))
	copy(packet[3:], payload)
	packet[len(packet)-1] = 0xff
	if _, err := r.tunnelPeer.Write(packet); err != nil {
		r.t.Fatalf("write to the tunnel failed: %v", err)
	}
}

// readUDPDatagram reads the next datagram of the user UDP endpoint.
func (r *udpTestRelay) readUDPDatagram() []byte {
	r.t.Helper()
	buf := make([]byte, maxUDPDatagramSize)
	n, err := r.clientConn.Read(buf)
	if err != nil {
		r.t.Fatalf("read from the UDP endpoint failed: %v", err)
	}
	return buf[:n]
}

// stop closes the tunnel and waits for the relay to stop.
func (r *udpTestRelay) stop() {
	r.t.Helper()
	r.tunnelPeer.Close()
	select {
	case <-r.done:
	case <-time.After(5 * time.Second):
		r.t.Fatalf("BidiCopyUDP() did not stop")
	}
}

// TestBidiCopyUDPRelaysDatagram verifies that a datagram which fits the small
// copy buffer of a UDP relay is relayed without any change in both directions.
func TestBidiCopyUDPRelaysDatagram(t *testing.T) {
	for _, size := range []int{1, 4, udpCopyBufferSize / 2, udpCopyBufferSize - 1} {
		t.Run(fmt.Sprintf("%d bytes", size), func(t *testing.T) {
			r := startUDPRelay(t)

			// user -> tunnel
			toTunnel := bytes.Repeat([]byte{'u'}, size)
			if _, err := r.clientConn.Write(toTunnel); err != nil {
				t.Fatalf("write to the UDP endpoint failed: %v", err)
			}
			if got := r.readTunnelPacket(); !bytes.Equal(got, toTunnel) {
				t.Fatalf("the tunnel received %d bytes, want the %d bytes of the datagram", len(got), size)
			}

			// tunnel -> user
			toUDP := bytes.Repeat([]byte{'d'}, size)
			r.writeTunnelPacket(toUDP)
			if got := r.readUDPDatagram(); !bytes.Equal(got, toUDP) {
				t.Fatalf("the UDP endpoint received %d bytes, want the %d bytes of the tunnel packet", len(got), size)
			}

			r.stop()
		})
	}
}

// TestBidiCopyUDPGrowsCopyBuffer verifies that a datagram which is larger than
// the initial copy buffer of the relay grows the buffer and is copied whole,
// and that the datagram which triggered the growth is dropped rather than
// copied truncated.
func TestBidiCopyUDPGrowsCopyBuffer(t *testing.T) {
	r := startUDPRelay(t)

	// The first datagram fills the copy buffer of the relay: the relay can't
	// tell whether it was truncated, so it drops the datagram and doubles the
	// buffer.
	size := udpCopyBufferSize + 512
	first := bytes.Repeat([]byte{'a'}, size)
	if _, err := r.clientConn.Write(first); err != nil {
		t.Fatalf("write the first datagram failed: %v", err)
	}
	second := bytes.Repeat([]byte{'b'}, size)
	if _, err := r.clientConn.Write(second); err != nil {
		t.Fatalf("write the second datagram failed: %v", err)
	}

	// The first packet of the tunnel is the second datagram: it fits the grown
	// buffer. The dropped datagram must not appear as a truncated packet.
	if got := r.readTunnelPacket(); !bytes.Equal(got, second) {
		t.Fatalf("the tunnel received %d bytes, want the %d bytes of the second datagram", len(got), size)
	}

	// The buffer stays large: the next datagram of that size is copied too.
	third := bytes.Repeat([]byte{'c'}, size)
	if _, err := r.clientConn.Write(third); err != nil {
		t.Fatalf("write the third datagram failed: %v", err)
	}
	if got := r.readTunnelPacket(); !bytes.Equal(got, third) {
		t.Fatalf("the tunnel received %d bytes, want the %d bytes of the third datagram", len(got), size)
	}

	r.stop()
}

// TestBidiCopyUDPRelaysLargeTunnelPacket verifies that a packet of the tunnel
// which is larger than the initial copy buffer of the relay reaches the UDP
// endpoint whole.
func TestBidiCopyUDPRelaysLargeTunnelPacket(t *testing.T) {
	r := startUDPRelay(t)

	// The UDP endpoint of the relay is learned from the first datagram.
	if _, err := r.clientConn.Write([]byte("connect")); err != nil {
		t.Fatalf("write to the UDP endpoint failed: %v", err)
	}
	_ = r.readTunnelPacket()

	// The relay reads the packet with a small buffer, then with a buffer which
	// is large enough to hold the whole packet.
	size := udpCopyBufferSize * 3
	toUDP := bytes.Repeat([]byte{'d'}, size)
	r.writeTunnelPacket(toUDP)
	if got := r.readUDPDatagram(); !bytes.Equal(got, toUDP) {
		t.Fatalf("the UDP endpoint received %d bytes, want the %d bytes of the tunnel packet", len(got), size)
	}

	r.stop()
}

// TestGrowUDPCopyBuffer verifies the size of the buffer returned by
// growUDPCopyBuffer().
func TestGrowUDPCopyBuffer(t *testing.T) {
	tests := []struct {
		name string
		size int
		want int
	}{
		{name: "initial buffer", size: udpCopyBufferSize, want: 2 * udpCopyBufferSize},
		{name: "below the maximum", size: maxUDPDatagramSize / 2, want: maxUDPDatagramSize},
		{name: "at the maximum", size: maxUDPDatagramSize, want: maxUDPDatagramSize},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got := growUDPCopyBuffer(make([]byte, test.size))
			if len(got) != test.want {
				t.Errorf("growUDPCopyBuffer(%d) returns a buffer of %d bytes, want %d", test.size, len(got), test.want)
			}
		})
	}
}
