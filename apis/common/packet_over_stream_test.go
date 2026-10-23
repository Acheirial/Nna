// Copyright (C) 2025  mieru authors
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

package common_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"net"
	"testing"

	"github.com/Acheirial/shadowlemon/v3/apis/common"
	"github.com/Acheirial/shadowlemon/v3/pkg/testtool"
)

// scriptedConn is a net.Conn which serves the bytes of a script, and which
// records the reads and the writes it receives. It is not safe for concurrent
// use.
type scriptedConn struct {
	net.Conn

	data  []byte
	off   int
	reads int
	write bytes.Buffer
}

func (c *scriptedConn) Read(p []byte) (int, error) {
	if c.off == len(c.data) {
		return 0, io.EOF
	}
	c.reads++
	n := copy(p, c.data[c.off:])
	c.off += n
	return n, nil
}

func (c *scriptedConn) Write(p []byte) (int, error) {
	return c.write.Write(p)
}

// packetFrame returns the bytes which PacketOverStreamTunnel uses to carry p.
func packetFrame(p []byte) []byte {
	frame := make([]byte, 4+len(p))
	frame[0] = 0x00
	binary.BigEndian.PutUint16(frame[1:3], uint16(len(p)))
	copy(frame[3:], p)
	frame[len(frame)-1] = 0xff
	return frame
}

func TestUDPAssociateTunnelConn(t *testing.T) {
	in, out := testtool.BufPipe()
	inConn := common.NewPacketOverStreamTunnel(in)
	outConn := common.NewPacketOverStreamTunnel(out)

	data := []byte{8, 9, 6, 4}
	n, err := inConn.Write(data)
	if err != nil {
		t.Fatalf("Write() failed: %v", err)
	}
	if n != 4 {
		t.Fatalf("Write() returns %d, want %d", n, 4)
	}

	buf := make([]byte, 16)
	n, err = outConn.Read(buf)
	if err != nil {
		t.Fatalf("Read() failed: %v", err)
	}
	if n != 4 {
		t.Fatalf("Read() returns %d, want %d", n, 4)
	}
	if !bytes.Equal(buf[:n], data) {
		t.Errorf("Read() returns %v, want %v", buf[:n], data)
	}

	if err = inConn.Close(); err != nil {
		t.Errorf("Close() failed: %v", err)
	}
	if err = outConn.Close(); err != nil {
		t.Errorf("Close() failed: %v", err)
	}
}

// TestPacketOverStreamTunnelWrite verifies the bytes which a packet is wrapped
// into, and that the maximum length of a packet is enforced.
func TestPacketOverStreamTunnelWrite(t *testing.T) {
	tests := []struct {
		name    string
		payload []byte
		want    []byte
		wantErr bool
	}{
		{
			name:    "empty packet",
			payload: []byte{},
			want:    []byte{0x00, 0x00, 0x00, 0xff},
		},
		{
			name:    "one byte packet",
			payload: []byte{0x42},
			want:    []byte{0x00, 0x00, 0x01, 0x42, 0xff},
		},
		{
			name:    "packet with a 0xff content",
			payload: []byte{0xff, 0x00, 0xff},
			want:    []byte{0x00, 0x00, 0x03, 0xff, 0x00, 0xff, 0xff},
		},
		{
			name:    "maximum length packet",
			payload: make([]byte, 65535),
			want:    packetFrame(make([]byte, 65535)),
		},
		{
			name:    "packet which is too large",
			payload: make([]byte, 65536),
			wantErr: true,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := &scriptedConn{}
			tunnel := common.NewPacketOverStreamTunnel(conn)
			n, err := tunnel.Write(test.payload)
			if test.wantErr {
				if err == nil {
					t.Fatalf("Write() of %d bytes succeeded, want an error", len(test.payload))
				}
				if conn.write.Len() != 0 {
					t.Errorf("Write() wrote %d bytes to the connection, want nothing", conn.write.Len())
				}
				return
			}
			if err != nil {
				t.Fatalf("Write() failed: %v", err)
			}
			if n != len(test.payload) {
				t.Errorf("Write() returns %d, want %d", n, len(test.payload))
			}
			if got := conn.write.Bytes(); !bytes.Equal(got, test.want) {
				t.Errorf("Write() wrote %v, want %v", got, test.want)
			}
		})
	}
}

// TestPacketOverStreamTunnelRead verifies that packets of the boundary sizes
// are copied without any change, whatever the size of the buffer of the caller
// is, and that the exact number of bytes of a packet is consumed.
func TestPacketOverStreamTunnelRead(t *testing.T) {
	sizes := []int{0, 1, 2, 3, 255, 256, 2048, 4096, 65535}
	for _, size := range sizes {
		for _, extra := range []int{0, 1, 64} {
			t.Run(fmt.Sprintf("%d bytes with a buffer %d bytes larger", size, extra), func(t *testing.T) {
				payload := bytes.Repeat([]byte{'p'}, size)
				next := []byte("next packet")
				conn := &scriptedConn{data: append(packetFrame(payload), packetFrame(next)...)}
				tunnel := common.NewPacketOverStreamTunnel(conn)

				buf := make([]byte, size+extra)
				n, err := tunnel.Read(buf)
				if err != nil {
					t.Fatalf("Read() failed: %v", err)
				}
				if n != size {
					t.Fatalf("Read() returns %d, want %d", n, size)
				}
				if !bytes.Equal(buf[:n], payload) {
					t.Fatalf("Read() returns a different content than the packet")
				}
				if got := conn.off; got != len(packetFrame(payload)) {
					t.Fatalf("Read() consumed %d bytes, want the %d bytes of the packet", got, len(packetFrame(payload)))
				}

				// The next packet is still delimited correctly.
				nextBuf := make([]byte, len(next)+1)
				n, err = tunnel.Read(nextBuf)
				if err != nil {
					t.Fatalf("Read() of the next packet failed: %v", err)
				}
				if !bytes.Equal(nextBuf[:n], next) {
					t.Fatalf("Read() returns %v, want %v", nextBuf[:n], next)
				}
			})
		}
	}
}

// TestPacketOverStreamTunnelReadShortBuffer verifies that a packet which is
// larger than the buffer of the caller is not consumed, and that reading it
// again with a larger buffer returns the whole packet.
func TestPacketOverStreamTunnelReadShortBuffer(t *testing.T) {
	payload := bytes.Repeat([]byte("large-packet-"), 100)
	next := []byte("next packet")
	conn := &scriptedConn{data: append(packetFrame(payload), packetFrame(next)...)}
	tunnel := common.NewPacketOverStreamTunnel(conn)

	// The packet is larger than the buffer: only its header is consumed.
	small := make([]byte, 16)
	n, err := tunnel.Read(small)
	if !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("Read() error = %v, want %v", err, io.ErrShortBuffer)
	}
	if n != 0 {
		t.Errorf("Read() returns %d, want 0", n)
	}
	headerLen := 3
	if conn.off != headerLen {
		t.Fatalf("Read() consumed %d bytes, want the %d bytes of the packet header", conn.off, headerLen)
	}

	// A buffer which is still too small doesn't consume the packet either.
	if _, err := tunnel.Read(make([]byte, len(payload)-1)); !errors.Is(err, io.ErrShortBuffer) {
		t.Fatalf("Read() error = %v, want %v", err, io.ErrShortBuffer)
	}
	if conn.off != headerLen {
		t.Fatalf("Read() consumed %d bytes, want the %d bytes of the packet header", conn.off, headerLen)
	}

	// The retry returns the whole packet, not the content of the next one.
	buf := make([]byte, len(payload))
	n, err = tunnel.Read(buf)
	if err != nil {
		t.Fatalf("Read() failed: %v", err)
	}
	if !bytes.Equal(buf[:n], payload) {
		t.Fatalf("Read() returns %d bytes, want the %d bytes of the packet", n, len(payload))
	}

	// The tunnel is back in sync with the boundary of the next packet.
	nextBuf := make([]byte, len(next)+1)
	n, err = tunnel.Read(nextBuf)
	if err != nil {
		t.Fatalf("Read() of the next packet failed: %v", err)
	}
	if !bytes.Equal(nextBuf[:n], next) {
		t.Fatalf("Read() returns %v, want %v", nextBuf[:n], next)
	}
}

// TestPacketOverStreamTunnelReadError verifies the errors of Read().
func TestPacketOverStreamTunnelReadError(t *testing.T) {
	tests := []struct {
		name       string
		data       []byte
		bufSize    int
		wantErr    error
		wantErrMsg string
	}{
		{
			name:       "packet with a wrong prefix",
			data:       []byte{0x01, 0x00, 0x00, 0xff},
			bufSize:    16,
			wantErrMsg: "packet prefix 0x1 is not 0x00",
		},
		{
			name:    "stream which ends before the header",
			data:    []byte{0x00},
			bufSize: 16,
			wantErr: io.ErrUnexpectedEOF,
		},
		{
			name:    "stream which ends before the packet",
			data:    []byte{0x00, 0x00, 0x04, 0x01, 0x02},
			bufSize: 16,
			wantErr: io.ErrUnexpectedEOF,
		},
		{
			name:    "stream which ends before the suffix",
			data:    []byte{0x00, 0x00, 0x02, 0x01, 0x02},
			bufSize: 16,
			wantErr: io.ErrUnexpectedEOF,
		},
		{
			name:       "packet with a wrong suffix",
			data:       []byte{0x00, 0x00, 0x02, 0x01, 0x02, 0x00},
			bufSize:    16,
			wantErrMsg: "packet suffix 0x0 is not 0xff",
		},
		{
			name:       "packet with a wrong suffix when the buffer is exact",
			data:       []byte{0x00, 0x00, 0x02, 0x01, 0x02, 0x00},
			bufSize:    2,
			wantErrMsg: "packet suffix 0x0 is not 0xff",
		},
		{
			name:    "empty stream",
			data:    []byte{},
			bufSize: 16,
			wantErr: io.EOF,
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := &scriptedConn{data: test.data}
			tunnel := common.NewPacketOverStreamTunnel(conn)
			n, err := tunnel.Read(make([]byte, test.bufSize))
			if err == nil {
				t.Fatalf("Read() succeeded with %d bytes, want an error", n)
			}
			if test.wantErr != nil && !errors.Is(err, test.wantErr) {
				t.Errorf("Read() error = %v, want %v", err, test.wantErr)
			}
			if test.wantErrMsg != "" && err.Error() != test.wantErrMsg {
				t.Errorf("Read() error = %q, want %q", err.Error(), test.wantErrMsg)
			}
		})
	}
}

// TestPacketOverStreamTunnelReadAllocation verifies that reading a packet
// doesn't allocate, thanks to the header buffer which is reused by the tunnel.
func TestPacketOverStreamTunnelReadAllocation(t *testing.T) {
	payload := bytes.Repeat([]byte("packet"), 100)
	// AllocsPerRun() calls the measured function once to warm it up, in
	// addition to the runs it measures.
	const runs = 100
	conn := &scriptedConn{data: bytes.Repeat(packetFrame(payload), runs+1)}
	tunnel := common.NewPacketOverStreamTunnel(conn)
	buf := make([]byte, len(payload)+1)

	allocs := testing.AllocsPerRun(runs, func() {
		n, err := tunnel.Read(buf)
		if err != nil {
			t.Fatalf("Read() failed: %v", err)
		}
		if n != len(payload) {
			t.Fatalf("Read() returns %d, want %d", n, len(payload))
		}
	})
	if allocs != 0 {
		t.Errorf("Read() allocates %v times per packet, want 0", allocs)
	}
}

// TestPacketOverStreamTunnelReadCalls verifies the number of reads of the
// connection which a packet costs: the header with one read, then the content
// together with its suffix when the buffer of the caller leaves room for the
// suffix, or the content and the suffix separately when it doesn't.
func TestPacketOverStreamTunnelReadCalls(t *testing.T) {
	payload := bytes.Repeat([]byte("packet"), 100)
	tests := []struct {
		name     string
		bufSize  int
		wantRead int
	}{
		{name: "the buffer leaves room for the suffix", bufSize: len(payload) + 1, wantRead: 2},
		{name: "the buffer holds the packet exactly", bufSize: len(payload), wantRead: 3},
		{name: "the buffer is too small", bufSize: len(payload) - 1, wantRead: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			conn := &scriptedConn{data: packetFrame(payload)}
			tunnel := common.NewPacketOverStreamTunnel(conn)
			n, err := tunnel.Read(make([]byte, test.bufSize))
			if test.bufSize < len(payload) {
				if !errors.Is(err, io.ErrShortBuffer) {
					t.Fatalf("Read() error = %v, want %v", err, io.ErrShortBuffer)
				}
			} else if err != nil || n != len(payload) {
				t.Fatalf("Read() = (%d, %v), want (%d, nil)", n, err, len(payload))
			}
			if conn.reads != test.wantRead {
				t.Errorf("Read() read the connection %d times, want %d", conn.reads, test.wantRead)
			}
		})
	}
}
