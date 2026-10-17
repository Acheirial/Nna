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

package common

import (
	"encoding/binary"
	"fmt"
	"io"
	"net"
)

// PacketOverStreamTunnel keeps the boundary of packets when transmitted
// inside a streaming tunnel.
//
// Each original packet will be wrapped like this
//
//	0x00 + 2 bytes of original length + original packet content + 0xff
//
// the length is encoded with big endian.
//
// The destination of packets are negotiated separately.
type PacketOverStreamTunnel struct {
	net.Conn

	// rxHeader is the buffer of the packet header: the 0x00 prefix followed by
	// the 2 bytes of the packet length. Keeping it here instead of allocating
	// it for every packet removes two allocations per read. It is reused to
	// read the 0xff suffix of a packet which doesn't leave room for the suffix
	// in the buffer of the caller.
	rxHeader [3]byte

	// pendingLength is the length of the packet which a previous Read() didn't
	// copy because it was larger than the buffer of the caller. The header of
	// such a packet is consumed already, so the next Read() must continue that
	// packet instead of parsing the next header. It is 0 when no packet is
	// pending, which is unambiguous because a packet longer than p is at least
	// 1 byte long.
	pendingLength int
}

var _ net.PacketConn = (*PacketOverStreamTunnel)(nil)

// Read reads the content of the next packet into p and returns its length.
//
// Read returns io.ErrShortBuffer when the packet is larger than p. In that case
// the header of the packet is consumed but its content is not: calling Read
// again with a larger p returns the whole content of that packet, so a caller
// which doesn't know the size of the packets in advance (such as a UDP relay
// which starts with a small buffer) can copy them without losing the packet
// boundary.
//
// Read is not safe to call from multiple goroutines at the same time.
func (c *PacketOverStreamTunnel) Read(p []byte) (n int, err error) {
	length := c.pendingLength
	if length == 0 {
		if _, err = io.ReadFull(c.Conn, c.rxHeader[:3]); err != nil {
			return 0, err
		}
		if c.rxHeader[0] != 0x00 {
			return 0, fmt.Errorf("packet prefix 0x%x is not 0x00", c.rxHeader[0])
		}
		length = int(binary.BigEndian.Uint16(c.rxHeader[1:3]))
	}
	if length > len(p) {
		c.pendingLength = length
		return 0, io.ErrShortBuffer
	}
	c.pendingLength = 0

	if length < len(p) {
		// The packet content and its 0xff suffix are read with one call. The
		// suffix is stored in the byte which follows the content, which is
		// inside p: only the first length bytes of p are part of the packet.
		if _, err = io.ReadFull(c.Conn, p[:length+1]); err != nil {
			return 0, err
		}
		if p[length] != 0xff {
			return 0, fmt.Errorf("packet suffix 0x%x is not 0xff", p[length])
		}
		return length, nil
	}

	// p is exactly the size of the packet content, so the suffix is read with a
	// second call.
	if n, err = io.ReadFull(c.Conn, p[:length]); err != nil {
		return 0, err
	}
	if _, err = io.ReadFull(c.Conn, c.rxHeader[:1]); err != nil {
		return 0, err
	}
	if c.rxHeader[0] != 0xff {
		return 0, fmt.Errorf("packet suffix 0x%x is not 0xff", c.rxHeader[0])
	}
	return n, nil
}

func (c *PacketOverStreamTunnel) Write(p []byte) (int, error) {
	if len(p) > 65535 {
		return 0, fmt.Errorf("packet length %d is larger than maximum length 65535", len(p))
	}
	data := make([]byte, 4+len(p))
	data[0] = 0x00
	binary.BigEndian.PutUint16(data[1:], uint16(len(p)))
	copy(data[3:], p)
	data[3+len(p)] = 0xff

	if _, err := c.Conn.Write(data); err != nil {
		return 0, err
	}
	return len(p), nil
}

func (c *PacketOverStreamTunnel) ReadFrom(p []byte) (n int, addr net.Addr, err error) {
	addr = c.RemoteAddr()
	n, err = c.Read(p)
	return
}

func (c *PacketOverStreamTunnel) WriteTo(p []byte, _ net.Addr) (n int, err error) {
	return c.Write(p)
}

func (c *PacketOverStreamTunnel) Close() error {
	return c.Conn.Close()
}

// NewPacketOverStreamTunnel creates a PacketOverStreamTunnel on top of
// an existing stream oriented network connection.
func NewPacketOverStreamTunnel(conn net.Conn) *PacketOverStreamTunnel {
	return &PacketOverStreamTunnel{Conn: conn}
}
