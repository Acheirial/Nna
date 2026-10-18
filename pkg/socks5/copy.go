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
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"

	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/pkg/log"
	"github.com/enfein/mieru/v3/pkg/stderror"
)

// copyBufferSize is the size of the buffers used to move data between a user
// stream connection and the proxy tunnel.
const copyBufferSize = 1 << 16

// udpCopyBufferSize is the initial size of the buffer which each direction of a
// UDP relay uses to copy one datagram.
//
// A UDP relay is a cheap and short lived object, but the server holds one for
// every UDP association of every user, and the datagrams they carry are usually
// a few hundred bytes. The buffer is therefore small on purpose: memory is
// traded for throughput, 2 KiB per direction instead of the 64 KiB which is
// needed to hold the largest possible datagram. A relay which receives a
// datagram that doesn't fit the buffer doubles it, up to maxUDPDatagramSize, so
// the memory is spent only by the relays which need it.
const udpCopyBufferSize = 2 << 10

// maxUDPDatagramSize is the size of the largest datagram a UDP relay copies, and
// the largest buffer a UDP relay grows to. It is the limit of the packet
// framing used by apis/common.PacketOverStreamTunnel, whose length field is 2
// bytes long, and of a UDP payload.
const maxUDPDatagramSize = 1 << 16

// copyBufferPool reuses the copy buffers of the SOCKS5 proxy, so that a new
// connection doesn't allocate 64 KiB per copy direction. A buffer is only used
// by the goroutine that takes it from the pool, and it is returned to the pool
// after the copy loop of that goroutine ends. It is safe to hand a used buffer
// to another connection because neither net.Conn.Write(), nor
// PacketOverStreamTunnel.Write() keeps a reference to the data after it returns.
var copyBufferPool = sync.Pool{
	New: func() any {
		b := make([]byte, copyBufferSize)
		return &b
	},
}

// getCopyBuffer returns a buffer of copyBufferSize bytes from the pool. The
// returned pointer is the handle of the buffer and must be passed back to
// putCopyBuffer() unchanged.
func getCopyBuffer() *[]byte {
	return copyBufferPool.Get().(*[]byte)
}

// putCopyBuffer returns a buffer to the pool. The caller must not use the buffer
// after this call.
func putCopyBuffer(p *[]byte) {
	if p == nil || cap(*p) < copyBufferSize {
		// Don't pool a buffer that was not allocated by this file.
		return
	}
	*p = (*p)[:copyBufferSize]
	copyBufferPool.Put(p)
}

// growUDPCopyBuffer returns a buffer which is twice as large as buf, up to
// maxUDPDatagramSize. The content of buf is not preserved.
func growUDPCopyBuffer(buf []byte) []byte {
	size := 2 * len(buf)
	if size > maxUDPDatagramSize {
		size = maxUDPDatagramSize
	}
	return make([]byte, size)
}

// BidiCopyUDP does bi-directional data copy between a proxy client UDP endpoint
// and the proxy tunnel.
//
// Each direction copies one datagram at a time with a buffer of
// udpCopyBufferSize bytes, and doubles its buffer up to maxUDPDatagramSize when
// a datagram doesn't fit it, so that a relay which carries large datagrams
// still copies them whole while the other relays stay small.
func BidiCopyUDP(udpConn *net.UDPConn, tunnelConn *apicommon.PacketOverStreamTunnel) error {
	var addr atomic.Value
	errCh := make(chan error, 2)

	go func() {
		// udpConn -> tunnelConn
		buf := make([]byte, udpCopyBufferSize)
		for {
			n, a, err := udpConn.ReadFrom(buf)
			if err != nil {
				// This is typically due to close of UDP listener.
				errCh <- fmt.Errorf("ReadFrom UDP connection failed: %w", err)
				break
			}
			udpAddr := addr.Load()
			if udpAddr == nil {
				addr.Store(a)
			} else if udpAddr.(net.Addr).String() != a.String() {
				errCh <- fmt.Errorf("ReadFrom new UDP endpoint %s, first use is %s", a.String(), udpAddr.(net.Addr).String())
				break
			}
			if n == len(buf) && len(buf) < maxUDPDatagramSize {
				// The datagram may have been truncated: a UDP socket discards
				// the bytes which don't fit the read buffer, and it doesn't
				// report the original length of the datagram. The datagram is
				// dropped rather than forwarded truncated, which would deliver
				// a corrupted payload to the destination, and the buffer is
				// doubled so that the next datagram of the same size is copied
				// whole. The datagram of a relay which keeps sending datagrams
				// of exactly the current buffer size also grows the buffer, so
				// at most one datagram is dropped per buffer size.
				log.Debugf("BidiCopyUDP() with endpoint %v drops a datagram of at least %d bytes and grows the copy buffer", udpConn.LocalAddr(), len(buf))
				buf = growUDPCopyBuffer(buf)
				continue
			}
			if _, err = tunnelConn.Write(buf[:n]); err != nil {
				errCh <- fmt.Errorf("write tunnel failed: %w", err)
				break
			}
		}
	}()
	go func() {
		// tunnelConn -> udpConn
		buf := make([]byte, udpCopyBufferSize)
		for {
			n, err := tunnelConn.Read(buf)
			if err == io.ErrShortBuffer && len(buf) < maxUDPDatagramSize {
				// The datagram is larger than the buffer. The tunnel keeps the
				// packet whose header it consumed, so reading it again with a
				// larger buffer returns the whole datagram instead of the
				// truncated content of the previous one.
				buf = growUDPCopyBuffer(buf)
				continue
			}
			if err != nil {
				errCh <- fmt.Errorf("read tunnel failed: %w", err)
				break
			}
			udpAddr := addr.Load()
			if udpAddr == nil {
				errCh <- fmt.Errorf("UDP address is not ready")
				break
			}
			_, err = udpConn.WriteTo(buf[:n], udpAddr.(net.Addr))
			if err != nil {
				errCh <- fmt.Errorf("WriteTo UDP connetion failed: %w", err)
				break
			}
		}
	}()

	var err error
	err = <-errCh
	if !stderror.IsEOF(err) && !stderror.IsClosed(err) {
		log.Debugf("BidiCopyUDP() with endpoint %v failed 1: %v", udpConn.LocalAddr(), err)
	}

	tunnelConn.Close()
	udpConn.Close()

	err = <-errCh
	if !stderror.IsEOF(err) && !stderror.IsClosed(err) {
		log.Debugf("BidiCopyUDP() with endpoint %v failed 2: %v", udpConn.LocalAddr(), err)
	}
	return nil
}

// BidiCopySocks5 does bi-directional data copy.
// This function is aware of socks5 protocol and doesn't copy the socks5 reply header
// sent by the server.
// If pendingReq is not empty, it is prepended to proxyConn.
func BidiCopySocks5(conn, proxyConn io.ReadWriteCloser, pendingReq []byte) error {
	errCh := make(chan error, 2)

	go func() {
		// conn -> proxyConn
		bufPtr := getCopyBuffer()
		defer putCopyBuffer(bufPtr)
		buf := *bufPtr
		reqLen := len(pendingReq)
		if reqLen > 0 {
			log.Debugf("HANDSHAKE_NO_WAIT mode socks5 client request: %v", pendingReq)
			reqLen = copy(buf, pendingReq)
		}
		n, err := conn.Read(buf[reqLen:])
		if err != nil {
			proxyConn.Close()
			errCh <- fmt.Errorf("failed to read connection request from the client: %w", err)
			return
		}
		n += reqLen
		_, err = proxyConn.Write(buf[:n])
		if err != nil {
			proxyConn.Close()
			errCh <- fmt.Errorf("failed to write connection request to the server: %w", err)
			return
		}
		// CopyBuffer() behaves exactly like Copy(), but it doesn't allocate a
		// 32 KiB buffer for every connection when the reader and the writer
		// don't implement WriterTo and ReaderFrom.
		_, err = io.CopyBuffer(proxyConn, conn, buf)
		proxyConn.Close()
		errCh <- err
	}()

	go func() {
		// proxyConn -> conn
		connResp, err := model.ReadSocks5Response(proxyConn)
		if err != nil {
			conn.Close()
			errCh <- fmt.Errorf("failed to read connection response from the server: %w", err)
			return
		}
		log.Debugf("HANDSHAKE_NO_WAIT mode socks5 server reply: %v", connResp.Raw)
		bufPtr := getCopyBuffer()
		defer putCopyBuffer(bufPtr)
		_, err = io.CopyBuffer(conn, proxyConn, *bufPtr)
		conn.Close()
		errCh <- err
	}()

	err := <-errCh
	<-errCh
	return err
}
