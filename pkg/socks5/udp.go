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
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"sync"
	"sync/atomic"
	"time"

	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/pkg/common"
	"github.com/enfein/mieru/v3/pkg/log"
	"github.com/enfein/mieru/v3/pkg/stderror"
)

// RunUDPAssociateLoop exchanges socks5 UDP packets between a socks5 proxy client and a mieru proxy server,
// the proxy server is connected via the PacketOverStreamTunnel.
// check verifies whether a UDP datagram can be sent to a destination address.
// A nil check allows all the destinations.
func RunUDPAssociateLoop(udpConn *net.UDPConn, conn *apicommon.PacketOverStreamTunnel, resolver apicommon.DNSResolver, check udpDestinationChecker) error {
	var udpErr atomic.Value

	// addrMap maps the UDPAddr in string to the bytes in UDP associate header.
	addrMap := newUDPAddrTable()

	var wg sync.WaitGroup
	wg.Add(2)

	// Packets from socks5 proxy client -> mieru proxy server.
	go func() {
		defer wg.Done()
		defer udpConn.Close()
		buf := make([]byte, 1<<16)
		var n int
		var err error
		for {
			n, err = conn.Read(buf)
			if err != nil {
				udpErr.Store(err)
				return
			}

			datagram, err := parseSocks5UDPDatagram(buf[:n])
			if err != nil {
				// A malformed datagram only drops this packet, it doesn't
				// terminate the whole UDP association.
				log.Debugf("UDP associate %v dropped invalid packet: %v", udpConn.LocalAddr(), err)
				continue
			}
			dstAddr, err := resolveSocks5UDPAddr(context.Background(), resolver, datagram.Addr)
			if err != nil {
				log.Debugf("UDP associate %v ResolveUDPAddr() failed: %v", udpConn.LocalAddr(), err)
				continue
			}
			if err := checkUDPDestination(check, dstAddr); err != nil {
				log.Debugf("UDP associate %v dropped packet to %v: %v", udpConn.LocalAddr(), dstAddr, err)
				continue
			}
			if !addrMap.store(dstAddr.String(), datagram.Header) {
				log.Debugf("UDP associate %v dropped packet to %v: too many destination addresses", udpConn.LocalAddr(), dstAddr)
				continue
			}
			_, err = udpConn.WriteToUDP(datagram.Payload, dstAddr)
			if err != nil {
				log.Debugf("UDP associate [%v - %v] WriteToUDP() failed: %v", udpConn.LocalAddr(), dstAddr, err)
			}
		}
	}()

	// Packets from mieru proxy server -> socks5 proxy client.
	go func() {
		defer wg.Done()
		buf := make([]byte, 1<<16)
		var n int
		var addr *net.UDPAddr
		var err error
		for {
			n, addr, err = udpConn.ReadFromUDP(buf)
			if err != nil {
				// This is typically due to close of UDP listener.
				if !stderror.IsEOF(err) && !stderror.IsClosed(err) {
					log.Debugf("UDP associate %v Read() failed: %v", udpConn.LocalAddr(), err)
				}
				if udpErr.Load() == nil {
					udpErr.Store(err)
				}
				return
			}
			// Only the response of a destination that we sent a datagram to is
			// relayed back. Otherwise an off-path host can inject data to the
			// socks5 client by sending a datagram to this UDP listener.
			header, ok := addrMap.load(addr.String())
			if !ok {
				log.Debugf("UDP associate %v dropped packet from unexpected endpoint %v", udpConn.LocalAddr(), addr)
				continue
			}
			_, err = conn.Write(append(append([]byte(nil), header...), buf[:n]...))
			if err != nil {
				log.Debugf("UDP associate %v Write() to proxy client failed: %v", udpConn.LocalAddr(), err)
				if udpErr.Load() == nil {
					udpErr.Store(err)
				}
				return
			}
		}
	}()

	wg.Wait()
	return udpErr.Load().(error)
}

// RunUDPForwardingLoop exchanges socks5 UDP packets between a mieru proxy client and a socks5 proxy server,
// the proxy client is connected via the PacketOverStreamTunnel.
func RunUDPForwardingLoop(udpConn *net.UDPConn, conn *apicommon.PacketOverStreamTunnel, downstreamAddr *net.UDPAddr, ctrlConn net.Conn) error {
	var udpErr error
	var closeOnce sync.Once
	closeAll := func(err error) {
		closeOnce.Do(func() {
			udpErr = err
			ctrlConn.Close()
			udpConn.Close()
			conn.Close()
		})
	}

	var wg sync.WaitGroup
	wg.Add(3)

	// Monitor TCP connection for closure (signals end of socks5 UDP association).
	go func() {
		defer wg.Done()
		buf := make([]byte, 1)
		_, err := ctrlConn.Read(buf)
		closeAll(err)
	}()

	// Packets from mieru proxy client -> socks5 proxy server.
	go func() {
		defer wg.Done()
		defer udpConn.Close()
		buf := make([]byte, 1<<16)
		for {
			n, err := conn.Read(buf)
			if err != nil {
				closeAll(err)
				return
			}
			_, err = udpConn.WriteToUDP(buf[:n], downstreamAddr)
			if err != nil {
				log.Debugf("UDP forwarding [%v - %v] WriteToUDP() failed: %v", udpConn.LocalAddr(), downstreamAddr, err)
			}
		}
	}()

	// Packets from socks5 proxy server -> mieru proxy client.
	go func() {
		defer wg.Done()
		buf := make([]byte, 1<<16)
		for {
			n, addr, err := udpConn.ReadFromUDP(buf)
			if err != nil {
				if !stderror.IsEOF(err) && !stderror.IsClosed(err) {
					log.Debugf("UDP forwarding %v ReadFromUDP() failed: %v", udpConn.LocalAddr(), err)
				}
				closeAll(err)
				return
			}
			// Only relay the response of the downstream socks5 proxy server.
			// Otherwise an off-path host can inject data to the mieru proxy
			// client by sending a datagram to this UDP listener.
			if !sameUDPAddr(addr, downstreamAddr) {
				log.Debugf("UDP forwarding %v dropped packet from unexpected endpoint %v", udpConn.LocalAddr(), addr)
				continue
			}
			_, err = conn.Write(buf[:n])
			if err != nil {
				log.Debugf("UDP forwarding %v Write() to client failed: %v", udpConn.LocalAddr(), err)
				closeAll(err)
				return
			}
		}
	}()

	wg.Wait()
	return udpErr
}

// TransceiveUDPPacket sends a single UDP associate message and returns the response.
func TransceiveUDPPacket(conn *net.UDPConn, proxyAddr, dstAddr *net.UDPAddr, payload []byte) ([]byte, error) {
	header := []byte{0, 0, 0}
	if dstAddr.IP.To4() != nil {
		header = append(header, constant.Socks5IPv4Address)
		header = append(header, dstAddr.IP.To4()...)
		header = append(header, byte(dstAddr.Port>>8))
		header = append(header, byte(dstAddr.Port))
	} else {
		header = append(header, constant.Socks5IPv6Address)
		header = append(header, dstAddr.IP.To16()...)
		header = append(header, byte(dstAddr.Port>>8))
		header = append(header, byte(dstAddr.Port))
	}
	if _, err := conn.WriteToUDP(append(header, payload...), proxyAddr); err != nil {
		return nil, fmt.Errorf("WriteToUDP() failed: %v", err)
	}
	buf := make([]byte, 65536)
	n, readAddr, err := conn.ReadFromUDP(buf)
	if err != nil {
		return nil, fmt.Errorf("ReadFromUDP() failed: %v", err)
	}
	if readAddr.Port != proxyAddr.Port {
		// We don't compare the IP address because a wildcard address like 0.0.0.0 can be used.
		return nil, fmt.Errorf("unexpected read from a different address")
	}
	if n < 4 {
		return nil, fmt.Errorf("UDP associate response is too short")
	}
	switch buf[3] {
	case constant.Socks5IPv4Address:
		if n <= 10 {
			return nil, fmt.Errorf("UDP associate response is too short for IPv4 address")
		}
		// Header length is 10 bytes.
		return buf[10:n], nil
	case constant.Socks5IPv6Address:
		if n <= 22 {
			return nil, fmt.Errorf("UDP associate response is too short for IPv6 address")
		}
		// Header length is 22 bytes.
		return buf[22:n], nil
	case constant.Socks5FQDNAddress:
		if n < 5 {
			return nil, fmt.Errorf("UDP associate response is too short for FQDN address")
		}
		domainLen := int(buf[4])
		headerLen := 7 + domainLen
		if n <= headerLen {
			return nil, fmt.Errorf("UDP associate response is too short for FQDN address")
		}
		return buf[headerLen:n], nil
	default:
		return nil, fmt.Errorf("UDP associate unsupported address type: %d", buf[3])
	}
}

// runUDPAssociateDatagramLoop exchanges RFC 1928 SOCKS5 UDP datagrams between
// a SOCKS5 proxy client and UDP destinations until the TCP control connection
// is closed.
// req is the UDP associate request sent by the client. It may declare the IP
// address that the client sends datagrams from, which is used to reject
// datagrams sent by other hosts.
// check verifies whether a UDP datagram can be sent to a destination address.
// A nil check allows all the destinations.
func runUDPAssociateDatagramLoop(udpConn *net.UDPConn, ctrlConn net.Conn, req *model.Request, resolver apicommon.DNSResolver, check udpDestinationChecker) error {
	if resolver == nil {
		resolver = &net.Resolver{}
	}

	var monitorWG sync.WaitGroup
	monitorWG.Add(1)
	go func() {
		defer monitorWG.Done()
		common.ReadAllAndDiscard(ctrlConn)
		udpConn.Close()
	}()
	defer func() {
		ctrlConn.Close()
		udpConn.Close()
		monitorWG.Wait()
	}()

	// clientAddr is the UDP endpoint of the SOCKS5 client. It is learned from
	// the first datagram sent by the client.
	var clientAddr *net.UDPAddr
	// clientIP is the source IP address declared in the associate request. If
	// it is set, datagrams from other IP addresses are rejected.
	clientIP := associateClientIP(req)
	targetAddrs := newUDPAddrTable()
	buf := make([]byte, 1<<16)
	for {
		n, addr, err := udpConn.ReadFromUDP(buf)
		if err != nil {
			if !stderror.IsEOF(err) && !stderror.IsClosed(err) {
				return fmt.Errorf("UDP datagram relay %v ReadFromUDP() failed: %w", udpConn.LocalAddr(), err)
			}
			return nil
		}

		if clientAddr == nil || sameUDPAddr(addr, clientAddr) {
			if clientIP != nil && !addr.IP.Equal(clientIP) {
				log.Debugf("UDP datagram relay %v dropped packet from unexpected source %v", udpConn.LocalAddr(), addr)
				continue
			}
			dstAddr, payload, err := parseUDPAssociateDatagram(buf[:n], resolver)
			if err != nil {
				log.Debugf("UDP datagram relay %v dropped invalid packet from %v: %v", udpConn.LocalAddr(), addr, err)
				continue
			}
			if clientAddr == nil {
				clientAddr = &net.UDPAddr{
					IP:   append(net.IP(nil), addr.IP...),
					Port: addr.Port,
					Zone: addr.Zone,
				}
			}
			if err := checkUDPDestination(check, dstAddr); err != nil {
				log.Debugf("UDP datagram relay %v dropped packet to %v: %v", udpConn.LocalAddr(), dstAddr, err)
				continue
			}
			if !targetAddrs.store(dstAddr.String(), nil) {
				log.Debugf("UDP datagram relay %v dropped packet to %v: too many destination addresses", udpConn.LocalAddr(), dstAddr)
				continue
			}

			_, err = udpConn.WriteToUDP(payload, dstAddr)
			if err != nil {
				log.Debugf("UDP datagram relay [%v - %v] WriteToUDP() failed: %v", udpConn.LocalAddr(), dstAddr, err)
				continue
			}
			continue
		}

		if _, ok := targetAddrs.load(addr.String()); !ok {
			log.Debugf("UDP datagram relay %v dropped packet from unexpected endpoint %v", udpConn.LocalAddr(), addr)
			continue
		}

		header := udpAddrToHeader(addr)
		_, err = udpConn.WriteToUDP(append(header, buf[:n]...), clientAddr)
		if err != nil {
			log.Debugf("UDP datagram relay [%v - %v] WriteToUDP() to client failed: %v", udpConn.LocalAddr(), clientAddr, err)
			continue
		}
	}
}

// associateClientIP returns the IP address that the SOCKS5 client declares to
// send UDP datagrams from, according to the UDP associate request. It returns
// nil when the request doesn't declare one, in which case the client endpoint
// is learned from the first datagram.
// The port declared in the request is intentionally ignored, because it is not
// reliable: some SOCKS5 clients, including the mieru socks5 client dialer, put
// the destination address and port there instead of the source endpoint.
func associateClientIP(req *model.Request) net.IP {
	if req == nil {
		return nil
	}
	ip := req.DstAddr.IP
	if len(ip) == 0 || ip.IsUnspecified() {
		return nil
	}
	return ip
}

// checkUDPDestination returns an error when the egress policy of the UDP
// association rejects the destination address. A nil check allows all the
// destinations.
func checkUDPDestination(check udpDestinationChecker, addr *net.UDPAddr) error {
	if check == nil || addr == nil || addr.IP == nil {
		return nil
	}
	return check(addr.IP)
}

// maxUDPAddrTableSize is the maximum number of remote UDP endpoints that a
// single UDP association tracks. Without a limit, a peer can grow the table
// without bound by sending datagrams to many different destinations.
const maxUDPAddrTableSize = 4096

// udpAddrTableIdleTimeout is the idle timeout of a remote UDP endpoint in the
// table created by udpAddrTable.
const udpAddrTableIdleTimeout = 5 * time.Minute

// udpAddrTableSweepInterval is the minimum interval between two sweeps that
// evict the idle entries of a udpAddrTable. It bounds the cost of the sweep.
const udpAddrTableSweepInterval = time.Minute

// udpAddrTable maps a remote UDP endpoint to a value, such as the header used
// to relay the response. The table is bounded in size, and the entries that
// are not active are evicted.
type udpAddrTable struct {
	mu        sync.Mutex
	entries   map[string]*udpAddrTableEntry
	lastSweep time.Time
}

type udpAddrTableEntry struct {
	value    []byte
	lastSeen time.Time
}

func newUDPAddrTable() *udpAddrTable {
	return &udpAddrTable{
		entries: make(map[string]*udpAddrTableEntry),
	}
}

// load returns the value associated with key, and marks the entry as active.
func (t *udpAddrTable) load(key string) ([]byte, bool) {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	t.sweepLocked(now)
	e, ok := t.entries[key]
	if !ok {
		return nil, false
	}
	e.lastSeen = now
	return e.value, true
}

// store adds key to the table. It returns false if the table is full, and key
// was not in the table.
func (t *udpAddrTable) store(key string, value []byte) bool {
	t.mu.Lock()
	defer t.mu.Unlock()
	now := time.Now()
	t.sweepLocked(now)
	if e, ok := t.entries[key]; ok {
		e.lastSeen = now
		if value != nil {
			e.value = value
		}
		return true
	}
	if len(t.entries) >= maxUDPAddrTableSize {
		return false
	}
	t.entries[key] = &udpAddrTableEntry{
		value:    value,
		lastSeen: now,
	}
	return true
}

// sweepLocked evicts the entries that are idle, at most once per
// udpAddrTableSweepInterval.
// Caller must hold t.mu.
func (t *udpAddrTable) sweepLocked(now time.Time) {
	if now.Sub(t.lastSweep) < udpAddrTableSweepInterval {
		return
	}
	t.lastSweep = now
	for k, e := range t.entries {
		if now.Sub(e.lastSeen) > udpAddrTableIdleTimeout {
			delete(t.entries, k)
		}
	}
}

func rewriteSocks5ResponseBindPort(resp *model.Response, port int) error {
	if resp == nil {
		return fmt.Errorf("socks5 response is nil")
	}
	if port < 0 || port > 65535 {
		return fmt.Errorf("port %d is out of range", port)
	}
	resp.BindAddr.Port = port
	if len(resp.Raw) >= 2 {
		resp.Raw[len(resp.Raw)-2] = byte(port >> 8)
		resp.Raw[len(resp.Raw)-1] = byte(port)
		return nil
	}

	var buf bytes.Buffer
	if err := resp.WriteToSocks5(&buf); err != nil {
		return err
	}
	resp.Raw = buf.Bytes()
	return nil
}

func socks5UDPAddrFromResponse(conn net.Conn, resp *model.Response) (*net.UDPAddr, error) {
	tcpRemote, ok := conn.RemoteAddr().(*net.TCPAddr)
	if !ok {
		return nil, fmt.Errorf("socks5 proxy remote address has unexpected type %T", conn.RemoteAddr())
	}
	port := resp.BindAddr.Port
	if port < 1 || port > 65535 {
		return nil, fmt.Errorf("socks5 UDP bind port %d is invalid", port)
	}
	ip := resp.BindAddr.IP
	if ip == nil || ip.IsUnspecified() {
		ip = tcpRemote.IP
	}
	if ip == nil || ip.IsUnspecified() {
		return nil, fmt.Errorf("socks5 UDP bind address is unspecified")
	}
	return &net.UDPAddr{IP: ip, Port: port}, nil
}

type socks5UDPDatagram struct {
	Addr    model.AddrSpec
	Header  []byte
	Payload []byte
}

func parseSocks5UDPDatagram(pkt []byte) (*socks5UDPDatagram, error) {
	if len(pkt) <= 6 {
		return nil, stderror.ErrNoEnoughData
	}
	if pkt[0] != 0x00 || pkt[1] != 0x00 {
		return nil, stderror.ErrInvalidArgument
	}
	if pkt[2] != 0x00 {
		return nil, stderror.ErrUnsupported
	}

	r := bytes.NewReader(pkt[3:])
	dst := model.AddrSpec{}
	if err := dst.ReadFromSocks5(r); err != nil {
		if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
			return nil, stderror.ErrNoEnoughData
		}
		return nil, err
	}
	headerLen := len(pkt) - r.Len()

	return &socks5UDPDatagram{
		Addr:    dst,
		Header:  append([]byte(nil), pkt[:headerLen]...),
		Payload: pkt[headerLen:],
	}, nil
}

func newSocks5UDPDatagram(addr model.AddrSpec, payload []byte) ([]byte, error) {
	var buf bytes.Buffer
	buf.Write([]byte{0, 0, 0})
	if err := addr.WriteToSocks5(&buf); err != nil {
		return nil, err
	}
	buf.Write(payload)
	return buf.Bytes(), nil
}

func resolveSocks5UDPAddr(ctx context.Context, resolver apicommon.DNSResolver, addr model.AddrSpec) (*net.UDPAddr, error) {
	if addr.IP.To4() != nil || addr.IP.To16() != nil {
		return &net.UDPAddr{IP: addr.IP, Port: addr.Port}, nil
	}
	if addr.FQDN != "" {
		return apicommon.ResolveUDPAddr(ctx, resolver, "udp", addr.String())
	}
	return nil, model.ErrUnrecognizedAddrType
}

func parseUDPAssociateDatagram(pkt []byte, resolver apicommon.DNSResolver) (*net.UDPAddr, []byte, error) {
	datagram, err := parseSocks5UDPDatagram(pkt)
	if err != nil {
		return nil, nil, err
	}
	dstAddr, err := resolveSocks5UDPAddr(context.Background(), resolver, datagram.Addr)
	if err != nil {
		return nil, nil, err
	}
	return dstAddr, datagram.Payload, nil
}

func udpAddrSpec(addr *net.UDPAddr) model.AddrSpec {
	return model.AddrSpec{
		IP:   addr.IP,
		Port: addr.Port,
	}
}

// udpAddrToHeader returns a UDP associate header with the given
// destination address.
func udpAddrToHeader(addr *net.UDPAddr) []byte {
	if addr == nil {
		panic("When translating UDP address to UDP associate header, the UDP address is nil")
	}
	header, err := newSocks5UDPDatagram(udpAddrSpec(addr), nil)
	if err != nil {
		panic(err)
	}
	return header
}

func wrapSocks5UDPPacket(addr net.Addr, payload []byte) ([]byte, error) {
	var netAddr model.NetAddrSpec
	if err := netAddr.From(addr); err != nil {
		return nil, err
	}
	return newSocks5UDPDatagram(netAddr.AddrSpec, payload)
}

func unwrapSocks5UDPPacket(pkt []byte) ([]byte, error) {
	datagram, err := parseSocks5UDPDatagram(pkt)
	if err != nil {
		return nil, err
	}
	return datagram.Payload, nil
}

func localUDPPort(conn *net.UDPConn) (int, error) {
	local, ok := conn.LocalAddr().(*net.UDPAddr)
	if !ok {
		return 0, fmt.Errorf("UDP listener local address has unexpected type %T", conn.LocalAddr())
	}
	return local.Port, nil
}

func sameUDPAddr(a, b *net.UDPAddr) bool {
	if a == nil || b == nil {
		return a == b
	}
	return a.Port == b.Port && a.IP.Equal(b.IP)
}
