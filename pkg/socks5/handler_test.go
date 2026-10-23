package socks5

import (
	"bytes"
	"context"
	"encoding/binary"
	"fmt"
	"io"
	"net"
	"testing"
	"time"

	apicommon "github.com/Acheirial/shadowlemon/v3/apis/common"
	"github.com/Acheirial/shadowlemon/v3/apis/constant"
	"github.com/Acheirial/shadowlemon/v3/pkg/appctl/appctlpb"
	"github.com/Acheirial/shadowlemon/v3/pkg/egress"
	"github.com/Acheirial/shadowlemon/v3/pkg/stderror"
	"github.com/Acheirial/shadowlemon/v3/pkg/testtool"
	"google.golang.org/protobuf/proto"
)

type failResolver struct{}

func (r failResolver) LookupIP(_ context.Context, _ string, host string) ([]net.IP, error) {
	return nil, fmt.Errorf("unexpected DNS lookup for %s", host)
}

func TestHandleConnect(t *testing.T) {
	// Create a local listener as the destination target.
	dst, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	go func() {
		conn, err := dst.Accept()
		if err != nil {
			t.Errorf("Accept() failed: %v", err)
			return
		}

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
		conn.Write([]byte("pong"))
	}()
	dstAddr := dst.Addr().(*net.TCPAddr)

	// Create a socks server.
	s := &Server{
		config: &Config{
			AllowLoopbackDestination: true,
		},
	}

	// Create the connect request.
	clientConn, serverConn := testtool.BufPipe()
	defer serverConn.Close()
	defer clientConn.Close()

	clientConn.Write([]byte{constant.Socks5Version, constant.Socks5ConnectCmd, 0, constant.Socks5IPv4Address, 127, 0, 0, 1})
	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(dstAddr.Port))
	clientConn.Write(port)
	clientConn.Write([]byte("ping"))

	// Socks server handles the request.
	go func() {
		req, err := s.readRequest(serverConn)
		if err != nil {
			t.Errorf("NewRequest() failed: %v", err)
		}
		if err := s.handleRequest(context.Background(), req, serverConn); err != nil && !stderror.IsEOF(err) && !stderror.IsClosed(err) {
			t.Errorf("handleRequest() failed: %v", err)
		}
	}()
	time.Sleep(100 * time.Millisecond)

	// Verify response from socks server.
	out := make([]byte, 14)
	if _, err := io.ReadFull(clientConn, out); err != nil {
		t.Fatalf("io.ReadFull() failed: %v", err)
	}
	want := []byte{
		constant.Socks5Version, constant.Socks5ReplySuccess, 0, constant.Socks5IPv4Address,
		127, 0, 0, 1,
		0, 0,
		'p', 'o', 'n', 'g',
	}

	// Ignore the port number before comparing the result.
	out[8] = 0
	out[9] = 0

	if !bytes.Equal(out, want) {
		t.Fatalf("got %v, want %v", out, want)
	}
}

func TestHandleConnectWithDNSHostMapping(t *testing.T) {
	// Create a local listener as the destination target.
	dst, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	defer dst.Close()
	go func() {
		conn, err := dst.Accept()
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
		if !bytes.Equal(buf, []byte("ping")) {
			t.Errorf("got %v, want %v", buf, []byte("ping"))
			return
		}
		conn.Write([]byte("pong"))
	}()
	dstAddr := dst.Addr().(*net.TCPAddr)

	// Create a socks server with DNS host mapping.
	s := &Server{
		config: &Config{
			AllowLoopbackDestination: true,
			Resolver: apicommon.HostMapResolver{
				Resolver: failResolver{},
				Hosts: map[string]net.IP{
					apicommon.NormalizeDomainName("Study.OK.Com"): net.IPv4(127, 0, 0, 1),
				},
			},
		},
	}

	// Create the connect request.
	clientConn, serverConn := testtool.BufPipe()
	defer serverConn.Close()
	defer clientConn.Close()

	hostName := "study.ok.com"
	clientConn.Write([]byte{constant.Socks5Version, constant.Socks5ConnectCmd, 0, constant.Socks5FQDNAddress, byte(len(hostName))})
	clientConn.Write([]byte(hostName))
	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(dstAddr.Port))
	clientConn.Write(port)
	clientConn.Write([]byte("ping"))

	// Socks server handles the request.
	go func() {
		req, err := s.readRequest(serverConn)
		if err != nil {
			t.Errorf("NewRequest() failed: %v", err)
		}
		if err := s.handleRequest(context.Background(), req, serverConn); err != nil && !stderror.IsEOF(err) && !stderror.IsClosed(err) {
			t.Errorf("handleRequest() failed: %v", err)
		}
	}()
	time.Sleep(100 * time.Millisecond)

	// Verify response from socks server.
	out := make([]byte, 14)
	if _, err := io.ReadFull(clientConn, out); err != nil {
		t.Fatalf("io.ReadFull() failed: %v", err)
	}
	want := []byte{
		constant.Socks5Version, constant.Socks5ReplySuccess, 0, constant.Socks5IPv4Address,
		127, 0, 0, 1,
		0, 0,
		'p', 'o', 'n', 'g',
	}

	// Ignore the port number before comparing the result.
	out[8] = 0
	out[9] = 0

	if !bytes.Equal(out, want) {
		t.Fatalf("got %v, want %v", out, want)
	}
}

func TestHandleBind(t *testing.T) {
	testcases := []struct {
		req  []byte
		resp []byte
	}{
		{
			[]byte{5, constant.Socks5BindCmd, 0, 1, 127, 0, 0, 1, 0, 1},
			[]byte{5, constant.Socks5ReplyCommandNotSupported, 0, 1, 0, 0, 0, 0, 0, 0},
		},
	}

	// Create a socks server.
	s := &Server{
		config: &Config{
			AllowLoopbackDestination: true,
		},
	}

	for _, tc := range testcases {
		// Create the connect request.
		clientConn, serverConn := testtool.BufPipe()
		clientConn.Write(tc.req)

		// Socks server handles the request.
		req, err := s.readRequest(serverConn)
		if err != nil {
			t.Fatalf("NewRequest() failed: %v", err)
		}
		if err := s.handleRequest(context.Background(), req, serverConn); err != nil {
			t.Fatalf("handleRequest() failed: %v", err)
		}

		// Verify response from socks server.
		out := make([]byte, len(tc.resp))
		clientConn.Read(out)
		if !bytes.Equal(out, tc.resp) {
			t.Errorf("got %v, want %v", out, tc.resp)
		}
	}
}

func TestHandleAssociate(t *testing.T) {
	// Create a local UDP listener as the destination target.
	udpServerAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ResolveUDPAddr() failed: %v", err)
	}
	udpServer, err := net.ListenUDP("udp", udpServerAddr)
	if err != nil {
		t.Fatalf("net.ListenUDP() failed: %v", err)
	}
	defer udpServer.Close()
	udpServerAddr, err = net.ResolveUDPAddr("udp", udpServer.LocalAddr().String())
	if err != nil {
		t.Fatalf("net.ResolveUDPAddr() failed: %v", err)
	}
	udpServerPort := udpServerAddr.Port

	// The UDP server reads a single UDP packet "ping" and responds with "pong".
	go func() {
		buf := make([]byte, 4)
		_, addr, err := udpServer.ReadFrom(buf)
		if err != nil {
			t.Errorf("ReadFrom() failed: %v", err)
			return
		}

		want := []byte("ping")
		if !bytes.Equal(buf, want) {
			t.Errorf("got %v, want %v", buf, want)
			return
		}
		if _, err := udpServer.WriteTo([]byte("pong"), addr); err != nil {
			t.Errorf("WriteTo() failed: %v", err)
		}
	}()

	// Create a socks server.
	s := &Server{
		config: &Config{
			AllowLoopbackDestination: true,
			Resolver:                 &net.Resolver{},
		},
	}

	clientConn, serverConn := testtool.BufPipe()
	defer serverConn.Close()
	defer clientConn.Close()

	// Create UDP Associate request.
	clientConn.Write([]byte{
		constant.Socks5Version, constant.Socks5UDPAssociateCmd, 0, constant.Socks5IPv4Address,
		127, 0, 0, 1,
		byte(udpServerPort >> 8), byte(udpServerPort),
	})

	// Socks server handles the request.
	go func() {
		req, err := s.readRequest(serverConn)
		if err != nil {
			t.Errorf("readRequest() failed: %v", err)
			return
		}
		if err := s.handleRequest(context.Background(), req, serverConn); err != nil && !stderror.IsEOF(err) && !stderror.IsClosed(err) {
			t.Errorf("handleRequest() failed: %v", err)
		}
	}()
	time.Sleep(100 * time.Millisecond)

	// Verify response from socks server.
	out := make([]byte, 10)
	if _, err := io.ReadFull(clientConn, out); err != nil {
		t.Fatalf("io.ReadFull() failed: %v", err)
	}
	want := []byte{
		constant.Socks5Version, constant.Socks5ReplySuccess, 0, constant.Socks5IPv4Address,
		0, 0, 0, 0,
		0, 0,
	}

	// Verify the port is non-zero (a valid port was assigned).
	port := binary.BigEndian.Uint16(out[8:10])
	if port == 0 {
		t.Errorf("expected non-zero port, got 0")
	}

	// Ignore the port number before comparing the result.
	out[8] = 0
	out[9] = 0
	if !bytes.Equal(out, want) {
		t.Fatalf("got %v, want %v", out, want)
	}

	// Send UDP packet "ping".
	wrappedConn := apicommon.NewPacketOverStreamTunnel(clientConn)
	udpReq := bytes.NewBuffer(nil)
	udpReq.Write([]byte{0, 0, 0, constant.Socks5IPv4Address, 127, 0, 0, 1})
	udpReq.WriteByte(byte(udpServerPort >> 8))
	udpReq.WriteByte(byte(udpServerPort))
	udpReq.Write([]byte("ping"))
	if _, err := wrappedConn.Write(udpReq.Bytes()); err != nil {
		t.Fatalf("Write() failed: %v", err)
	}

	// Verify UDP server responds with "pong".
	wantUDP := append([]byte{0, 0, 0, constant.Socks5IPv4Address, 127, 0, 0, 1, byte(udpServerPort >> 8), byte(udpServerPort)}, []byte("pong")...)
	outUDP := make([]byte, len(wantUDP))
	if _, err := io.ReadFull(wrappedConn, outUDP); err != nil {
		t.Fatalf("io.ReadFull() failed: %v", err)
	}
	if !bytes.Equal(outUDP, wantUDP) {
		t.Fatalf("got %v, want %v", outUDP, wantUDP)
	}
}

func TestHandleForwardingTCP(t *testing.T) {
	// Create a local listener as the destination target.
	dst, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	defer dst.Close()
	go func() {
		conn, err := dst.Accept()
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
		conn.Write([]byte("pong"))
	}()
	dstAddr := dst.Addr().(*net.TCPAddr)

	// Create a downstream socks5 server that will connect to the destination.
	downstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	defer downstreamListener.Close()
	downstreamAddr := downstreamListener.Addr().(*net.TCPAddr)

	downstreamServer := &Server{
		config: &Config{
			AllowLoopbackDestination: true,
		},
	}

	go func() {
		conn, err := downstreamListener.Accept()
		if err != nil {
			t.Errorf("downstream Accept() failed: %v", err)
			return
		}
		defer conn.Close()

		// Handle socks5 authentication, no authentication required.
		authReq := make([]byte, 3)
		if _, err := io.ReadFull(conn, authReq); err != nil {
			t.Errorf("downstream io.ReadFull() auth failed: %v", err)
			return
		}
		if authReq[0] != constant.Socks5Version || authReq[1] != 1 || authReq[2] != constant.Socks5NoAuth {
			t.Errorf("downstream got unexpected auth request: %v", authReq)
			return
		}
		if _, err := conn.Write([]byte{constant.Socks5Version, constant.Socks5NoAuth}); err != nil {
			t.Errorf("downstream write auth response failed: %v", err)
			return
		}

		// Read and handle the socks5 request.
		req, err := downstreamServer.readRequest(conn)
		if err != nil {
			t.Errorf("downstream readRequest() failed: %v", err)
			return
		}
		if err := downstreamServer.handleRequest(context.Background(), req, conn); err != nil && !stderror.IsEOF(err) && !stderror.IsClosed(err) {
			t.Errorf("downstream handleRequest() failed: %v", err)
		}
	}()

	// Create the front socks5 server with forwarding configuration.
	proxyName := "test-proxy"
	proxyAction := appctlpb.EgressAction_PROXY
	frontServer := &Server{
		config: &Config{
			AllowLoopbackDestination: true,
			Egress: &appctlpb.Egress{
				Proxies: []*appctlpb.EgressProxy{
					{
						Name: &proxyName,
						Host: func() *string { s := "127.0.0.1"; return &s }(),
						Port: func() *int32 { p := int32(downstreamAddr.Port); return &p }(),
					},
				},
				Rules: []*appctlpb.EgressRule{
					{
						IpRanges:   []string{"*"},
						Action:     &proxyAction,
						ProxyNames: []string{proxyName},
					},
				},
			},
		},
	}

	// Create the connect request.
	clientConn, serverConn := testtool.BufPipe()
	defer serverConn.Close()
	defer clientConn.Close()

	clientConn.Write([]byte{constant.Socks5Version, constant.Socks5ConnectCmd, 0, constant.Socks5IPv4Address, 127, 0, 0, 1})
	port := []byte{0, 0}
	binary.BigEndian.PutUint16(port, uint16(dstAddr.Port))
	clientConn.Write(port)
	clientConn.Write([]byte("ping"))

	// Front socks5 server handles the request and forwards to downstream.
	go func() {
		req, err := frontServer.readRequest(serverConn)
		if err != nil {
			t.Errorf("readRequest() failed: %v", err)
			return
		}

		// Find the action, should be PROXY.
		egressInput := egress.Input{
			Protocol: appctlpb.ProxyProtocol_SOCKS5_PROXY_PROTOCOL,
			Data:     req.Raw,
		}
		action := frontServer.FindAction(context.Background(), egressInput)
		if action.Action != appctlpb.EgressAction_PROXY {
			t.Errorf("expected PROXY action, got %v", action.Action)
			return
		}
		if err := frontServer.handleForwarding(req, serverConn, action.Proxy); err != nil && !stderror.IsEOF(err) && !stderror.IsClosed(err) {
			t.Errorf("handleForwarding() failed: %v", err)
		}
	}()
	time.Sleep(100 * time.Millisecond)

	// Verify response from socks server.
	out := make([]byte, 14)
	if _, err := io.ReadFull(clientConn, out); err != nil {
		t.Fatalf("io.ReadFull() failed: %v", err)
	}
	want := []byte{
		constant.Socks5Version, constant.Socks5ReplySuccess, 0, constant.Socks5IPv4Address,
		127, 0, 0, 1,
		0, 0,
		'p', 'o', 'n', 'g',
	}

	// Ignore the port number before comparing the result.
	out[8] = 0
	out[9] = 0

	if !bytes.Equal(out, want) {
		t.Fatalf("got %v, want %v", out, want)
	}
}

func TestHandleForwardingUDP(t *testing.T) {
	// Create a local UDP listener as the destination target.
	dstAddr, err := net.ResolveUDPAddr("udp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.ResolveUDPAddr() failed: %v", err)
	}
	dst, err := net.ListenUDP("udp", dstAddr)
	if err != nil {
		t.Fatalf("net.ListenUDP() failed: %v", err)
	}
	defer dst.Close()
	dstAddr, err = net.ResolveUDPAddr("udp", dst.LocalAddr().String())
	if err != nil {
		t.Fatalf("net.ResolveUDPAddr() failed: %v", err)
	}
	dstPort := dstAddr.Port

	// The UDP server reads a single UDP packet "ping" and responds with "pong".
	go func() {
		buf := make([]byte, 4)
		_, addr, err := dst.ReadFrom(buf)
		if err != nil {
			t.Errorf("ReadFrom() failed: %v", err)
			return
		}

		want := []byte("ping")
		if !bytes.Equal(buf, want) {
			t.Errorf("got %v, want %v", buf, want)
			return
		}
		if _, err := dst.WriteTo([]byte("pong"), addr); err != nil {
			t.Errorf("WriteTo() failed: %v", err)
		}
	}()

	// Create a downstream socks5 server that handles UDP associate.
	downstreamListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatalf("net.Listen() failed: %v", err)
	}
	defer downstreamListener.Close()
	downstreamAddr := downstreamListener.Addr().(*net.TCPAddr)

	go func() {
		conn, err := downstreamListener.Accept()
		if err != nil {
			t.Errorf("downstream Accept() failed: %v", err)
			return
		}
		defer conn.Close()

		// Handle socks5 authentication, no authentication required.
		authReq := make([]byte, 3)
		if _, err := io.ReadFull(conn, authReq); err != nil {
			t.Errorf("downstream io.ReadFull() auth failed: %v", err)
			return
		}
		if authReq[0] != constant.Socks5Version || authReq[1] != 1 || authReq[2] != constant.Socks5NoAuth {
			t.Errorf("downstream got unexpected auth request: %v", authReq)
			return
		}
		if _, err := conn.Write([]byte{constant.Socks5Version, constant.Socks5NoAuth}); err != nil {
			t.Errorf("downstream write auth response failed: %v", err)
			return
		}

		// Read socks5 request header.
		reqHeader := make([]byte, 10)
		if _, err := io.ReadFull(conn, reqHeader); err != nil {
			t.Errorf("downstream io.ReadFull() request failed: %v", err)
			return
		}
		if reqHeader[1] != constant.Socks5UDPAssociateCmd {
			t.Errorf("expected UDP associate command, got %v", reqHeader[1])
			return
		}
		wantReqHeader := []byte{
			constant.Socks5Version, constant.Socks5UDPAssociateCmd, 0, constant.Socks5IPv4Address,
			0, 0, 0, 0, 0, 0,
		}
		if !bytes.Equal(reqHeader, wantReqHeader) {
			t.Errorf("downstream got UDP associate request %v, want %v", reqHeader, wantReqHeader)
			return
		}

		// Create a UDP listener for the socks5 UDP relay.
		downstreamUDP, err := net.ListenUDP("udp", &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: 0})
		if err != nil {
			t.Errorf("downstream net.ListenUDP() failed: %v", err)
			return
		}
		defer downstreamUDP.Close()
		downstreamUDPPort := downstreamUDP.LocalAddr().(*net.UDPAddr).Port

		// Send success response with our UDP listener's address.
		resp := []byte{
			constant.Socks5Version, constant.Socks5ReplySuccess, 0, constant.Socks5IPv4Address,
			127, 0, 0, 1,
			byte(downstreamUDPPort >> 8), byte(downstreamUDPPort),
		}
		if _, err := conn.Write(resp); err != nil {
			t.Errorf("downstream write response failed: %v", err)
			return
		}

		// Receive packet from socks5 proxy client.
		buf := make([]byte, 1024)
		n, clientAddr, err := downstreamUDP.ReadFromUDP(buf)
		if err != nil {
			t.Errorf("downstream ReadFromUDP() failed: %v", err)
			return
		}

		// Parse socks5 UDP header.
		if n < 10 {
			t.Errorf("downstream UDP packet too short: %d", n)
			return
		}
		dstPort := int(buf[8])<<8 | int(buf[9])
		data := buf[10:n]

		// Send data to destination.
		dstAddr := &net.UDPAddr{IP: net.IPv4(127, 0, 0, 1), Port: dstPort}
		if _, err := downstreamUDP.WriteToUDP(data, dstAddr); err != nil {
			t.Errorf("downstream WriteToUDP() to destination failed: %v", err)
			return
		}

		// Receive response from destination.
		n, _, err = downstreamUDP.ReadFromUDP(buf[10:])
		if err != nil {
			t.Errorf("downstream ReadFromUDP() from destination failed: %v", err)
			return
		}

		// Build response with socks5 UDP header.
		respUDP := []byte{0, 0, 0, constant.Socks5IPv4Address, 127, 0, 0, 1, byte(dstPort >> 8), byte(dstPort)}
		respUDP = append(respUDP, buf[10:10+n]...)
		if _, err := downstreamUDP.WriteToUDP(respUDP, clientAddr); err != nil {
			t.Errorf("downstream WriteToUDP() to client failed: %v", err)
			return
		}

		// Keep TCP connection alive until it's closed.
		io.ReadAll(conn)
	}()

	// Create the front socks5 server with forwarding configuration.
	proxyName := "test-proxy"
	proxyAction := appctlpb.EgressAction_PROXY
	frontServer := &Server{
		config: &Config{
			AllowLoopbackDestination: true,
			Egress: &appctlpb.Egress{
				Proxies: []*appctlpb.EgressProxy{
					{
						Name: &proxyName,
						Host: func() *string { s := "127.0.0.1"; return &s }(),
						Port: func() *int32 { p := int32(downstreamAddr.Port); return &p }(),
					},
				},
				Rules: []*appctlpb.EgressRule{
					{
						IpRanges:   []string{"*"},
						Action:     &proxyAction,
						ProxyNames: []string{proxyName},
					},
				},
			},
		},
	}

	// Create the UDP associate request.
	clientConn, serverConn := testtool.BufPipe()
	defer serverConn.Close()
	defer clientConn.Close()

	clientConn.Write([]byte{
		constant.Socks5Version, constant.Socks5UDPAssociateCmd, 0, constant.Socks5IPv4Address,
		127, 0, 0, 1,
		byte(dstPort >> 8), byte(dstPort),
	})

	// Front socks5 server handles the request and forwards to downstream.
	go func() {
		req, err := frontServer.readRequest(serverConn)
		if err != nil {
			t.Errorf("readRequest() failed: %v", err)
			return
		}

		egressInput := egress.Input{
			Protocol: appctlpb.ProxyProtocol_SOCKS5_PROXY_PROTOCOL,
			Data:     req.Raw,
		}
		action := frontServer.FindAction(context.Background(), egressInput)
		if action.Action != appctlpb.EgressAction_PROXY {
			t.Errorf("expected PROXY action, got %v", action.Action)
			return
		}
		if err := frontServer.handleForwarding(req, serverConn, action.Proxy); err != nil && !stderror.IsEOF(err) && !stderror.IsClosed(err) {
			t.Errorf("handleForwarding() failed: %v", err)
		}
	}()
	time.Sleep(100 * time.Millisecond)

	// Verify response from socks server.
	out := make([]byte, 10)
	if _, err := io.ReadFull(clientConn, out); err != nil {
		t.Fatalf("io.ReadFull() failed: %v", err)
	}
	want := []byte{
		constant.Socks5Version, constant.Socks5ReplySuccess, 0, constant.Socks5IPv4Address,
		127, 0, 0, 1,
		0, 0,
	}

	// Verify the port is non-zero.
	port := binary.BigEndian.Uint16(out[8:10])
	if port == 0 {
		t.Errorf("expected non-zero port, got 0")
	}

	// Ignore the port number before comparing the result.
	out[8] = 0
	out[9] = 0
	if !bytes.Equal(out, want) {
		t.Fatalf("got %v, want %v", out, want)
	}

	// Send UDP packet "ping".
	wrappedConn := apicommon.NewPacketOverStreamTunnel(clientConn)
	udpReq := bytes.NewBuffer(nil)
	udpReq.Write([]byte{0, 0, 0, constant.Socks5IPv4Address, 127, 0, 0, 1})
	udpReq.WriteByte(byte(dstPort >> 8))
	udpReq.WriteByte(byte(dstPort))
	udpReq.Write([]byte("ping"))
	if _, err := wrappedConn.Write(udpReq.Bytes()); err != nil {
		t.Fatalf("Write() failed: %v", err)
	}

	// Verify UDP server responds with "pong".
	wantUDP := append([]byte{0, 0, 0, constant.Socks5IPv4Address, 127, 0, 0, 1, byte(dstPort >> 8), byte(dstPort)}, []byte("pong")...)
	outUDP := make([]byte, len(wantUDP))
	if _, err := io.ReadFull(wrappedConn, outUDP); err != nil {
		t.Fatalf("io.ReadFull() failed: %v", err)
	}
	if !bytes.Equal(outUDP, wantUDP) {
		t.Fatalf("got %v, want %v", outUDP, wantUDP)
	}
}

// userConn attaches the name of the authenticated user to a connection, so
// that the tests can check the egress policy that depends on the user.
type userConn struct {
	net.Conn

	userName string
}

func (c userConn) UserName() string {
	return c.userName
}

// TestHandleConnectRejectsDomainResolvedToPrivateIP checks that a CONNECT
// request to a domain name that resolves to a private IP address is rejected
// when the user did not enable allowPrivateIP. The egress policy check that
// runs before the DNS resolution only sees the domain name, so the resolved
// address has to be checked again before the connection is established.
func TestHandleConnectRejectsDomainResolvedToPrivateIP(t *testing.T) {
	const host = "private.example"
	tests := []struct {
		name           string
		user           string
		allowPrivateIP bool
	}{
		{
			name: "user without allowPrivateIP is rejected",
			user: "plain",
		},
		{
			name:           "user with allowPrivateIP is not rejected",
			user:           "private",
			allowPrivateIP: true,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			user := &appctlpb.User{Name: proto.String(tt.user)}
			if tt.allowPrivateIP {
				user.AllowPrivateIP = proto.Bool(true)
			}
			s := &Server{
				config: &Config{
					// The domain name resolves to a private IP address.
					Resolver: apicommon.HostMapResolver{
						Resolver: failResolver{},
						Hosts: map[string]net.IP{
							apicommon.NormalizeDomainName(host): net.IPv4(10, 0, 0, 5),
						},
					},
					// The connection attempt is expected to fail, so it is
					// bounded to keep the test fast.
					HandshakeTimeout: 200 * time.Millisecond,
					Users: map[string]*appctlpb.User{
						tt.user: user,
					},
				},
			}

			clientConn, serverConn := testtool.BufPipe()
			defer clientConn.Close()
			defer serverConn.Close()

			req := bytes.NewBuffer(nil)
			req.Write([]byte{constant.Socks5Version, constant.Socks5ConnectCmd, 0, constant.Socks5FQDNAddress, byte(len(host))})
			req.Write([]byte(host))
			req.Write([]byte{0, 80})
			if _, err := clientConn.Write(req.Bytes()); err != nil {
				t.Fatalf("Write() failed: %v", err)
			}

			request, err := s.readRequest(serverConn)
			if err != nil {
				t.Fatalf("readRequest() failed: %v", err)
			}
			done := make(chan error, 1)
			go func() {
				done <- s.handleRequest(context.Background(), request, userConn{Conn: serverConn, userName: tt.user})
			}()

			out := make([]byte, 10)
			if _, err := io.ReadFull(clientConn, out); err != nil {
				t.Fatalf("io.ReadFull() failed: %v", err)
			}
			if out[0] != constant.Socks5Version {
				t.Fatalf("reply version = %d, want %d", out[0], constant.Socks5Version)
			}
			rejected := out[1] == constant.Socks5ReplyNotAllowedByRuleSet
			if tt.allowPrivateIP {
				if rejected {
					t.Errorf("reply = %d, want the egress policy to allow the destination", out[1])
				}
				return
			}
			if !rejected {
				t.Errorf("reply = %d, want %d", out[1], constant.Socks5ReplyNotAllowedByRuleSet)
			}
			select {
			case err := <-done:
				if err == nil {
					t.Errorf("handleRequest() error = nil, want error")
				}
			case <-time.After(time.Second):
				t.Errorf("handleRequest() did not return after the destination was rejected")
			}
		})
	}
}

// TestServeConnRejectsEmptyDomainName checks that a SOCKS5 request with the
// domain name address type and a domain name of length 0 is answered with a
// protocol error, instead of being connected to an empty destination.
func TestServeConnRejectsEmptyDomainName(t *testing.T) {
	serv, err := New(&Config{AllowLoopbackDestination: true})
	if err != nil {
		t.Fatalf("New() failed: %v", err)
	}
	clientConn, serverConn := testtool.BufPipe()
	defer clientConn.Close()
	defer serverConn.Close()
	if err := clientConn.SetDeadline(time.Now().Add(5 * time.Second)); err != nil {
		t.Fatalf("SetDeadline() failed: %v", err)
	}

	done := make(chan error, 1)
	go func() {
		done <- serv.ServeConn(serverConn)
	}()

	// The greeting requests no authentication, then the request declares a
	// domain name with a length of 0.
	req := []byte{
		constant.Socks5Version, 1, constant.Socks5NoAuth,
		constant.Socks5Version, constant.Socks5ConnectCmd, 0, constant.Socks5FQDNAddress, 0, 0, 80,
	}
	if _, err := clientConn.Write(req); err != nil {
		t.Fatalf("Write() failed: %v", err)
	}

	// The authentication response, followed by the connection response.
	out := make([]byte, 12)
	if _, err := io.ReadFull(clientConn, out); err != nil {
		t.Fatalf("io.ReadFull() failed: %v", err)
	}
	if out[1] != constant.Socks5NoAuth {
		t.Errorf("authentication reply = %d, want %d", out[1], constant.Socks5NoAuth)
	}
	if out[3] == constant.Socks5ReplySuccess {
		t.Errorf("connection reply = %d, want a failure reply", out[3])
	}
	if out[3] != constant.Socks5ReplyAddrTypeNotSupported {
		t.Errorf("connection reply = %d, want %d", out[3], constant.Socks5ReplyAddrTypeNotSupported)
	}

	select {
	case err := <-done:
		if err == nil {
			t.Errorf("ServeConn() error = nil, want error")
		}
	case <-time.After(time.Second):
		t.Errorf("ServeConn() did not return after the request was rejected")
	}
}

// TestUDPAssociationLimitPerUser checks the accounting of the UDP associations
// of a user.
func TestUDPAssociationLimitPerUser(t *testing.T) {
	s := &Server{config: &Config{}}

	t.Run("the limit is per user", func(t *testing.T) {
		for i := range maxUDPAssociationsPerUser {
			if !s.acquireUDPAssociation("alice") {
				t.Fatalf("acquireUDPAssociation(alice) = false for association %d, want true", i+1)
			}
		}
		if !s.acquireUDPAssociation("bob") {
			t.Errorf("acquireUDPAssociation(bob) = false, want true")
		}
		if s.acquireUDPAssociation("alice") {
			t.Errorf("acquireUDPAssociation(alice) = true after %d associations, want false", maxUDPAssociationsPerUser)
		}
	})

	t.Run("a released slot can be reused", func(t *testing.T) {
		s.releaseUDPAssociation("alice")
		if !s.acquireUDPAssociation("alice") {
			t.Errorf("acquireUDPAssociation(alice) = false after a slot was released, want true")
		}
		// Releasing more associations than acquired doesn't underflow.
		for range maxUDPAssociationsPerUser + 2 {
			s.releaseUDPAssociation("alice")
		}
		if !s.acquireUDPAssociation("alice") {
			t.Errorf("acquireUDPAssociation(alice) = false after all the slots were released, want true")
		}
	})
}

// TestHandleAssociateLimitReached checks that a UDP associate request is
// answered with a ruleset error when the user already holds the maximum number
// of concurrent UDP associations.
func TestHandleAssociateLimitReached(t *testing.T) {
	s := &Server{
		config: &Config{
			Resolver: &net.Resolver{},
		},
		// The connection used by this test doesn't carry a user name.
		udpAssocCount: map[string]int{"": maxUDPAssociationsPerUser},
	}
	clientConn, serverConn := testtool.BufPipe()
	defer clientConn.Close()
	defer serverConn.Close()

	reqBytes := []byte{
		constant.Socks5Version, constant.Socks5UDPAssociateCmd, 0, constant.Socks5IPv4Address,
		127, 0, 0, 1, 0, 0,
	}
	if _, err := clientConn.Write(reqBytes); err != nil {
		t.Fatalf("Write() failed: %v", err)
	}
	req, err := s.readRequest(serverConn)
	if err != nil {
		t.Fatalf("readRequest() failed: %v", err)
	}
	if err := s.handleAssociate(context.Background(), req, serverConn); err == nil {
		t.Errorf("handleAssociate() error = nil, want error")
	}

	out := make([]byte, 10)
	if _, err := io.ReadFull(clientConn, out); err != nil {
		t.Fatalf("io.ReadFull() failed: %v", err)
	}
	if out[1] != constant.Socks5ReplyNotAllowedByRuleSet {
		t.Errorf("reply = %d, want %d", out[1], constant.Socks5ReplyNotAllowedByRuleSet)
	}
}
