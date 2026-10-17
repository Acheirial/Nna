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

package socks5

import (
	"context"
	crand "crypto/rand"
	mrand "math/rand"
	"net"
	"testing"

	apicommon "github.com/enfein/mieru/v3/apis/common"
	"github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/egress"
	"google.golang.org/protobuf/proto"
)

var (
	inputIPv4 = egress.Input{
		Protocol: appctlpb.ProxyProtocol_SOCKS5_PROXY_PROTOCOL,
		Data:     []byte{5, 1, 0, 1, 1, 2, 3, 4, 5, 6},
	}
	inputPrivateIPv4 = egress.Input{
		Protocol: appctlpb.ProxyProtocol_SOCKS5_PROXY_PROTOCOL,
		Data:     []byte{5, 1, 0, 1, 192, 168, 0, 1, 1, 187},
		Env:      map[string]string{"user": "password1"},
	}
	inputLoopbackIPv4 = egress.Input{
		Protocol: appctlpb.ProxyProtocol_SOCKS5_PROXY_PROTOCOL,
		Data:     []byte{5, 1, 0, 1, 127, 0, 0, 1, 1, 187},
		Env:      map[string]string{"user": "password1"},
	}
	inputIPv6 = egress.Input{
		Protocol: appctlpb.ProxyProtocol_SOCKS5_PROXY_PROTOCOL,
		Data:     []byte{5, 1, 0, 4, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10, 11, 12, 13, 14, 15, 16, 17, 18},
	}
	inputDomainName = egress.Input{
		Protocol: appctlpb.ProxyProtocol_SOCKS5_PROXY_PROTOCOL,
		Data:     []byte{5, 1, 0, 3, 10, 'g', 'o', 'o', 'g', 'l', 'e', '.', 'c', 'o', 'm', 1, 187},
	}
)

func TestNoEgressRule(t *testing.T) {
	controller := &Server{
		config: &Config{
			Egress:   &appctlpb.Egress{},
			Resolver: apicommon.NilDNSResolver{},
		},
	}
	var action egress.Action
	action = controller.FindAction(context.Background(), inputIPv4)
	if action.Action != appctlpb.EgressAction_DIRECT || action.Proxy != nil {
		t.Errorf("got unexpected action for IPv4 input")
	}
	action = controller.FindAction(context.Background(), inputIPv6)
	if action.Action != appctlpb.EgressAction_DIRECT || action.Proxy != nil {
		t.Errorf("got unexpected action for IPv6 input")
	}
	action = controller.FindAction(context.Background(), inputDomainName)
	if action.Action != appctlpb.EgressAction_DIRECT || action.Proxy != nil {
		t.Errorf("got unexpected action for domain name input")
	}
	action = controller.FindAction(context.Background(), inputPrivateIPv4)
	if action.Action != appctlpb.EgressAction_REJECT || action.Proxy != nil {
		t.Errorf("got unexpected action for private IPv4 input")
	}
	action = controller.FindAction(context.Background(), inputLoopbackIPv4)
	if action.Action != appctlpb.EgressAction_REJECT || action.Proxy != nil {
		t.Errorf("got unexpected action for loopback IPv4 input")
	}

	controller.config.Users = map[string]*appctlpb.User{
		"password1": {
			Name:            proto.String("password1"),
			AllowPrivateIP:  proto.Bool(true),
			AllowLoopbackIP: proto.Bool(true),
		},
	}
	action = controller.FindAction(context.Background(), inputPrivateIPv4)
	if action.Action != appctlpb.EgressAction_DIRECT || action.Proxy != nil {
		t.Errorf("got unexpected action for private IPv4 input")
	}
	action = controller.FindAction(context.Background(), inputLoopbackIPv4)
	if action.Action != appctlpb.EgressAction_DIRECT || action.Proxy != nil {
		t.Errorf("got unexpected action for loopback IPv4 input")
	}
}

func TestEgressRule(t *testing.T) {
	controller := &Server{
		config: &Config{
			Egress: &appctlpb.Egress{
				Proxies: []*appctlpb.EgressProxy{
					{
						Name:     proto.String("wrap"),
						Protocol: appctlpb.ProxyProtocol_SOCKS5_PROXY_PROTOCOL.Enum(),
						Host:     proto.String("127.0.0.1"),
						Port:     proto.Int32(6789),
					},
				},
				Rules: []*appctlpb.EgressRule{
					{
						IpRanges:    []string{"*"},
						DomainNames: []string{"*"},
						Action:      appctlpb.EgressAction_PROXY.Enum(),
						ProxyNames:  []string{"wrap"},
					},
				},
			},
			Resolver: apicommon.NilDNSResolver{},
		},
	}
	var action egress.Action
	action = controller.FindAction(context.Background(), inputIPv4)
	if action.Action != appctlpb.EgressAction_PROXY || action.Proxy == nil {
		t.Errorf("got unexpected action for IPv4 input")
	}
	action = controller.FindAction(context.Background(), inputIPv6)
	if action.Action != appctlpb.EgressAction_PROXY || action.Proxy == nil {
		t.Errorf("got unexpected action for IPv6 input")
	}
	action = controller.FindAction(context.Background(), inputDomainName)
	if action.Action != appctlpb.EgressAction_PROXY || action.Proxy == nil {
		t.Errorf("got unexpected action for domain name input")
	}
	for i := 0; i < 1000; i++ {
		input := egress.Input{}
		input.Protocol = appctlpb.ProxyProtocol(mrand.Int31n(2))
		inputLen := mrand.Intn(11)
		b := make([]byte, inputLen)
		if _, err := crand.Read(b); err != nil {
			t.Fatalf("Read() failed: %v", err)
		}
		if len(b) >= 2 && b[0] == constant.Socks5Version && (b[1] == constant.Socks5ConnectCmd || b[1] == constant.Socks5UDPAssociateCmd) {
			continue
		}
		input.Data = b
		action = controller.FindAction(context.Background(), input)
		if action.Action != appctlpb.EgressAction_DIRECT || action.Proxy != nil {
			t.Errorf("got unexpected action for random input %v", b)
		}
	}
}

// makeSocks5ConnectDomainInput builds an egress.Input for a SOCKS5 CONNECT
// request to the given domain name.
func makeSocks5ConnectDomainInput(domain, user string) egress.Input {
	data := []byte{constant.Socks5Version, constant.Socks5ConnectCmd, 0, constant.Socks5FQDNAddress, byte(len(domain))}
	data = append(data, []byte(domain)...)
	data = append(data, 0, 80)
	in := egress.Input{
		Protocol: appctlpb.ProxyProtocol_SOCKS5_PROXY_PROTOCOL,
		Data:     data,
	}
	if user != "" {
		in.Env = map[string]string{"user": user}
	}
	return in
}

// TestRejectPrivateAndLoopbackDomainName checks that the well-known local
// domain names are recognized regardless of the DNS-equivalent spelling used
// by the client. DNS names are case-insensitive and a trailing dot denotes the
// same absolute name, so all of these spellings address the loopback interface
// and must be rejected when the user did not enable allowLoopbackIP.
func TestRejectPrivateAndLoopbackDomainName(t *testing.T) {
	controller := &Server{
		config: &Config{
			Egress:   &appctlpb.Egress{},
			Resolver: apicommon.NilDNSResolver{},
			Users: map[string]*appctlpb.User{
				"password1": {Name: proto.String("password1")},
			},
		},
	}
	for _, domain := range []string{"localhost", "LOCALHOST", "LocalHost", "localhost.", "LOCALHOST.", "IP6-LOCALHOST"} {
		t.Run(domain, func(t *testing.T) {
			action := controller.FindAction(context.Background(), makeSocks5ConnectDomainInput(domain, "password1"))
			if action.Action != appctlpb.EgressAction_REJECT {
				t.Errorf("FindAction(%q) = %v, want %v", domain, action.Action, appctlpb.EgressAction_REJECT)
			}
		})
	}
}

func TestMatchEgressRule(t *testing.T) {
	controller := &Server{
		config: &Config{
			Egress: &appctlpb.Egress{
				Proxies: []*appctlpb.EgressProxy{
					{
						Name:     proto.String("cloudflare"),
						Protocol: appctlpb.ProxyProtocol_SOCKS5_PROXY_PROTOCOL.Enum(),
						Host:     proto.String("127.0.0.1"),
						Port:     proto.Int32(6789),
					},
				},
				Rules: []*appctlpb.EgressRule{
					{
						IpRanges: []string{"192.168.0.0/16"},
						Action:   appctlpb.EgressAction_DIRECT.Enum(),
					},
					{
						DomainNames: []string{"google.com"},
						Action:      appctlpb.EgressAction_DIRECT.Enum(),
					},
					{
						IpRanges:    []string{"*"},
						DomainNames: []string{"*"},
						Action:      appctlpb.EgressAction_PROXY.Enum(),
						ProxyNames:  []string{"cloudflare"},
					},
				},
			},
			Resolver: apicommon.NilDNSResolver{},
			Users: map[string]*appctlpb.User{
				"test": {
					Name:           proto.String("test"),
					AllowPrivateIP: proto.Bool(true),
				},
			},
		},
	}

	tests := []struct {
		name       string
		input      egress.Input
		wantAction appctlpb.EgressAction
	}{
		{
			name: "IP matching explicit rule",
			input: egress.Input{
				Protocol: appctlpb.ProxyProtocol_SOCKS5_PROXY_PROTOCOL,
				Data:     []byte{5, 1, 0, 1, 192, 168, 0, 1, 1, 187},
				Env:      map[string]string{"user": "test"},
			},
			wantAction: appctlpb.EgressAction_DIRECT,
		},
		{
			name: "Domain matching explicit rule",
			input: egress.Input{
				Protocol: appctlpb.ProxyProtocol_SOCKS5_PROXY_PROTOCOL,
				Data:     []byte{5, 1, 0, 3, 12, 'a', '.', 'g', 'o', 'o', 'g', 'l', 'e', '.', 'c', 'o', 'm', 1, 187},
			},
			wantAction: appctlpb.EgressAction_DIRECT,
		},
		{
			name: "IP matching default rule",
			input: egress.Input{
				Protocol: appctlpb.ProxyProtocol_SOCKS5_PROXY_PROTOCOL,
				Data:     []byte{5, 1, 0, 1, 8, 8, 8, 8, 0, 53},
			},
			wantAction: appctlpb.EgressAction_PROXY,
		},
		{
			name: "Domain matching default rule",
			input: egress.Input{
				Protocol: appctlpb.ProxyProtocol_SOCKS5_PROXY_PROTOCOL,
				Data:     []byte{5, 1, 0, 3, 11, 'e', 'x', 'a', 'm', 'p', 'l', 'e', '.', 'c', 'o', 'm', 1, 187},
			},
			wantAction: appctlpb.EgressAction_PROXY,
		},
		{
			name: "Domain matching explicit rule exactly",
			input: egress.Input{
				Protocol: appctlpb.ProxyProtocol_SOCKS5_PROXY_PROTOCOL,
				Data:     []byte{5, 1, 0, 3, 10, 'g', 'o', 'o', 'g', 'l', 'e', '.', 'c', 'o', 'm', 1, 187},
			},
			wantAction: appctlpb.EgressAction_DIRECT,
		},
		{
			name: "Partial domain suffix does not match",
			input: egress.Input{
				Protocol: appctlpb.ProxyProtocol_SOCKS5_PROXY_PROTOCOL,
				Data:     []byte{5, 1, 0, 3, 14, 'e', 'v', 'i', 'l', 'g', 'o', 'o', 'g', 'l', 'e', '.', 'c', 'o', 'm', 1, 187},
			},
			wantAction: appctlpb.EgressAction_PROXY,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			action := controller.FindAction(context.Background(), tt.input)
			if action.Action != tt.wantAction {
				t.Errorf("expected %v, but got %v", tt.wantAction, action.Action)
			}
			if action.Action == appctlpb.EgressAction_PROXY && action.Proxy == nil {
				t.Errorf("expected Proxy to be non-nil, but got nil")
			}
		})
	}
}

// TestCheckDestinationIP checks the destination policy that is applied to the
// IP address of a SOCKS5 request, including the address that a domain name
// resolves to.
func TestCheckDestinationIP(t *testing.T) {
	users := map[string]*appctlpb.User{
		"plain": {
			Name: proto.String("plain"),
		},
		"private": {
			Name:           proto.String("private"),
			AllowPrivateIP: proto.Bool(true),
		},
		"loopback": {
			Name:            proto.String("loopback"),
			AllowLoopbackIP: proto.Bool(true),
		},
	}
	tests := []struct {
		name              string
		user              string
		ip                net.IP
		allowLoopbackDest bool
		wantErr           bool
	}{
		{
			name: "public IP is allowed",
			user: "plain",
			ip:   net.ParseIP("8.8.8.8"),
		},
		{
			// An unknown user is not allowed to access a non-public address.
			name:    "private IP of an unknown user is rejected",
			user:    "unknown",
			ip:      net.ParseIP("10.0.0.5"),
			wantErr: true,
		},
		{
			name:    "private IP without allowPrivateIP is rejected",
			user:    "plain",
			ip:      net.ParseIP("10.0.0.5"),
			wantErr: true,
		},
		{
			name: "private IP with allowPrivateIP is allowed",
			user: "private",
			ip:   net.ParseIP("10.0.0.5"),
		},
		{
			name:    "cloud metadata IP is rejected",
			user:    "private",
			ip:      net.ParseIP("169.254.169.254"),
			wantErr: true,
		},
		{
			name:    "CGNAT IP is rejected",
			user:    "private",
			ip:      net.ParseIP("100.64.0.1"),
			wantErr: true,
		},
		{
			name:    "loopback IP without allowLoopbackIP is rejected",
			user:    "plain",
			ip:      net.ParseIP("127.0.0.1"),
			wantErr: true,
		},
		{
			name: "loopback IP with allowLoopbackIP is allowed",
			user: "loopback",
			ip:   net.ParseIP("127.0.0.1"),
		},
		{
			name:              "loopback IP with allowLoopbackDestination is allowed",
			user:              "plain",
			ip:                net.ParseIP("127.0.0.1"),
			allowLoopbackDest: true,
		},
		{
			name:    "unspecified IP is rejected",
			user:    "plain",
			ip:      net.IPv4(0, 0, 0, 0),
			wantErr: true,
		},
		{
			name:    "unknown IP is rejected",
			user:    "plain",
			ip:      nil,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			s := &Server{
				config: &Config{
					Users:                    users,
					AllowLoopbackDestination: tt.allowLoopbackDest,
				},
			}
			err := s.checkDestinationIP(tt.user, tt.ip)
			if tt.wantErr && err == nil {
				t.Fatalf("checkDestinationIP(%q, %v) = nil, want error", tt.user, tt.ip)
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("checkDestinationIP(%q, %v) = %v, want nil", tt.user, tt.ip, err)
			}
		})
	}
}

// TestUDPDestinationCheckerRejectsPrivateAndUnknownIP checks that the UDP
// destination checker applies the same policy as the TCP destination check,
// and that it rejects an unknown destination IP address.
func TestUDPDestinationCheckerRejectsPrivateAndUnknownIP(t *testing.T) {
	s := &Server{
		config: &Config{
			Users: map[string]*appctlpb.User{
				"plain": {Name: proto.String("plain")},
			},
		},
	}
	check := s.newUDPDestinationChecker("plain")
	if err := check(nil); err == nil {
		t.Errorf("check(nil) = nil, want error")
	}
	if err := check(net.ParseIP("10.0.0.5")); err == nil {
		t.Errorf("check(10.0.0.5) = nil, want error")
	}
	if err := check(net.ParseIP("8.8.8.8")); err != nil {
		t.Errorf("check(8.8.8.8) = %v, want nil", err)
	}
}

// TestEmptyAddressIsRejected checks that a destination address with neither an
// IP address nor a domain name is rejected instead of being handled as a local
// connection.
func TestEmptyAddressIsRejected(t *testing.T) {
	s := &Server{
		config: &Config{
			Egress: &appctlpb.Egress{},
			Users: map[string]*appctlpb.User{
				"test": {
					Name:            proto.String("test"),
					AllowPrivateIP:  proto.Bool(true),
					AllowLoopbackIP: proto.Bool(true),
				},
			},
		},
	}
	in := egress.Input{
		Protocol: appctlpb.ProxyProtocol_SOCKS5_PROXY_PROTOCOL,
		Env:      map[string]string{"user": "test"},
	}
	req := &model.Request{
		Command: constant.Socks5ConnectCmd,
		DstAddr: model.AddrSpec{Port: 80},
	}

	if action := s.rejectPrivateAndLoopbackIPAction(context.Background(), in, req); action.Action != appctlpb.EgressAction_REJECT {
		t.Errorf("rejectPrivateAndLoopbackIPAction() = %v, want %v", action.Action, appctlpb.EgressAction_REJECT)
	}
	if action := s.forwardToProxyAction(context.Background(), req); action.Action != appctlpb.EgressAction_REJECT {
		t.Errorf("forwardToProxyAction() = %v, want %v", action.Action, appctlpb.EgressAction_REJECT)
	}
}
