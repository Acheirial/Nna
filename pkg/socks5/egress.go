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
	"bytes"
	"context"
	"fmt"
	mrand "math/rand"
	"net"
	"strings"

	"github.com/enfein/mieru/v3/apis/constant"
	"github.com/enfein/mieru/v3/apis/model"
	"github.com/enfein/mieru/v3/pkg/appctl/appctlpb"
	"github.com/enfein/mieru/v3/pkg/egress"
	"github.com/enfein/mieru/v3/pkg/log"
)

var (
	// socks5.Server implements egress.Controller interface.
	_ egress.Controller = (*Server)(nil)
)

var wellKnownIPv4LocalDomainNames = []string{
	"localhost", // can be resolved to IPv6 address
	"localhost4",
	"localhost.localdomain", // can be resolved to IPv6 address
	"localhost4.localdomain4",
}

var wellKnownIPv6LocalDomainNames = []string{
	"localhost6",
	"ip6-localhost",
	"ip6-loopback",
	"localhost6.localdomain6",
}

func (s *Server) FindAction(ctx context.Context, in egress.Input) egress.Action {
	// DIRECT is used for all invalid inputs, such that they are handled by
	// the subsequent logic.
	if in.Protocol != appctlpb.ProxyProtocol_SOCKS5_PROXY_PROTOCOL {
		log.Debugf("socks5 egress controller: %s is not supported", in.Protocol.String())
		return egress.Action{
			Action: appctlpb.EgressAction_DIRECT,
		}
	}
	if len(in.Data) < 4 {
		log.Debugf("socks5 egress controller: input %v is too short", in.Data)
		return egress.Action{
			Action: appctlpb.EgressAction_DIRECT,
		}
	}
	if in.Data[0] != constant.Socks5Version {
		log.Debugf("socks5 egress controller: input %v is not socks5 protocol", in.Data)
		return egress.Action{
			Action: appctlpb.EgressAction_DIRECT,
		}
	}
	req, err := parseEgressSocks5Request(in.Data)
	if err != nil {
		log.Debugf("socks5 egress controller: failed to parse input %v: %v", in.Data, err)
		return egress.Action{
			Action: appctlpb.EgressAction_DIRECT,
		}
	}
	if req.Command == constant.Socks5ConnectCmd || req.Command == constant.Socks5UDPAssociateCmd {
		// 1. Check if the request should be rejected because the destination is
		// private or loopback IP.
		action := s.rejectPrivateAndLoopbackIPAction(ctx, in, req)
		if action.Action == appctlpb.EgressAction_REJECT {
			return action
		}
		// 2. Check if the request should be forwarded to another proxy.
		return s.forwardToProxyAction(ctx, req)
	}
	return egress.Action{
		Action: appctlpb.EgressAction_DIRECT,
	}
}

func parseEgressSocks5Request(data []byte) (*model.Request, error) {
	req := &model.Request{}
	if err := req.ReadFromSocks5(bytes.NewReader(data)); err != nil {
		return nil, err
	}
	return req, nil
}

func (s *Server) rejectPrivateAndLoopbackIPAction(_ context.Context, in egress.Input, req *model.Request) egress.Action {
	ip := req.DstAddr.IP
	if len(ip) == 0 && req.DstAddr.FQDN != "" {
		// If we do a DNS lookup, we leak the destination domain name to the DNS server.
		// For user privacy, we only check some well-known local domain names.
		// DNS names are case-insensitive and a trailing dot denotes the same
		// absolute name, so normalize the name before matching.
		domainName := normalizeDomainName(req.DstAddr.FQDN)
		if matchLocalDomainName(domainName, wellKnownIPv4LocalDomainNames) {
			ip = net.ParseIP("127.0.0.1")
		} else if matchLocalDomainName(domainName, wellKnownIPv6LocalDomainNames) {
			ip = net.ParseIP("::1")
		} else {
			return egress.Action{
				Action: appctlpb.EgressAction_DIRECT,
			}
		}
	} else if len(ip) == 0 {
		return egress.Action{
			Action: appctlpb.EgressAction_DIRECT,
		}
	}

	// Load user information. An unknown or unregistered user is not allowed to
	// access a non-public address.
	allowPrivateIP := false
	allowLoopbackIP := false
	if userName := in.Env["user"]; userName != "" {
		if user, ok := s.config.Users[userName]; ok {
			allowPrivateIP = user.GetAllowPrivateIP()
			allowLoopbackIP = user.GetAllowLoopbackIP()
		}
	}
	if allowIPAccess(classifyIP(ip), allowPrivateIP, allowLoopbackIP, s.config.AllowLoopbackDestination) {
		return egress.Action{
			Action: appctlpb.EgressAction_DIRECT,
		}
	}
	return egress.Action{
		Action: appctlpb.EgressAction_REJECT,
	}
}

// ipScope classifies an IP address for the egress policy check.
type ipScope int

const (
	// ipScopePublic means the address is neither private, loopback, nor unspecified.
	ipScopePublic ipScope = iota
	// ipScopePrivate means the address is a private, link local, or carrier
	// grade NAT address.
	ipScopePrivate
	// ipScopeLoopback means the address is a loopback address.
	ipScopeLoopback
	// ipScopeUnspecified means the address is an unspecified address such as
	// 0.0.0.0 or ::, which is equivalent to a local address on Linux.
	ipScopeUnspecified
)

func (s ipScope) String() string {
	switch s {
	case ipScopePrivate:
		return "private"
	case ipScopeLoopback:
		return "loopback"
	case ipScopeUnspecified:
		return "unspecified"
	default:
		return "public"
	}
}

// cgnatIPv4 is the carrier grade NAT address range defined in RFC 6598.
// net.IP.IsPrivate() doesn't cover it.
var cgnatIPv4 = mustParseCIDR("100.64.0.0/10")

func mustParseCIDR(s string) *net.IPNet {
	_, ipNet, err := net.ParseCIDR(s)
	if err != nil {
		panic(fmt.Sprintf("failed to parse CIDR %q: %v", s, err))
	}
	return ipNet
}

// classifyIP classifies a destination IP address for the egress policy check.
func classifyIP(ip net.IP) ipScope {
	switch {
	case ip.IsUnspecified():
		// The unspecified address is not a public address. On Linux,
		// connecting to 0.0.0.0 or :: reaches a local address.
		return ipScopeUnspecified
	case ip.IsLoopback():
		return ipScopeLoopback
	case ip.IsPrivate(), ip.IsLinkLocalUnicast(), ip.IsLinkLocalMulticast(), cgnatIPv4.Contains(ip):
		// net.IP.IsPrivate() covers RFC 1918 and RFC 4193 addresses, but not
		// IPv6 link local (RFC 4291), IPv4 link local (RFC 3927) or CGNAT
		// (RFC 6598) ranges. Those ranges reach local services and cloud
		// provider metadata endpoints such as 169.254.169.254, so they are
		// treated as private addresses.
		return ipScopePrivate
	}
	return ipScopePublic
}

// allowIPAccess checks whether an address of the given scope can be accessed
// according to the egress policy.
// allowLoopbackDestination is for testing purpose only.
func allowIPAccess(scope ipScope, allowPrivateIP, allowLoopbackIP, allowLoopbackDestination bool) bool {
	switch scope {
	case ipScopePublic:
		return true
	case ipScopePrivate:
		return allowPrivateIP
	case ipScopeLoopback:
		return allowLoopbackIP || allowLoopbackDestination
	case ipScopeUnspecified:
		// The user never asked for the unspecified address explicitly, so
		// accessing it requires opting in to the loopback policy.
		return allowLoopbackIP || allowLoopbackDestination
	}
	return false
}

// normalizeDomainName returns the canonical form of a DNS name. DNS names are
// case-insensitive and a trailing dot denotes the same absolute name.
func normalizeDomainName(name string) string {
	return strings.ToLower(strings.TrimSuffix(name, "."))
}

// matchLocalDomainName checks whether the normalized domain name is one of the
// well-known local domain names, or a subdomain of it.
func matchLocalDomainName(domainName string, names []string) bool {
	for _, d := range names {
		if domainName == d || strings.HasSuffix(domainName, "."+d) {
			return true
		}
	}
	return false
}

// udpDestinationChecker checks whether a SOCKS5 UDP datagram can be sent to a
// destination IP address.
type udpDestinationChecker func(ip net.IP) error

// newUDPDestinationChecker returns the checker of the UDP datagrams relayed by
// a SOCKS5 UDP association, according to the egress policy of the given user.
// A UDP association is checked once when it is established, but every datagram
// can be sent to a different destination, so each datagram must be checked
// separately.
// The user information is loaded once, so the returned checker is cheap to
// call for every datagram.
func (s *Server) newUDPDestinationChecker(userName string) udpDestinationChecker {
	allowPrivateIP := false
	allowLoopbackIP := false
	if user, ok := s.config.Users[userName]; ok {
		allowPrivateIP = user.GetAllowPrivateIP()
		allowLoopbackIP = user.GetAllowLoopbackIP()
	}
	allowLoopbackDestination := s.config.AllowLoopbackDestination
	return func(ip net.IP) error {
		if ip == nil {
			return fmt.Errorf("destination IP address is unknown")
		}
		scope := classifyIP(ip)
		if allowIPAccess(scope, allowPrivateIP, allowLoopbackIP, allowLoopbackDestination) {
			return nil
		}
		return fmt.Errorf("destination %v is a %s address and it is rejected by egress policy", ip, scope)
	}
}

func (s *Server) forwardToProxyAction(_ context.Context, req *model.Request) egress.Action {
	addr := req.DstAddr.IP
	domain := req.DstAddr.FQDN
	if len(addr) == 0 && domain == "" {
		return egress.Action{Action: appctlpb.EgressAction_DIRECT}
	}

	for _, rule := range s.config.Egress.GetRules() {
		if s.matchEgressRule(addr, domain, rule) {
			if rule.GetAction() == appctlpb.EgressAction_PROXY {
				allProxyNames := rule.GetProxyNames()
				var selectedProxyName string
				if len(allProxyNames) > 0 {
					idx := mrand.Intn(len(allProxyNames))
					selectedProxyName = allProxyNames[idx]
				}
				for _, proxy := range s.config.Egress.GetProxies() {
					if proxy.GetName() == selectedProxyName {
						return egress.Action{
							Action: rule.GetAction(),
							Proxy:  proxy,
						}
					}
				}
			}
			return egress.Action{Action: rule.GetAction()}
		}
	}

	return egress.Action{Action: appctlpb.EgressAction_DIRECT}
}

func (s *Server) matchEgressRule(addr net.IP, domain string, rule *appctlpb.EgressRule) bool {
	if addr != nil {
		// IP based rule
		for _, ipRange := range rule.GetIpRanges() {
			if ipRange == "*" {
				return true
			}
			_, cidr, err := net.ParseCIDR(ipRange)
			if err != nil {
				continue
			}
			if cidr.Contains(addr) {
				return true
			}
		}
	} else if domain != "" {
		// Domain name based rule. Normalize the names before comparing,
		// because DNS names are case-insensitive and a trailing dot denotes
		// the same absolute name. Otherwise a rule that rejects "blocked.com"
		// can be bypassed with "BLOCKED.COM".
		domain = normalizeDomainName(domain)
		for _, d := range rule.GetDomainNames() {
			if d == "*" {
				return true
			}
			d = normalizeDomainName(d)
			if d == "" {
				continue
			}
			if domain == d || strings.HasSuffix(domain, "."+d) {
				return true
			}
		}
	}
	return false
}
