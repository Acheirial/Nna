// Copyright (C) 2024  mieru authors
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
	"context"
	"fmt"
	"net"
	"net/netip"
	"strconv"
	"strings"
	"time"
)

// DNSResolver provides a way to look up IP addresses from host name.
type DNSResolver interface {
	LookupIP(ctx context.Context, network, host string) ([]net.IP, error)
}

// Standard library net.Resolver implements the DNSResolver interface.
var _ DNSResolver = (*net.Resolver)(nil)

// NilDNSResolver implements the DNSResolver interface but
// it is not able to look up IP addresses.
type NilDNSResolver struct{}

func (r NilDNSResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	return nil, fmt.Errorf("look up IP address of %s is not supported", host)
}

var _ DNSResolver = NilDNSResolver{}

// NormalizeDomainName canonicalizes a domain name for resolver lookups.
func NormalizeDomainName(host string) string {
	return strings.TrimSuffix(strings.ToLower(host), ".")
}

// HostMapResolver consults static host mappings before delegating to Resolver.
// It is not safe to modify this object after its first use.
type HostMapResolver struct {
	Resolver DNSResolver
	Hosts    map[string]net.IP
}

var _ DNSResolver = HostMapResolver{}

func (r HostMapResolver) LookupIP(ctx context.Context, network, host string) ([]net.IP, error) {
	ip, found := r.Hosts[NormalizeDomainName(host)]
	if found {
		switch network {
		case "", "ip":
			// Return a copy of net.IP object. Same below.
			return []net.IP{append(net.IP(nil), ip...)}, nil
		case "ip4":
			if ipv4 := ip.To4(); ipv4 != nil {
				return []net.IP{append(net.IP(nil), ipv4...)}, nil
			}
			return nil, nil
		case "ip6":
			if ipv4 := ip.To4(); ipv4 == nil {
				return []net.IP{append(net.IP(nil), ip.To16()...)}, nil
			}
			return nil, nil
		default:
			return nil, net.UnknownNetworkError(network)
		}
	}
	if r.Resolver == nil {
		return nil, fmt.Errorf("look up IP address of %s is not supported", host)
	}
	return r.Resolver.LookupIP(ctx, network, host)
}

// ClientDNSConfig provides DNS configurations used by proxy client.
type ClientDNSConfig struct {
	// If enabled, when creating a stream oriented network connection,
	// Resolver is not used. The proxy server endpoint is passed to Dialer as is.
	//
	// You may enable this when Dialer has an internal mechanism to resolve DNS.
	BypassDialerDNS bool
}

// defaultDNSResolveTimeout is the timeout applied to a DNS lookup when the
// caller provided a context without a deadline.
const defaultDNSResolveTimeout = 10 * time.Second

// withDNSResolveTimeout returns a context that is guaranteed to have a deadline.
// If ctx already has a deadline, ctx is returned as is. Otherwise
// defaultDNSResolveTimeout is applied so that the DNS lookup is bounded.
//
// The returned context.CancelFunc must be called to release resources.
func withDNSResolveTimeout(ctx context.Context) (context.Context, context.CancelFunc) {
	if _, ok := ctx.Deadline(); ok {
		return ctx, func() {}
	}
	return context.WithTimeout(ctx, defaultDNSResolveTimeout)
}

// sortIPs returns a new slice with IPv4 addresses placed before IPv6 addresses.
// The relative order of addresses within the same IP family is preserved.
func sortIPs(ips []net.IP) []net.IP {
	sorted := make([]net.IP, 0, len(ips))
	for _, ip := range ips {
		if ip.To4() != nil {
			sorted = append(sorted, ip)
		}
	}
	for _, ip := range ips {
		if ip.To4() == nil {
			sorted = append(sorted, ip)
		}
	}
	return sorted
}

// ResolveTCPAddrs returns all TCP addresses of the given network and address
// using the DNSResolver.
//
// If the host in address is a literal IP address, at most one address is
// returned. Otherwise all IP addresses returned by the DNSResolver are used,
// with IPv4 addresses placed before IPv6 addresses.
//
// If ctx has no deadline, a default timeout is applied to the DNS lookup.
func ResolveTCPAddrs(ctx context.Context, r DNSResolver, network, address string) ([]*net.TCPAddr, error) {
	dnsQueryNetwork := "ip"
	switch network {
	case "tcp":
	case "tcp4":
		dnsQueryNetwork = "ip4"
	case "tcp6":
		dnsQueryNetwork = "ip6"
	case "":
		network = "tcp"
	default:
		return nil, net.UnknownNetworkError(network)
	}

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	if host == "" {
		return []*net.TCPAddr{{Port: port}}, nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return []*net.TCPAddr{{IP: net.IP(ip.AsSlice()), Port: port, Zone: ip.Zone()}}, nil
	}

	ctx, cancel := withDNSResolveTimeout(ctx)
	defer cancel()
	ips, err := r.LookupIP(ctx, dnsQueryNetwork, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, &net.AddrError{Err: "IP address not found", Addr: address}
	}

	ips = sortIPs(ips)
	addrs := make([]*net.TCPAddr, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, &net.TCPAddr{IP: ip, Port: port})
	}
	return addrs, nil
}

// ResolveTCPAddr returns a TCP address using the DNSResolver.
// It returns the first TCP address resolved by ResolveTCPAddrs.
func ResolveTCPAddr(ctx context.Context, r DNSResolver, network, address string) (*net.TCPAddr, error) {
	addrs, err := ResolveTCPAddrs(ctx, r, network, address)
	if err != nil {
		return nil, err
	}
	return addrs[0], nil
}

// ResolveUDPAddrs returns all UDP addresses of the given network and address
// using the DNSResolver.
//
// If the host in address is a literal IP address, at most one address is
// returned. Otherwise all IP addresses returned by the DNSResolver are used,
// with IPv4 addresses placed before IPv6 addresses.
//
// If ctx has no deadline, a default timeout is applied to the DNS lookup.
func ResolveUDPAddrs(ctx context.Context, r DNSResolver, network, address string) ([]*net.UDPAddr, error) {
	dnsQueryNetwork := "ip"
	switch network {
	case "udp":
	case "udp4":
		dnsQueryNetwork = "ip4"
	case "udp6":
		dnsQueryNetwork = "ip6"
	case "":
		network = "udp"
	default:
		return nil, net.UnknownNetworkError(network)
	}

	host, portStr, err := net.SplitHostPort(address)
	if err != nil {
		return nil, err
	}
	port, err := strconv.Atoi(portStr)
	if err != nil {
		return nil, err
	}
	if host == "" {
		return []*net.UDPAddr{{Port: port}}, nil
	}
	if ip, err := netip.ParseAddr(host); err == nil {
		return []*net.UDPAddr{{IP: net.IP(ip.AsSlice()), Port: port, Zone: ip.Zone()}}, nil
	}

	ctx, cancel := withDNSResolveTimeout(ctx)
	defer cancel()
	ips, err := r.LookupIP(ctx, dnsQueryNetwork, host)
	if err != nil {
		return nil, err
	}
	if len(ips) == 0 {
		return nil, &net.AddrError{Err: "IP address not found", Addr: address}
	}

	ips = sortIPs(ips)
	addrs := make([]*net.UDPAddr, 0, len(ips))
	for _, ip := range ips {
		addrs = append(addrs, &net.UDPAddr{IP: ip, Port: port})
	}
	return addrs, nil
}

// ResolveUDPAddr returns a UDP address using the DNSResolver.
// It returns the first UDP address resolved by ResolveUDPAddrs.
func ResolveUDPAddr(ctx context.Context, r DNSResolver, network, address string) (*net.UDPAddr, error) {
	addrs, err := ResolveUDPAddrs(ctx, r, network, address)
	if err != nil {
		return nil, err
	}
	return addrs[0], nil
}
