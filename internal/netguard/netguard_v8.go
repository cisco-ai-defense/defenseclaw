// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     https://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

package netguard

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// V8 network-safety errors are deliberately bounded and contain neither the
// configured endpoint nor resolver, dialer, or response text. Exporters may
// safely use errors.Is to turn them into bounded platform.health reason codes.
var (
	ErrV8EndpointInvalid   = errors.New("netguard: invalid v8 push endpoint")
	ErrV8AddressProhibited = errors.New("netguard: v8 push address is prohibited")
	ErrV8ResolutionFailed  = errors.New("netguard: v8 push resolution failed")
	ErrV8ConnectionFailed  = errors.New("netguard: v8 push connection failed")
	ErrV8RedirectBlocked   = errors.New("netguard: v8 push redirect blocked")
)

// V8NetworkSafetyPolicy is the complete destination-scoped address policy for
// an observability-v8 push exporter. It intentionally has no package-global or
// environment-backed state.
//
// AllowPrivateNetworks permits loopback, RFC 1918, and IPv6 ULA addresses.
// AllowCGNAT independently permits RFC 6598 addresses. Neither option permits
// link-local, metadata/task-credential, unspecified, multicast, or reserved
// addresses.
type V8NetworkSafetyPolicy struct {
	AllowPrivateNetworks bool
	AllowCGNAT           bool
}

// V8Resolver is the resolver surface needed by v8 validation and guarded
// dialing. *net.Resolver satisfies this interface.
type V8Resolver interface {
	LookupIPAddr(context.Context, string) ([]net.IPAddr, error)
}

// V8Dialer is the dialer surface needed by v8 guarded dialing. *net.Dialer
// satisfies this interface.
type V8Dialer interface {
	DialContext(context.Context, string, string) (net.Conn, error)
}

var (
	v8CGNATPrefix = netip.MustParsePrefix("100.64.0.0/10")

	// These endpoints are permanently prohibited even when the containing
	// private or CGNAT range is explicitly allowed. The link-local entries are
	// redundant with the general link-local check by design: naming them here
	// prevents a future address-category refactor from weakening the metadata
	// invariant. Prefixes cover current cloud metadata and container/task
	// credential listener assignments.
	v8MetadataPrefixes = []netip.Prefix{
		netip.MustParsePrefix("169.254.169.254/32"),
		netip.MustParsePrefix("169.254.170.0/24"),
		netip.MustParsePrefix("100.100.100.200/32"),
		netip.MustParsePrefix("fd00:ec2::254/128"),
		netip.MustParsePrefix("fe80::a9fe:a9fe/128"),
	}

	// Special-purpose ranges that must never be exporter targets. Loopback,
	// RFC 1918, IPv6 ULA, and RFC 6598 are excluded because they have explicit,
	// independently-scoped policy above.
	v8ReservedPrefixes = []netip.Prefix{
		netip.MustParsePrefix("0.0.0.0/8"),
		netip.MustParsePrefix("192.0.0.0/24"),
		netip.MustParsePrefix("192.0.2.0/24"),
		netip.MustParsePrefix("192.88.99.0/24"),
		netip.MustParsePrefix("198.18.0.0/15"),
		netip.MustParsePrefix("198.51.100.0/24"),
		netip.MustParsePrefix("203.0.113.0/24"),
		netip.MustParsePrefix("240.0.0.0/4"),
		// Deprecated IPv4-compatible and both standardized IPv4/IPv6
		// translation prefixes can otherwise tunnel a prohibited IPv4 target
		// through an apparently public IPv6 literal.
		netip.MustParsePrefix("::/96"),
		netip.MustParsePrefix("64:ff9b::/96"),
		netip.MustParsePrefix("100::/64"),
		netip.MustParsePrefix("64:ff9b:1::/48"),
		netip.MustParsePrefix("2001::/23"),
		netip.MustParsePrefix("2001:db8::/32"),
		netip.MustParsePrefix("2002::/16"),
		netip.MustParsePrefix("3fff::/20"),
		netip.MustParsePrefix("5f00::/16"),
	}
)

// ValidateIP rejects an address that this destination may not contact.
func (p V8NetworkSafetyPolicy) ValidateIP(ip net.IP) error {
	addr, ok := netip.AddrFromSlice(ip)
	if !ok || !p.allowsAddr(addr.Unmap()) {
		return ErrV8AddressProhibited
	}
	return nil
}

func (p V8NetworkSafetyPolicy) allowsAddr(addr netip.Addr) bool {
	if !addr.IsValid() || addr.Zone() != "" {
		return false
	}
	addr = addr.Unmap()
	if prefixContains(v8MetadataPrefixes, addr) {
		return false
	}
	if addr.IsUnspecified() || addr.IsLinkLocalUnicast() ||
		addr.IsLinkLocalMulticast() || addr.IsInterfaceLocalMulticast() ||
		addr.IsMulticast() {
		return false
	}
	if v8CGNATPrefix.Contains(addr) {
		return p.AllowCGNAT
	}
	if addr.IsLoopback() || addr.IsPrivate() {
		return p.AllowPrivateNetworks
	}
	if prefixContains(v8ReservedPrefixes, addr) {
		return false
	}
	return true
}

func prefixContains(prefixes []netip.Prefix, addr netip.Addr) bool {
	for _, prefix := range prefixes {
		if prefix.Contains(addr) {
			return true
		}
	}
	return false
}

// ParseV8PushURL performs the offline portion of v8 push-endpoint validation.
// It performs no DNS or network I/O. Hostname resolution is deliberately left
// to ResolveV8PushURL at activation and V8SafeDialContext on every connection.
func ParseV8PushURL(raw string, policy V8NetworkSafetyPolicy) (*url.URL, error) {
	u, err := url.Parse(raw)
	if err != nil || u == nil {
		return nil, ErrV8EndpointInvalid
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return nil, ErrUnsupportedScheme
	}
	if err := RejectInlineCredentials(u); err != nil {
		return nil, err
	}
	host := u.Hostname()
	if host == "" || !validV8URLPort(u) {
		return nil, ErrV8EndpointInvalid
	}
	if addr, ok := parseV8Literal(host); ok {
		if !policy.allowsAddr(addr) {
			return nil, ErrV8AddressProhibited
		}
	}
	return u, nil
}

// ResolveV8PushURL performs activation-time guarded resolution. Every DNS
// answer must be allowed; mixed safe/unsafe answers fail the whole endpoint.
// A temporary resolution failure remains distinguishable from a prohibited
// address so the destination can degrade without accepting an unsafe graph.
func ResolveV8PushURL(ctx context.Context, u *url.URL, policy V8NetworkSafetyPolicy, resolver V8Resolver) error {
	if ctx == nil || u == nil {
		return ErrV8EndpointInvalid
	}
	if !strings.EqualFold(u.Scheme, "http") && !strings.EqualFold(u.Scheme, "https") {
		return ErrUnsupportedScheme
	}
	if err := RejectInlineCredentials(u); err != nil {
		return err
	}
	host := u.Hostname()
	if host == "" || !validV8URLPort(u) {
		return ErrV8EndpointInvalid
	}
	if addr, ok := parseV8Literal(host); ok {
		if !policy.allowsAddr(addr) {
			return ErrV8AddressProhibited
		}
		return nil
	}
	_, err := resolveV8(ctx, host, policy, resolver, "tcp")
	return err
}

// V8SafeDialContext returns a guarded dial function for one immutable
// destination policy. Hostnames are resolved and classified immediately before
// every connection, preventing validation-time DNS rebinding. The selected IP
// literal, rather than the hostname, is passed to the underlying dialer.
func V8SafeDialContext(policy V8NetworkSafetyPolicy, dialer V8Dialer, resolver V8Resolver) func(context.Context, string, string) (net.Conn, error) {
	if dialer == nil {
		dialer = &net.Dialer{Timeout: 10 * time.Second, KeepAlive: 30 * time.Second}
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	return func(ctx context.Context, network, address string) (net.Conn, error) {
		if ctx == nil {
			return nil, ErrV8EndpointInvalid
		}
		if network != "tcp" && network != "tcp4" && network != "tcp6" {
			return nil, ErrV8EndpointInvalid
		}
		host, port, err := net.SplitHostPort(address)
		if err != nil || host == "" || !validV8Port(port) {
			return nil, ErrV8EndpointInvalid
		}

		var selected netip.Addr
		if literal, ok := parseV8Literal(host); ok {
			if !policy.allowsAddr(literal) || !v8NetworkMatches(network, literal) {
				return nil, ErrV8AddressProhibited
			}
			selected = literal
		} else {
			selected, err = resolveV8(ctx, host, policy, resolver, network)
			if err != nil {
				return nil, err
			}
		}

		if err := ctx.Err(); err != nil {
			return nil, err
		}
		conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(selected.String(), port))
		if err != nil {
			if contextErr := boundedContextError(ctx, err); contextErr != nil {
				return nil, contextErr
			}
			return nil, ErrV8ConnectionFailed
		}
		if conn == nil {
			return nil, ErrV8ConnectionFailed
		}
		if err := ctx.Err(); err != nil {
			_ = conn.Close()
			return nil, err
		}
		return conn, nil
	}
}

func resolveV8(ctx context.Context, host string, policy V8NetworkSafetyPolicy, resolver V8Resolver, network string) (netip.Addr, error) {
	if ctx == nil {
		return netip.Addr{}, ErrV8EndpointInvalid
	}
	if err := ctx.Err(); err != nil {
		return netip.Addr{}, err
	}
	if resolver == nil {
		resolver = net.DefaultResolver
	}
	ips, err := resolver.LookupIPAddr(ctx, host)
	if err != nil {
		if contextErr := boundedContextError(ctx, err); contextErr != nil {
			return netip.Addr{}, contextErr
		}
		return netip.Addr{}, ErrV8ResolutionFailed
	}
	if err := ctx.Err(); err != nil {
		return netip.Addr{}, err
	}
	if len(ips) == 0 {
		return netip.Addr{}, ErrV8ResolutionFailed
	}

	var selected netip.Addr
	for _, candidate := range ips {
		addr, ok := netip.AddrFromSlice(candidate.IP)
		if !ok || !policy.allowsAddr(addr.Unmap()) {
			return netip.Addr{}, ErrV8AddressProhibited
		}
		addr = addr.Unmap()
		if !selected.IsValid() && v8NetworkMatches(network, addr) {
			selected = addr
		}
	}
	if !selected.IsValid() {
		return netip.Addr{}, ErrV8ResolutionFailed
	}
	return selected, nil
}

func parseV8Literal(host string) (netip.Addr, bool) {
	addr, err := netip.ParseAddr(host)
	if err != nil {
		return netip.Addr{}, false
	}
	return addr.Unmap(), true
}

func validV8Port(port string) bool {
	n, err := strconv.Atoi(port)
	return err == nil && n > 0 && n <= 65535
}

func validV8URLPort(u *url.URL) bool {
	if u == nil || strings.HasSuffix(u.Host, ":") {
		return false
	}
	port := u.Port()
	return port == "" || validV8Port(port)
}

func v8NetworkMatches(network string, addr netip.Addr) bool {
	switch network {
	case "tcp4":
		return addr.Is4()
	case "tcp6":
		return addr.Is6()
	default:
		return true
	}
}

func boundedContextError(ctx context.Context, err error) error {
	if ctx != nil && ctx.Err() != nil {
		return ctx.Err()
	}
	if errors.Is(err, context.Canceled) {
		return context.Canceled
	}
	if errors.Is(err, context.DeadlineExceeded) {
		return context.DeadlineExceeded
	}
	return nil
}

// BlockV8Redirects is the v8 http.Client redirect policy. It deliberately does
// not inspect or format the request or redirect history, so the returned error
// cannot echo either endpoint or response-controlled content.
func BlockV8Redirects(_ *http.Request, _ []*http.Request) error {
	return ErrV8RedirectBlocked
}
