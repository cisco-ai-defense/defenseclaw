// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package egress

import (
	"context"
	"errors"
	"net"
	"net/http"
	"net/netip"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/netguard"
)

// Resolver resolves destination names on the proxy side; *net.Resolver
// satisfies it.
type Resolver = netguard.V8Resolver

// Dialer opens the upstream TCP connection to an already-validated address
// literal; *net.Dialer satisfies it.
type Dialer = netguard.V8Dialer

// dialError is a classified upstream dial failure. Its text is bounded and
// never contains resolver or socket details, so it is safe to return to the
// sandbox and to put in events.
type dialError struct {
	// category is set for policy refusals (host_internal, private_network,
	// operator_block, or a blocklist feed's category); empty for plain
	// failures.
	category Category
	status   int
	reason   string
	rule     string
	// feed is the blocklist feed entry whose IP or CIDR pattern covers the
	// resolved address.
	feed *FeedMatch
	// retry marks connection failures worth one attempt on the other
	// address family.
	retry bool
	err   error
}

func (e *dialError) Error() string { return e.reason }
func (e *dialError) Unwrap() error { return e.err }

// errRefusedAddr stops netguard when a dial hook refused an address; the
// hook's dialError is what the dial returns.
var errRefusedAddr = errors.New("egress: resolved address refused")

// guardDialer dials upstreams through netguard's guarded dialer.
type guardDialer struct {
	resolver Resolver
	dialer   Dialer
	timeout  time.Duration
	// local is this machine's own addresses; nil checks none.
	local *localAddrs
}

// dialRules carry a decider's address rules for one decided destination to
// the checks of its literal or of every address its name resolves to. The
// zero value applies the guard alone.
type dialRules struct {
	d *Decider
	p Principal
	// nameAllowed reports an operator allow rule covering the destination
	// name: the private addresses it resolves to are open.
	nameAllowed bool
	// feeds applies the blocklist feeds' IP and CIDR entries to the address;
	// off when an unblock or an operator allow rule admitted the
	// destination, which lifts the feeds as it does in Decide.
	feeds bool
}

// dialRules returns the dial-time rules for p's destination that Decide
// allowed as dec.
func (d *Decider) dialRules(p Principal, dec Decision) dialRules {
	r := dialRules{d: d, p: p, feeds: dec.Source != SourceUnblock && dec.Source != SourceOperator}
	if _, err := netip.ParseAddr(dec.Host); err != nil {
		_, r.nameAllowed = d.allow.match(dec.Host, netip.Addr{})
	}
	return r
}

// mayOpenPrivate reports whether any private address can be open, which
// needs the netguard policy that admits private ranges.
func (r dialRules) mayOpenPrivate() bool {
	return r.nameAllowed || (r.d != nil && len(r.d.allow.prefixes) > 0)
}

// guard applies the address guard to one address: this machine and what
// only it can reach are refused, private addresses unless an operator allow
// rule opened them.
func (r dialRules) guard(addr netip.Addr, local *localAddrs) *dialError {
	v := classifyAddr(addr, local)
	switch v.class {
	case guardHost:
		return &dialError{category: CategoryHostInternal, status: http.StatusForbidden, reason: "the destination resolves to " + v.what}
	case guardPrivate:
		if r.nameAllowed {
			return nil
		}
		if r.d != nil {
			if _, ok := r.d.allowsPrivate("", addr.Unmap(), v.scope); ok {
				return nil
			}
		}
		return &dialError{category: CategoryPrivateNetwork, status: http.StatusForbidden, reason: "the destination resolves to " + v.what}
	}
	return nil
}

// check applies every address rule to the address about to be dialed, in
// Decide's order for an IP literal: the guard, the operator's CIDR blocks,
// then the blocklist feeds' IP and CIDR entries unless an unblock or an
// operator allow rule covers the address. Feeds match names only against
// name patterns, so without this a feed CIDR would never apply to a name.
func (r dialRules) check(addr netip.Addr, local *localAddrs) *dialError {
	if de := r.guard(addr, local); de != nil {
		return de
	}
	if r.d == nil {
		return nil
	}
	addr = addr.Unmap()
	if item, ok := r.d.block.match("", addr); ok {
		return &dialError{
			category: CategoryOperatorBlock, status: http.StatusForbidden, rule: item.pattern,
			reason: "the destination resolves to an address the operator blocked",
		}
	}
	if !r.feeds {
		return nil
	}
	m, ok := matchFeeds(r.d.blocklists, "", addr)
	if !ok || r.addrLifted(addr) {
		return nil
	}
	return &dialError{
		category: m.Entry.Category, status: http.StatusForbidden, rule: m.Pattern, feed: &m,
		reason: "the destination resolves to an address the " + m.Feed.Name + " blocklist lists (" + m.Entry.Name + ")",
	}
}

// addrLifted reports an unblock or operator allow rule covering addr.
func (r dialRules) addrLifted(addr netip.Addr) bool {
	if _, ok := r.d.allow.match("", addr); ok {
		return true
	}
	if r.d.unblocks == nil {
		return false
	}
	_, ok := r.d.unblocks.Unblocked(r.p, addr.String())
	return ok
}

// dialerFunc adapts a function to Dialer.
type dialerFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (f dialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

// resolverFunc adapts a function to Resolver.
type resolverFunc func(ctx context.Context, host string) ([]net.IPAddr, error)

func (f resolverFunc) LookupIPAddr(ctx context.Context, host string) ([]net.IPAddr, error) {
	return f(ctx, host)
}

// dial connects to host:port. netguard resolves the name immediately before
// connecting, refuses the whole destination when any answer is prohibited,
// and hands the dialer the validated literal, so a rebinding resolver cannot
// swap the address between check and connect. The guard runs on every
// answer first: this machine's own addresses and what only it can reach are
// refused, and private addresses (RFC 1918, CGNAT, ULA, the other hosts on
// its public subnets) unless an operator allow rule opened them. Operator
// CIDR blocks are checked against the literal, and a connection that turns
// out to lead back to this machine is closed before any byte is relayed.
// When a name's first address fails to connect, one more attempt targets
// the other address family (broken IPv6 is common); that attempt resolves
// and validates again.
func (g *guardDialer) dial(ctx context.Context, host string, port int, rules dialRules) (net.Conn, netip.AddrPort, error) {
	literal, notLiteral := netip.ParseAddr(host)
	if notLiteral == nil {
		// netguard would refuse a private literal itself, before the dial
		// hook could tell which kind of address it is.
		if de := rules.check(literal, g.local); de != nil {
			return nil, netip.AddrPortFrom(literal.Unmap(), uint16(port)), de
		}
	}
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, remote, err := g.attempt(ctx, "tcp", address, rules)
	if err == nil {
		return conn, remote, nil
	}
	var de *dialError
	if notLiteral == nil || !errors.As(err, &de) || !de.retry || !remote.IsValid() || ctx.Err() != nil {
		return nil, remote, err
	}
	other := "tcp6"
	if remote.Addr().Is6() {
		other = "tcp4"
	}
	conn, remote2, err2 := g.attempt(ctx, other, address, rules)
	if err2 == nil {
		return conn, remote2, nil
	}
	var de2 *dialError
	if errors.As(err2, &de2) && de2.category != "" {
		return nil, remote2, err2
	}
	return nil, remote, err
}

func (g *guardDialer) attempt(ctx context.Context, network, address string, rules dialRules) (net.Conn, netip.AddrPort, error) {
	var (
		selected netip.AddrPort
		refused  *dialError
	)
	refuse := func(de *dialError) error {
		refused = de
		return errRefusedAddr
	}
	resolve := resolverFunc(func(ctx context.Context, host string) ([]net.IPAddr, error) {
		ips, err := g.resolver.LookupIPAddr(ctx, rootedName(host))
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if addr, ok := netip.AddrFromSlice(ip.IP); ok {
				if de := rules.guard(addr, g.local); de != nil {
					return nil, refuse(de)
				}
			}
		}
		return ips, nil
	})
	record := dialerFunc(func(ctx context.Context, network, literal string) (net.Conn, error) {
		selected, _ = netip.ParseAddrPort(literal)
		addr := selected.Addr().Unmap()
		if de := rules.check(addr, g.local); de != nil {
			return nil, refuse(de)
		}
		conn, err := g.dialer.DialContext(ctx, network, literal)
		if err == nil && selfConnected(conn, addr) {
			_ = conn.Close()
			return nil, refuse(&dialError{
				category: CategoryHostInternal, status: http.StatusForbidden,
				reason: "the destination is an address of this machine",
			})
		}
		return conn, err
	})
	policy := guardPolicy
	if rules.mayOpenPrivate() {
		policy = openPolicy
	}
	dctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	conn, err := netguard.V8SafeDialContext(policy, record, resolve)(dctx, network, address)
	if err == nil {
		return &dialedConn{Conn: conn, remote: selected}, selected, nil
	}
	if refused != nil {
		refused.err = err
		return nil, selected, refused
	}
	switch {
	case errors.Is(err, netguard.ErrV8AddressProhibited):
		return nil, selected, &dialError{
			category: CategoryHostInternal, status: http.StatusForbidden,
			reason: "the destination resolves to " + reservedWhat, err: err,
		}
	case errors.Is(err, netguard.ErrV8EndpointInvalid):
		return nil, selected, &dialError{
			category: CategoryInvalidDestination, status: http.StatusBadRequest,
			reason: "the destination is not a valid host and port", err: err,
		}
	case errors.Is(err, netguard.ErrV8ResolutionFailed):
		return nil, selected, &dialError{status: http.StatusBadGateway, reason: "DNS resolution failed", err: err}
	case ctx.Err() != nil:
		return nil, selected, &dialError{status: http.StatusBadGateway, reason: "the request was canceled", err: err}
	case errors.Is(err, context.DeadlineExceeded):
		return nil, selected, &dialError{status: http.StatusGatewayTimeout, reason: "connecting to the destination timed out", retry: true, err: err}
	default:
		return nil, selected, &dialError{status: http.StatusBadGateway, reason: "connecting to the destination failed", retry: true, err: err}
	}
}

// rootedName makes a destination name fully qualified. Decisions work on
// names without the trailing dot, but a resolver treats such a name as
// relative: it tries the host's DNS search domains (glibc and Go when the
// name has fewer dots than ndots, and after it fails to resolve), so
// "ci.build" could reach ci.build.<search domain> on the internal network.
func rootedName(host string) string {
	if strings.HasSuffix(host, ".") {
		return host
	}
	return host + "."
}

// dialedConn reports the validated address as its remote address (the
// Dialer may be a test double that maps public literals to local listeners)
// and keeps half-close available.
type dialedConn struct {
	net.Conn
	remote netip.AddrPort
}

func (c *dialedConn) RemoteAddr() net.Addr {
	if !c.remote.IsValid() {
		return c.Conn.RemoteAddr()
	}
	return net.TCPAddrFromAddrPort(c.remote)
}

func (c *dialedConn) CloseWrite() error { return closeWrite(c.Conn) }

// closeWrite half-closes conn. TCP and TLS connections support it; for any
// other conn it is a no-op and the idle timeout ends the tunnel.
func closeWrite(conn net.Conn) error {
	if cw, ok := conn.(interface{ CloseWrite() error }); ok {
		return cw.CloseWrite()
	}
	return nil
}
