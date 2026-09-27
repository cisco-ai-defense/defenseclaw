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
	// category is set for policy refusals (private_network,
	// operator_block); empty for plain failures.
	category Category
	status   int
	reason   string
	rule     string
	// retry marks connection failures worth one attempt on the other
	// address family.
	retry bool
	err   error
}

func (e *dialError) Error() string { return e.reason }
func (e *dialError) Unwrap() error { return e.err }

var (
	errOperatorBlockedAddr = errors.New("egress: resolved address blocked by operator rule")
	errOwnAddr             = errors.New("egress: destination is an address of this machine")
)

// guardDialer dials upstreams through netguard's guarded dialer.
type guardDialer struct {
	resolver Resolver
	dialer   Dialer
	timeout  time.Duration
	// local is this machine's own addresses; nil checks none.
	local *localAddrs
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
// swap the address between check and connect. A name with any answer that
// is one of this machine's own addresses is refused like one with a private
// answer; operator CIDR blocks are checked against the literal, and a
// connection that turns out to lead back to this machine is closed before
// any byte is relayed. When a name's first address fails to
// connect, one more attempt targets the other address family (broken IPv6
// is common); that attempt resolves and validates again.
func (g *guardDialer) dial(ctx context.Context, host string, port int, block *hostSet[struct{}]) (net.Conn, netip.AddrPort, error) {
	address := net.JoinHostPort(host, strconv.Itoa(port))
	conn, remote, err := g.attempt(ctx, "tcp", address, block)
	if err == nil {
		return conn, remote, nil
	}
	var de *dialError
	_, notLiteral := netip.ParseAddr(host)
	if notLiteral == nil || !errors.As(err, &de) || !de.retry || !remote.IsValid() || ctx.Err() != nil {
		return nil, remote, err
	}
	other := "tcp6"
	if remote.Addr().Is6() {
		other = "tcp4"
	}
	conn, remote2, err2 := g.attempt(ctx, other, address, block)
	if err2 == nil {
		return conn, remote2, nil
	}
	var de2 *dialError
	if errors.As(err2, &de2) && de2.category != "" {
		return nil, remote2, err2
	}
	return nil, remote, err
}

func (g *guardDialer) attempt(ctx context.Context, network, address string, block *hostSet[struct{}]) (net.Conn, netip.AddrPort, error) {
	var (
		selected  netip.AddrPort
		blockedBy string
		own       bool
	)
	resolve := resolverFunc(func(ctx context.Context, host string) ([]net.IPAddr, error) {
		ips, err := g.resolver.LookupIPAddr(ctx, rootedName(host))
		if err != nil {
			return nil, err
		}
		for _, ip := range ips {
			if addr, ok := netip.AddrFromSlice(ip.IP); ok && g.local.contains(addr) {
				own = true
				return nil, errOwnAddr
			}
		}
		return ips, nil
	})
	record := dialerFunc(func(ctx context.Context, network, literal string) (net.Conn, error) {
		selected, _ = netip.ParseAddrPort(literal)
		addr := selected.Addr().Unmap()
		if g.local.contains(addr) {
			own = true
			return nil, errOwnAddr
		}
		if block != nil {
			if item, ok := block.match("", addr); ok {
				blockedBy = item.pattern
				return nil, errOperatorBlockedAddr
			}
		}
		conn, err := g.dialer.DialContext(ctx, network, literal)
		if err == nil && selfConnected(conn, addr) {
			_ = conn.Close()
			own = true
			return nil, errOwnAddr
		}
		return conn, err
	})
	dctx, cancel := context.WithTimeout(ctx, g.timeout)
	defer cancel()
	conn, err := netguard.V8SafeDialContext(guardPolicy, record, resolve)(dctx, network, address)
	if err == nil {
		return &dialedConn{Conn: conn, remote: selected}, selected, nil
	}
	switch {
	case own:
		return nil, selected, &dialError{
			category: CategoryPrivateNetwork, status: http.StatusForbidden,
			reason: "the destination is an address of this machine", err: err,
		}
	case blockedBy != "":
		return nil, selected, &dialError{
			category: CategoryOperatorBlock, status: http.StatusForbidden, rule: blockedBy,
			reason: "the destination resolves to an address the operator blocked", err: err,
		}
	case errors.Is(err, netguard.ErrV8AddressProhibited):
		return nil, selected, &dialError{
			category: CategoryPrivateNetwork, status: http.StatusForbidden,
			reason: "the destination resolves to a private, loopback, link-local, carrier-grade NAT, metadata or reserved address", err: err,
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
