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
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

func newTestGuard(t *testing.T) (*guardDialer, *fakeResolver, *mapDialer) {
	t.Helper()
	r, d := newFakeResolver(), newMapDialer()
	d.route(443, startEcho(t))
	d.route(80, startEcho(t))
	return &guardDialer{resolver: r, dialer: d, timeout: 2 * time.Second, local: fixedLocalAddrs(ownV4, ownV6)}, r, d
}

// isPrivateTarget reports addresses the dialer must never be handed: the
// guard policy's ranges and the fake interface lists' own addresses and
// on-link subnets.
func isPrivateTarget(addr string) bool {
	ap, err := netip.ParseAddrPort(addr)
	if err != nil {
		return true
	}
	if own, subnet := fixedLocalAddrs(ownV4, ownV6).lookup(ap.Addr()); own || subnet.IsValid() {
		return true
	}
	return guardPolicy.ValidateIP(net.IP(ap.Addr().AsSlice())) != nil
}

// TestGuardDialSSRFMatrix: the dialer must only ever be handed public
// literals, and any prohibited answer refuses the whole destination.
func TestGuardDialSSRFMatrix(t *testing.T) {
	g, r, d := newTestGuard(t)
	answers := map[string][]string{
		"public.example":     {publicV4},
		"public6.example":    {publicV6},
		"dual.example":       {publicV4, publicV6},
		"mixed.example":      {publicV4, "10.0.0.1"},
		"mixed-rev.example":  {"192.168.1.10", publicV4},
		"mixed6.example":     {publicV6, "fd00::1"},
		"private.example":    {"172.16.0.9"},
		"loop.example":       {"127.0.0.1"},
		"loop6.example":      {"::1"},
		"meta.example":       {"169.254.169.254"},
		"meta6.example":      {"fd00:ec2::254"},
		"alibaba.example":    {"100.100.100.200"},
		"cgnat.example":      {"100.64.1.1"},
		"linklocal.example":  {"fe80::1"},
		"mapped.example":     {"::ffff:10.0.0.1"},
		"nat64.example":      {"64:ff9b::a00:1"},
		"sixtofour.example":  {"2002:a00:1::1"},
		"bench.example":      {"198.18.0.2"},
		"zero.example":       {"0.0.0.0"},
		"multicast.example":  {"239.1.2.3"},
		"own.example":        {ownV4},
		"own6.example":       {ownV6},
		"own-mixed.example":  {publicV4, ownV6},
		"own-mapped.example": {"::ffff:" + ownV4},
		// Other hosts on this machine's public subnets (2620:fe::/64 and
		// 9.9.0.0/16 in the fake interface list).
		"lan-device.example": {"2620:fe::1"},
		"lan4.example":       {"9.9.200.1"},
		"lan-mixed.example":  {publicV6, "2620:fe::abcd"},
		"empty.example":      {},
	}
	for host, ips := range answers {
		r.set(host, ips)
	}
	r.fail("broken.example", errors.New("SERVFAIL"))

	tests := []struct {
		host     string
		category Category
		status   int
	}{
		{host: "public.example"},
		{host: "public6.example"},
		{host: "dual.example"},
		{host: publicV4},
		{host: publicV6},
		{host: "mixed.example", category: CategoryPrivateNetwork, status: http.StatusForbidden},
		{host: "mixed-rev.example", category: CategoryPrivateNetwork, status: http.StatusForbidden},
		{host: "mixed6.example", category: CategoryPrivateNetwork, status: http.StatusForbidden},
		{host: "private.example", category: CategoryPrivateNetwork, status: http.StatusForbidden},
		{host: "loop.example", category: CategoryHostInternal, status: http.StatusForbidden},
		{host: "loop6.example", category: CategoryHostInternal, status: http.StatusForbidden},
		{host: "meta.example", category: CategoryHostInternal, status: http.StatusForbidden},
		{host: "meta6.example", category: CategoryHostInternal, status: http.StatusForbidden},
		{host: "alibaba.example", category: CategoryHostInternal, status: http.StatusForbidden},
		{host: "cgnat.example", category: CategoryPrivateNetwork, status: http.StatusForbidden},
		{host: "linklocal.example", category: CategoryHostInternal, status: http.StatusForbidden},
		{host: "mapped.example", category: CategoryPrivateNetwork, status: http.StatusForbidden},
		{host: "nat64.example", category: CategoryHostInternal, status: http.StatusForbidden},
		{host: "sixtofour.example", category: CategoryHostInternal, status: http.StatusForbidden},
		{host: "bench.example", category: CategoryHostInternal, status: http.StatusForbidden},
		{host: "zero.example", category: CategoryHostInternal, status: http.StatusForbidden},
		{host: "multicast.example", category: CategoryHostInternal, status: http.StatusForbidden},
		{host: "10.0.0.1", category: CategoryPrivateNetwork, status: http.StatusForbidden},
		{host: "::1", category: CategoryHostInternal, status: http.StatusForbidden},
		// This machine's own public addresses, as literals and in any answer.
		{host: ownV4, category: CategoryHostInternal, status: http.StatusForbidden},
		{host: ownV6, category: CategoryHostInternal, status: http.StatusForbidden},
		{host: "own.example", category: CategoryHostInternal, status: http.StatusForbidden},
		{host: "own6.example", category: CategoryHostInternal, status: http.StatusForbidden},
		{host: "own-mixed.example", category: CategoryHostInternal, status: http.StatusForbidden},
		{host: "own-mapped.example", category: CategoryHostInternal, status: http.StatusForbidden},
		{host: "lan-device.example", category: CategoryPrivateNetwork, status: http.StatusForbidden},
		{host: "lan4.example", category: CategoryPrivateNetwork, status: http.StatusForbidden},
		{host: "lan-mixed.example", category: CategoryPrivateNetwork, status: http.StatusForbidden},
		{host: "2620:fe::1", category: CategoryPrivateNetwork, status: http.StatusForbidden},
		{host: "empty.example", status: http.StatusBadGateway},
		{host: "broken.example", status: http.StatusBadGateway},
		{host: "nxdomain.example", status: http.StatusBadGateway},
	}
	for _, tt := range tests {
		conn, remote, err := g.dial(context.Background(), tt.host, 443, dialRules{})
		if tt.status == 0 {
			if err != nil {
				t.Errorf("dial(%s) = %v, want success", tt.host, err)
				continue
			}
			if isPrivateTarget(remote.String()) || conn.RemoteAddr().String() != remote.String() {
				t.Errorf("dial(%s) connected to %s (conn reports %s)", tt.host, remote, conn.RemoteAddr())
			}
			_ = conn.Close()
			continue
		}
		var de *dialError
		if !errors.As(err, &de) || de.category != tt.category || de.status != tt.status {
			t.Errorf("dial(%s) = %v (%+v), want category %q status %d", tt.host, err, de, tt.category, tt.status)
			continue
		}
		if strings.Contains(de.Error(), "10.") || strings.Contains(de.Error(), "SERVFAIL") {
			t.Errorf("dial(%s) error leaks resolver detail: %q", tt.host, de.Error())
		}
	}
	for _, addr := range d.addresses() {
		if isPrivateTarget(addr) {
			t.Errorf("dialer was handed prohibited address %s", addr)
		}
	}
	if r.callCount("10.0.0.1") != 0 {
		t.Error("an IP literal was sent to the resolver")
	}
}

// TestGuardDialRebinding: every connection resolves and validates afresh
// and connects to the literal it validated, so an answer that flips
// between lookups is caught on the lookup that returns it and can never be
// dialed.
func TestGuardDialRebinding(t *testing.T) {
	g, r, d := newTestGuard(t)
	r.set("rebind.example", []string{publicV4}, []string{"127.0.0.1"})
	r.set("rebind-back.example", []string{"10.9.9.9"}, []string{publicV4})

	conn, remote, err := g.dial(context.Background(), "rebind.example", 443, dialRules{})
	if err != nil || remote.Addr().String() != publicV4 {
		t.Fatalf("first dial = %v, %v", remote, err)
	}
	_ = conn.Close()
	if _, _, err := g.dial(context.Background(), "rebind.example", 443, dialRules{}); !isCategory(err, CategoryHostInternal) {
		t.Fatalf("second dial after rebinding = %v, want host_internal", err)
	}
	if _, _, err := g.dial(context.Background(), "rebind-back.example", 443, dialRules{}); !isCategory(err, CategoryPrivateNetwork) {
		t.Fatalf("private-first answer = %v, want private_network", err)
	}
	if r.callCount("rebind.example") != 2 {
		t.Errorf("resolver called %d times for two dials", r.callCount("rebind.example"))
	}
	for _, addr := range d.addresses() {
		if isPrivateTarget(addr) {
			t.Errorf("dialer was handed prohibited address %s", addr)
		}
	}
}

// selfDialer connects like mapDialer but reports the dialed address as the
// local end, which is what the kernel does for a connection to one of this
// machine's own addresses.
type selfDialer struct {
	*mapDialer
	closed atomic.Int32
}

type closeCountingConn struct {
	addrConn
	closed *atomic.Int32
}

func (c closeCountingConn) Close() error {
	c.closed.Add(1)
	return c.Conn.Close()
}

func (d *selfDialer) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	conn, err := d.mapDialer.DialContext(ctx, network, address)
	if err != nil {
		return nil, err
	}
	local := net.TCPAddrFromAddrPort(netip.AddrPortFrom(netip.MustParseAddrPort(address).Addr(), 50000))
	return closeCountingConn{addrConn: addrConn{Conn: conn, local: local}, closed: &d.closed}, nil
}

// TestGuardDialSelfConnection: an own address the interface list does not
// know yet is still refused once the connection shows it leads back to this
// machine, and that connection is closed without being handed out.
func TestGuardDialSelfConnection(t *testing.T) {
	g, r, d := newTestGuard(t)
	sd := &selfDialer{mapDialer: d}
	g.dialer = sd
	r.set("new-own.example", []string{publicV4Alt})
	for _, host := range []string{publicV4Alt, "new-own.example"} {
		conn, _, err := g.dial(context.Background(), host, 443, dialRules{})
		var de *dialError
		if !errors.As(err, &de) || de.category != CategoryHostInternal || de.status != http.StatusForbidden {
			t.Fatalf("dial(%s) = %v, %v; want a host_internal refusal", host, conn, err)
		}
	}
	if n := sd.closed.Load(); n != 2 {
		t.Errorf("%d of 2 self-connections closed", n)
	}
}

func isCategory(err error, c Category) bool {
	var de *dialError
	return errors.As(err, &de) && de.category == c
}

func TestGuardDialOperatorCIDRBlock(t *testing.T) {
	g, r, d := newTestGuard(t)
	r.set("cdn.example", []string{publicV4})
	d2, err := NewDecider(DeciderOptions{Block: []string{"8.8.8.0/24"}})
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = g.dial(context.Background(), "cdn.example", 443, d2.dialRules(testPrincipal, Decision{Host: "cdn.example"}))
	var de *dialError
	if !errors.As(err, &de) || de.category != CategoryOperatorBlock || de.rule != "8.8.8.0/24" || de.status != http.StatusForbidden {
		t.Fatalf("dial = %v (%+v)", err, de)
	}
	if n := len(d.addresses()); n != 0 {
		t.Errorf("blocked address reached the dialer %d times", n)
	}
}

func TestGuardDialFamilyFallback(t *testing.T) {
	g, r, d := newTestGuard(t)
	r.set("dual.example", []string{publicV6, publicV4})
	d.fail[publicV6] = errors.New("network is unreachable")
	conn, remote, err := g.dial(context.Background(), "dual.example", 443, dialRules{})
	if err != nil {
		t.Fatalf("dial = %v", err)
	}
	_ = conn.Close()
	if remote.Addr().String() != publicV4 {
		t.Errorf("fell back to %s", remote)
	}
	if got := d.addresses(); len(got) != 2 || !strings.Contains(got[0], publicV6) {
		t.Errorf("attempts = %v", got)
	}

	// No fallback for literals, and a single-family name fails with the
	// original error.
	d.fail[publicV4] = errors.New("refused")
	if _, _, err := g.dial(context.Background(), publicV4, 443, dialRules{}); err == nil || isCategory(err, CategoryHostInternal) {
		t.Errorf("literal dial = %v", err)
	}
	r.set("v4only.example", []string{publicV4})
	_, _, err = g.dial(context.Background(), "v4only.example", 443, dialRules{})
	var de *dialError
	if !errors.As(err, &de) || de.status != http.StatusBadGateway || de.category != "" {
		t.Errorf("single-family failure = %v", err)
	}
}

func TestGuardDialTimeout(t *testing.T) {
	g, r, d := newTestGuard(t)
	g.timeout = 50 * time.Millisecond
	r.set("slow.example", []string{publicV4})
	d.hang[publicV4] = true
	start := time.Now()
	_, _, err := g.dial(context.Background(), "slow.example", 443, dialRules{})
	var de *dialError
	if !errors.As(err, &de) || de.status != http.StatusGatewayTimeout {
		t.Fatalf("dial = %v, want a 504 timeout", err)
	}
	if elapsed := time.Since(start); elapsed > 2*time.Second {
		t.Errorf("timeout took %v", elapsed)
	}

	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if _, _, err := g.dial(ctx, "slow.example", 443, dialRules{}); err == nil {
		t.Error("canceled dial succeeded")
	}
}

// Names are resolved fully qualified, so the host's DNS search domains never
// turn a public-looking name such as ci.build into an internal machine
// (ci.build.<search domain>). Decisions keep the name without the dot.
func TestGuardDialResolvesRootedNames(t *testing.T) {
	g, r, _ := newTestGuard(t)
	r.set("ci.build", []string{publicV4})
	for _, host := range []string{"ci.build", "ci.build."} {
		conn, _, err := g.dial(context.Background(), host, 443, dialRules{})
		if err != nil {
			t.Fatalf("dial(%s) = %v", host, err)
		}
		_ = conn.Close()
	}
	if got := r.names(); len(got) != 2 || got[0] != "ci.build." || got[1] != "ci.build." {
		t.Errorf("resolver asked for %q, want the rooted name twice", got)
	}
	if got := rootedName("example.com"); got != "example.com." {
		t.Errorf("rootedName = %q", got)
	}
}

// An operator allow rule opens private answers at dial time: an exact name
// every private address it resolves to, an intranet wildcard (*.corp) those
// of the names it covers, an IP or CIDR the private addresses it covers when
// it is no wider than their range. A wildcard under a public domain opens
// only public answers: names under it are often not the operator's (a cloud
// provider's internal load balancer names resolve to private addresses).
// Nothing opens this machine, loopback or metadata, whatever the rule says.
func TestGuardDialOperatorOpensPrivate(t *testing.T) {
	g, r, d := newTestGuard(t)
	dec, err := NewDecider(DeciderOptions{Allow: []string{
		"artifactory.corp.example", "loop.corp.example", "meta.corp.example", "own.corp.example",
		"*.cloud.example", "*.corp", "192.168.7.0/24", "0.0.0.0/0",
	}})
	if err != nil {
		t.Fatal(err)
	}
	r.set("artifactory.corp.example", []string{"10.1.2.3"})
	r.set("loop.corp.example", []string{"10.1.2.3", "127.0.0.1"})
	r.set("meta.corp.example", []string{"169.254.169.254"})
	r.set("own.corp.example", []string{ownV4})
	r.set("git.corp", []string{"10.1.2.3"})
	r.set("nas.example", []string{"192.168.7.7"})
	r.set("other.example", []string{"192.168.8.8"})
	r.set("internal-lb.cloud.example", []string{"10.4.4.4"})
	r.set("cdn.cloud.example", []string{publicV4})
	r.set("office.cloud.example", []string{"192.168.7.8"})
	tests := []struct {
		host     string
		category Category // empty: the dial succeeds
	}{
		{host: "artifactory.corp.example"},
		{host: "git.corp"},
		{host: "nas.example"},
		{host: "192.168.7.7"},
		{host: "cdn.cloud.example"},
		// The public-domain wildcard does not open the private answer; the
		// allow CIDR covering the address does.
		{host: "internal-lb.cloud.example", category: CategoryPrivateNetwork},
		{host: "office.cloud.example"},
		{host: "loop.corp.example", category: CategoryHostInternal},
		{host: "meta.corp.example", category: CategoryHostInternal},
		{host: "own.corp.example", category: CategoryHostInternal},
		{host: "other.example", category: CategoryPrivateNetwork},
		{host: "192.168.8.8", category: CategoryPrivateNetwork},
	}
	for _, tt := range tests {
		conn, _, err := g.dial(context.Background(), tt.host, 443, dec.dialRules(testPrincipal, Decision{Host: tt.host}))
		if tt.category == "" {
			if err != nil {
				t.Errorf("dial(%s) = %v, want success", tt.host, err)
				continue
			}
			_ = conn.Close()
			continue
		}
		if !isCategory(err, tt.category) {
			t.Errorf("dial(%s) = %v, want %s", tt.host, err, tt.category)
		}
	}
	for _, addr := range d.addresses() {
		switch netip.MustParseAddrPort(addr).Addr().String() {
		case "10.1.2.3", "192.168.7.7", "192.168.7.8", publicV4:
		default:
			t.Errorf("dialer was handed %s", addr)
		}
	}
	// Without the rules the same answers are refused.
	if _, _, err := g.dial(context.Background(), "artifactory.corp.example", 443, dialRules{}); !isCategory(err, CategoryPrivateNetwork) {
		t.Errorf("dial without rules = %v", err)
	}
}

// testFeedCIDR is a blocklist feed whose only entry is a CIDR.
func testFeedCIDR(t *testing.T) *Feed {
	t.Helper()
	feed, err := ParseFeed([]byte("schema_version: 1\nkind: blocklist\nname: team\nfeed_version: \"7\"\nentries:\n" +
		"  - {name: Drop net, category: file_drop, hosts: [\"8.8.4.0/24\"]}\n"))
	if err != nil {
		t.Fatal(err)
	}
	return feed
}

// A blocklist feed's IP and CIDR entries apply to the address a name
// resolves to, not only to IP-literal destinations; an unblock or operator
// allow of the name, or of the address, lifts them as in Decide.
func TestGuardDialFeedCIDRs(t *testing.T) {
	g, r, d := newTestGuard(t)
	r.set("cdn.example", []string{publicV4Alt})
	r.set("clean.example", []string{publicV4})
	unblocks, err := NewMemoryUnblocks(Unblock{Pattern: publicV4Alt, SandboxID: "sb-2"})
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewDecider(DeciderOptions{Blocklists: []*Feed{testFeedCIDR(t)}, Unblocks: unblocks})
	if err != nil {
		t.Fatal(err)
	}

	_, _, err = g.dial(context.Background(), "cdn.example", 443, dec.dialRules(testPrincipal, dec.Decide(testPrincipal, "cdn.example", 443)))
	var de *dialError
	if !errors.As(err, &de) || de.category != CategoryFileDrop || de.rule != "8.8.4.0/24" || de.feed == nil || de.status != http.StatusForbidden {
		t.Fatalf("dial into a feed CIDR = %v (%+v)", err, de)
	}
	refused := dialRefusal(dec, Decision{Host: "cdn.example", Port: 443, Mode: ModeOpen}, de)
	if refused.Source != SourceFeed || refused.Feed != "team" || refused.FeedVersion != "7" || refused.Entry != "Drop net" ||
		!refused.Unblockable || !strings.Contains(refused.Reason, "blocklist") {
		t.Errorf("refusal = %+v", refused)
	}
	if n := len(d.addresses()); n != 0 {
		t.Errorf("a feed-blocked address reached the dialer %d times", n)
	}

	lifted := []dialRules{
		dec.dialRules(testPrincipal, Decision{Host: "cdn.example", Source: SourceUnblock}),
		dec.dialRules(testPrincipal, Decision{Host: "cdn.example", Source: SourceOperator}),
		dec.dialRules(Principal{BindingID: "b-2", SandboxID: "sb-2"}, Decision{Host: "cdn.example", Source: SourceDefault}),
	}
	withAllow, err := NewDecider(DeciderOptions{Blocklists: []*Feed{testFeedCIDR(t)}, Allow: []string{"8.8.4.4"}})
	if err != nil {
		t.Fatal(err)
	}
	lifted = append(lifted, withAllow.dialRules(testPrincipal, Decision{Host: "cdn.example", Source: SourceDefault}))
	for i, rules := range lifted {
		conn, _, err := g.dial(context.Background(), "cdn.example", 443, rules)
		if err != nil {
			t.Errorf("lifted dial %d = %v", i, err)
			continue
		}
		_ = conn.Close()
	}
	conn, _, err := g.dial(context.Background(), "clean.example", 443, dec.dialRules(testPrincipal, Decision{Host: "clean.example"}))
	if err != nil {
		t.Fatalf("dial outside the feed CIDR = %v", err)
	}
	_ = conn.Close()
}

// An unblock of a name (the sandbox manager's "always" decisions) lifts
// blocklist and allowlist refusals only: the private addresses the name
// resolves to stay closed, so a DNS answer the name's owner controls cannot
// reach the user's network. Only an operator allow entry for the exact name
// opens them.
func TestGuardDialUnblockKeepsPrivateAddressesClosed(t *testing.T) {
	g, r, _ := newTestGuard(t)
	r.set("cdn.example", []string{"10.0.0.7"})
	unblocks, err := NewMemoryUnblocks(Unblock{Pattern: "cdn.example"})
	if err != nil {
		t.Fatal(err)
	}
	dec, err := NewDecider(DeciderOptions{Mode: ModeAllowlist, Allowlists: []*Feed{}, Unblocks: unblocks})
	if err != nil {
		t.Fatal(err)
	}
	decision := dec.Decide(testPrincipal, "cdn.example", 443)
	if !decision.Allowed || decision.Source != SourceUnblock {
		t.Fatalf("decision = %+v, want allowed by the unblock", decision)
	}
	_, _, err = g.dial(context.Background(), "cdn.example", 443, dec.dialRules(testPrincipal, decision))
	var de *dialError
	if !errors.As(err, &de) || de.category != CategoryPrivateNetwork {
		t.Fatalf("unblocked name resolving to a private address = %v, want a private-network refusal", err)
	}

	allowed, err := NewDecider(DeciderOptions{Mode: ModeAllowlist, Allowlists: []*Feed{}, Allow: []string{"cdn.example"}})
	if err != nil {
		t.Fatal(err)
	}
	conn, _, err := g.dial(context.Background(), "cdn.example", 443, allowed.dialRules(testPrincipal, allowed.Decide(testPrincipal, "cdn.example", 443)))
	if err != nil {
		t.Fatalf("operator allow of the name = %v", err)
	}
	_ = conn.Close()
}
