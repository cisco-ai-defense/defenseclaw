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
	"runtime"
	"strings"
	"sync/atomic"
	"testing"
	"time"
)

// Public-looking addresses the fake interface lists assign to this machine.
const (
	ownV4 = "9.9.9.9"
	ownV6 = "2620:fe::fe"
)

func ipNet(s string) net.Addr {
	ip := net.ParseIP(s)
	bits := 128
	if ip.To4() != nil {
		bits = 32
	}
	return &net.IPNet{IP: ip, Mask: net.CIDRMask(bits/2, bits)}
}

// fixedLocalAddrs is a localAddrs whose interfaces hold exactly addrs.
func fixedLocalAddrs(addrs ...string) *localAddrs {
	list := make([]net.Addr, 0, len(addrs))
	for _, a := range addrs {
		list = append(list, ipNet(a))
	}
	return newLocalAddrs(func() ([]net.Addr, error) { return list, nil })
}

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

func isCategory(err error, c Category) bool {
	var de *dialError
	return errors.As(err, &de) && de.category == c
}

// dialOK dials host with rules and fails unless the dial succeeds.
func dialOK(t *testing.T, g *guardDialer, host string, rules dialRules) netip.AddrPort {
	t.Helper()
	conn, remote, err := g.dial(context.Background(), host, 443, rules)
	if err != nil {
		t.Fatalf("dial(%s) = %v, want success", host, err)
	}
	_ = conn.Close()
	return remote
}

// TestGuardDialSSRFMatrix: the dialer must only ever be handed public
// literals, and any prohibited answer refuses the whole destination.
func TestGuardDialSSRFMatrix(t *testing.T) {
	g, r, d := newTestGuard(t)
	type want struct {
		category Category
		status   int
	}
	ok, private, host, unreachable := want{}, want{CategoryPrivateNetwork, http.StatusForbidden},
		want{CategoryHostInternal, http.StatusForbidden}, want{"", http.StatusBadGateway}
	tests := map[string]struct {
		answers []string // nil: a literal, or a name without an answer
		want    want
	}{
		"public.example": {[]string{publicV4}, ok}, "public6.example": {[]string{publicV6}, ok},
		"dual.example": {[]string{publicV4, publicV6}, ok}, publicV4: {nil, ok}, publicV6: {nil, ok},
		"mixed.example":     {[]string{publicV4, "10.0.0.1"}, private},
		"mixed-rev.example": {[]string{"192.168.1.10", publicV4}, private},
		"mixed6.example":    {[]string{publicV6, "fd00::1"}, private},
		"private.example":   {[]string{"172.16.0.9"}, private},
		"cgnat.example":     {[]string{"100.64.1.1"}, private},
		"mapped.example":    {[]string{"::ffff:10.0.0.1"}, private},
		"10.0.0.1":          {nil, private},
		"loop.example":      {[]string{"127.0.0.1"}, host},
		"loop6.example":     {[]string{"::1"}, host},
		"meta.example":      {[]string{"169.254.169.254"}, host},
		"meta6.example":     {[]string{"fd00:ec2::254"}, host},
		"alibaba.example":   {[]string{"100.100.100.200"}, host},
		"linklocal.example": {[]string{"fe80::1"}, host},
		"nat64.example":     {[]string{"64:ff9b::a00:1"}, host},
		"sixtofour.example": {[]string{"2002:a00:1::1"}, host},
		"bench.example":     {[]string{"198.18.0.2"}, host},
		"zero.example":      {[]string{"0.0.0.0"}, host},
		"multicast.example": {[]string{"239.1.2.3"}, host},
		"::1":               {nil, host},
		// This machine's own public addresses, as literals and in any answer.
		ownV4: {nil, host}, ownV6: {nil, host},
		"own.example":        {[]string{ownV4}, host},
		"own6.example":       {[]string{ownV6}, host},
		"own-mixed.example":  {[]string{publicV4, ownV6}, host},
		"own-mapped.example": {[]string{"::ffff:" + ownV4}, host},
		// Other hosts on this machine's public subnets (2620:fe::/64 and
		// 9.9.0.0/16 in the fake interface list).
		"lan-device.example": {[]string{"2620:fe::1"}, private},
		"lan4.example":       {[]string{"9.9.200.1"}, private},
		"lan-mixed.example":  {[]string{publicV6, "2620:fe::abcd"}, private},
		"2620:fe::1":         {nil, private},
		"empty.example":      {[]string{}, unreachable},
		"broken.example":     {nil, unreachable}, // SERVFAIL
		"nxdomain.example":   {nil, unreachable},
	}
	for name, tt := range tests {
		if tt.answers != nil {
			r.set(name, tt.answers)
		}
	}
	r.fail("broken.example", errors.New("SERVFAIL"))
	for name, tt := range tests {
		conn, remote, err := g.dial(context.Background(), name, 443, dialRules{})
		if tt.want == ok {
			if err != nil || isPrivateTarget(remote.String()) || conn.RemoteAddr().String() != remote.String() {
				t.Errorf("dial(%s) = %v, connected to %s; want success to a public address", name, err, remote)
			} else {
				_ = conn.Close()
			}
			continue
		}
		var de *dialError
		if !errors.As(err, &de) || de.category != tt.want.category || de.status != tt.want.status {
			t.Errorf("dial(%s) = %v (%+v), want %+v", name, err, de, tt.want)
		} else if strings.Contains(de.Error(), "10.") || strings.Contains(de.Error(), "SERVFAIL") {
			t.Errorf("dial(%s) error leaks resolver detail: %q", name, de.Error())
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
	if remote := dialOK(t, g, "rebind.example", dialRules{}); remote.Addr().String() != publicV4 {
		t.Fatalf("first dial connected to %v", remote)
	}
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

func TestGuardDialFamilyFallback(t *testing.T) {
	g, r, d := newTestGuard(t)
	r.set("dual.example", []string{publicV6, publicV4})
	d.fail[publicV6] = errors.New("network is unreachable")
	if remote := dialOK(t, g, "dual.example", dialRules{}); remote.Addr().String() != publicV4 {
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
	_, _, err := g.dial(context.Background(), "v4only.example", 443, dialRules{})
	if de := (*dialError)(nil); !errors.As(err, &de) || de.status != http.StatusBadGateway || de.category != "" {
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
	if de := (*dialError)(nil); !errors.As(err, &de) || de.status != http.StatusGatewayTimeout || time.Since(start) > 2*time.Second {
		t.Fatalf("dial = %v after %v, want a prompt 504 timeout", err, time.Since(start))
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
	dialOK(t, g, "ci.build", dialRules{})
	dialOK(t, g, "ci.build.", dialRules{})
	if got := r.names(); len(got) != 2 || got[0] != "ci.build." || got[1] != "ci.build." {
		t.Errorf("resolver asked for %q, want the rooted name twice", got)
	}
}

// An operator allow rule opens private answers at dial time: an exact name
// every private address it resolves to, an intranet wildcard (*.corp) those
// of the names it covers, an IP or CIDR the private addresses it covers when
// it is no wider than their range. A wildcard under a public domain opens
// only public answers: names under it are often not the operator's (a cloud
// provider's internal load balancer names resolve to private addresses).
// Nothing opens this machine, loopback or metadata, whatever the rule says.
// An operator CIDR block refuses a name resolving into it before the dial.
func TestGuardDialOperatorRules(t *testing.T) {
	g, r, d := newTestGuard(t)
	dec := mustDecider(t, DeciderOptions{Allow: []string{
		"artifactory.corp.example", "loop.corp.example", "meta.corp.example", "own.corp.example",
		"*.cloud.example", "*.corp", "192.168.7.0/24", "0.0.0.0/0",
	}})
	for host, answers := range map[string][]string{
		"artifactory.corp.example": {"10.1.2.3"}, "loop.corp.example": {"10.1.2.3", "127.0.0.1"}, "meta.corp.example": {"169.254.169.254"},
		"own.corp.example": {ownV4}, "git.corp": {"10.1.2.3"}, "nas.example": {"192.168.7.7"}, "other.example": {"192.168.8.8"},
		"internal-lb.cloud.example": {"10.4.4.4"}, "cdn.cloud.example": {publicV4}, "office.cloud.example": {"192.168.7.8"},
	} {
		r.set(host, answers)
	}
	for host, category := range map[string]Category{ // empty: the dial succeeds
		"artifactory.corp.example": "", "git.corp": "", "nas.example": "", "192.168.7.7": "", "cdn.cloud.example": "",
		// The public-domain wildcard does not open the private answer; the
		// allow CIDR covering the address does.
		"internal-lb.cloud.example": CategoryPrivateNetwork, "office.cloud.example": "",
		"loop.corp.example": CategoryHostInternal, "meta.corp.example": CategoryHostInternal, "own.corp.example": CategoryHostInternal,
		"other.example": CategoryPrivateNetwork, "192.168.8.8": CategoryPrivateNetwork,
	} {
		rules := dec.dialRules(testPrincipal, Decision{Host: host})
		if category == "" {
			dialOK(t, g, host, rules)
		} else if _, _, err := g.dial(context.Background(), host, 443, rules); !isCategory(err, category) {
			t.Errorf("dial(%s) = %v, want %s", host, err, category)
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

	dialed := len(d.addresses())
	blocked := mustDecider(t, DeciderOptions{Block: []string{"8.8.8.0/24"}})
	_, _, err := g.dial(context.Background(), "cdn.cloud.example", 443, blocked.dialRules(testPrincipal, Decision{Host: "cdn.cloud.example"}))
	if de := (*dialError)(nil); !errors.As(err, &de) || de.category != CategoryOperatorBlock || de.rule != "8.8.8.0/24" ||
		de.status != http.StatusForbidden || len(d.addresses()) != dialed {
		t.Fatalf("dial into an operator CIDR block = %v (%+v); it must not reach the dialer", err, de)
	}
}

// testFeedCIDR is a blocklist feed whose only entry is a CIDR.
func testFeedCIDR(t *testing.T) *Feed {
	t.Helper()
	feed, err := ParseFeed([]byte("schema_version: 1\nkind: blocklist\nname: team\nfeed_version: \"7\"\nentries:\n" +
		"  - {name: Drop net, category: file_drop, hosts: [\"8.8.4.0/24\"]}\n"))
	must(t, err)
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
	must(t, err)
	dec := mustDecider(t, DeciderOptions{Blocklists: []*Feed{testFeedCIDR(t)}, Unblocks: unblocks})

	_, _, err = g.dial(context.Background(), "cdn.example", 443, dec.dialRules(testPrincipal, dec.Decide(testPrincipal, "cdn.example", 443)))
	var de *dialError
	if !errors.As(err, &de) || de.category != CategoryFileDrop || de.rule != "8.8.4.0/24" || de.feed == nil || de.status != http.StatusForbidden {
		t.Fatalf("dial into a feed CIDR = %v (%+v)", err, de)
	}
	if refused := dialRefusal(dec, Decision{Host: "cdn.example", Port: 443, Mode: ModeOpen}, de); refused.Source != SourceFeed ||
		refused.Feed != "team" || refused.FeedVersion != "7" || refused.Entry != "Drop net" || !refused.Unblockable ||
		!strings.Contains(refused.Reason, "blocklist") {
		t.Errorf("refusal = %+v", refused)
	}
	if n := len(d.addresses()); n != 0 {
		t.Errorf("a feed-blocked address reached the dialer %d times", n)
	}

	withAllow := mustDecider(t, DeciderOptions{Blocklists: []*Feed{testFeedCIDR(t)}, Allow: []string{"8.8.4.4"}})
	for _, rules := range []dialRules{
		dec.dialRules(testPrincipal, Decision{Host: "cdn.example", Source: SourceUnblock}),
		dec.dialRules(testPrincipal, Decision{Host: "cdn.example", Source: SourceOperator}),
		dec.dialRules(Principal{BindingID: "b-2", SandboxID: "sb-2"}, Decision{Host: "cdn.example", Source: SourceDefault}),
		withAllow.dialRules(testPrincipal, Decision{Host: "cdn.example", Source: SourceDefault}),
	} {
		dialOK(t, g, "cdn.example", rules)
	}
	dialOK(t, g, "clean.example", dec.dialRules(testPrincipal, Decision{Host: "clean.example"}))
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
	must(t, err)
	dec := mustDecider(t, DeciderOptions{Mode: ModeAllowlist, Allowlists: []*Feed{}, Unblocks: unblocks})
	decision := dec.Decide(testPrincipal, "cdn.example", 443)
	if !decision.Allowed || decision.Source != SourceUnblock {
		t.Fatalf("decision = %+v, want allowed by the unblock", decision)
	}
	if _, _, err := g.dial(context.Background(), "cdn.example", 443, dec.dialRules(testPrincipal, decision)); !isCategory(err, CategoryPrivateNetwork) {
		t.Fatalf("unblocked name resolving to a private address = %v, want a private-network refusal", err)
	}
	allowed := mustDecider(t, DeciderOptions{Mode: ModeAllowlist, Allowlists: []*Feed{}, Allow: []string{"cdn.example"}})
	dialOK(t, g, "cdn.example", allowed.dialRules(testPrincipal, allowed.Decide(testPrincipal, "cdn.example", 443)))
}

func TestLocalAddrsRefresh(t *testing.T) {
	now := time.Unix(1_700_000_000, 0)
	var ifaces []net.Addr
	var listErr error
	calls := 0
	l := newLocalAddrs(func() ([]net.Addr, error) { calls++; return ifaces, listErr })
	l.now = func() time.Time { return now }
	own := func(s string) bool {
		isOwn, _ := l.lookup(netip.MustParseAddr(s))
		return isOwn
	}
	ifaces = []net.Addr{ipNet("127.0.0.1"), ipNet(ownV4), &net.IPAddr{IP: net.ParseIP(ownV6), Zone: "eth0"}, &net.UnixAddr{Name: "x"}}
	if !own(ownV4) || !own(ownV6) || !own("::ffff:"+ownV4) || !own(ownV6+"%eth0") || !own("127.0.0.1") {
		t.Fatal("interface addresses not recognized")
	}
	if isOwn, subnet := l.lookup(netip.Addr{}); own(publicV4) || isOwn || subnet.IsValid() {
		t.Fatal("a foreign address was recognized")
	}
	if calls != 1 {
		t.Fatalf("interfaces listed %d times within the refresh interval, want 1", calls)
	}

	// A new address is picked up by the first miss once the list is a
	// second old, and a miss does not refresh more often than that.
	ifaces = []net.Addr{ipNet(ownV4), ipNet(publicV4)}
	if own(publicV4) {
		t.Fatal("miss refreshed before localAddrsMissRefresh")
	}
	now = now.Add(localAddrsMissRefresh)
	if !own(publicV4) || calls != 2 {
		t.Fatalf("added address not picked up (calls %d)", calls)
	}

	// Hits keep the list until it is localAddrsMaxAge old; then a removed
	// address stops matching.
	ifaces = []net.Addr{ipNet(ownV4)}
	now = now.Add(localAddrsMaxAge - time.Millisecond)
	if !own(publicV4) {
		t.Fatal("hit refreshed before localAddrsMaxAge")
	}
	now = now.Add(time.Millisecond)
	if own(publicV4) {
		t.Fatal("removed address still recognized after localAddrsMaxAge")
	}

	// A listing error keeps the previous list and waits a full interval
	// before trying again.
	ifaces, listErr = nil, errors.New("netlink: no buffer space")
	now = now.Add(localAddrsMaxAge)
	before := calls
	if !own(ownV4) || calls != before+1 {
		t.Fatal("a failed refresh dropped the known addresses")
	}
	if own(publicV4Alt) || calls != before+1 {
		t.Fatal("a failed refresh was retried immediately")
	}

	var none *localAddrs
	if isOwn, subnet := none.lookup(netip.MustParseAddr(ownV4)); isOwn || subnet.IsValid() {
		t.Error("nil localAddrs matched")
	}
}

// The public subnets of the interface addresses are this machine's local
// network: at least the /64 of a global IPv6 address, whatever its interface
// prefix says, and the interface prefix of a public IPv4 address. Private,
// loopback and link-local interfaces add nothing (their ranges are refused
// anyway), and neither do single addresses.
func TestLocalAddrsSubnets(t *testing.T) {
	cidr := func(s string) net.Addr {
		ip, n, err := net.ParseCIDR(s)
		must(t, err)
		n.IP = ip
		return n
	}
	l := newLocalAddrs(func() ([]net.Addr, error) {
		return []net.Addr{
			cidr("127.0.0.1/8"), cidr("::1/128"), cidr("fe80::1/64"), cidr("192.168.1.5/24"), cidr("fd00:1::5/64"),
			cidr("2620:fe::fe/64"),          // SLAAC
			cidr("2600:1f18:aa:bb::10/128"), // DHCPv6, as on EC2: the link is still the /64
			cidr("2a01:4f8:1:2::3/48"),      // an interface prefix wider than the /64
			cidr("203.0.114.9/24"),          // a public IPv4 LAN
			cidr("45.1.2.3/32"),             // a point-to-point address: no neighbours
			cidr("11.0.0.1/4"),              // not a link
			// An IPv4 address with a 16-byte /24 mask, as some platforms report.
			&net.IPNet{IP: net.ParseIP("198.51.99.7"), Mask: net.CIDRMask(120, 128)},
			&net.IPAddr{IP: net.ParseIP("2001:470:1:2::5")}, // no mask: the /64
		}, nil
	})
	for addr, want := range map[string]string{ // "own": an own address; "": neither own nor on a subnet
		"2620:fe::fe": "own", "45.1.2.3": "own",
		"2620:fe::1": "2620:fe::/64", "2620:fe::ffff:1": "2620:fe::/64", "2600:1f18:aa:bb::1": "2600:1f18:aa:bb::/64",
		"2a01:4f8:1:9::1": "2a01:4f8:1::/48", "203.0.114.1": "203.0.114.0/24", "::ffff:203.0.114.200": "203.0.114.0/24",
		"198.51.99.1": "198.51.99.0/24", "2001:470:1:2::1": "2001:470:1:2::/64",
		"2620:fe:0:1::1": "", "203.0.115.1": "", "45.1.2.4": "", "11.0.0.2": "", "192.168.1.7": "", "fd00:1::7": "",
		publicV4: "", publicV6: "",
	} {
		own, subnet := l.lookup(netip.MustParseAddr(addr))
		got := ""
		switch {
		case own && !subnet.IsValid():
			got = "own"
		case subnet.IsValid():
			got = subnet.String()
		}
		if got != want {
			t.Errorf("lookup(%s) = %v, %v; want %q", addr, own, subnet, want)
		}
	}
}

// addrConn reports a chosen local address.
type addrConn struct {
	net.Conn
	local net.Addr
}

func (c addrConn) LocalAddr() net.Addr { return c.local }

func TestSelfConnected(t *testing.T) {
	tcp := func(s string) net.Addr { return net.TCPAddrFromAddrPort(netip.MustParseAddrPort(s)) }
	for _, tt := range []struct {
		local  net.Addr
		dialed string
		want   bool
	}{
		{tcp(ownV4 + ":50000"), ownV4, true},
		{tcp("[::ffff:" + ownV4 + "]:50000"), ownV4, true},
		{tcp("[" + ownV6 + "]:50000"), ownV6, true},
		{tcp("10.0.1.16:50000"), publicV4, false},
		{tcp("[2001:db8::5]:50000"), ownV6, false},
		{&net.UnixAddr{Name: "sock"}, ownV4, false},
	} {
		if got := selfConnected(addrConn{local: tt.local}, netip.MustParseAddr(tt.dialed)); got != tt.want {
			t.Errorf("selfConnected(local %v, dialed %s) = %v", tt.local, tt.dialed, got)
		}
	}
}

// TestSelfConnectedKernel checks the kernel behaviour selfConnected relies
// on: a connection to one of this machine's non-loopback addresses gets that
// address as its local end. It also checks the real interface listing.
func TestSelfConnectedKernel(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("listening on a non-loopback address can prompt the macOS and Windows firewalls")
	}
	list, err := net.InterfaceAddrs()
	must(t, err)
	var target netip.Addr
	addrs, _ := interfaceAddrSet(list)
	for addr := range addrs {
		if !addr.IsLoopback() && !addr.IsLinkLocalUnicast() && addr.Is4() {
			target = addr
			break
		}
	}
	if !target.IsValid() {
		t.Skip("no non-loopback IPv4 interface address")
	}
	if own, _ := hostAddrs.lookup(target); !own {
		t.Fatalf("hostAddrs does not list interface address %s", target)
	}
	ln, err := net.ListenTCP("tcp", net.TCPAddrFromAddrPort(netip.AddrPortFrom(target, 0)))
	if err != nil {
		t.Skipf("listen on %s: %v", target, err)
	}
	defer ln.Close()
	conn, err := net.DialTimeout("tcp", ln.Addr().String(), 5*time.Second)
	must(t, err)
	defer conn.Close()
	if !selfConnected(conn, target) {
		t.Errorf("connection to own address %s has local end %s", target, conn.LocalAddr())
	}
}

// TestLocalReach pins how a directly opened range (an OpenShell rule's
// allowed_ips) relates to this machine: one that holds an own address
// reaches it, one that overlaps a public on-link subnet reaches its local
// network, and an IPv4-mapped range is judged as the IPv4 range. The test
// hook other packages use to fix this machine's addresses restores the real
// source.
func TestLocalReach(t *testing.T) {
	d := mustDecider(t, DeciderOptions{})
	d.local = fixedLocalAddrs(ownV4, ownV6)
	for prefix, want := range map[string]string{ // "own": reaches an own address; "": neither
		ownV4 + "/32": "own", "9.0.0.0/8": "own", "::ffff:" + ownV4 + "/128": "own", ownV6 + "/128": "own", "2620::/16": "own",
		"9.9.200.0/24": "9.9.0.0/16", "9.9.0.1/32": "9.9.0.0/16", "2620:fe::1/128": "2620:fe::/64", "2620:fe::1:0/112": "2620:fe::/64",
		"9.10.0.0/16": "", "2620:fe:0:1::/64": "", "8.8.8.8/32": "",
	} {
		own, subnet := d.LocalReach(netip.MustParsePrefix(prefix))
		got := ""
		switch {
		case own && !subnet.IsValid():
			got = "own"
		case subnet.IsValid():
			got = subnet.String()
		}
		if got != want {
			t.Errorf("LocalReach(%s) = %v %v, want %q", prefix, own, subnet, want)
		}
	}
	if own, subnet := d.LocalReach(netip.Prefix{}); own || subnet.IsValid() {
		t.Fatal("an invalid prefix reached this machine")
	}

	restore := OverrideInterfaceAddrsForTest(func() ([]net.Addr, error) { return []net.Addr{ipNet(ownV4)}, nil })
	if own, _ := mustDecider(t, DeciderOptions{}).LocalReach(netip.MustParsePrefix(ownV4 + "/32")); !own {
		t.Fatal("the overridden address is not this machine's")
	}
	restore()
	if own, _ := mustDecider(t, DeciderOptions{}).LocalReach(netip.MustParsePrefix(ownV4 + "/32")); own {
		t.Fatal("the override outlived its restore")
	}
}
