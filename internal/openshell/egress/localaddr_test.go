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
	"errors"
	"net"
	"net/netip"
	"runtime"
	"sync"
	"testing"
	"time"
)

// Public-looking addresses the fake interface lists assign to this machine.
const (
	ownV4 = "9.9.9.9"
	ownV6 = "2620:fe::fe"
)

// fakeInterfaces is a mutable interface address list with a manual clock.
type fakeInterfaces struct {
	mu    sync.Mutex
	addrs []net.Addr
	err   error
	calls int
	now   time.Time
}

func (f *fakeInterfaces) set(err error, addrs ...net.Addr) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.addrs, f.err = addrs, err
}

func (f *fakeInterfaces) list() ([]net.Addr, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return f.addrs, f.err
}

func (f *fakeInterfaces) advance(d time.Duration) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.now = f.now.Add(d)
}

func (f *fakeInterfaces) clock() time.Time {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.now
}

func (f *fakeInterfaces) callCount() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.calls
}

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

func TestLocalAddrsRefresh(t *testing.T) {
	f := &fakeInterfaces{now: time.Unix(1_700_000_000, 0)}
	f.set(nil, ipNet("127.0.0.1"), ipNet(ownV4), &net.IPAddr{IP: net.ParseIP(ownV6), Zone: "eth0"}, &net.UnixAddr{Name: "x"})
	l := newLocalAddrs(f.list)
	l.now = f.clock
	own := func(s string) bool {
		isOwn, _ := l.lookup(netip.MustParseAddr(s))
		return isOwn
	}

	if !own(ownV4) || !own(ownV6) || !own("::ffff:"+ownV4) || !own(ownV6+"%eth0") || !own("127.0.0.1") {
		t.Fatal("interface addresses not recognized")
	}
	if isOwn, subnet := l.lookup(netip.Addr{}); own(publicV4) || isOwn || subnet.IsValid() {
		t.Fatal("a foreign address was recognized")
	}
	if n := f.callCount(); n != 1 {
		t.Fatalf("interfaces listed %d times within the refresh interval, want 1", n)
	}

	// A new address is picked up by the first miss once the list is a
	// second old, and a miss does not refresh more often than that.
	f.set(nil, ipNet(ownV4), ipNet(publicV4))
	if own(publicV4) {
		t.Fatal("miss refreshed before localAddrsMissRefresh")
	}
	f.advance(localAddrsMissRefresh)
	if !own(publicV4) || f.callCount() != 2 {
		t.Fatalf("added address not picked up (calls %d)", f.callCount())
	}

	// Hits keep the list until it is localAddrsMaxAge old; then a removed
	// address stops matching.
	f.set(nil, ipNet(ownV4))
	f.advance(localAddrsMaxAge - time.Millisecond)
	if !own(publicV4) {
		t.Fatal("hit refreshed before localAddrsMaxAge")
	}
	f.advance(time.Millisecond)
	if own(publicV4) {
		t.Fatal("removed address still recognized after localAddrsMaxAge")
	}

	// A listing error keeps the previous list and waits a full interval
	// before trying again.
	f.set(errors.New("netlink: no buffer space"))
	f.advance(localAddrsMaxAge)
	calls := f.callCount()
	if !own(ownV4) || f.callCount() != calls+1 {
		t.Fatal("a failed refresh dropped the known addresses")
	}
	if own(publicV4Alt) || f.callCount() != calls+1 {
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
		if err != nil {
			t.Fatal(err)
		}
		n.IP = ip
		return n
	}
	// An IPv4 address with a 16-byte /24 mask, as some platforms report.
	v4mask16 := &net.IPNet{IP: net.ParseIP("198.51.99.7"), Mask: net.CIDRMask(120, 128)}
	l := newLocalAddrs(func() ([]net.Addr, error) {
		return []net.Addr{
			cidr("127.0.0.1/8"), cidr("::1/128"), cidr("fe80::1/64"), cidr("192.168.1.5/24"), cidr("fd00:1::5/64"),
			cidr("2620:fe::fe/64"),          // SLAAC
			cidr("2600:1f18:aa:bb::10/128"), // DHCPv6, as on EC2: the link is still the /64
			cidr("2a01:4f8:1:2::3/48"),      // an interface prefix wider than the /64
			cidr("203.0.114.9/24"),          // a public IPv4 LAN
			cidr("45.1.2.3/32"),             // a point-to-point address: no neighbours
			cidr("11.0.0.1/4"),              // not a link
			v4mask16,
			&net.IPAddr{IP: net.ParseIP("2001:470:1:2::5")}, // no mask: the /64
		}, nil
	})
	tests := []struct {
		addr   string
		own    bool
		subnet string
	}{
		{"2620:fe::fe", true, ""},
		{"2620:fe::1", false, "2620:fe::/64"},
		{"2620:fe::ffff:1", false, "2620:fe::/64"},
		{"2620:fe:0:1::1", false, ""},
		{"2600:1f18:aa:bb::1", false, "2600:1f18:aa:bb::/64"},
		{"2a01:4f8:1:9::1", false, "2a01:4f8:1::/48"},
		{"203.0.114.1", false, "203.0.114.0/24"},
		{"::ffff:203.0.114.200", false, "203.0.114.0/24"},
		{"203.0.115.1", false, ""},
		{"45.1.2.3", true, ""},
		{"45.1.2.4", false, ""},
		{"11.0.0.2", false, ""},
		{"198.51.99.1", false, "198.51.99.0/24"},
		{"2001:470:1:2::1", false, "2001:470:1:2::/64"},
		{"192.168.1.7", false, ""},
		{"fd00:1::7", false, ""},
		{publicV4, false, ""},
		{publicV6, false, ""},
	}
	for _, tt := range tests {
		own, subnet := l.lookup(netip.MustParseAddr(tt.addr))
		got := ""
		if subnet.IsValid() {
			got = subnet.String()
		}
		if own != tt.own || got != tt.subnet {
			t.Errorf("lookup(%s) = %v, %q; want %v, %q", tt.addr, own, got, tt.own, tt.subnet)
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
	tests := []struct {
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
	}
	for _, tt := range tests {
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
	if err != nil {
		t.Fatal(err)
	}
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
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close()
	if !selfConnected(conn, target) {
		t.Errorf("connection to own address %s has local end %s", target, conn.LocalAddr())
	}
}

// TestLocalReach pins how a directly opened range (an OpenShell rule's
// allowed_ips) relates to this machine: one that holds an own address
// reaches it, one that overlaps a public on-link subnet reaches its local
// network, and an IPv4-mapped range is judged as the IPv4 range.
func TestLocalReach(t *testing.T) {
	d := mustDecider(t, DeciderOptions{})
	d.local = fixedLocalAddrs(ownV4, ownV6)
	for _, tc := range []struct {
		prefix string
		own    bool
		subnet string
	}{
		{ownV4 + "/32", true, ""},
		{"9.0.0.0/8", true, ""},
		{"::ffff:" + ownV4 + "/128", true, ""},
		{ownV6 + "/128", true, ""},
		{"2620::/16", true, ""},
		{"9.9.200.0/24", false, "9.9.0.0/16"},
		{"9.9.0.1/32", false, "9.9.0.0/16"},
		{"2620:fe::1/128", false, "2620:fe::/64"},
		{"2620:fe::1:0/112", false, "2620:fe::/64"},
		{"9.10.0.0/16", false, ""},
		{"2620:fe:0:1::/64", false, ""},
		{"8.8.8.8/32", false, ""},
	} {
		t.Run(tc.prefix, func(t *testing.T) {
			own, subnet := d.LocalReach(netip.MustParsePrefix(tc.prefix))
			got := ""
			if subnet.IsValid() {
				got = subnet.String()
			}
			if own != tc.own || got != tc.subnet {
				t.Fatalf("LocalReach(%s) = %v %q, want %v %q", tc.prefix, own, got, tc.own, tc.subnet)
			}
		})
	}
	if own, subnet := d.LocalReach(netip.Prefix{}); own || subnet.IsValid() {
		t.Fatal("an invalid prefix reached this machine")
	}
}

// TestOverrideInterfaceAddrsForTest pins the test hook other packages use
// to fix this machine's addresses, and that it restores the real source.
func TestOverrideInterfaceAddrsForTest(t *testing.T) {
	restore := OverrideInterfaceAddrsForTest(func() ([]net.Addr, error) { return []net.Addr{ipNet(ownV4)}, nil })
	d := mustDecider(t, DeciderOptions{})
	if own, _ := d.LocalReach(netip.MustParsePrefix(ownV4 + "/32")); !own {
		t.Fatal("the overridden address is not this machine's")
	}
	restore()
	if own, _ := d.LocalReach(netip.MustParsePrefix(ownV4 + "/32")); own {
		t.Fatal("the override outlived its restore")
	}
}
