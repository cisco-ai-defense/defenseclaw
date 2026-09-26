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
	own := func(s string) bool { return l.contains(netip.MustParseAddr(s)) }

	if !own(ownV4) || !own(ownV6) || !own("::ffff:"+ownV4) || !own(ownV6+"%eth0") || !own("127.0.0.1") {
		t.Fatal("interface addresses not recognized")
	}
	if own(publicV4) || l.contains(netip.Addr{}) {
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
	if none.contains(netip.MustParseAddr(ownV4)) {
		t.Error("nil localAddrs matched")
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
	for addr := range interfaceAddrSet(list) {
		if !addr.IsLoopback() && !addr.IsLinkLocalUnicast() && addr.Is4() {
			target = addr
			break
		}
	}
	if !target.IsValid() {
		t.Skip("no non-loopback IPv4 interface address")
	}
	if !hostAddrs.contains(target) {
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
