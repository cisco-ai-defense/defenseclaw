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
	"net"
	"net/netip"
	"slices"
	"sync"
	"time"
)

// How stale the cached interface address list may get. A lookup that misses
// refreshes a list older than localAddrsMissRefresh, so an address added to an
// interface is refused within about a second; a hit refreshes a list older
// than localAddrsMaxAge, so a removed address stops being refused. Either way
// at most one interface dump runs per interval, however many dials check.
const (
	localAddrsMissRefresh = time.Second
	localAddrsMaxAge      = 30 * time.Second
)

// Bounds on the interface prefixes taken for on-link subnets. An IPv4
// prefix shorter than /8 is a misconfiguration, not a link, and is ignored;
// an IPv6 prefix longer than /64 (a /128 from DHCPv6, as on EC2) or shorter
// than /32 is taken as the /64 the link almost certainly is.
const (
	minSubnetBitsV4 = 8
	minSubnetBitsV6 = 32
	linkBitsV6      = 64
)

// localAddrs caches this machine's own interface addresses and the public
// subnets they sit on. The address policy refuses ranges, but a host with a
// global IPv6 or public IPv4 address on an interface (dual-stack home
// networks, VPS and bare-metal hosts) would otherwise let a sandbox CONNECT
// to that address and reach every host service listening on all interfaces,
// bypassing the loopback refusal and the --host-port consent flow; and the
// rest of that subnet is the local network (the router's admin page, a NAS,
// other VPC instances, containers on an IPv6 bridge), which is no more
// public than an RFC 1918 LAN.
type localAddrs struct {
	list func() ([]net.Addr, error)
	now  func() time.Time

	mu    sync.Mutex
	addrs map[netip.Addr]struct{}
	// subnets are the on-link prefixes of the public interface addresses.
	subnets []netip.Prefix
	loaded  time.Time
}

func newLocalAddrs(list func() ([]net.Addr, error)) *localAddrs {
	return &localAddrs{list: list, now: time.Now}
}

// hostAddrs is the process-wide view of this machine's addresses.
var hostAddrs = newLocalAddrs(net.InterfaceAddrs)

// lookup reports whether addr is assigned to one of this machine's
// interfaces (own), and otherwise the public on-link subnet of one of them
// that contains it, if any. When the interface list cannot be read the
// previous list is kept; the self-connection check at dial time still
// applies.
func (l *localAddrs) lookup(addr netip.Addr) (own bool, subnet netip.Prefix) {
	if l == nil || !addr.IsValid() {
		return false, netip.Prefix{}
	}
	addr = addr.Unmap().WithZone("")
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	age := now.Sub(l.loaded)
	own, subnet = l.findLocked(addr)
	hit := own || subnet.IsValid()
	if l.loaded.IsZero() || age >= localAddrsMaxAge || (!hit && age >= localAddrsMissRefresh) {
		l.loaded = now
		if list, err := l.list(); err == nil {
			l.addrs, l.subnets = interfaceAddrSet(list)
		}
		own, subnet = l.findLocked(addr)
	}
	return own, subnet
}

func (l *localAddrs) findLocked(addr netip.Addr) (bool, netip.Prefix) {
	if _, ok := l.addrs[addr]; ok {
		return true, netip.Prefix{}
	}
	for _, p := range l.subnets {
		if p.Contains(addr) {
			return false, p
		}
	}
	return false, netip.Prefix{}
}

// interfaceAddrSet splits an interface address list into the addresses and
// the on-link subnets of the public ones.
func interfaceAddrSet(list []net.Addr) (map[netip.Addr]struct{}, []netip.Prefix) {
	set := make(map[netip.Addr]struct{}, len(list))
	var subnets []netip.Prefix
	for _, a := range list {
		var (
			ip   net.IP
			mask net.IPMask
		)
		switch v := a.(type) {
		case *net.IPNet:
			ip, mask = v.IP, v.Mask
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			continue
		}
		addr = addr.Unmap()
		set[addr] = struct{}{}
		if p, ok := onLinkSubnet(addr, mask); ok && !slices.Contains(subnets, p) {
			subnets = append(subnets, p)
		}
	}
	return set, subnets
}

// onLinkSubnet returns the subnet other hosts on a public interface
// address's link are in: its interface prefix, and for IPv6 at least the
// /64. Private, loopback and link-local interface addresses need none; their
// whole ranges are refused already.
func onLinkSubnet(addr netip.Addr, mask net.IPMask) (netip.Prefix, bool) {
	if guardPolicy.ValidateIP(net.IP(addr.AsSlice())) != nil {
		return netip.Prefix{}, false
	}
	ones, bits := mask.Size()
	if addr.Is4() && bits == 8*net.IPv6len {
		ones, bits = ones-96, 32 // an IPv4 address with a 16-byte mask
	}
	if addr.Is4() {
		if bits != 32 || ones < minSubnetBitsV4 || ones == 32 {
			return netip.Prefix{}, false
		}
	} else if bits != 128 || ones > linkBitsV6 || ones < minSubnetBitsV6 {
		ones = linkBitsV6
	}
	return netip.PrefixFrom(addr, ones).Masked(), true
}

// selfConnected reports a connection whose local end is the address it
// dialed, which only happens when the kernel routed it back to this machine
// (the source address chosen for a local destination is the destination
// itself). It catches own addresses the cached list has not seen yet and
// addresses the host accepts without having them on an interface, such as
// Linux "local" routes.
func selfConnected(conn net.Conn, dialed netip.Addr) bool {
	local, ok := conn.LocalAddr().(*net.TCPAddr)
	if !ok {
		return false
	}
	return local.AddrPort().Addr().Unmap().WithZone("") == dialed.Unmap().WithZone("")
}
