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

// localAddrs caches this machine's own interface addresses. The address
// policy refuses ranges, but a host with a global IPv6 or public IPv4 address
// on an interface (dual-stack home networks, VPS and bare-metal hosts) would
// otherwise let a sandbox CONNECT to that address and reach every host
// service listening on all interfaces, bypassing the loopback refusal and the
// --host-port consent flow.
type localAddrs struct {
	list func() ([]net.Addr, error)
	now  func() time.Time

	mu     sync.Mutex
	addrs  map[netip.Addr]struct{}
	loaded time.Time
}

func newLocalAddrs(list func() ([]net.Addr, error)) *localAddrs {
	return &localAddrs{list: list, now: time.Now}
}

// hostAddrs is the process-wide view of this machine's addresses.
var hostAddrs = newLocalAddrs(net.InterfaceAddrs)

// contains reports whether addr is assigned to one of this machine's
// interfaces. When the interface list cannot be read the previous list is
// kept; the self-connection check at dial time still applies.
func (l *localAddrs) contains(addr netip.Addr) bool {
	if l == nil || !addr.IsValid() {
		return false
	}
	addr = addr.Unmap().WithZone("")
	l.mu.Lock()
	defer l.mu.Unlock()
	now := l.now()
	age := now.Sub(l.loaded)
	_, hit := l.addrs[addr]
	if l.loaded.IsZero() || age >= localAddrsMaxAge || (!hit && age >= localAddrsMissRefresh) {
		l.loaded = now
		if list, err := l.list(); err == nil {
			l.addrs = interfaceAddrSet(list)
		}
		_, hit = l.addrs[addr]
	}
	return hit
}

func interfaceAddrSet(list []net.Addr) map[netip.Addr]struct{} {
	set := make(map[netip.Addr]struct{}, len(list))
	for _, a := range list {
		var ip net.IP
		switch v := a.(type) {
		case *net.IPNet:
			ip = v.IP
		case *net.IPAddr:
			ip = v.IP
		default:
			continue
		}
		if addr, ok := netip.AddrFromSlice(ip); ok {
			set[addr.Unmap()] = struct{}{}
		}
	}
	return set
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
