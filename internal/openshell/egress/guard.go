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
	"fmt"
	"net"
	"net/netip"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/netguard"
)

// guardPolicy is the netguard address policy for sandbox egress: private
// networks and CGNAT stay prohibited regardless of the operator's
// private-upstream allowlist or DEFENSECLAW_ALLOW_CGNAT, which exist for the
// daemon's own upstreams and must never widen what a sandbox can reach.
var guardPolicy = netguard.V8NetworkSafetyPolicy{}

// openPolicy is the netguard policy for a dial an operator allow rule may
// open to private networks. It also admits loopback, which the dial hooks
// refuse themselves (classifyAddr) before netguard sees an address.
var openPolicy = netguard.V8NetworkSafetyPolicy{AllowPrivateNetworks: true, AllowCGNAT: true}

// privateRanges are the ranges openPolicy admits beyond guardPolicy, other
// than loopback. An operator allow CIDR opens an address in one of them
// only when it is no wider than the range.
var privateRanges = []netip.Prefix{
	netip.MustParsePrefix("10.0.0.0/8"),
	netip.MustParsePrefix("172.16.0.0/12"),
	netip.MustParsePrefix("192.168.0.0/16"),
	netip.MustParsePrefix("100.64.0.0/10"),
	netip.MustParsePrefix("fc00::/7"),
}

// neverReach are addresses no sandbox reaches, whatever else would admit
// them, that netguard's address policy (built for the daemon's own
// exporters) passes as public or treats as private: cloud metadata and host
// services outside the link-local range, and the deprecated IPv6 site-local
// range (RFC 3879), which netguard does not reserve. They are refused as
// host-internal, like 169.254.169.254, and allowed_ips ranges that overlap
// them are never approved (NeverReachPrefixes, packs.ClassifyAllowedIP).
var neverReach = []netip.Prefix{
	// Azure WireServer: the VM agent's host channel, a public address
	// reachable only from inside Azure.
	netip.MustParsePrefix("168.63.129.16/32"),
	// Google Cloud's IPv6 metadata server.
	netip.MustParsePrefix("fd20:ce::254/128"),
	// Oracle Cloud's IPv6 instance metadata service.
	netip.MustParsePrefix("fd00:c1::a9fe:a9fe/128"),
	netip.MustParsePrefix("fec0::/10"),
}

// NeverReachPrefixes returns the addresses the sandbox guard refuses as
// host-internal beyond netguard's metadata and reserved ranges.
func NeverReachPrefixes() []netip.Prefix { return slices.Clone(neverReach) }

// guardClass is how the guard treats a destination.
type guardClass uint8

const (
	// guardPass is a public destination; the other layers decide it.
	guardPass guardClass = iota
	// guardPrivate is on a private network: an RFC 1918, carrier-grade NAT
	// or unique local address, another host on one of this machine's public
	// subnets, or an intranet name. Only an operator allow rule opens it
	// (CategoryPrivateNetwork).
	guardPrivate
	// guardHost is this machine or what only it can reach: loopback, its own
	// addresses, host-internal names, link-local and metadata addresses,
	// multicast, reserved and translated ranges. Nothing opens it
	// (CategoryHostInternal).
	guardHost
	// guardInvalid is a single-label name (CategoryInvalidDestination).
	guardInvalid
)

// guardVerdict is the guard's classification of one destination.
type guardVerdict struct {
	class guardClass
	// reason explains a refused destination (a sentence); what names the
	// kind of refused address for dial-time refusals ("an address of this
	// machine").
	reason, what string
	// scope is the private range or on-link subnet a private address is in.
	scope netip.Prefix
}

func mustHostSet(patterns ...string) *hostSet[struct{}] {
	set := newHostSet[struct{}]()
	for _, raw := range patterns {
		p, err := parsePattern(raw)
		if err != nil {
			panic(fmt.Sprintf("egress: reserved name %q: %v", raw, err))
		}
		set.add(p, struct{}{})
	}
	return set
}

// hostInternalNames name this machine, or what only it can reach, by
// definition: the sandbox's view of host loopback (host.openshell.internal),
// container runtimes' names for the host, and the cloud metadata service.
var hostInternalNames = mustHostSet(
	"localhost", "*.localhost",
	"*.localdomain", // distro defaults for this machine's own name
	"openshell.internal", "*.openshell.internal",
	"host.docker.internal", "gateway.docker.internal", "host.containers.internal",
	"metadata.google.internal",
)

// intranetNames are names that resolve to a private network by convention,
// refused before any DNS lookup unless an operator allow rule names them.
var intranetNames = mustHostSet(
	"*.internal",  // ICANN private-use TLD
	"*.local",     // mDNS
	"*.home.arpa", // RFC 8375 home networks
	"*.lan", "*.home", "*.corp", "*.intranet", "*.private",
)

// classifyName applies the name-level guard. Names that resolve to private,
// own or on-link addresses are caught at dial time (classifyAddr).
func classifyName(host string) guardVerdict {
	if _, ok := hostInternalNames.match(host, netip.Addr{}); ok {
		return guardVerdict{class: guardHost, reason: "The name is host-internal: localhost, host.openshell.internal and similar names reach this machine."}
	}
	if !strings.Contains(host, ".") {
		return guardVerdict{class: guardInvalid, reason: "Single-label names are not resolved: the proxy looks names up fully qualified, " +
			"never through the host's DNS search domains, which lead to internal machines. Use the fully qualified name."}
	}
	if _, ok := intranetNames.match(host, netip.Addr{}); ok {
		return guardVerdict{class: guardPrivate, reason: "The name is an intranet name (.internal, .local, .lan, .corp and similar) on a private network."}
	}
	return guardVerdict{}
}

// classifyAddr applies the address-level guard to an IP literal or a
// resolved address. This machine's own addresses come first: its private
// LAN address is still this machine.
func classifyAddr(addr netip.Addr, local *localAddrs) guardVerdict {
	if addr.Zone() != "" {
		return guardVerdict{class: guardHost, what: "a zoned, link-scoped address",
			reason: "Zoned IPv6 addresses are link-scoped and never public."}
	}
	addr = addr.Unmap()
	own, subnet := local.lookup(addr)
	if own {
		return guardVerdict{class: guardHost, what: "an address of this machine",
			reason: "The address belongs to this machine; sandboxes never reach services on the host through it."}
	}
	for _, never := range neverReach {
		if never.Contains(addr) {
			return guardVerdict{class: guardHost, what: reservedWhat, reason: reservedReason}
		}
	}
	ip := net.IP(addr.AsSlice())
	if guardPolicy.ValidateIP(ip) == nil {
		if subnet.IsValid() {
			return guardVerdict{class: guardPrivate, scope: subnet,
				what:   "another host on one of this machine's own subnets",
				reason: "The address is another host on one of this machine's own subnets, part of its local network."}
		}
		return guardVerdict{}
	}
	if !addr.IsLoopback() && openPolicy.ValidateIP(ip) == nil {
		for _, r := range privateRanges {
			if r.Contains(addr) {
				return guardVerdict{class: guardPrivate, scope: r,
					what:   "a private network address",
					reason: "The address is on a private network (" + r.String() + ")."}
			}
		}
	}
	return guardVerdict{class: guardHost, what: reservedWhat, reason: reservedReason}
}

const (
	reservedWhat   = "a loopback, link-local, cloud metadata, multicast or reserved address"
	reservedReason = "The address is loopback, link-local, cloud metadata, multicast, reserved or otherwise not publicly routable."
)

// allowsPrivate reports the operator allow rule (or administrator
// allow-only entry) that opens a private destination: any allow pattern
// covering an intranet name (only those are private by name, and a wildcard
// opens their answers too, see opensPrivateName), or for an address an allow
// IP or CIDR no wider than the private range or subnet it is in, so that a
// wide CIDR meant for public IP literals (0.0.0.0/0) opens no private
// network.
func (d *Decider) allowsPrivate(host string, addr netip.Addr, scope netip.Prefix) (string, bool) {
	for _, set := range d.openingSets() {
		if !addr.IsValid() {
			if item, ok := set.match(host, addr); ok {
				return item.pattern, true
			}
			continue
		}
		if prefix, item, ok := set.matchPrefix(addr); ok && prefix.Bits() >= scope.Bits() {
			return item.pattern, true
		}
	}
	return "", false
}

// openingSets are the pattern sets whose entries open private networks:
// the operator allow list and the administrator's allow-only list.
func (d *Decider) openingSets() [2]*hostSet[struct{}] {
	return [2]*hostSet[struct{}]{d.allow, d.allowOnly}
}
