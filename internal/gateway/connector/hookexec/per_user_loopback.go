// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"errors"
	"net"
	"net/netip"
	"strconv"
	"strings"
)

// perUserLoopbackTargets is the one spelling rule for a per-user gateway
// address: the loopback endpoints the native helper dials, in order. The
// shell preflight's defenseclaw_loopback_targets implements the same rule,
// and both are checked against testdata/per_user_loopback_addrs.json.
//
// localhost is 127.0.0.1, then ::1 (the gateway's own localhost listener
// binds IPv4); an IPv4-mapped address is its IPv4 address; any 127.0.0.0/8
// or ::1 spelling netip accepts is itself. Brackets are required exactly for
// IPv6, the port is plain decimal without a leading zero, and zones, other
// hosts and non-loopback addresses are refused.
func perUserLoopbackTargets(apiAddr string) ([]netip.AddrPort, error) {
	host, rawPort, err := net.SplitHostPort(apiAddr)
	if err != nil {
		return nil, errors.New("invalid per-user gateway address")
	}
	port, err := strconv.ParseUint(rawPort, 10, 16)
	if err != nil || port == 0 || rawPort[0] < '1' || rawPort[0] > '9' {
		return nil, errors.New("per-user gateway port is invalid")
	}
	bracketed := strings.HasPrefix(apiAddr, "[")
	if strings.EqualFold(host, "localhost") && !bracketed {
		return []netip.AddrPort{
			netip.AddrPortFrom(netip.AddrFrom4([4]byte{127, 0, 0, 1}), uint16(port)),
			netip.AddrPortFrom(netip.IPv6Loopback(), uint16(port)),
		}, nil
	}
	addr, err := netip.ParseAddr(host)
	if err != nil || addr.Zone() != "" || bracketed != addr.Is6() {
		return nil, errors.New("per-user gateway target must be loopback")
	}
	addr = addr.Unmap()
	if !addr.IsLoopback() {
		return nil, errors.New("per-user gateway target must be loopback")
	}
	return []netip.AddrPort{netip.AddrPortFrom(addr, uint16(port))}, nil
}

// perUserTargetMatches reports whether a connected peer is one of the
// normalised endpoints.
func perUserTargetMatches(targets []netip.AddrPort, peer *net.TCPAddr) bool {
	if peer == nil {
		return false
	}
	got := peer.AddrPort()
	got = netip.AddrPortFrom(got.Addr().Unmap(), got.Port())
	for _, target := range targets {
		if got == target {
			return true
		}
	}
	return false
}
