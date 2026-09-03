// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package netguard

import (
	"net"
	"net/netip"
	"os"
	"strings"
	"sync"
)

var (
	allowedPrivateMu sync.RWMutex
	allowedPrivate   map[netip.Addr]struct{}
)

// SetAllowedPrivateIPs replaces the set of private IPs that are exempt from
// the SSRF guard. Thread-safe; called at sidecar startup and on config reload.
func SetAllowedPrivateIPs(ips []net.IP) {
	m := make(map[netip.Addr]struct{}, len(ips))
	for _, ip := range ips {
		if addr, ok := netip.AddrFromSlice(ip); ok {
			m[addr.Unmap()] = struct{}{}
		}
	}
	allowedPrivateMu.Lock()
	allowedPrivate = m
	allowedPrivateMu.Unlock()
}

// IsAllowedPrivateIP reports whether ip is in the operator-configured allowlist.
func IsAllowedPrivateIP(ip net.IP) bool {
	if ip == nil {
		return false
	}
	addr, ok := netip.AddrFromSlice(ip)
	if !ok {
		return false
	}
	allowedPrivateMu.RLock()
	_, found := allowedPrivate[addr.Unmap()]
	allowedPrivateMu.RUnlock()
	return found
}

// ParseAllowedPrivateUpstreams parses IP strings from config + env var into
// net.IP values suitable for SetAllowedPrivateIPs. It merges config.yaml entries
// with the DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS env var (comma-separated).
func ParseAllowedPrivateUpstreams(configIPs []string) []net.IP {
	seen := make(map[netip.Addr]struct{})
	var result []net.IP

	add := func(s string) {
		s = strings.TrimSpace(s)
		if s == "" {
			return
		}
		ip := net.ParseIP(s)
		if ip == nil {
			return
		}
		addr, ok := netip.AddrFromSlice(ip)
		if !ok {
			return
		}
		addr = addr.Unmap()
		if _, dup := seen[addr]; dup {
			return
		}
		seen[addr] = struct{}{}
		result = append(result, ip)
	}

	for _, s := range configIPs {
		add(s)
	}

	if env := os.Getenv("DEFENSECLAW_ALLOW_PRIVATE_UPSTREAMS"); env != "" {
		for _, s := range strings.Split(env, ",") {
			add(s)
		}
	}

	return result
}
