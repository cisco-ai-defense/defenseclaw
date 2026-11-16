// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"net/netip"
	"net/url"
	"strconv"
	"strings"
)

// LegacyIPv4Host reads host as the resolvers do (inet_aton): one to four
// numbers, each decimal, octal (a leading 0) or hex (0x), the last one
// filling the rest of the address. 127.1, 0, 2130706433, 0x7f000001 and
// 0177.0.0.1 are IPv4 addresses to the agent that dials them, whatever the
// text looks like. A host that is not entirely such numbers, or one with a
// part out of range, is not an address and is reported false.
func LegacyIPv4Host(host string) (netip.Addr, bool) {
	parts := strings.Split(host, ".")
	var widths []uint
	switch len(parts) {
	case 1:
		widths = []uint{32}
	case 2:
		widths = []uint{8, 24}
	case 3:
		widths = []uint{8, 8, 16}
	case 4:
		widths = []uint{8, 8, 8, 8}
	default:
		return netip.Addr{}, false
	}
	var address uint64
	var shift uint = 32
	for i, part := range parts {
		base, digits := 10, part
		switch {
		case strings.HasPrefix(part, "0x") || strings.HasPrefix(part, "0X"):
			base, digits = 16, part[2:]
		case len(part) > 1 && part[0] == '0':
			base, digits = 8, part[1:]
		}
		if digits == "" {
			return netip.Addr{}, false
		}
		value, err := strconv.ParseUint(digits, base, 32)
		if err != nil || value > (uint64(1)<<widths[i])-1 {
			return netip.Addr{}, false
		}
		shift -= widths[i]
		address |= value << shift
	}
	return netip.AddrFrom4([4]byte{byte(address >> 24), byte(address >> 16), byte(address >> 8), byte(address)}), true
}

// CanonicalMCPURL is the one spelling of the address an MCP server URL names:
// the scheme and the host lower case, an IPv4 address written as the resolvers
// read it (127.1, 0x7f000001) or an IPv6 address in its short form written the
// canonical way, an IPv4-mapped IPv6 address as the IPv4 address. Everything
// else is kept as written, so two URLs that are one string stay one string, and
// a URL that does not parse, or that carries credentials, is returned as it
// came. The rule that allows or denies a server and the definition the agent
// lists are compared on this form, so an exact allow of the canonical address
// admits the server written with an alias of it, and the other way round.
func CanonicalMCPURL(raw string) string {
	raw = strings.TrimSpace(raw)
	u, err := url.Parse(raw)
	if err != nil || u.User != nil || u.Opaque != "" || u.Hostname() == "" {
		return raw
	}
	host := strings.ToLower(u.Hostname())
	if addr, err := netip.ParseAddr(host); err == nil {
		if addr.Zone() != "" {
			return raw
		}
		host = addr.Unmap().String()
	} else if addr, ok := LegacyIPv4Host(host); ok {
		host = addr.String()
	}
	if strings.Contains(host, ":") {
		host = "[" + host + "]"
	}
	if port := u.Port(); port != "" {
		host += ":" + port
	}
	u.Scheme, u.Host = strings.ToLower(u.Scheme), host
	return u.String()
}
