// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"net"
	"sort"
	"strconv"
	"strings"
)

// Native OTLP exporter ownership is shared by every writer that cleans up a
// DefenseClaw exporter on upgrade: Codex and Claude Code Setup, the managed
// per-user cleanup (Linux, macOS and the Windows enterprise module, which calls
// RemoveUserNativeOTLP), Verify and residue checks. A product-owned route is
// removed or repointed; an operator-owned route keeps its bytes. The helpers
// below normalise only what HTTP or the socket layer already treats as equal,
// so a respelling can neither hide a product credential nor claim an operator
// setting.

// otlpLocalHost reports a URL host whose connections stay on this machine: the
// localhost names, any IP loopback address (127.0.0.0/8, ::1, IPv4-mapped
// loopback), the unspecified address (which Linux and macOS route to the local
// host) and the inet_aton shorthand forms of those (127.1, 0x7f.1, 2130706433).
// Ownership still needs product proof (a marker, the scoped path or the scoped
// bearer), so the wider host set never claims an operator's collector.
func otlpLocalHost(host string) bool {
	host = strings.TrimSuffix(strings.TrimSpace(host), ".")
	if host == "" {
		return false
	}
	lower := strings.ToLower(host)
	if lower == "localhost" || strings.HasSuffix(lower, ".localhost") {
		return true
	}
	if zone := strings.IndexByte(host, '%'); zone >= 0 {
		host = host[:zone]
	}
	if ip := net.ParseIP(host); ip != nil {
		return ip.IsLoopback() || ip.IsUnspecified()
	}
	ip, ok := otlpInetAtonIPv4(host)
	return ok && (ip[0] == 127 || ip.Equal(net.IPv4zero.To4()))
}

// otlpInetAtonIPv4 parses the one- to four-part numeric IPv4 forms that the C
// resolver accepts (decimal, 0x hex and leading-zero octal parts).
func otlpInetAtonIPv4(host string) (net.IP, bool) {
	parts := strings.Split(host, ".")
	if len(parts) == 0 || len(parts) > 4 {
		return nil, false
	}
	values := make([]uint64, len(parts))
	for i, part := range parts {
		if part == "" || strings.ContainsAny(part, "_+-") {
			return nil, false
		}
		base, digits := 10, part
		switch {
		case len(part) > 2 && (part[:2] == "0x" || part[:2] == "0X"):
			base, digits = 16, part[2:]
		case len(part) > 1 && part[0] == '0':
			base, digits = 8, part[1:]
		}
		value, err := strconv.ParseUint(digits, base, 32)
		if err != nil {
			return nil, false
		}
		values[i] = value
	}
	var addr uint64
	last := len(values) - 1
	for i := 0; i < last; i++ {
		if values[i] > 0xff {
			return nil, false
		}
		addr |= values[i] << (24 - 8*uint(i))
	}
	if values[last] >= uint64(1)<<(32-8*uint(last)) {
		return nil, false
	}
	addr |= values[last]
	return net.IPv4(byte(addr>>24), byte(addr>>16), byte(addr>>8), byte(addr)).To4(), true
}

// otlpBearerCredential returns the credential of an Authorization value that
// uses the Bearer scheme. The scheme is case-insensitive (RFC 9110 section
// 11.1) and the whitespace around it is not significant, so "bearer <token>"
// and "BEARER  <token>" carry the same credential as "Bearer <token>".
func otlpBearerCredential(value string) (string, bool) {
	value = strings.TrimSpace(value)
	cut := strings.IndexAny(value, " \t")
	if cut < 0 || !strings.EqualFold(value[:cut], "Bearer") {
		return "", false
	}
	credential := strings.TrimSpace(value[cut:])
	return credential, credential != ""
}

// otlpHeaderKeys returns every spelling of one header name in a headers table,
// sorted. Header names are case-insensitive (RFC 9110 section 5.1), and a
// TOML or JSON table keeps "authorization" and "Authorization" as two keys.
func otlpHeaderKeys(headers map[string]interface{}, name string) []string {
	var keys []string
	for key := range headers {
		if strings.EqualFold(strings.TrimSpace(key), name) {
			keys = append(keys, key)
		}
	}
	sort.Strings(keys)
	return keys
}

// otlpHeaderHas reports a spelling of name whose value is exactly want.
func otlpHeaderHas(headers map[string]interface{}, name, want string) bool {
	for _, key := range otlpHeaderKeys(headers, name) {
		if value, _ := headers[key].(string); value == want {
			return true
		}
	}
	return false
}
