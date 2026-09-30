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
	"fmt"
	"net/netip"
	"strings"
)

var (
	// ErrInvalidHost reports a destination that is neither a syntactically
	// valid DNS name nor an IP literal.
	ErrInvalidHost = errors.New("egress: invalid host")
	// ErrInvalidPattern reports a block, allow, feed or unblock pattern that
	// cannot be parsed.
	ErrInvalidPattern = errors.New("egress: invalid host pattern")
)

const (
	maxHostLen  = 253
	maxLabelLen = 63
)

// normalizeHost canonicalizes a destination host: ASCII lower case, one
// trailing dot and any brackets removed, IPv4-mapped IPv6 unmapped. The
// returned addr is valid when the host is an IP literal.
//
// DNS names must be syntactically valid and their last label must start with
// a letter. No real top-level domain is numeric, while resolvers (inet_aton)
// accept shorthand such as 127.1, 0x7f.1 or 2130706433 as IPv4 addresses;
// refusing those forms keeps pattern matching and the SSRF guard looking at
// the same destination the resolver would.
func normalizeHost(raw string) (string, netip.Addr, error) {
	h := strings.TrimSpace(raw)
	if len(h) >= 2 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	}
	if h == "" {
		return "", netip.Addr{}, ErrInvalidHost
	}
	if addr, err := netip.ParseAddr(h); err == nil {
		addr = addr.Unmap()
		return addr.String(), addr, nil
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if h == "" || len(h) > maxHostLen {
		return "", netip.Addr{}, ErrInvalidHost
	}
	labels := strings.Split(h, ".")
	for _, label := range labels {
		if !validLabel(label) {
			return "", netip.Addr{}, ErrInvalidHost
		}
	}
	if last := labels[len(labels)-1]; last[0] < 'a' || last[0] > 'z' {
		return "", netip.Addr{}, ErrInvalidHost
	}
	return h, netip.Addr{}, nil
}

func validLabel(label string) bool {
	if label == "" || len(label) > maxLabelLen {
		return false
	}
	for i := 0; i < len(label); i++ {
		c := label[i]
		if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' && c != '_' {
			return false
		}
	}
	return true
}

type patternKind uint8

const (
	patternExact  patternKind = iota + 1 // example.com
	patternSuffix                        // *.example.com: any subdomain, any depth
	patternPrefix                        // an IP literal or CIDR
)

// pattern is one parsed host pattern. raw is its canonical spelling, which
// decisions and events report as the matched rule.
type pattern struct {
	raw    string
	kind   patternKind
	host   string
	prefix netip.Prefix
}

// parsePattern accepts an exact host ("example.com"), a leading wildcard
// ("*.example.com", which covers every subdomain at any depth but not the
// apex), an IP literal or a CIDR prefix.
func parsePattern(raw string) (pattern, error) {
	s := strings.ToLower(strings.TrimSpace(raw))
	switch {
	case s == "":
		return pattern{}, fmt.Errorf("%w: empty pattern", ErrInvalidPattern)
	case strings.HasPrefix(s, "*."):
		host, addr, err := normalizeHost(s[2:])
		if err != nil || addr.IsValid() {
			return pattern{}, fmt.Errorf("%w: %q: a wildcard must precede a DNS name", ErrInvalidPattern, raw)
		}
		return pattern{raw: "*." + host, kind: patternSuffix, host: host}, nil
	case strings.Contains(s, "*"):
		return pattern{}, fmt.Errorf("%w: %q: only a leading \"*.\" wildcard is supported", ErrInvalidPattern, raw)
	case strings.Contains(s, "/"):
		prefix, err := netip.ParsePrefix(s)
		if err != nil {
			return pattern{}, fmt.Errorf("%w: %q: %v", ErrInvalidPattern, raw, err)
		}
		if prefix.Addr().Is4In6() {
			bits := prefix.Bits() - 96
			if bits < 0 {
				return pattern{}, fmt.Errorf("%w: %q: mapped prefix shorter than /96", ErrInvalidPattern, raw)
			}
			prefix = netip.PrefixFrom(prefix.Addr().Unmap(), bits)
		}
		prefix = prefix.Masked()
		return pattern{raw: prefix.String(), kind: patternPrefix, prefix: prefix}, nil
	default:
		host, addr, err := normalizeHost(s)
		if err != nil {
			return pattern{}, fmt.Errorf("%w: %q", ErrInvalidPattern, raw)
		}
		if addr.IsValid() {
			if addr.Zone() != "" {
				return pattern{}, fmt.Errorf("%w: %q: zoned addresses are not destinations", ErrInvalidPattern, raw)
			}
			return pattern{raw: host, kind: patternPrefix, prefix: netip.PrefixFrom(addr, addr.BitLen())}, nil
		}
		return pattern{raw: host, kind: patternExact, host: host}, nil
	}
}

// matches reports whether p covers a normalized destination.
func (p pattern) matches(host string, addr netip.Addr) bool {
	switch p.kind {
	case patternExact:
		return !addr.IsValid() && host == p.host
	case patternSuffix:
		return !addr.IsValid() && strings.HasSuffix(host, "."+p.host)
	case patternPrefix:
		return addr.IsValid() && p.prefix.Contains(addr)
	}
	return false
}

// hostSet indexes patterns for lookup by destination. Lookups cost one map
// probe per label of the host plus a scan of the (short) prefix list.
type hostSet[T any] struct {
	exact    map[string]setItem[T]
	suffix   map[string]setItem[T]
	prefixes []prefixItem[T]
}

type setItem[T any] struct {
	pattern string
	value   T
}

type prefixItem[T any] struct {
	prefix netip.Prefix
	item   setItem[T]
}

func newHostSet[T any]() *hostSet[T] {
	return &hostSet[T]{exact: map[string]setItem[T]{}, suffix: map[string]setItem[T]{}}
}

// add registers p with value v and reports false when the same pattern is
// already present; the first registration wins.
func (s *hostSet[T]) add(p pattern, v T) bool {
	item := setItem[T]{pattern: p.raw, value: v}
	switch p.kind {
	case patternExact:
		if _, dup := s.exact[p.host]; dup {
			return false
		}
		s.exact[p.host] = item
	case patternSuffix:
		if _, dup := s.suffix[p.host]; dup {
			return false
		}
		s.suffix[p.host] = item
	case patternPrefix:
		for _, existing := range s.prefixes {
			if existing.prefix == p.prefix {
				return false
			}
		}
		s.prefixes = append(s.prefixes, prefixItem[T]{prefix: p.prefix, item: item})
	}
	return true
}

func (s *hostSet[T]) len() int {
	return len(s.exact) + len(s.suffix) + len(s.prefixes)
}

// match returns the most specific pattern covering a normalized destination.
// IP literals match only IP and CIDR patterns (longest prefix wins); names
// match an exact pattern first, then the longest wildcard suffix.
func (s *hostSet[T]) match(host string, addr netip.Addr) (setItem[T], bool) {
	if addr.IsValid() {
		_, item, ok := s.matchPrefix(addr)
		return item, ok
	}
	if item, ok := s.exact[host]; ok {
		return item, true
	}
	for i := 0; i < len(host); i++ {
		if host[i] == '.' {
			if item, ok := s.suffix[host[i+1:]]; ok {
				return item, true
			}
		}
	}
	return setItem[T]{}, false
}

// matchPrefix returns the longest IP or CIDR pattern covering addr.
func (s *hostSet[T]) matchPrefix(addr netip.Addr) (netip.Prefix, setItem[T], bool) {
	best := -1
	for i := range s.prefixes {
		if s.prefixes[i].prefix.Contains(addr) && (best < 0 || s.prefixes[i].prefix.Bits() > s.prefixes[best].prefix.Bits()) {
			best = i
		}
	}
	if best < 0 {
		return netip.Prefix{}, setItem[T]{}, false
	}
	return s.prefixes[best].prefix, s.prefixes[best].item, true
}
