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

package extproc

import (
	"errors"
	"fmt"
	"net"
	"net/netip"
	"strings"
)

var errInvalidHost = errors.New("invalid host")

// normalizeHost canonicalizes a destination host the way the egress Decider
// does: lower case, brackets and one trailing dot removed, IPv4-mapped IPv6
// unmapped. It does not validate DNS syntax; the Decider does.
func normalizeHost(raw string) (string, bool, error) {
	h := strings.TrimSpace(raw)
	if len(h) >= 2 && h[0] == '[' && h[len(h)-1] == ']' {
		h = h[1 : len(h)-1]
	}
	if addr, err := netip.ParseAddr(h); err == nil {
		return addr.Unmap().String(), true, nil
	}
	h = strings.TrimSuffix(strings.ToLower(h), ".")
	if h == "" || len(h) > 253 || strings.ContainsAny(h, " /\\@?#%:\t\r\n") {
		return "", false, errInvalidHost
	}
	return h, false, nil
}

// splitAuthority returns the normalized host and the port of an :authority.
func splitAuthority(authority string) (host string, port string, err error) {
	a := strings.TrimSpace(authority)
	h := a
	if strings.HasPrefix(a, "[") || strings.Count(a, ":") == 1 {
		if hh, p, e := net.SplitHostPort(a); e == nil {
			h, port = hh, p
		}
	}
	host, _, err = normalizeHost(h)
	return host, port, err
}

// hostMatcher matches normalized hosts against exact names, IP literals and
// leading "*." wildcards (any subdomain, not the apex), the forms the egress
// lists take.
type hostMatcher struct {
	exact  map[string]string
	suffix []string
}

func newHostMatcher(patterns []string) (*hostMatcher, error) {
	m := &hostMatcher{exact: map[string]string{}}
	for _, raw := range patterns {
		p := strings.TrimSpace(raw)
		wild := strings.HasPrefix(p, "*.")
		if wild {
			p = p[2:]
		}
		if strings.Contains(p, "*") {
			return nil, fmt.Errorf("%q: only a leading \"*.\" wildcard is supported", raw)
		}
		h, isIP, err := normalizeHost(p)
		if err != nil {
			return nil, fmt.Errorf("%q: invalid host pattern", raw)
		}
		if wild {
			if isIP {
				return nil, fmt.Errorf("%q: a wildcard must precede a DNS name", raw)
			}
			m.suffix = append(m.suffix, "."+h)
			continue
		}
		m.exact[h] = h
	}
	return m, nil
}

// match returns the pattern covering host ("" when none).
func (m *hostMatcher) match(host string) (string, bool) {
	if m == nil {
		return "", false
	}
	if _, ok := m.exact[host]; ok {
		return host, true
	}
	for _, s := range m.suffix {
		if strings.HasSuffix(host, s) {
			return "*" + s, true
		}
	}
	return "", false
}

func mustHostMatcher(patterns []string) *hostMatcher {
	m, err := newHostMatcher(patterns)
	if err != nil {
		panic(err)
	}
	return m
}
