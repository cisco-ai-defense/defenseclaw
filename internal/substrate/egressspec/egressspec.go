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

// Package egressspec holds the dependency-free parts of Substrate egress
// rules that both config validation and the renderer need: hostname
// patterns as ate-api-server v1.0.0 accepts them, credential reference and
// header checks mirroring its admission, and the ecosystem allow packs. It
// imports only the standard library, so internal/config can use it without
// pulling the Substrate API stubs into every binary.
package egressspec

import (
	"net/url"
	"slices"
	"strings"
)

// Secret scopes and the per-person source placeholder.
const (
	ScopeShared       = "shared"
	ScopePerPerson    = "per_person"
	PersonPlaceholder = "{person}"
)

// Pattern is a Substrate hostname pattern: an exact name, "*.<Name>"
// (exactly one more label, unlike OpenShell's any-depth wildcard) or "*".
type Pattern struct {
	Name     string
	Wildcard bool
	Any      bool
}

func (p Pattern) String() string {
	switch {
	case p.Any:
		return "*"
	case p.Wildcard:
		return "*." + p.Name
	}
	return p.Name
}

// ParsePattern normalizes (lower case, trimmed, one trailing dot dropped)
// and parses a hostname pattern. It refuses IP addresses, URLs, ports and
// any other wildcard form, as upstream's ParseHostnamePattern does.
func ParsePattern(raw string) (Pattern, bool) {
	s := strings.TrimSuffix(strings.ToLower(strings.TrimSpace(raw)), ".")
	if s == "*" {
		return Pattern{Any: true}, true
	}
	name, wildcard := strings.CutPrefix(s, "*.")
	if !IsHostname(name) {
		return Pattern{}, false
	}
	return Pattern{Name: name, Wildcard: wildcard}, true
}

// IsHostname mirrors upstream egresspolicy.isHostname: a DNS-1123
// subdomain whose top label is not all digits.
func IsHostname(name string) bool {
	if !IsDNS1123Subdomain(name) {
		return false
	}
	top := name[strings.LastIndexByte(name, '.')+1:]
	return strings.Trim(top, "0123456789") != ""
}

// IsDNS1123Subdomain reports a lowercase RFC 1123 subdomain of at most 253
// bytes with labels of 1-63 bytes.
func IsDNS1123Subdomain(s string) bool {
	if len(s) == 0 || len(s) > 253 {
		return false
	}
	for _, l := range strings.Split(s, ".") {
		if len(l) == 0 || len(l) > 63 || l[0] == '-' || l[len(l)-1] == '-' {
			return false
		}
		for i := 0; i < len(l); i++ {
			if c := l[i]; !isLowerAlnum(c) && c != '-' {
				return false
			}
		}
	}
	return true
}

// IsDNS1123Label reports a single DNS-1123 label (Kubernetes short names,
// atespaces).
func IsDNS1123Label(s string) bool {
	return !strings.Contains(s, ".") && len(s) <= 63 && IsDNS1123Subdomain(s)
}

// ValidCredentialURI mirrors upstream validCredentialURI:
// ate-secret://<DNS-1123 provider class>/<provider-name>/<tail>, with no
// user, port, query, fragment, percent-encoding or empty path segment.
func ValidCredentialURI(raw string) bool {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != "ate-secret" || u.Host == "" || u.Host != u.Hostname() || u.User != nil ||
		u.RawQuery != "" || u.Fragment != "" || strings.ContainsAny(raw, "?#") || !IsDNS1123Subdomain(u.Host) {
		return false
	}
	p := u.EscapedPath()
	if p != u.Path || !strings.HasPrefix(p, "/") || strings.HasSuffix(p, "/") {
		return false
	}
	parts := strings.Split(strings.TrimPrefix(p, "/"), "/")
	return len(parts) >= 2 && !slices.Contains(parts, "")
}

// ValidHeaderName reports an HTTP header field name (an RFC 9110 token).
func ValidHeaderName(v string) bool {
	if v == "" {
		return false
	}
	for i := 0; i < len(v); i++ {
		c := v[i]
		if !isLowerAlnum(c) && (c < 'A' || c > 'Z') && strings.IndexByte("!#$%&'*+-.^_`|~", c) < 0 {
			return false
		}
	}
	return true
}

// ValidHeaderValue reports text allowed in an HTTP field value prefix: no
// control character but tab.
func ValidHeaderValue(v string) bool {
	for i := 0; i < len(v); i++ {
		if c := v[i]; c != '\t' && (c < ' ' || c == 0x7f) {
			return false
		}
	}
	return true
}

func isLowerAlnum(c byte) bool { return c >= 'a' && c <= 'z' || c >= '0' && c <= '9' }

// Ecosystem allow packs (E22): the package indexes and mirrors a coding
// agent needs to install dependencies.
var ecosystemPacks = map[string][]string{
	"pypi":   {"pypi.org", "files.pythonhosted.org"},
	"npm":    {"registry.npmjs.org", "registry.yarnpkg.com"},
	"crates": {"crates.io", "index.crates.io", "static.crates.io"},
	"go":     {"proxy.golang.org", "sum.golang.org"},
}

// EcosystemPacks are the pack names, sorted.
func EcosystemPacks() []string {
	out := make([]string, 0, len(ecosystemPacks))
	for k := range ecosystemPacks {
		out = append(out, k)
	}
	slices.Sort(out)
	return out
}

// PackHosts returns a pack's hosts, or nil for an unknown pack.
func PackHosts(name string) []string { return slices.Clone(ecosystemPacks[name]) }
