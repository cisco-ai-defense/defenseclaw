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

package config

import (
	"fmt"
	"net/netip"
	"strings"
)

// maxInternalDomains bounds guardrail.internal_domains.
const maxInternalDomains = 256

// validateInternalDomains accepts domain names only (letters, digits and
// hyphens in dot-separated labels, an optional leading dot), so an entry can
// never be a URL, a wildcard or an address.
func validateInternalDomains(domains []string) error {
	if len(domains) > maxInternalDomains {
		return fmt.Errorf("guardrail.internal_domains: at most %d entries, got %d", maxInternalDomains, len(domains))
	}
	for _, raw := range domains {
		domain := normalizeInternalDomain(raw)
		if !validInternalDomain(domain) {
			return fmt.Errorf("guardrail.internal_domains: %q is not a domain name (use a name such as corp.example.com, without a scheme, port, path or wildcard)", raw)
		}
	}
	return nil
}

func normalizeInternalDomain(domain string) string {
	return strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(domain), "."), "."))
}

func validInternalDomain(domain string) bool {
	if domain == "" || len(domain) > 253 {
		return false
	}
	if _, err := netip.ParseAddr(domain); err == nil {
		return false
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for index := 0; index < len(label); index++ {
			c := label[index]
			if (c < 'a' || c > 'z') && (c < '0' || c > '9') && c != '-' {
				return false
			}
		}
	}
	return true
}

// IsInternalDomainHost reports whether host is one of guardrail.internal_domains
// or a name under one ("mirror.corp.example.com" is under "corp.example.com",
// "notcorp.example.com" is not). An IP address never matches.
func (g *GuardrailConfig) IsInternalDomainHost(host string) bool {
	if g == nil || len(g.InternalDomains) == 0 {
		return false
	}
	host = strings.ToLower(strings.TrimSuffix(strings.Trim(strings.TrimSpace(host), "[]"), "."))
	if host == "" {
		return false
	}
	if _, err := netip.ParseAddr(host); err == nil {
		return false
	}
	for _, raw := range g.InternalDomains {
		domain := normalizeInternalDomain(raw)
		if !validInternalDomain(domain) {
			continue
		}
		if host == domain || strings.HasSuffix(host, "."+domain) {
			return true
		}
	}
	return false
}
