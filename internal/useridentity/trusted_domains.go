// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package useridentity

import (
	"fmt"
	"slices"
	"strings"
	"sync/atomic"
)

// Trusted Active Directory child domains.
//
// An account of a child domain of the joined realm (alice of
// emea.corp.example.com on a host joined to corp.example.com) is verified only
// when the administrator lists its domain in
// ai_discovery.trusted_ad_child_domains. Nothing on the host proves to a
// process that is not root that a domain is a trusted child of the joined
// realm: a plain LDAP domain configured next to the AD domain can carry a
// name below it and objectSid values, and DNS or adcli answers are not
// authenticated (GAP-1255). An account of a domain that is not listed gets no
// domain, realm, directory type or principal, so no users assignment matches
// it. An empty list trusts the joined domain only.

// MaxTrustedADChildDomains bounds the list.
const MaxTrustedADChildDomains = 256

var trustedADChildDomains atomic.Pointer[[]string]

// NormalizeTrustedADChildDomain returns entry as a lower-case DNS domain of
// at least two labels, or an error that says what is wrong with it.
func NormalizeTrustedADChildDomain(entry string) (string, error) {
	domain := strings.ToLower(strings.TrimSuffix(strings.TrimSpace(entry), "."))
	switch {
	case domain == "":
		return "", fmt.Errorf("empty domain")
	case len(domain) > 253:
		return "", fmt.Errorf("%q is longer than 253 characters", entry)
	case !strings.Contains(domain, "."):
		return "", fmt.Errorf("%q is not a DNS domain: a NetBIOS name or a single label names no child domain", entry)
	}
	for _, label := range strings.Split(domain, ".") {
		if label == "" || len(label) > 63 || strings.HasPrefix(label, "-") || strings.HasSuffix(label, "-") {
			return "", fmt.Errorf("%q is not a DNS domain", entry)
		}
		for _, r := range label {
			if (r < 'a' || r > 'z') && (r < '0' || r > '9') && r != '-' {
				return "", fmt.Errorf("%q is not a DNS domain: only letters, digits, hyphens and dots are allowed", entry)
			}
		}
	}
	return domain, nil
}

// SetTrustedADChildDomains records ai_discovery.trusted_ad_child_domains and
// reports whether the list changed. An entry that does not normalize is
// dropped; config validation refuses it before a config is committed.
func SetTrustedADChildDomains(entries []string) bool {
	var domains []string
	for _, entry := range entries {
		if domain, err := NormalizeTrustedADChildDomain(entry); err == nil && !slices.Contains(domains, domain) {
			domains = append(domains, domain)
		}
	}
	slices.Sort(domains)
	previous := trustedADChildDomains.Swap(&domains)
	if previous == nil {
		return len(domains) > 0
	}
	return !slices.Equal(*previous, domains)
}

// TrustedADChildDomains returns the recorded list, sorted.
func TrustedADChildDomains() []string {
	if domains := trustedADChildDomains.Load(); domains != nil {
		return slices.Clone(*domains)
	}
	return nil
}

// TrustedADChildDomain reports whether domain is listed.
func TrustedADChildDomain(domain string) bool {
	domain = strings.ToLower(strings.TrimSuffix(strings.TrimSpace(domain), "."))
	domains := trustedADChildDomains.Load()
	return domain != "" && domains != nil && slices.Contains(*domains, domain)
}
