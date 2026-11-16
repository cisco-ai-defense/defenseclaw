// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"slices"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// directoryUnreachable reports whether the hook guardian lists domain ("":
// any domain) as away, in a current, trusted record of its identity spool:
// on a Mac a domain none of whose domain controllers answers (GAP-0092), on
// Linux an SSSD domain SSSD reports offline (GAP-0191). Tests replace it.
var directoryUnreachable = func(domain string) bool {
	domains := enterprisehooks.ReadDirectoryUnreachable(currentIdentitySpoolDir(), validateManagedGuardianAuthorization, time.Now())
	if domain == "" {
		return len(domains) > 0
	}
	return slices.Contains(domains, domain)
}

// sssdGroupsUnavailable is the lookup error for an SSSD account whose groups
// SSSD cannot list now, or nil: SSSD listed only its primary group, and the
// guardian lists its SSSD domain offline (unreachable). The domain is the
// guardian record's SSSD domain, else the domain of the account's SID, else
// "" (any domain). Facts cached before are dropped too: SSSD would list the
// memberships it holds, so it holds none.
func sssdGroupsUnavailable(record *enterprisehooks.IdentitySpoolRecord, facts useridentity.DirectoryFacts,
	unreachable func(domain string) bool, now time.Time) error {
	if facts.Source != useridentity.SourceSSSD || !facts.OnlyPrimaryGroup || unreachable == nil {
		return nil
	}
	domain := ""
	if record != nil {
		domain = strings.TrimSpace(record.SSSDDomain)
	}
	if domain == "" {
		domain = strings.TrimSpace(facts.Domain)
	}
	domain = strings.ToLower(domain)
	if !unreachable(domain) {
		return nil
	}
	openDirectoryOfflineAt.Store(now.UnixNano())
	label := domain
	if label == "" {
		label = "the account's domain"
	}
	return &identityFactsUnconfirmedError{err: fmt.Errorf("SSSD is offline for %s (the hook guardian asks SSSD every 15 seconds while it "+
		"is) and lists this account in its primary group only, as it does for an account whose memberships it never looked up: "+
		"its domain groups are unknown; the lookup is retried every %s", label, identityDirectoryRetry)}
}
