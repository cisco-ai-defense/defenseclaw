// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package gateway

import (
	"time"

	osuser "os/user"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// resolvePeerDirectoryFacts returns a verified uid's directory facts. The
// groups always come from the system account database, which on macOS
// answers through Open Directory (local groups and an AD binding's), so
// users and groups assignments match on a per-user install and on a managed
// Mac alike, and agree with what guardrail profile explain resolves. On a
// managed install the root enumerator's record adds what only root can read
// (the AD binding, the Platform SSO provider).
func resolvePeerDirectoryFacts(key string) (useridentity.DirectoryFacts, error) {
	now := time.Now().UTC()
	account, lookupErr := osuser.LookupId(key)
	var groups []string
	if lookupErr == nil {
		groups = localAccountGroups(account)
	}
	if record, ok := readIdentitySpoolFacts(key, now); ok {
		return spoolFactsWithGroups(record.Facts, groups, now), nil
	}
	if lookupErr != nil {
		return useridentity.DirectoryFacts{}, lookupErr
	}
	// Groups that could not be listed fail the lookup: facts cached as
	// resolved without them would select the default profile as "default"
	// for 15 minutes instead of "default_lookup_failed".
	groups, err := accountGroups(account)
	if err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	return useridentity.DirectoryFacts{
		Directory:  useridentity.DirectoryLocal,
		Source:     useridentity.SourceMacOSOpenDirectory,
		Groups:     groups,
		Assurance:  useridentity.AssuranceVerified,
		ResolvedAt: now,
	}, nil
}
