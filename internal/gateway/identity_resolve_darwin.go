// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package gateway

import (
	"time"

	osuser "os/user"

	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// resolvePeerDirectoryFacts returns a verified uid's directory facts: the
// account's own facts from the system account database, which on macOS
// answers through Open Directory (directory local, groups), with the root
// enumerator's record laid over them when the guardian wrote one (a managed
// install: the dscl directory, Kerberos principal and domain of a bound Mac,
// the Platform SSO tenant). The record carries no groups, so the gateway's
// own answer stays under it, as on Linux; returning the record alone made
// every group assignment miss on a managed Mac. Guardrail profile explain
// resolves through the same function.
func resolvePeerDirectoryFacts(key string) (useridentity.DirectoryFacts, error) {
	now := time.Now().UTC()
	account, err := osuser.LookupId(key)
	if err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	// Groups that could not be listed fail the lookup: facts cached as
	// resolved without them would select the default profile as "default"
	// for 15 minutes instead of "default_lookup_failed".
	groups, err := accountGroups(account)
	if err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	own := useridentity.DirectoryFacts{
		Directory:  useridentity.DirectoryLocal,
		Source:     useridentity.SourceMacOSOpenDirectory,
		Groups:     groups,
		Assurance:  useridentity.AssuranceVerified,
		ResolvedAt: now,
	}
	if record, ok := readIdentitySpoolFactsForAccount(key, account.Username, now); ok {
		if err := openDirectoryGroupsUnavailable(record, account.Gid, primaryGroupNamed); err != nil {
			return useridentity.DirectoryFacts{}, err
		}
		return mergeSpoolFacts(own, record), nil
	}
	return own, nil
}

// primaryGroupNamed reports whether Open Directory names the group gid.
// Tests replace it.
var primaryGroupNamed = func(gid string) bool {
	group, err := osuser.LookupGroupId(gid)
	return err == nil && group.Name != ""
}
