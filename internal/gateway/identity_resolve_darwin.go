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
	record, haveRecord := readIdentitySpoolFacts(key, now)
	account, err := osuser.LookupId(key)
	if err != nil {
		if haveRecord {
			return mergeSpoolFacts(useridentity.DirectoryFacts{}, record.Facts), nil
		}
		return useridentity.DirectoryFacts{}, err
	}
	own := useridentity.DirectoryFacts{
		Directory:  useridentity.DirectoryLocal,
		Source:     useridentity.SourceMacOSOpenDirectory,
		Groups:     localAccountGroups(account),
		Assurance:  useridentity.AssuranceVerified,
		ResolvedAt: now,
	}
	if haveRecord {
		return mergeSpoolFacts(own, record.Facts), nil
	}
	return own, nil
}
