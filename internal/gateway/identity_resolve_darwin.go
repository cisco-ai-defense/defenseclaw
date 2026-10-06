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
// root enumerator's Open Directory record when the guardian wrote one (a
// managed install), otherwise the account's groups from the system account
// database, which on macOS answers through Open Directory. The fallback
// keeps users and groups assignments working on a per-user install, and
// matches what guardrail profile explain resolves there.
func resolvePeerDirectoryFacts(key string) (useridentity.DirectoryFacts, error) {
	now := time.Now().UTC()
	if record, ok := readIdentitySpoolFacts(key, now); ok {
		facts := record.Facts
		facts.Assurance = useridentity.AssuranceVerified
		return facts, nil
	}
	account, err := osuser.LookupId(key)
	if err != nil {
		return useridentity.DirectoryFacts{}, err
	}
	return useridentity.DirectoryFacts{
		Directory:  useridentity.DirectoryLocal,
		Source:     useridentity.SourceMacOSOpenDirectory,
		Groups:     localAccountGroups(account),
		Assurance:  useridentity.AssuranceVerified,
		ResolvedAt: now,
	}, nil
}
