//go:build !linux && !darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os/user"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// userScopedIdentityName names the account a per-user credential is bound
// to: the SID's account on Windows, by its sAMAccountName even while the
// LSA answers the UPN its user signed in with (GAP-0382).
var userScopedIdentityName = useridentity.CanonicalNameForID

// userScopedIdentityForName is the identity (SID) of the account an
// account name names now, or false when none has it.
var userScopedIdentityForName = func(name string) (string, bool) {
	account, err := user.Lookup(strings.TrimSpace(name))
	if err != nil || account == nil {
		return "", false
	}
	return connector.CanonicalUserScopedIdentity(account.Uid)
}

// userScopedIdentityHome is the profile directory of the account a per-user
// credential is bound to (the SID's ProfileList entry on Windows), or "".
var userScopedIdentityHome = useridentity.HomeForID

// agentIdentityAccountName names no account on Windows: an agent identity
// is keyed on a SID, which no other account ever gets.
var agentIdentityAccountName = func(string) string { return "" }

// agentIdentityIncarnation keys no agent identity on an account incarnation
// on Windows, for the same reason.
var agentIdentityIncarnation = func(string) string { return "" }

// agentIdentityAccountToken and agentIdentityHolderHistory name no account
// token here: a SID is never handed to another account.
var agentIdentityAccountToken = func(string) string { return "" }

var agentIdentityVerifiedAccountToken = func(string) string { return "" }

var agentIdentityHolderHistory = func(string) (string, bool) { return "", false }

var agentIdentityAdminHolderToken = func(string, string) (string, bool) { return "", false }

// legacyAgentOwnerBound binds no 1.0.3 agent identity here: Windows keyed
// them on the SID, which did not change, so its agents entries match as
// they did.
var legacyAgentOwnerBound = func(string, string) bool { return false }

// managedHookPeerLastName keeps no last name off Linux and macOS, where no
// sandbox runs.
var managedHookPeerLastName = func(int) string { return "" }

// setManagedHookPeerHomeStore persists nothing on Windows: a profile path
// comes from the SID's ProfileList entry, not from a directory lookup.
func setManagedHookPeerHomeStore(string) {}
