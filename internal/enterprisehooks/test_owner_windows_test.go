// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import "github.com/defenseclaw/defenseclaw/internal/testenv"

// ownTestObjectsAsTokenUser makes the test account the default owner of every
// fixture, before the first one exists. The fixtures build a home tree with
// the test process's own token and then target the test account's SID. As
// the elevated built-in Administrator (an SSH or S4U session, an elevated
// prompt) that token's default owner is BUILTIN\Administrators, so every new
// folder and file was Administrators-owned and 26 tests failed with
// "refusing to canonicalize wrong-owner path (owner S-1-5-32-544, target
// <user SID>)" (GAP-0684). In production the per-user tree belongs to its
// user: the per-user processes own what they create as their user
// (managed.UseCurrentUserAsWindowsDefaultOwner), and the LocalSystem guardian
// hands an administrator-owned element back to the target
// (reclaimWindowsGuardianACLOwner). A standard user's and LocalSystem's
// tokens already default to their own account.
func ownTestObjectsAsTokenUser() error {
	_, err := testenv.OwnNewObjectsAsTokenUser()
	return err
}
