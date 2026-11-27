// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
)

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

// requireElevatedManagedWindows skips a test of the native Windows managed
// install on a standard-user token. The install, its runtime generations and
// the guardian's folder repairs refuse any caller that is not an elevated
// administrator or LocalSystem ("native Windows managed policy install
// requires an elevated administrator or LocalSystem token"), and the fixtures
// give objects an Administrators owner, which a standard user cannot assign
// ("This security ID may not be assigned as the owner of this object"). That
// refusal is the product's contract, so no fixture the token owns can satisfy
// it: the 174 tests that call this ran 174 of 174 green on the same merge
// under the elevated token and were red under the standard one (GAP-2108).
// The Windows CI runners and the native test hosts run them elevated.
func requireElevatedManagedWindows(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token: the managed install refuses a standard user and its fixtures are Administrators-owned")
	}
}
