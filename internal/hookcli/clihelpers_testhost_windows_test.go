// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookcli

import (
	"testing"

	"golang.org/x/sys/windows"
)

// skipIfLocalSystem skips a test whose fixture cannot hold when it runs as
// LocalSystem, saying why.
func skipIfLocalSystem(t *testing.T, why string) {
	t.Helper()
	if testRunsAsLocalSystem() {
		t.Skip("skipped as LocalSystem: " + why)
	}
}

func testRunsAsLocalSystem() bool {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	return err == nil && user != nil && user.User.Sid != nil && user.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}

// testTokenIsElevated reports whether the test binary's own token is
// elevated. A fixture that needs a privilege (an Administrators owner) asks
// the real token; windowsEnterpriseIsElevated answers for the product and is
// pinned (pinTestProcessIdentity).
func testTokenIsElevated() bool { return windows.GetCurrentProcessToken().IsElevated() }

// requireAdministratorTestToken skips a test whose fixture, or whose product
// writer, only an administrator token can build (a BUILTIN\Administrators
// owner, or a protected admin-only object), saying why. A standard user
// cannot create them, so the test cannot give the same answer as a standard
// user (GAP-0079); the elevated CI runner, an elevated administrator and
// LocalSystem run it. A folder under C:\ProgramData alone does not need it:
// BUILTIN\Users can create one.
func requireAdministratorTestToken(t *testing.T, why string) {
	t.Helper()
	if !testTokenIsElevated() && !testRunsAsLocalSystem() {
		t.Skip("needs an administrator token: " + why)
	}
}
