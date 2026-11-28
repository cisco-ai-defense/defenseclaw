// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package testenv

import (
	"testing"

	"golang.org/x/sys/windows"
)

// RequireElevated skips a test whose fixture, or whose product writer, only
// an administrator token can build (a BUILTIN\Administrators owner, a
// protected admin-only DACL, a folder under C:\Program Files), saying why. A
// standard user cannot create them, so such a test cannot give the same
// answer as a standard user: the Limited row skips with the reason and the
// elevated twin row (an elevated administrator, or LocalSystem) runs it. Under
// GitHub Actions, or with CI_REQUIRE_ELEVATED=1, a token without the rights
// fails the test instead of skipping, so an elevated gate that lost its rights
// cannot go green on skips.
func RequireElevated(t testing.TB, why string) {
	t.Helper()
	switch action, reason := elevationOutcome(processIsAdministrator(), elevationStrict(), why); action {
	case "skip":
		t.Skip(reason)
	case "fail":
		t.Fatal(reason)
	}
}

// processIsAdministrator reports whether the test process holds an elevated
// administrator token or runs as LocalSystem.
func processIsAdministrator() bool {
	token := windows.GetCurrentProcessToken()
	if token.IsElevated() {
		return true
	}
	user, err := token.GetTokenUser()
	return err == nil && user != nil && user.User.Sid != nil && user.User.Sid.IsWellKnown(windows.WinLocalSystemSid)
}
