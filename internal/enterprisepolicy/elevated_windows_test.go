// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisepolicy

import (
	"testing"

	"golang.org/x/sys/windows"
)

// requireElevatedMachinePolicyWindows skips a test that publishes machine
// policy on Windows below an elevated token. Every directory the publisher
// creates is born with the Administrators owner and a protected DACL
// (createProtectedDir), which a standard user cannot assign ("This security
// ID may not be assigned as the owner of this object", GAP-2240), and the real
// guardian that runs it is an administrator or LocalSystem. No fixture the
// token owns satisfies that, so these tests run in the elevated native leg
// and on the Windows CI runners; the tests that only read policy run in both.
func requireElevatedMachinePolicyWindows(t *testing.T) {
	t.Helper()
	if !windows.GetCurrentProcessToken().IsElevated() {
		t.Skip("needs an elevated token: published machine-policy folders are Administrators-owned, which a standard user cannot assign")
	}
}
