// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"testing"
)

// GAP-0644: a protected target an earlier release wrote waits for its
// account's next sign-in on both profiles (a Secure Client upgrade with a
// signed-out enrolled account failed the same way), so the release check
// reads the target on both; one it cannot pin to its profile is no wait.
func TestWindowsProtectedTargetFromOtherReleaseReadsTheTargetOnBothProfiles(t *testing.T) {
	previous := windowsEnterpriseStandaloneProcess
	t.Cleanup(func() { windowsEnterpriseStandaloneProcess = previous })
	opts := InstallOptions{ConnectorName: "codex", UserHome: `C:\Users\does-not-exist`, OwnerSID: "S-1-12-1-1-2-3-1002"}
	for _, standalone := range []bool{false, true} {
		windowsEnterpriseStandaloneProcess = func() bool { return standalone }
		if _, other, err := WindowsProtectedTargetFromOtherRelease(opts); other || err == nil {
			t.Fatalf("standalone=%t, unpinned profile: other=%t err=%v, want an error and no wait", standalone, other, err)
		}
		if WindowsSecureClientProfileProcess() == standalone {
			t.Fatalf("standalone=%t: WindowsSecureClientProfileProcess = %t", standalone, !standalone)
		}
	}
}

// Setup's verify runs outside LocalSystem; only that exact refusal is
// recognised, wrapped or not.
func TestIsWindowsEnterpriseNotLocalSystem(t *testing.T) {
	if !IsWindowsEnterpriseNotLocalSystem(errWindowsEnterpriseNotLocalSystem) ||
		!IsWindowsEnterpriseNotLocalSystem(fmt.Errorf("session check: %w", errWindowsEnterpriseNotLocalSystem)) {
		t.Fatal("the not-LocalSystem refusal was not recognised")
	}
	if IsWindowsEnterpriseNotLocalSystem(errors.New("enterprise hooks: WTS query failed: access is denied")) ||
		IsWindowsEnterpriseNotLocalSystem(nil) {
		t.Fatal("another error was taken for the not-LocalSystem refusal")
	}
}
