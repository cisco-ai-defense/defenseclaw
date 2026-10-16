// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import "testing"

// GAP-0644: the Secure Client profile never defers a protected target to a
// sign-in, so the release check answers no without reading the target; on a
// standalone host a target it cannot pin to its profile is no wait either.
func TestWindowsProtectedTargetFromOtherReleaseStandaloneOnly(t *testing.T) {
	previous := windowsEnterpriseStandaloneProcess
	t.Cleanup(func() { windowsEnterpriseStandaloneProcess = previous })
	opts := InstallOptions{ConnectorName: "codex", UserHome: `C:\Users\does-not-exist`, OwnerSID: "S-1-12-1-1-2-3-1002"}
	windowsEnterpriseStandaloneProcess = func() bool { return false }
	if written, other, err := WindowsProtectedTargetFromOtherRelease(opts); written != "" || other || err != nil {
		t.Fatalf("Secure Client: %q %t %v, want no wait and no error", written, other, err)
	}
	windowsEnterpriseStandaloneProcess = func() bool { return true }
	if _, other, err := WindowsProtectedTargetFromOtherRelease(opts); other || err == nil {
		t.Fatalf("standalone, unpinned profile: other=%t err=%v, want an error and no wait", other, err)
	}
}
