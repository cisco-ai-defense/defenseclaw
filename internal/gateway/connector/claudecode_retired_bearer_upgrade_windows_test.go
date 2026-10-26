// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"testing"

	"golang.org/x/sys/windows"
)

// Elevated Windows runners otherwise create temporary fixtures owned by the
// Administrators group, which the target-user writer correctly refuses.
func pinClaudeUpgradeTestOwner(t *testing.T, path string) {
	t.Helper()
	owner := windowsProcessUserSIDForTest(t)
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION, owner, nil, nil, nil); err != nil {
		t.Fatalf("set fixture owner: %v", err)
	}
}
