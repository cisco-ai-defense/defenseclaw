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
