// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"strings"
	"testing"
)

// Each platform gets the status command its own lifecycle has, by absolute
// path, and never another platform command.
func TestAdminStatusHintNamesTheCommandOfThePlatform(t *testing.T) {
	for goos, want := range map[string]string{
		"linux":   "`sudo /opt/defenseclaw/bin/defenseclaw-gateway enterprise linux status`",
		"darwin":  "enterprise macos status`",
		"windows": "enterprise windows status --profile standalone` in an elevated PowerShell prompt",
	} {
		got := AdminStatusHint(goos)
		if !strings.Contains(got, want) {
			t.Errorf("AdminStatusHint(%q) = %q, want it to contain %q", goos, got, want)
		}
		if strings.Contains(got, "defenseclaw-managed") {
			t.Errorf("AdminStatusHint(%q) = %q names a command that does not exist", goos, got)
		}
	}
	if windows := AdminStatusHint("windows"); !strings.Contains(windows, "& \x27") || !strings.Contains(windows, "defenseclaw.exe\x27") {
		t.Errorf("the Windows hint %q does not run the managed CLI by its path in PowerShell", windows)
	}
	for _, goos := range []string{"linux", "darwin"} {
		if hint := AdminStatusHint(goos); !strings.HasPrefix(hint, "`sudo ") || strings.Contains(hint, "windows") {
			t.Errorf("AdminStatusHint(%q) = %q is not a sudo command of that platform", goos, hint)
		}
	}
}
