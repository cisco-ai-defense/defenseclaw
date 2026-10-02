// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"path/filepath"
	"testing"
)

// GAP-1364: a DefenseClaw launcher renamed in place stays DefenseClaw's, so
// repair replaces it; the same name in any other directory is never claimed.
func TestRenamedDefenseClawHookExecutable(t *testing.T) {
	binDir := filepath.Join(t.TempDir(), "bin")
	defer PinNativeHookExecutableForTest(filepath.Join(binDir, "defenseclaw-hook.exe"))()

	for _, tc := range []struct {
		exe  string
		want bool
	}{
		{filepath.Join(binDir, "defenseclaw-hook-renamed.exe"), true},
		{filepath.Join(binDir, "DefenseClaw-Hook2.exe"), true},
		{filepath.Join(binDir, "other-hook.exe"), false},
		{filepath.Join(t.TempDir(), "defenseclaw-hook-renamed.exe"), false},
		{"defenseclaw-hook-renamed.exe", false},
		{"", false},
	} {
		if got := isRenamedDefenseClawHookExecutable(tc.exe); got != tc.want {
			t.Errorf("isRenamedDefenseClawHookExecutable(%q) = %v, want %v", tc.exe, got, tc.want)
		}
	}
}
