// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package tactics

import "testing"

func TestRunsProgramLauncherChildren(t *testing.T) {
	for _, tc := range []struct {
		command string
		want    bool
	}{
		{"find . -exec apply_patch < patch.txt \\; | head", true},
		{"flock lockfile apply_patch < patch.txt | head", true},
		{"watch -n 1 apply_patch | head", true},
		{"su -c 'apply_patch < patch.txt' | head", true},
		{"chrt -i 0 apply_patch | head", true},
		{"parallel apply_patch ::: x | head", true},
		{"systemd-run --scope apply_patch | head", true},
		{"find . -exec echo apply_patch \\; | head", false},
		{"find . -exec apply_patch < patch.txt", false},
		{"find . -exec apply_patch < patch.txt ;", false},
		{"find . -execdir apply_patch < patch.txt", false},
		{"flock lockfile echo apply_patch | head", false},
		{"watch echo apply_patch | head", false},
		{"su -c 'echo apply_patch' | head", false},
		{"chrt -i 0 echo apply_patch | head", false},
		{"parallel echo ::: apply_patch | head", false},
		{"systemd-run echo apply_patch | head", false},
	} {
		if got := RunsProgramIncludingLaunchers(tc.command, "apply_patch"); got != tc.want {
			t.Errorf("launcher child for %q: %t, want %t", tc.command, got, tc.want)
		}
	}
}

func TestRunsProgramKeepsShellLevelMeaning(t *testing.T) {
	if RunsProgram("find . -exec mv {} build/ \\;", "mv") {
		t.Fatal("find child is not a direct shell command")
	}
	if !RunsProgramIncludingLaunchers("find . -exec mv {} build/ \\;", "mv") {
		t.Fatal("launcher-aware reading missed the child")
	}
}
