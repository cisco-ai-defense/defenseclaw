// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-1739: an unreadable sibling directory made every glob in a write
// position unproved, so a benign `cp payload */payl*` was an SSH
// authorized keys mutation in action mode. A process that runs as the user
// cannot list what the user's shell cannot list either, so the shell
// expands nothing there; a match found beside it still decides (GAP-1481).
func TestActionGlobUnreadableSiblingOfTheUserHoldsNoMatch(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root reads every directory")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(cwd, "other"), filepath.Join(cwd, "aaa_unread"), filepath.Join(cwd, "a")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, file := range []string{keys, filepath.Join(cwd, "payload")} {
		if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(keys, filepath.Join(cwd, "a", "keylink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(filepath.Join(cwd, "aaa_unread"), 0); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(cwd, "aaa_unread"), 0o700) })
	for _, tc := range []struct{ command, want string }{
		{"cp payload */payl*", ""},
		{"cp payload */keyl*", "protected-target"},
		{"cp payload a/*", "protected-target"},
	} {
		if got := ActionCommandDecision(tc.command, cwd, home); got != tc.want {
			t.Errorf("ActionCommandDecision(%q) = %q, want %q", tc.command, got, tc.want)
		}
	}
}
