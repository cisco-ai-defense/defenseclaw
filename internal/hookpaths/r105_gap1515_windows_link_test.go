// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-1515: on a native Windows home the target scan compared words
// lexically, so a cwd alias of authorized_keys (a symbolic link or a
// junction to .ssh) let `echo marker >> alias` through in action mode. The
// scan follows the links of a resolved word on the Windows file system.
func TestActionWindowsWordFollowsALinkToTheKeyFile(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(cwd, "alias")); err != nil {
		t.Skipf("no symbolic link privilege: %v", err)
	}
	for _, command := range []string{"echo marker >> alias", "Add-Content -Path alias -Value marker"} {
		if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
			t.Errorf("ActionCommandDecision(%q) = %q, want protected-target", command, got)
		}
	}
	if got := ActionCommandDecision("echo marker >> notes.txt", cwd, home); got != "" {
		t.Errorf("a project write = %q, want allow", got)
	}
}
