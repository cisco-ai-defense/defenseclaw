// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-1725: with a home below a linked directory and no ~/.ssh yet, a write
// that creates ~/.ssh/authorized_keys was allowed: the target was compared
// in its resolved form, the protected list in the home's spelling, and a
// file that does not exist has no identity to compare. The protected list
// now has the resolved form of each key file too.
func TestActionLinkedHomeProtectsAKeyFileBeforeItExists(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	real := filepath.Join(root, "real")
	if err := os.MkdirAll(filepath.Join(real, "h", "project"), 0o700); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(link, "h")
	cwd := filepath.Join(home, "project")
	for _, command := range []string{
		"echo k >> ~/.ssh/authorized_keys",
		"cp payload ~/.ssh/authorized_keys",
		"mkdir -p ~/.ssh && echo k >> ~/.ssh/authorized_keys",
		"echo k > " + filepath.Join(real, "h", ".ssh", "authorized_keys2"),
	} {
		if got := ActionCommandDecision(command, cwd, home); got != "protected-target" {
			t.Errorf("ActionCommandDecision(%q) = %q, want protected-target", command, got)
		}
	}
	if got := ActionCommandDecision("echo k >> notes.txt", cwd, home); got != "" {
		t.Errorf("a project write = %q, want allow", got)
	}
}
