// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// TestRecursiveKeyDirectoryReadWhenHomeIsUnreadable pins GAP-2565: a gateway
// that cannot walk the caller's home (ProtectHome, the managed macOS service
// account) reads a recursive grep or rg of the SSH directory, spelled as
// itself, as the key read the per-user gateway blocks. Named files below it
// and project directories stay plain reads.
func TestRecursiveKeyDirectoryReadWhenHomeIsUnreadable(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged walk")
	}
	root := t.TempDir()
	homes := filepath.Join(root, "homes")
	home := filepath.Join(homes, "eng1")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(home, "project")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join(home, ".ssh", "id_ed25519"), filepath.Join(home, ".ssh", "config")} {
		if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	project := filepath.Join(home, "project")
	rows := []struct {
		command string
		read    bool
	}{
		{"grep -r . ~/.ssh", true},
		{"grep -r . " + home + "/.ssh", true},
		{"grep -r . " + home + "/.ssh/", true},
		{"grep -rn . ~/.ssh", true},
		{"rg . ~/.ssh", true},
		{"grep -R PRIVATE ~/.ssh", true},
		{"grep -r . ../.ssh", true},
		{"grep -r Host ~/.ssh/config", false},
		{"grep -r TODO .", false},
		{"grep -r TODO ~/project", false},
		{"grep TODO ~/.sshnotes", false},
		{"ls -la ~/.ssh", false},
	}
	// The managed macOS service account can name the home (/Users is
	// listable) but not search it; a ProtectHome gateway cannot name it.
	locked := map[string]string{"readable": "", "home": home, "homes": homes}
	for _, view := range []string{"readable", "home", "homes"} {
		for _, dir := range []string{homes, home} {
			if err := os.Chmod(dir, 0o700); err != nil {
				t.Fatal(err)
			}
		}
		if dir := locked[view]; dir != "" {
			if err := os.Chmod(dir, 0); err != nil {
				t.Fatal(err)
			}
		}
		for _, row := range rows {
			if got := ActionPrivateKeyRead(row.command, project, home); got != row.read {
				t.Errorf("locked=%s %q: key read=%v, want %v", view, row.command, got, row.read)
			}
		}
	}
	for _, dir := range []string{homes, home} {
		if err := os.Chmod(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
}
