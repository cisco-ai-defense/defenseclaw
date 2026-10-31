// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// r106KeysHome is a home with an authorized-keys decoy, a project with an
// ordinary file and a project link to the keys file.
func r106KeysHome(t *testing.T) (homes, home, project string) {
	t.Helper()
	homes = filepath.Join(t.TempDir(), "homes")
	home = filepath.Join(homes, "alice")
	project = filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join(home, ".ssh", "authorized_keys"), filepath.Join(project, "notes.txt")} {
		if err := os.WriteFile(file, []byte("# decoy\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("../.ssh/authorized_keys", filepath.Join(project, "keylink")); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	return homes, home, project
}

// TestR106PosixCommentNamesNoTarget (rel-1-0-6:GAP-0133): a # that starts a
// word comments out the rest of its line, so a protected path that only a
// comment names is no target of the command. A quoted or escaped #, a #
// inside a word, a comment line followed by a real write, and every real
// write to the keys file (plain, quoted, wrapped, through a link) still
// decide.
func TestR106PosixCommentNamesNoTarget(t *testing.T) {
	_, home, project := r106KeysHome(t)
	for _, tc := range []struct {
		command string
		want    string
	}{
		{"echo done # see ~/.ssh/authorized_keys later", ""},
		{"echo done >> notes.txt # see ~/.ssh/authorized_keys later", ""},
		{"echo done >> notes.txt\t#keys live in ~/.ssh/authorized_keys", ""},
		{"echo a > notes.txt\n# then ~/.ssh/authorized_keys\necho b >> notes.txt", ""},
		{"{ echo a; } >> notes.txt # ~/.ssh/authorized_keys", ""},
		{"echo done >> notes.txt; # ~/.ssh/authorized_keys", ""},
		{"echo x >> ~/.ssh/authorized_keys # note", "protected-target"},
		{"echo x >> \"$HOME/.ssh/authorized_keys\" # note", "protected-target"},
		{"echo x >> '" + filepath.Join(home, ".ssh", "authorized_keys") + "' # note", "protected-target"},
		{"bash -c \"echo x >> ~/.ssh/authorized_keys\" # note", "protected-target"},
		{"echo x >> keylink # note", "protected-target"},
		{"echo \"# note\" >> ~/.ssh/authorized_keys", "protected-target"},
		{"echo '#' ~/.ssh/authorized_keys", "protected-target"},
		{"echo \\# ~/.ssh/authorized_keys", "protected-target"},
		{"echo a#b ~/.ssh/authorized_keys", "protected-target"},
		{"echo ok # c\necho x >> ~/.ssh/authorized_keys", "protected-target"},
		{"cat <<EOF >> ~/.ssh/authorized_keys\n# k\nEOF", "protected-target"},
		{"echo a\r#x; cp notes.txt ~/.ssh/authorized_keys", "protected-target"},
		{"echo a\r #x; cp notes.txt ~/.ssh/authorized_keys", ""},
		{"echo a\\ #x; cp notes.txt ~/.ssh/authorized_keys", "protected-target"},
		{"echo ok;# ~/.ssh/authorized_keys", ""},
		{"(echo ok)# ~/.ssh/authorized_keys", ""},
	} {
		if got := ActionCommandDecision(tc.command, project, home); got != tc.want {
			t.Errorf("ActionCommandDecision(%q) = %q, want %q", tc.command, got, tc.want)
		}
	}
}
