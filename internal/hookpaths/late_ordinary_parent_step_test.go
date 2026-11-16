// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// A ".." step in an operand goes to the parent of the physical folder in front
// of it, as the file system does. A call that only reaches an ordinary file
// that way is ordinary (the open tier of a late call allows it); a step that
// ends at a protected file, a link to one, the home or a parent of it, or at
// anything below a file, is not.
func TestLateOrdinaryCallStepsThroughParentFolders(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	home := filepath.Join(root, "h")
	plain := filepath.Join(root, "plain")
	child := filepath.Join(plain, "child")
	other := filepath.Join(root, "other")
	linkedChild := filepath.Join(other, "child")
	for _, dir := range []string{filepath.Join(home, ".ssh"), child, linkedChild} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for path, data := range map[string]string{
		keys:                              "decoy",
		filepath.Join(plain, "status"):    "ordinary",
		filepath.Join(other, "status"):    "ordinary",
		filepath.Join(child, "plain.txt"): "x",
	} {
		if err := os.WriteFile(path, []byte(data), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	jump := filepath.Join(plain, "jump")
	if err := os.Symlink(linkedChild, jump); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	if err := os.Symlink(keys, filepath.Join(plain, "keylink")); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(keys, filepath.Join(plain, "hardlink")); err != nil {
		t.Skipf("hard link unavailable: %v", err)
	}
	t.Setenv("HOME", home)
	for _, tc := range []struct {
		name, cwd, command string
		want               bool
	}{
		{"parent file", child, "cat ../status", true},
		{"parent file after a dot", child, "cat ./../status", true},
		{"parent file in an option value", child, "grep --file=../status x", true},
		{"parent file after a name", child, "cat plain.txt ../status", true},
		{"parent of the physical folder behind a link", jump, "cat ../status", true},
		{"parent step inside the operand", plain, "cat child/../status", true},
		{"parent step behind a link inside the operand", plain, "cat jump/../status", true},
		{"missing name before the step", plain, "cat nothing-here/../status", true},
		// Protected or unproved targets stay closed.
		{"keys by a parent path", child, "cat ../../h/.ssh/authorized_keys", false},
		{"link to the keys in the parent", child, "cat ../keylink", false},
		{"hard link to the keys in the parent", child, "cat ../hardlink", false},
		{"the home itself", child, "ls ../../h", false},
		{"a parent of the home", child, "ls ../..", false},
		{"parent step below a file", plain, "cat status/../x", false},
		{"link to the keys behind a step", plain, "cat child/../keylink", false},
		{"link to the keys in an option value", child, "grep --file=../keylink x", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			for _, connector := range []string{"claudecode", "codex"} {
				payload := lateBash(t, "Bash", tc.cwd, tc.command)
				if got := LateOrdinaryCall(connector, payload); got != tc.want {
					t.Errorf("%s: ordinary=%v, want %v, command=%q in %s", connector, got, tc.want, tc.command, tc.cwd)
				}
			}
		})
	}
}

// The process home is not always the account home (a hook run with a scratch
// HOME): the scan indexes the protected files of both, so a hard link to the
// account's keys file stays closed whichever home the process reports.
func TestLateOrdinaryCallIndexesBothHomes(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	account := filepath.Join(root, "account")
	scratch := filepath.Join(root, "scratch")
	project := filepath.Join(root, "project")
	for _, dir := range []string{filepath.Join(account, ".ssh"), scratch, project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(account, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("decoy"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(project, "plain.txt"), []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Link(keys, filepath.Join(project, "alias")); err != nil {
		t.Skipf("hard link unavailable: %v", err)
	}
	if err := os.Link(filepath.Join(project, "plain.txt"), filepath.Join(project, "plain-alias")); err != nil {
		t.Skipf("hard link unavailable: %v", err)
	}
	t.Setenv("HOME", scratch)
	restore := accountHomeDir
	accountHomeDir = func() (string, error) { return account, nil }
	t.Cleanup(func() { accountHomeDir = restore })
	for _, tc := range []struct {
		name, command string
		want          bool
	}{
		{"hard link to the account keys", "cat alias", false},
		{"hard link to the account keys by absolute path", "cat " + filepath.Join(project, "alias"), false},
		{"plain file", "cat plain.txt", true},
		{"hard link to an ordinary file", "cat plain-alias", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			payload := lateBash(t, "Bash", project, tc.command)
			if got := LateOrdinaryCall("claudecode", payload); got != tc.want {
				t.Errorf("ordinary=%v, want %v, command=%q", got, tc.want, tc.command)
			}
		})
	}
}
