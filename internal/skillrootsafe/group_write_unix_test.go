//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package skillrootsafe

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// linkedAgentRoot builds ~/.claude -> ~/dotfiles/claude-dir with a skills
// folder and returns the link route, the physical skills folder and the
// folders the link route passes through.
func linkedAgentRoot(t *testing.T) (root, physical, dotfiles string) {
	t.Helper()
	home := t.TempDir()
	dotfiles = filepath.Join(home, "dotfiles")
	physical = filepath.Join(dotfiles, "claude-dir", "skills")
	if err := os.MkdirAll(physical, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dotfiles, "claude-dir"), filepath.Join(home, ".claude")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	for _, dir := range []string{dotfiles, filepath.Dir(physical), physical} {
		if err := os.Chmod(dir, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	physical, err := filepath.EvalSymlinks(physical)
	if err != nil {
		t.Fatal(err)
	}
	return filepath.Join(home, ".claude", "skills"), physical, dotfiles
}

func stubPrivateGroup(t *testing.T, proof func(string, os.FileInfo) bool) {
	t.Helper()
	old := ownerPrivateGroup
	ownerPrivateGroup = proof
	t.Cleanup(func() { ownerPrivateGroup = old })
}

// GAP-0905: Ubuntu's umask 002 gives every folder its owner creates group
// write. A linked skill root through folders only the owner's private group
// can write is admitted; any other group, or other write, keeps the refusal
// and names the folder.
func TestLinkedRootAdmitsFoldersOnlyTheOwnersPrivateGroupWrites(t *testing.T) {
	for _, tc := range []struct {
		name    string
		mode    os.FileMode
		private bool
		final   bool
		wantErr bool
	}{
		{name: "private group ancestor", mode: 0o775, private: true},
		{name: "private group final folder", mode: 0o775, private: true, final: true},
		{name: "plain 0755 ancestor", mode: 0o755},
		{name: "shared group ancestor", mode: 0o775, wantErr: true},
		{name: "shared group final folder", mode: 0o775, final: true, wantErr: true},
		{name: "other writable beats private group", mode: 0o757, private: true, wantErr: true},
		{name: "world writable", mode: 0o777, private: true, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			root, physical, dotfiles := linkedAgentRoot(t)
			dir := dotfiles
			if tc.final {
				dir = physical
			}
			if err := os.Chmod(dir, tc.mode); err != nil {
				t.Fatal(err)
			}
			stubPrivateGroup(t, func(string, os.FileInfo) bool { return tc.private })
			got, err := Resolve(root, nil)
			if !tc.wantErr {
				if err != nil || got != physical {
					t.Fatalf("Resolve = %q, %v, want %q", got, err, physical)
				}
				return
			}
			var writable *WritableAncestorError
			if !errors.As(err, &writable) {
				t.Fatalf("Resolve = %q, %v, want a writable ancestor refusal", got, err)
			}
			if !strings.HasSuffix(writable.Ancestor, filepath.Base(dir)) || !strings.Contains(err.Error(), "chmod go-w") {
				t.Fatalf("refusal %q does not name %s and the fix", err, dir)
			}
		})
	}
}

// The 0755 route needs no group proof at all.
func TestLinkedRootWithoutWritableFoldersAsksNoGroupProof(t *testing.T) {
	root, physical, _ := linkedAgentRoot(t)
	stubPrivateGroup(t, func(path string, _ os.FileInfo) bool {
		t.Errorf("group proof asked for %s", path)
		return false
	})
	if got, err := Resolve(root, nil); err != nil || got != physical {
		t.Fatalf("Resolve = %q, %v, want %q", got, err, physical)
	}
}

// The real proof on this account: where the account has a private group, a
// default-mode (0775) dotfiles folder is accepted.
func TestLinkedRootAcceptsADefaultModeFolderOfARealPrivateGroup(t *testing.T) {
	root, physical, dotfiles := linkedAgentRoot(t)
	if err := os.Chmod(dotfiles, 0o775); err != nil {
		t.Fatal(err)
	}
	info, err := os.Lstat(dotfiles)
	if err != nil {
		t.Fatal(err)
	}
	if !ownerPrivateGroup(dotfiles, info) {
		t.Skip("the test account has no private group")
	}
	if got, err := Resolve(root, nil); err != nil || got != physical {
		t.Fatalf("Resolve = %q, %v, want %q", got, err, physical)
	}
}
