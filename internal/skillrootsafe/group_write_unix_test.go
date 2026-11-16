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

func stubPAMGroup(t *testing.T, loaded func() bool) {
	t.Helper()
	old := pamGroupLoaded
	pamGroupLoaded = loaded
	t.Cleanup(func() { pamGroupLoaded = old })
}

// GAP-0905: where pam_group is loaded it can add an account to a group at
// login, so the private group of the owner is no proof that nobody else writes
// the folder. The root is still admitted, never refused, and the folder is
// returned so the watcher scans the root again on every change and the user is
// told to run chmod g-w. Where the module is not loaded the root is trusted
// with no warning.
func TestLinkedRootThroughAPrivateGroupWarnsOnlyWhereThePAMGroupModuleIsLoaded(t *testing.T) {
	for _, tc := range []struct {
		name       string
		mode       os.FileMode
		private    bool
		pamLoaded  bool
		final      bool
		wantWarn   bool
		wantErr    bool
		wantPAMAsk bool
	}{
		{name: "private group, module not loaded", mode: 0o775, private: true, wantPAMAsk: true},
		{name: "private group, module loaded", mode: 0o775, private: true, pamLoaded: true, wantWarn: true, wantPAMAsk: true},
		{name: "private group final folder, module loaded", mode: 0o775, private: true, pamLoaded: true, final: true, wantWarn: true, wantPAMAsk: true},
		{name: "plain 0755 route, module loaded", mode: 0o755, pamLoaded: true},
		{name: "shared group, module loaded is still refused", mode: 0o775, pamLoaded: true, wantErr: true},
		{name: "other write, module loaded is still refused", mode: 0o757, private: true, pamLoaded: true, wantErr: true},
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
			wantFolder, err := filepath.EvalSymlinks(dir)
			if err != nil {
				t.Fatal(err)
			}
			stubPrivateGroup(t, func(string, os.FileInfo) bool { return tc.private })
			asked := false
			stubPAMGroup(t, func() bool { asked = true; return tc.pamLoaded })
			got, warnings, err := ResolveWithWarnings(root, nil)
			if tc.wantErr {
				var writable *WritableAncestorError
				if !errors.As(err, &writable) {
					t.Fatalf("ResolveWithWarnings = %q, %v, %v, want a writable ancestor refusal", got, warnings, err)
				}
				return
			}
			if err != nil || got != physical {
				t.Fatalf("ResolveWithWarnings = %q, %v, %v, want %q admitted", got, warnings, err, physical)
			}
			if tc.wantWarn != (len(warnings) > 0) || (tc.wantWarn && (len(warnings) != 1 || warnings[0] != wantFolder)) {
				t.Fatalf("warnings = %v, want [%s] = %v", warnings, wantFolder, tc.wantWarn)
			}
			if asked != tc.wantPAMAsk {
				t.Fatalf("pam_group asked = %v, want %v", asked, tc.wantPAMAsk)
			}
			// Resolve admits the same root and never asks about the module.
			asked = false
			if plain, err := Resolve(root, nil); err != nil || plain != physical || asked {
				t.Fatalf("Resolve = %q, %v (pam asked %v), want %q admitted without asking", plain, err, asked, physical)
			}
		})
	}
}
