// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-2147: whether only administrators can change a skill folder is decided
// from the handle the walk hashes, not from a second open of its path. A user
// who can move the folder cannot make hashed content of their own read as
// managed by putting an administrator's folder at its path while it is read.
func TestGAP2147ManagedIsDecidedFromTheHashedHandle(t *testing.T) {
	base := t.TempDir()
	user, admin, moved := filepath.Join(base, "skills"), filepath.Join(base, "admin"), filepath.Join(base, "moved")
	writeSkillFiles(t, user, map[string]string{"SKILL.md": "---\nname: user\n---\n"})
	writeSkillFiles(t, admin, map[string]string{"SKILL.md": "---\nname: admin\n---\n"})
	adminInfo, err := os.Stat(admin)
	if err != nil {
		t.Fatal(err)
	}
	// Only the administrator's folder reads as managed.
	probe := func(dir *os.File, _ string) bool {
		info, err := dir.Stat()
		return err == nil && os.SameFile(info, adminInfo)
	}
	// While the folder is read, the administrator's folder takes its path.
	swapped := false
	defer func(list func(*os.File, int) ([]os.DirEntry, error)) { skillReadDir = list }(skillReadDir)
	skillReadDir = func(dir *os.File, n int) ([]os.DirEntry, error) {
		if !swapped {
			swapped = true
			if err := os.Rename(user, moved); err != nil {
				t.Fatal(err)
			}
			if err := os.Rename(admin, user); err != nil {
				t.Fatal(err)
			}
		}
		return dir.ReadDir(n)
	}
	_, status, _, _, _, managed := hashSkillFolderCaptureNamed(user, maxSkillBytes, maxSkillBytes, skillHomeOwnerTrust(""), probe)
	if status != SkillContentOK || !swapped {
		t.Fatalf("status %s, swapped %t", status, swapped)
	}
	if managed {
		t.Fatal("the content of the user's folder was reported as managed because another folder took its path")
	}
}

// GAP-2147: the walk reports no decision when none was asked for, and the one
// the probe gives for the folder it hashed when one was.
func TestGAP2147ManagedFollowsTheProbe(t *testing.T) {
	root := t.TempDir()
	writeSkillFiles(t, root, map[string]string{"SKILL.md": "---\nname: s\n---\n"})
	for _, tc := range []struct {
		name  string
		probe func(*os.File, string) bool
		want  bool
	}{
		{"none asked", nil, false},
		{"probe refuses", func(*os.File, string) bool { return false }, false},
		{"probe approves", func(*os.File, string) bool { return true }, true},
	} {
		_, status, _, _, _, managed := hashSkillFolderCaptureNamed(root, maxSkillBytes, maxSkillBytes, skillHomeOwnerTrust(""), tc.probe)
		if status != SkillContentOK || managed != tc.want {
			t.Errorf("%s: status %s, managed %t, want %t", tc.name, status, managed, tc.want)
		}
	}
	// A folder past the scan budget is still decided.
	_, status, _, _, _, managed := hashSkillFolderCaptureNamed(root, 0, maxSkillBytes, skillHomeOwnerTrust(""), func(*os.File, string) bool { return true })
	if status != SkillContentTooLarge || !managed {
		t.Errorf("over budget: status %s, managed %t, want a decision", status, managed)
	}
}
