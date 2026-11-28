// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package claudecodepath

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// A Claude Code skill folder reached through a directory junction in the user
// skills root is a skill Claude Code loads, so discovery lists it at the
// folder the junction names, once, as for a symbolic link (rel-1-0-10:GAP-2193).
func TestGAP2193SkillDirsFollowsAJunctionedSkillFolder(t *testing.T) {
	base := t.TempDir()
	root := filepath.Join(base, ".claude", "skills")
	target := filepath.Join(base, "dotfiles", "skills", "linked-skill")
	for _, dir := range []string{root, target} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(target, "SKILL.md"), []byte("---\nname: linked-skill\n---\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(root, "linked-skill")
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", link, target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	// A second junction to the same folder is an alias of the same skill.
	if out, err := exec.Command("cmd", "/c", "mklink", "/J", filepath.Join(root, "alias"), target).CombinedOutput(); err != nil {
		t.Fatalf("mklink /J: %v: %s", err, out)
	}
	if info, err := os.Lstat(link); err != nil || info.Mode()&os.ModeIrregular == 0 {
		t.Fatalf("Lstat(junction) = %v, %v; want an irregular entry", info, err)
	}
	want, err := os.Stat(target)
	if err != nil {
		t.Fatal(err)
	}
	got := SkillDirs(root)
	if len(got) != 1 {
		t.Fatalf("SkillDirs() = %v, want the one junctioned skill folder", got)
	}
	info, err := os.Stat(got[0])
	if err != nil || !os.SameFile(info, want) {
		t.Fatalf("SkillDirs() = %v (%v), want the folder the junction names %s", got, err, target)
	}
}
