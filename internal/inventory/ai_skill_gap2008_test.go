// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package inventory

import (
	"os"
	"path/filepath"
	"slices"
	"syscall"
	"testing"
)

// GAP-2008: below a skill folder reached through a linked parent, the walk
// asks the trust for every folder and file it opens, so a link in a home
// cannot make a root scan list or hash what the home owner may not reach.
// An unlinked skill folder still asks nothing.
func TestGAP2008LinkedSkillWalkAsksTrustForEveryEntry(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	real := gap2001Skill(t, home)
	writeSkillFiles(t, filepath.Join(real, "sub"), map[string]string{"notes.txt": "n\n"})
	if err := os.Symlink(filepath.Join(home, "dotfiles", "claude"), filepath.Join(home, ".claude")); err != nil {
		t.Fatal(err)
	}
	var asked []string
	record := func(_ *os.File, path string) bool { asked = append(asked, path); return true }
	if _, status, _, _, _, _ := hashSkillFolderCaptureNamed(real, maxSkillBytes, maxSkillBytes, record, nil); status != SkillContentOK || len(asked) != 0 {
		t.Fatalf("unlinked folder: status %s, asked %v; want ok and no question", status, asked)
	}
	linked := filepath.Join(home, ".claude", "skills", "s")
	if _, status, _, _, _, _ := hashSkillFolderCaptureNamed(linked, maxSkillBytes, maxSkillBytes, record, nil); status != SkillContentOK {
		t.Fatalf("linked parent: status %s", status)
	}
	for _, below := range []string{"SKILL.md", "sub", filepath.Join("sub", "notes.txt")} {
		if !slices.Contains(asked, filepath.Join(real, below)) {
			t.Fatalf("asked %v; want %s below the linked skill folder", asked, below)
		}
	}
	for _, refuse := range []string{filepath.Join(real, "sub"), filepath.Join(real, "sub", "notes.txt"), filepath.Join(real, "SKILL.md")} {
		deny := func(_ *os.File, path string) bool { return path != refuse }
		hash, status, manifest, _, _, _ := hashSkillFolderCaptureNamed(linked, maxSkillBytes, maxSkillBytes, deny, nil)
		if hash != "" || status != SkillContentSymlink || manifest != nil {
			t.Fatalf("untrusted %s below a linked skill folder: %q %s %t; want symlink, no hash, no manifest", refuse, hash, status, manifest != nil)
		}
	}
}

// GAP-2008: the home owner trust approves a file the home owner owns or a
// root file others may read, never a root file kept from them.
func TestGAP2008HomeOwnerTrustFiles(t *testing.T) {
	home := t.TempDir()
	own := filepath.Join(home, "own.txt")
	if err := os.WriteFile(own, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	trust := skillHomeOwnerTrust(home)
	open := func(path string) *os.File {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = file.Close() })
		return file
	}
	if !trust(open(own), own) {
		t.Fatal("the home owner's own file is not trusted")
	}
	readable, kept := gap2008RootFiles(t)
	if readable != "" && !trust(open(readable), readable) {
		t.Fatalf("root file %s others may read is not trusted", readable)
	}
	if kept == "" || os.Geteuid() != 0 {
		return // only root opens a root file kept from others
	}
	if trust(open(kept), kept) {
		t.Fatalf("root file %s kept from others is trusted for a home that is not root's", kept)
	}
}

// gap2008RootFiles finds a root-owned regular file in /etc others may read
// and one they may not.
func gap2008RootFiles(t *testing.T) (readable, kept string) {
	t.Helper()
	entries, err := os.ReadDir("/etc")
	if err != nil {
		return "", ""
	}
	for _, entry := range entries {
		path := filepath.Join("/etc", entry.Name())
		info, err := os.Lstat(path)
		if err != nil || !info.Mode().IsRegular() {
			continue
		}
		st, ok := info.Sys().(*syscall.Stat_t)
		if !ok || st.Uid != 0 {
			continue
		}
		switch {
		case info.Mode().Perm()&0o004 != 0 && readable == "":
			readable = path
		case info.Mode().Perm()&0o004 == 0 && kept == "":
			kept = path
		}
	}
	return readable, kept
}
