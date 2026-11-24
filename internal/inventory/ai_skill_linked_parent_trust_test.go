// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package inventory

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-2001 hardening: a resolved parent chain is used only when every folder
// on it, the skill folder included, is trusted; an unlinked path asks
// nothing; a linked skill folder stays refused.
func TestGAP2001ResolvedParentNeedsTrustedOwners(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	real := gap2001Skill(t, home)
	if err := os.Symlink(filepath.Join(home, "dotfiles", "claude"), filepath.Join(home, ".claude")); err != nil {
		t.Fatal(err)
	}
	var asked []string
	record := func(_ *os.File, path string) bool { asked = append(asked, path); return true }
	if _, status, _, _, _, _ := hashSkillFolderCaptureNamed(real, maxSkillBytes, maxSkillBytes, record, nil); status != SkillContentOK || len(asked) != 0 {
		t.Fatalf("unlinked folder: status %s, asked %v; want ok and no question", status, asked)
	}
	linked := filepath.Join(home, ".claude", "skills", "s")
	_, status, manifest, manifestPath, _, _ := hashSkillFolderCaptureNamed(linked, maxSkillBytes, maxSkillBytes, record, nil)
	if status != SkillContentOK || manifest == nil || manifestPath != filepath.Join(real, "SKILL.md") {
		t.Fatalf("linked parent: status %s, manifest %t, path %s", status, manifest != nil, manifestPath)
	}
	// The chain from / to the skill folder first, then (GAP-2008) every entry
	// the walk opens below it.
	chain := strings.Count(real, "/") + 1
	if len(asked) <= chain || asked[0] != "/" || asked[chain-1] != real {
		t.Fatalf("asked %v; want every folder from / to %s, then the entries below it", asked, real)
	}
	for _, below := range asked[chain:] {
		if !strings.HasPrefix(below, real+"/") {
			t.Fatalf("asked %s after the chain; want only entries below %s", below, real)
		}
	}
	for _, refuse := range []string{real, filepath.Dir(real), "/"} {
		deny := func(_ *os.File, path string) bool { return path != refuse }
		if hash, status, manifest, _, read, _ := hashSkillFolderCaptureNamed(linked, maxSkillBytes, maxSkillBytes, deny, nil); hash != "" || status != SkillContentSymlink || manifest != nil || read != 0 {
			t.Fatalf("untrusted %s: %q %s %t %d; want symlink and no read", refuse, hash, status, manifest != nil, read)
		}
	}
	link := filepath.Join(home, "dotfiles", "claude", "skills", "link")
	if err := os.Symlink(real, link); err != nil {
		t.Fatal(err)
	}
	if hash, status, _, _, _, _ := hashSkillFolderCaptureNamed(filepath.Join(home, ".claude", "skills", "link"), maxSkillBytes, maxSkillBytes, record, nil); hash != "" || status != SkillContentSymlink {
		t.Fatalf("linked skill folder below a linked parent = %q, %s", hash, status)
	}
}

// The default trust accepts the home owner's folders and root's searchable
// ones, never a folder root keeps to itself.
func TestGAP2001HomeOwnerTrust(t *testing.T) {
	home := t.TempDir()
	trust := skillHomeOwnerTrust(home)
	open := func(path string) *os.File {
		file, err := os.Open(path)
		if err != nil {
			t.Fatal(err)
		}
		t.Cleanup(func() { _ = file.Close() })
		return file
	}
	if !trust(open(home), home) || !trust(open("/"), "/") {
		t.Fatal("the home owner's folder or / is not trusted")
	}
	if info, err := os.Stat("/root"); err == nil && info.Mode().Perm()&0o001 == 0 && os.Geteuid() != 0 {
		if file, err := os.Open("/root"); err == nil {
			defer file.Close()
			if trust(file, "/root") {
				t.Fatal("/root is trusted for a home that is not root's")
			}
		}
	}
	if skillHomeOwnerTrust(filepath.Join(home, "missing"))(open(home), home) {
		t.Fatal("a home that cannot be read trusts its folders")
	}
}
