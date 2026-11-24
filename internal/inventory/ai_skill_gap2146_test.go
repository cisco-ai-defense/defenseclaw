// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package inventory

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-2146 (a): a folder root owns is trusted only when others may list and
// search it, as Windows asks LIST and TRAVERSE: the walk lists every folder it
// approves, so a 0711 folder (search by name only) must not pass.
func TestGAP2146RootFolderNeedsListAndSearch(t *testing.T) {
	const root, owner, other = 0, 501, 502
	for _, tc := range []struct {
		name string
		mode os.FileMode
		uid  uint32
		want bool
	}{
		{"root folder 0755", os.ModeDir | 0o755, root, true},
		{"root folder 0711, search only", os.ModeDir | 0o711, root, false},
		{"root folder 0744, list only", os.ModeDir | 0o744, root, false},
		{"root folder 0700", os.ModeDir | 0o700, root, false},
		{"owner folder 0700", os.ModeDir | 0o700, owner, true},
		{"other account folder 0755", os.ModeDir | 0o755, other, false},
		{"root file 0644", 0o644, root, true},
		{"root file 0640", 0o640, root, false},
		{"owner file 0600", 0o600, owner, true},
		{"other account file 0644", 0o644, other, false},
		{"root device", os.ModeDevice | 0o666, root, false},
		{"owner socket", os.ModeSocket | 0o600, owner, false},
	} {
		if got := skillTrusted(tc.mode, tc.uid, owner); got != tc.want {
			t.Errorf("%s: trusted = %t, want %t", tc.name, got, tc.want)
		}
	}
}

// GAP-2146 (c): below a skill folder with no trust of its own, a file with
// more than one name is asked about, because its other name may be a file only
// a root scan can read (macOS has no protected hard links). A file with one
// name is never asked.
func TestGAP2146HardLinkedFileInAnUnlinkedSkillAsksTrust(t *testing.T) {
	dir := t.TempDir()
	elsewhere := filepath.Join(dir, "elsewhere.txt")
	if err := os.WriteFile(elsewhere, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	skill := filepath.Join(dir, "skill")
	writeSkillFiles(t, skill, map[string]string{"SKILL.md": "---\nname: s\n---\n"})
	if err := os.Link(elsewhere, filepath.Join(skill, "linked.txt")); err != nil {
		t.Skipf("hard link: %v", err)
	}
	linkedPath := filepath.Join(skill, "linked.txt")
	var asked []string
	for _, allow := range []bool{false, true} {
		asked = nil
		trust := func(_ *os.File, path string) bool { asked = append(asked, path); return allow }
		hash, status, manifest, _, _, _ := hashSkillFolderCaptureNamed(skill, maxSkillBytes, maxSkillBytes, trust, nil)
		if len(asked) != 1 || asked[0] != linkedPath {
			t.Fatalf("allow=%t: asked %v, want only the hard-linked file %s", allow, asked, linkedPath)
		}
		if allow && (status != SkillContentOK || hash == "" || manifest == nil) {
			t.Fatalf("a hard-linked file the trust approves: %q %s manifest %t; want an ordinary hash", hash, status, manifest != nil)
		}
		if !allow && (status != SkillContentSymlink || hash != "" || manifest != nil) {
			t.Fatalf("a hard-linked file the trust refuses: %q %s manifest %t; want symlink, no hash, no manifest", hash, status, manifest != nil)
		}
	}
}
