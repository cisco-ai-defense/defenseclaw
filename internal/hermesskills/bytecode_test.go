// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hermesskills

import (
	"os"
	"path/filepath"
	"testing"
)

// rel-1-0-10:GAP-0798 (review F5 of GAP-0765): the bundled-skill digest
// covers every file of the tree, a bytecode cache included, so a bytecode
// file planted in a pinned vendor skill makes it an ordinary, scannable
// skill. The clean copy stays bundled.
func TestVendorSkillWithPlantedBytecodeIsNotBundled(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HERMES_HOME", home)
	root := filepath.Join(home, "skills")
	marker, err := os.ReadFile(filepath.Join("testdata", "vendor", "media", "songsee", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	skill := filepath.Join(root, "media", "songsee")
	if err := os.MkdirAll(skill, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(skill, "SKILL.md"), marker, 0o600); err != nil {
		t.Fatal(err)
	}
	bundled := func() bool {
		t.Helper()
		entries, err := Discover(root, DefaultDirectoryLimit)
		if err != nil {
			t.Fatalf("Discover: %v", err)
		}
		for _, entry := range entries {
			if entry.Name == "songsee" {
				return entry.Bundled
			}
		}
		t.Fatalf("songsee missing from %+v", entries)
		return false
	}
	if !bundled() {
		t.Fatal("the clean pinned vendor skill is not bundled")
	}
	cache := filepath.Join(skill, "scripts", "__pycache__")
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, "tool.cpython-312.pyc"), []byte("planted bytecode"), 0o600); err != nil {
		t.Fatal(err)
	}
	if bundled() {
		t.Fatal("a vendor skill with planted bytecode is still bundled")
	}
}
