// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hermesskills

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverClassifiesOnlyPinnedVendorTreesBundled(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HERMES_HOME", home)
	root := filepath.Join(home, "skills")
	bundled := filepath.Join(root, "media", "songsee")
	if err := os.MkdirAll(bundled, 0o700); err != nil {
		t.Fatal(err)
	}
	marker, err := os.ReadFile(filepath.Join("testdata", "vendor", "media", "songsee", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(bundled, "SKILL.md"), marker, 0o600); err != nil {
		t.Fatal(err)
	}
	modified := writeTestSkill(t, root, filepath.Join("software-development", "modified-vendor"), "modified-vendor")
	forged := writeTestSkill(t, root, filepath.Join("productivity", "manifest-only"), "manifest-only")
	user := writeTestSkill(t, root, "operator-skill", "operator-skill")
	sourceRoot := filepath.Join(home, "hermes-agent", "skills")
	writeTestSkill(t, sourceRoot, filepath.Join("software-development", "modified-vendor"), "modified-vendor")
	writeTestSkill(t, sourceRoot, filepath.Join("productivity", "manifest-only"), "manifest-only")
	if err := os.WriteFile(filepath.Join(root, ".bundled_manifest"), []byte("modified-vendor:local\nmanifest-only:local\n"), 0o600); err != nil {
		t.Fatalf("write manifest: %v", err)
	}
	if err := os.WriteFile(
		filepath.Join(modified, "SKILL.md"),
		[]byte("---\nname: modified-vendor\n---\noperator changed this\n"),
		0o600,
	); err != nil {
		t.Fatalf("modify tracked skill: %v", err)
	}

	entries, err := Discover(root, DefaultDirectoryLimit)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	got := make(map[string]Entry, len(entries))
	for _, entry := range entries {
		got[entry.Name] = entry
	}
	for _, name := range []string{"songsee", "modified-vendor", "manifest-only", "operator-skill"} {
		if _, ok := got[name]; !ok {
			t.Fatalf("missing %q from %+v", name, entries)
		}
	}
	if !got["songsee"].Bundled {
		t.Fatal("pinned vendor skill was not bundled before a manifest exists")
	}
	if got["modified-vendor"].Bundled || got["manifest-only"].Bundled || got["operator-skill"].Bundled {
		t.Fatalf("modified/untracked skills became bundled: %+v", got)
	}
	if !IsBundledPath(filepath.Join(bundled, "SKILL.md")) {
		t.Fatal("bundled skill descendant was not protected")
	}
	if IsBundledPath(modified) || IsBundledPath(forged) || IsBundledPath(user) {
		t.Fatal("modified/untracked skill bypassed scanning")
	}
	if err := os.WriteFile(filepath.Join(bundled, "SKILL.md"), append(marker, []byte("\nlocal change\n")...), 0o600); err != nil {
		t.Fatal(err)
	}
	if IsBundledPath(bundled) {
		t.Fatal("changed pinned skill remained bundled")
	}
}

func writeTestSkill(t *testing.T, root, relative, name string) string {
	t.Helper()
	dir := filepath.Join(root, relative)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatalf("create skill %s: %v", name, err)
	}
	if err := os.WriteFile(
		filepath.Join(dir, "SKILL.md"),
		[]byte(fmt.Sprintf("---\nname: %s\n---\n", name)),
		0o600,
	); err != nil {
		t.Fatalf("write skill %s: %v", name, err)
	}
	return dir
}
