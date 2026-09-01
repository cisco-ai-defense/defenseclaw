// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hermesskills

import (
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

func TestDiscoverClassifiesOnlyUnchangedManifestTrackedSkillsBundled(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HERMES_HOME", home)
	root := filepath.Join(home, "skills")
	bundled := writeTestSkill(t, root, filepath.Join("productivity", "vendor-docs"), "vendor-docs")
	modified := writeTestSkill(t, root, filepath.Join("software-development", "modified-vendor"), "modified-vendor")
	forged := writeTestSkill(t, root, filepath.Join("productivity", "manifest-only"), "manifest-only")
	user := writeTestSkill(t, root, "operator-skill", "operator-skill")
	sourceRoot := filepath.Join(home, "hermes-agent", "skills")
	writeTestSkill(t, sourceRoot, filepath.Join("productivity", "vendor-docs"), "vendor-docs")
	writeTestSkill(t, sourceRoot, filepath.Join("software-development", "modified-vendor"), "modified-vendor")
	bundledHash, err := treeMD5(bundled)
	if err != nil {
		t.Fatalf("hash bundled skill: %v", err)
	}
	modifiedHash, err := treeMD5(modified)
	if err != nil {
		t.Fatalf("hash modified skill baseline: %v", err)
	}
	forgedHash, err := treeMD5(forged)
	if err != nil {
		t.Fatalf("hash forged skill baseline: %v", err)
	}
	manifest := fmt.Sprintf(
		"vendor-docs:%s\nmodified-vendor:%s\nmanifest-only:%s\n",
		bundledHash,
		modifiedHash,
		forgedHash,
	)
	if err := os.WriteFile(filepath.Join(root, ManifestName), []byte(manifest), 0o600); err != nil {
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
	for _, name := range []string{"vendor-docs", "modified-vendor", "manifest-only", "operator-skill"} {
		if _, ok := got[name]; !ok {
			t.Fatalf("missing %q from %+v", name, entries)
		}
	}
	if !got["vendor-docs"].Bundled {
		t.Fatal("unchanged manifest-tracked skill was not bundled")
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
