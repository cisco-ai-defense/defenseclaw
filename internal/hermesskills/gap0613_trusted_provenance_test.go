// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hermesskills

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestGAP0613TrustedLinkedAncestorPreservesPinnedProvenance(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix ownership checks")
	}
	for _, linked := range []bool{false, true} {
		name := "plain"
		if linked {
			name = "linked"
		}
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			root := filepath.Join(home, ".hermes", "skills")
			physical := root
			if linked {
				physical = filepath.Join(home, "dotfiles", "hermes", "skills")
			}
			pinned := filepath.Join(physical, "media", "songsee")
			ordinary := filepath.Join(physical, "ordinary")
			for _, dir := range []string{pinned, ordinary} {
				if err := os.MkdirAll(dir, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			marker, err := os.ReadFile(filepath.Join("testdata", "vendor", "media", "songsee", "SKILL.md"))
			if err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(pinned, "SKILL.md"), marker, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(filepath.Join(ordinary, "SKILL.md"), []byte("# ordinary\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			if linked {
				if err := os.Symlink(filepath.Dir(physical), filepath.Dir(root)); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			}
			entries, err := DiscoverTrusted(root, DefaultDirectoryLimit)
			if err != nil {
				t.Fatal(err)
			}
			found := map[string]Entry{}
			for _, entry := range entries {
				found[entry.Name] = entry
			}
			if !found["songsee"].Bundled || found["songsee"].Path != filepath.Join(root, "media", "songsee") {
				t.Fatalf("pinned entry: %+v", found["songsee"])
			}
			if found["ordinary"].Bundled || found["ordinary"].Path != filepath.Join(root, "ordinary") {
				t.Fatalf("ordinary entry: %+v", found["ordinary"])
			}
		})
	}
}
