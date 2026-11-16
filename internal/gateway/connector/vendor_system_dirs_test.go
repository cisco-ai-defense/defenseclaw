// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

func TestUnderVendorSystemRoot(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("unix path layout")
	}
	roots := DefaultVendorSystemRoots()
	for _, path := range []string{"/etc/codex/skills", "/private/etc/codex", "/Library/Application Support/ClaudeCode"} {
		if !UnderVendorSystemRoot(path, roots) {
			t.Errorf("%s should be under a vendor system root", path)
		}
	}
	for _, path := range []string{"/Users/me/.codex/skills", "/etcetera/x", "/tmp/Library"} {
		if UnderVendorSystemRoot(path, roots) {
			t.Errorf("%s should not be under a vendor system root", path)
		}
	}
}

// A root gateway of an older release recorded /etc/codex and
// /etc/codex/skills as watcher-created; the next start removes the empty
// ones and keeps a folder that gained content, and never touches recorded
// folders outside the vendor roots.
func TestRemoveVendorSystemCreatedDirs(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	if err := os.MkdirAll(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	etc := filepath.Join(root, "etc") // stands in for /etc
	codex := filepath.Join(etc, "codex")
	skills := filepath.Join(codex, "skills")
	cursor := filepath.Join(etc, "cursor")
	home := filepath.Join(root, "home", ".codex", "skills")
	for _, dir := range []string{skills, cursor, home} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(cursor, "hooks.json"), []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	record, _ := json.Marshal(watcherCreatedDirs{Dirs: []string{codex, skills, cursor, home, filepath.Join(etc, "gone")}})
	if err := os.WriteFile(filepath.Join(dataDir, watcherCreatedDirsFile), record, 0o600); err != nil {
		t.Fatal(err)
	}

	removed := RemoveVendorSystemCreatedDirs(dataDir, []string{etc})
	if len(removed) != 2 || removed[0] != skills || removed[1] != codex {
		t.Fatalf("removed = %v, want skills then codex", removed)
	}
	if _, err := os.Lstat(codex); !os.IsNotExist(err) {
		t.Fatalf("empty vendor folder tree should be gone: %v", err)
	}
	if _, err := os.Stat(filepath.Join(cursor, "hooks.json")); err != nil {
		t.Fatalf("a vendor folder with content must stay: %v", err)
	}
	if _, err := os.Stat(home); err != nil {
		t.Fatalf("a recorded folder outside the vendor roots must stay: %v", err)
	}
	kept := readWatcherCreatedDirs(filepath.Join(dataDir, watcherCreatedDirsFile))
	if len(kept.Dirs) != 2 || kept.Dirs[0] != cursor || kept.Dirs[1] != home {
		t.Fatalf("kept = %v, want the content folder and the home folder", kept.Dirs)
	}
}
