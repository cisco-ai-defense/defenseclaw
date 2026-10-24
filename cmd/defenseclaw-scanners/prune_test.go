// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"errors"
	"os"
	"path/filepath"
	"testing"
)

// GAP-0920: prune leaves a runtime a running scan still uses whole. It
// renames each old runtime aside before removing it; Windows refuses that
// rename while a scan holds a file in the folder open, and the folder stays
// untouched. Before, os.RemoveAll deleted the modules the scan had not
// imported yet and stopped only at the locked file.
func TestPruneOtherRuntimesLeavesARuntimeInUseWhole(t *testing.T) {
	root := t.TempDir()
	files := map[string]string{
		filepath.Join("keep", completeMarker):                       "new",
		filepath.Join("inuse", completeMarker):                      "old",
		filepath.Join("inuse", "python", "Lib", "late_import.py"):   "x = 1\n",
		filepath.Join("stale", "python", "Lib", "old_module.py"):    "y = 2\n",
		filepath.Join(".stale-0011223344556677", "leftover.txt"):    "z",
		filepath.Join(".unpack-8899aabbccddeeff", ".unpack-sha256"): "old",
	}
	for name, body := range files {
		path := filepath.Join(root, name)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	saved := renameRuntimeDir
	t.Cleanup(func() { renameRuntimeDir = saved })
	renameRuntimeDir = func(from, to string) error {
		if filepath.Base(from) == "inuse" {
			// A scan holds python.exe and the marker open.
			return errors.New("The process cannot access the file because it is being used by another process.")
		}
		return os.Rename(from, to)
	}
	pruneOtherRuntimes(root, "keep")
	for _, name := range []string{
		filepath.Join("keep", completeMarker),
		filepath.Join("inuse", completeMarker),
		filepath.Join("inuse", "python", "Lib", "late_import.py"),
	} {
		if _, err := os.Stat(filepath.Join(root, name)); err != nil {
			t.Fatalf("%s was removed: %v", name, err)
		}
	}
	entries, err := os.ReadDir(root)
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) != 2 {
		names := []string{}
		for _, entry := range entries {
			names = append(names, entry.Name())
		}
		t.Fatalf("root holds %q, want only keep and the runtime in use", names)
	}
}
