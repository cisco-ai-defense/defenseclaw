// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// TestR107DirectoryEnterableOnWindows: the cd check opens the folder as cd
// does (traverse, synchronize, backup semantics): an existing folder is
// enterable, a missing one, a file, and a folder whose traverse right is
// denied to everyone are not (rel-1-0-6:GAP-0320 review 6).
func TestR107DirectoryEnterableOnWindows(t *testing.T) {
	root := t.TempDir()
	open := filepath.Join(root, "open")
	locked := filepath.Join(root, "locked")
	file := filepath.Join(root, "file.txt")
	for _, dir := range []string{open, locked} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !directoryEnterable(open) {
		t.Errorf("existing folder not enterable")
	}
	if directoryEnterable(filepath.Join(root, "nosuch")) {
		t.Errorf("missing folder enterable")
	}
	if directoryEnterable(file) {
		t.Errorf("file enterable")
	}
	if out, err := exec.Command("icacls", locked, "/deny", "*S-1-1-0:(X)").CombinedOutput(); err != nil {
		t.Fatalf("icacls: %v %s", err, out)
	}
	t.Cleanup(func() { _ = exec.Command("icacls", locked, "/remove:d", "*S-1-1-0").Run() })
	if directoryEnterable(locked) {
		if _, err := os.ReadDir(locked); err == nil {
			t.Skip("this process bypasses a traverse deny (backup privilege enabled)")
		}
		t.Errorf("folder with traverse denied to everyone enterable")
	}
	check := cdEnterable(root, nil, false)
	if !check("open") || check("nosuch") || check("locked") || check("-") || check("../open") {
		t.Errorf("cdEnterable: open=%v nosuch=%v locked=%v dash=%v dotdot=%v",
			check("open"), check("nosuch"), check("locked"), check("-"), check("../open"))
	}
}
