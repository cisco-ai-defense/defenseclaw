// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

// rel-1-0-10:GAP-2210: a workspace named through a subst drive letter that
// maps into the DefenseClaw data folder is inside it. Before the fix the
// drive spelling was compared with the C:-spelled data folder across
// volumes, filepath.Rel failed and the workspace read as outside.
func TestGAP2210WorkspaceThroughASubstDriveIntoTheDataDirIsInside(t *testing.T) {
	base := t.TempDir()
	data := filepath.Join(base, "data")
	if err := os.MkdirAll(filepath.Join(data, "ws"), 0o700); err != nil {
		t.Fatal(err)
	}
	letter := ""
	for c := 'Y'; c >= 'M' && letter == ""; c-- {
		if _, err := os.Lstat(string(c) + `:\`); err != nil {
			letter = string(c) + ":"
		}
	}
	if letter == "" {
		t.Fatal("no free drive letter between M: and Y:")
	}
	if out, err := exec.Command("subst.exe", letter, data).CombinedOutput(); err != nil {
		t.Fatalf("subst %s %s: %v: %s", letter, data, err, out)
	}
	t.Cleanup(func() { _ = exec.Command("subst.exe", letter, "/d").Run() })
	for _, root := range []string{letter + `\`, letter + `\ws`} {
		if workspaceRootOutsideDataDir(root, data) {
			t.Errorf("workspace %s (subst into the data dir) was judged outside it", root)
		}
	}
	outside := filepath.Join(base, "repo")
	if err := os.MkdirAll(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	if !workspaceRootOutsideDataDir(outside, data) {
		t.Error("a workspace beside the data dir was judged inside it")
	}
}
