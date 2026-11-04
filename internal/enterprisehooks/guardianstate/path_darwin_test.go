//go:build darwin

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package guardianstate

import (
	"os"
	"path/filepath"
	"testing"
)

func TestPathForDataDirDarwinMatchesGuardianWriter(t *testing.T) {
	root := t.TempDir()
	runtimeDir := filepath.Join(root, "runtime")
	manifestDir := filepath.Join(root, StateDirName)
	for _, dir := range []string{runtimeDir, manifestDir} {
		if err := os.Mkdir(dir, 0o750); err != nil {
			t.Fatal(err)
		}
	}
	// The guardian writes next to targets.yaml.
	if err := WriteState(PathForStateRoot(manifestDir), StateReady); err != nil {
		t.Fatal(err)
	}
	if got := PathForDataDir(runtimeDir); got != PathForStateRoot(manifestDir) {
		t.Fatalf("state path = %q, want %q", got, PathForStateRoot(manifestDir))
	}
	if got := ReadState(PathForDataDir(runtimeDir)); got != StateReady {
		t.Fatalf("state = %q, want ready", got)
	}
}

func TestPathForDataDirDarwinIgnoresSymlinkedSibling(t *testing.T) {
	root := t.TempDir()
	runtimeDir := filepath.Join(root, "runtime")
	if err := os.Mkdir(runtimeDir, 0o750); err != nil {
		t.Fatal(err)
	}
	elsewhere := t.TempDir()
	if err := os.Symlink(elsewhere, filepath.Join(root, StateDirName)); err != nil {
		t.Fatal(err)
	}
	if got := PathForDataDir(runtimeDir); got != filepath.Join(runtimeDir, StateDirName, FileName) {
		t.Fatalf("symlinked sibling was used: %q", got)
	}
}
