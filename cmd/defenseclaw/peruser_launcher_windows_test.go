//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestWindowsPerUserLauncherDetectsJunctionAndAllowsFolder(t *testing.T) {
	target := t.TempDir()
	root := filepath.Join(t.TempDir(), "data")
	if output, err := exec.Command("cmd.exe", "/c", "mklink", "/J", root, target).CombinedOutput(); err != nil {
		t.Fatalf("create data-folder fixture: %v: %s", err, output)
	}
	t.Cleanup(func() { _ = os.Remove(root) })
	linked, err := windowsPerUserRootIsReparse(root)
	if err != nil || !linked {
		t.Fatalf("junction linked=%v err=%v", linked, err)
	}
	plain := filepath.Join(t.TempDir(), "data")
	if err := os.Mkdir(plain, 0o700); err != nil {
		t.Fatal(err)
	}
	linked, err = windowsPerUserRootIsReparse(plain)
	if err != nil || linked {
		t.Fatalf("folder linked=%v err=%v", linked, err)
	}
}
