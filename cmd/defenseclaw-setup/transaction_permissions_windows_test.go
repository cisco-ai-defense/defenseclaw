// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

func installLivePayloadTraversalTrap(t *testing.T, installRoot, path string) func() {
	t.Helper()
	target := t.TempDir()
	sentinelPath := filepath.Join(target, "sentinel")
	if err := os.WriteFile(sentinelPath, []byte("runtime-target"), 0o600); err != nil {
		t.Fatal(err)
	}
	trapPath := filepath.Join(path, "trap")
	output, err := exec.Command(
		"cmd.exe", "/D", "/C", "mklink", "/J", trapPath, target,
	).CombinedOutput()
	if err != nil {
		t.Fatalf("create live-runtime reparse trap: %v\n%s", err, output)
	}

	var once sync.Once
	restore := func() {
		once.Do(func() {
			reparse, err := isReparsePoint(trapPath)
			if err != nil {
				t.Errorf("inspect preserved live-runtime reparse trap: %v", err)
			} else if !reparse {
				t.Errorf("live-runtime reparse trap was removed or replaced")
			}
			data, err := os.ReadFile(filepath.Join(trapPath, "sentinel"))
			if err != nil {
				t.Errorf("read preserved live-runtime reparse target: %v", err)
			} else if string(data) != "runtime-target" {
				t.Errorf("live-runtime reparse target = %q, want runtime-target", data)
			}
			if err := os.Remove(trapPath); err != nil && !os.IsNotExist(err) {
				t.Errorf("remove live-runtime reparse trap: %v", err)
			}
		})
	}
	t.Cleanup(restore)

	reparse, err := isReparsePoint(trapPath)
	if err != nil {
		restore()
		t.Fatalf("inspect live-runtime reparse trap: %v", err)
	}
	if !reparse {
		restore()
		t.Fatal("live-runtime traversal trap is not a reparse point")
	}
	if err := rejectReparseTree(installRoot); err == nil ||
		!strings.Contains(err.Error(), "transaction tree contains a reparse point") {
		restore()
		t.Fatalf("legacy full-tree validation error = %v, want reparse rejection", err)
	}
	return restore
}
