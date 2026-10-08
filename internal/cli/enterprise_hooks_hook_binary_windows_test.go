//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-0935: the guardian keeps a copy of the recorded hook binary and puts a
// missing (quarantined) binary back from it; a copy of another release is
// never restored.
func TestKeepWindowsManagedFileCopyRestoresAMissingHookBinary(t *testing.T) {
	root := t.TempDir()
	target := filepath.Join(root, "bin", "defenseclaw-hook.exe")
	copyPath := filepath.Join(root, "hook-guardian", "payload", "defenseclaw-hook.exe")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("hook release"), 0o600); err != nil {
		t.Fatal(err)
	}
	want, err := windowsFileSHA256Hex(target)
	if err != nil {
		t.Fatal(err)
	}
	if restored, err := keepWindowsManagedFileCopy(target, copyPath, want); err != nil || restored {
		t.Fatalf("keep copy: restored %t, %v", restored, err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if restored, err := keepWindowsManagedFileCopy(target, copyPath, want); err != nil || !restored {
		t.Fatalf("restore: restored %t, %v", restored, err)
	}
	if body, err := os.ReadFile(target); err != nil || string(body) != "hook release" {
		t.Fatalf("restored %q, %v", body, err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if restored, err := keepWindowsManagedFileCopy(target, copyPath, "0000"); err == nil || restored {
		t.Fatalf("a copy of another release was restored: %t, %v", restored, err)
	}
}
