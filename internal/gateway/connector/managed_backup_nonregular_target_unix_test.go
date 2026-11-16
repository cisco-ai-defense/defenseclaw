// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// A vendor file replaced by a named pipe (or any non-regular file) must never
// stall Setup: every managed-target inspection reports it at once instead of
// waiting for a writer, whether it is the first capture, the capture of a
// later Setup, or the read-back.
func TestManagedTargetInspectionNeverBlocksOnNonRegularTarget(t *testing.T) {
	root := t.TempDir()
	dataDir := filepath.Join(root, "data")
	target := filepath.Join(root, ".cursor", "hooks.json")
	if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("{\"operator\":true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	within := func(name string, fn func()) {
		t.Helper()
		done := make(chan struct{})
		go func() { fn(); close(done) }()
		select {
		case <-done:
		case <-time.After(3 * time.Second):
			// Release the blocked open so the goroutine can finish.
			if f, err := os.OpenFile(target, os.O_RDWR, 0); err == nil {
				f.Close()
			}
			<-done
			t.Fatalf("%s waited for a writer on a named pipe", name)
		}
	}

	if err := captureManagedFileBackup(dataDir, "cursor", "config", target); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := syscall.Mkfifo(target, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}

	within("later Setup capture", func() {
		if err := captureManagedFileBackup(dataDir, "cursor", "config", target); err != nil {
			t.Errorf("later capture: %v", err)
		}
	})
	within("post-hash read-back", func() {
		_ = updateManagedFileBackupPostHash(dataDir, "cursor", "config", target)
	})
	within("direct inspection", func() {
		if data, info, err := readManagedTarget(target); err == nil || data != nil || info != nil {
			t.Errorf("a named pipe must be reported, got data=%q info=%v err=%v", data, info, err)
		}
	})
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, info, err := readManagedTarget(target); err == nil || info != nil {
		t.Fatalf("a directory must be reported, got info=%v err=%v", info, err)
	}
}

// Benign twin: a regular file and a missing file read as before.
func TestManagedTargetInspectionStillReadsRegularAndMissingTargets(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "hooks.json")
	if data, info, err := readManagedTarget(path); err != nil || data != nil || info != nil {
		t.Fatalf("missing: data=%q info=%v err=%v", data, info, err)
	}
	if err := os.WriteFile(path, []byte("x"), 0o640); err != nil {
		t.Fatal(err)
	}
	data, info, err := readManagedTarget(path)
	if err != nil || string(data) != "x" || info == nil || info.Mode().Perm() != 0o640 {
		t.Fatalf("regular: data=%q info=%v err=%v", data, info, err)
	}
}
