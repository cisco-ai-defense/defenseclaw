// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package watcher

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestR109G501BSnapshotSpecialEntryIsBounded(t *testing.T) {
	root := t.TempDir()
	dependency := filepath.Join(root, "node_modules", "dependency")
	if err := os.MkdirAll(dependency, 0o700); err != nil {
		t.Fatal(err)
	}
	pipe := filepath.Join(dependency, "named-pipe")
	if err := syscall.Mkfifo(pipe, 0o600); err != nil {
		t.Fatal(err)
	}

	// A file can also change into a pipe after the walk has inspected it.
	done := make(chan error, 1)
	go func() { _, err := hashFile(pipe); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Fatal("special entry was hashed as a regular file")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("snapshot file open waited on a special entry")
	}
	doneEndpoints := make(chan struct{}, 1)
	go func() { _ = extractEndpoints(pipe); doneEndpoints <- struct{}{} }()
	select {
	case <-doneEndpoints:
	case <-time.After(2 * time.Second):
		t.Fatal("snapshot endpoint read waited on a special entry")
	}

	before, err := snapshotTarget(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(pipe); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pipe, []byte("ordinary file\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	after, err := snapshotTarget(root, true)
	if err != nil {
		t.Fatal(err)
	}
	if before.ContentHash == after.ContentHash {
		t.Fatal("special entry replacement did not change the snapshot")
	}
}
