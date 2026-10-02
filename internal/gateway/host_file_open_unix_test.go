// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"io"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

// TestOpenHostFileForInspectionNeverBlocksOnAFIFO pins the open used by the
// Codex git-diff source verifier and promoted-artifact reads: a FIFO swapped
// in after their Lstat opens at once (and its Stat shows it is not a regular
// file) instead of parking the hook until a writer appears.
func TestOpenHostFileForInspectionNeverBlocksOnAFIFO(t *testing.T) {
	dir := t.TempDir()
	fifo := filepath.Join(dir, "pipe")
	if err := syscall.Mkfifo(fifo, 0o600); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	type result struct {
		regular bool
		err     error
	}
	done := make(chan result, 1)
	go func() {
		f, err := openHostFileForInspection(fifo)
		if err != nil {
			done <- result{err: err}
			return
		}
		defer f.Close()
		info, err := f.Stat()
		done <- result{regular: err == nil && info.Mode().IsRegular(), err: err}
	}()
	select {
	case got := <-done:
		if got.regular {
			t.Fatal("a FIFO reported as a regular file")
		}
	case <-time.After(5 * time.Second):
		if w, err := os.OpenFile(fifo, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = w.Close()
		}
		t.Fatal("opening a FIFO blocked")
	}

	regular := filepath.Join(dir, "rules.go")
	if err := os.WriteFile(regular, []byte("package gateway\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := openHostFileForInspection(regular)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil || string(data) != "package gateway\n" {
		t.Fatalf("regular read = %q, %v", data, err)
	}
}
