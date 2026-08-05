// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package safefile

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"
)

func TestReadRegularFileBoundedRejectsFIFOWithoutBlocking(t *testing.T) {
	path := filepath.Join(t.TempDir(), "dotenv.fifo")
	if err := syscall.Mkfifo(path, 0o600); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	result := make(chan error, 1)
	go func() {
		_, err := ReadRegularFileBounded(path, 1024)
		result <- err
	}()

	select {
	case err := <-result:
		if err == nil {
			t.Fatal("ReadRegularFileBounded accepted a FIFO")
		}
	case <-time.After(500 * time.Millisecond):
		// Unblock a regressed plain reader so the test process can finish cleanly.
		if writer, err := os.OpenFile(path, os.O_WRONLY|syscall.O_NONBLOCK, 0); err == nil {
			_ = writer.Close()
		}
		t.Fatal("ReadRegularFileBounded blocked while opening a FIFO")
	}
}
