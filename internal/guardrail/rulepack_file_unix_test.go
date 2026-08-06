// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package guardrail

import (
	"os"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

func TestReadRulePackFileRejectsFIFOReplacementWithoutBlocking(t *testing.T) {
	dir := t.TempDir()
	const rel = "suppressions.yaml"
	writeRulePackFile(t, dir, rel, "version: 1\n")

	inventory, err := inspectRulePackDirectory(dir)
	if err != nil {
		t.Fatalf("inspectRulePackDirectory: %v", err)
	}
	file := inventory.files[rel]
	if err := os.Remove(file.full); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(file.full, 0o600); err != nil {
		t.Fatalf("Mkfifo: %v", err)
	}

	result := make(chan error, 1)
	go func() {
		_, readErr := readRulePackFile(file)
		result <- readErr
	}()

	select {
	case err := <-result:
		requireRulePackError(t, err, "file_type")
	case <-time.After(time.Second):
		// Unblock an implementation that opened the FIFO without O_NONBLOCK
		// so the test does not leave a stuck goroutine behind.
		fd, openErr := unix.Open(file.full, unix.O_RDWR|unix.O_NONBLOCK, 0)
		if openErr == nil {
			_ = unix.Close(fd)
		}
		select {
		case <-result:
		case <-time.After(time.Second):
		}
		t.Fatal("readRulePackFile blocked on a FIFO replacement")
	}
}
