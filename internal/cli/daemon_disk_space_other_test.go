// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package cli

import (
	"os"
	"strings"
	"syscall"
	"testing"
)

// GAP-1813: APFS reports MBs free that no file can use, so start and restart
// also refuse when a small test file cannot be written, and leave nothing behind.
func TestGatewayDiskFullErrorRefusesWhenWriteProbeHitsFullDisk(t *testing.T) {
	previousFree, previousProbe := dataDirFreeBytes, dataDirWriteProbe
	t.Cleanup(func() { dataDirFreeBytes, dataDirWriteProbe = previousFree, previousProbe })
	dir := t.TempDir()
	if err := probeDataDirWrite(dir); err != nil {
		t.Fatalf("probe on a writable folder: %v", err)
	}
	if entries, _ := os.ReadDir(dir); len(entries) != 0 {
		t.Fatalf("probe left %d files behind", len(entries))
	}

	dataDirFreeBytes = func(string) (uint64, error) { return 40 << 20, nil }
	dataDirWriteProbe = func(string) error {
		return &os.PathError{Op: "write", Path: dir, Err: syscall.ENOSPC}
	}
	err := gatewayDiskFullError("restart", dir)
	if err == nil || !strings.Contains(err.Error(), "is full (40 MB reported free") ||
		!strings.Contains(err.Error(), "Nothing was stopped.") {
		t.Fatalf("restart with a failing write probe = %v", err)
	}
	if note := gatewayStartFailureDiskNote(dir); !strings.Contains(note, "is full") {
		t.Fatalf("start failure note = %q", note)
	}

	dataDirWriteProbe = func(string) error { return os.ErrPermission }
	if err := gatewayDiskFullError("start", dir); err != nil {
		t.Fatalf("a probe that fails for another reason must not block a start: %v", err)
	}
}
