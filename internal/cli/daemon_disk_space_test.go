// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"errors"
	"strings"
	"testing"
)

// GAP-1813: start and restart refuse a full data disk before they stop or
// launch anything, and say so.
func TestGatewayDiskFullErrorRefusesBeforeStopping(t *testing.T) {
	if free, err := platformFreeDiskBytes(t.TempDir()); err != nil || free == 0 {
		t.Fatalf("platformFreeDiskBytes() = %d, %v", free, err)
	}
	previous := dataDirFreeBytes
	t.Cleanup(func() { dataDirFreeBytes = previous })
	dir := t.TempDir()

	dataDirFreeBytes = func(string) (uint64, error) { return 1 << 20, nil }
	err := gatewayDiskFullError("restart", dir)
	if err == nil || !strings.Contains(err.Error(), "is full (1 MB free") ||
		!strings.Contains(err.Error(), "Nothing was stopped.") ||
		!strings.Contains(err.Error(), "then run: defenseclaw-gateway restart") {
		t.Fatalf("restart on a full disk = %v", err)
	}
	if note := gatewayStartFailureDiskNote(dir); !strings.Contains(note, "is full") {
		t.Fatalf("start failure note = %q", note)
	}

	dataDirFreeBytes = func(string) (uint64, error) { return 1 << 30, nil }
	if err := gatewayDiskFullError("start", dir); err != nil || gatewayStartFailureDiskNote(dir) != "" {
		t.Fatalf("enough space: err %v, note %q", err, gatewayStartFailureDiskNote(dir))
	}
	dataDirFreeBytes = func(string) (uint64, error) { return 0, errors.New("unreadable") }
	if err := gatewayDiskFullError("start", dir); err != nil {
		t.Fatalf("unreadable free space must not block a start: %v", err)
	}
}
