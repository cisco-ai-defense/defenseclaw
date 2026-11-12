// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"os"
	"testing"

	"golang.org/x/sys/unix"
)

func sandboxReceiptScratchDir(t *testing.T) string {
	t.Helper()
	var fs unix.Statfs_t
	if err := unix.Statfs("/dev/shm", &fs); err != nil || fs.Type != unix.TMPFS_MAGIC ||
		uint64(fs.Bavail)*uint64(fs.Bsize) < 128<<20 {
		return ""
	}
	dir, err := os.MkdirTemp("/dev/shm", "dc-receipts-")
	if err != nil {
		return ""
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })
	return dir
}
