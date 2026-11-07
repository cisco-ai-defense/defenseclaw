// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package watcher

import (
	"fmt"
	"os"
	"syscall"
)

func openSnapshotFile(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0)
}

// snapshotFileIdentity names the volume and file ID of the entry a path
// resolves to.
func snapshotFileIdentity(path string) (string, error) {
	info, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	sys, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return "", fmt.Errorf("no file identity for %s", path)
	}
	return fmt.Sprintf("%d:%d", sys.Dev, sys.Ino), nil
}
