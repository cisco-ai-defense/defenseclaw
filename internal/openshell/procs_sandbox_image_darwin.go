// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package openshell

import (
	"bytes"
	"context"
	"fmt"
	"path/filepath"
	"syscall"
	"unsafe"
)

// sandboxDaemonProcessPath obtains the process image path through the same
// kernel interface used by libproc's proc_pidpath. It works without cgo.
func sandboxDaemonProcessPath(ctx context.Context, pid int) (string, error) {
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if pid <= 0 {
		return "", fmt.Errorf("invalid process pid %d", pid)
	}
	// proc_info(PIDINFO, pid, PIDPATHINFO, 0, buffer, size).
	// PROC_PIDPATHINFO_MAXSIZE is four times MAXPATHLEN (4096 bytes).
	var path [4096]byte
	_, _, errno := syscall.Syscall6(syscall.SYS_PROC_INFO, 2, uintptr(pid), 11, 0,
		uintptr(unsafe.Pointer(&path[0])), uintptr(len(path)))
	if errno != 0 {
		return "", fmt.Errorf("process image for pid %d: %w", pid, errno)
	}
	end := bytes.IndexByte(path[:], 0)
	if end <= 0 || !filepath.IsAbs(string(path[:end])) {
		return "", fmt.Errorf("process image for pid %d has no absolute path", pid)
	}
	return string(path[:end]), nil
}
