// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package inventory

import (
	"os"

	"golang.org/x/sys/unix"
)

// openReadOnlyNonblocking opens path read-only without blocking on a FIFO,
// and without following a final link unless follow is set.
func openReadOnlyNonblocking(path string, follow bool) (*boundedReadFile, error) {
	flags := unix.O_RDONLY | unix.O_CLOEXEC | unix.O_NONBLOCK
	if !follow {
		flags |= unix.O_NOFOLLOW
	}
	fd, err := unix.Open(path, flags, 0)
	if err != nil {
		return nil, err
	}
	return os.NewFile(uintptr(fd), path), nil
}
