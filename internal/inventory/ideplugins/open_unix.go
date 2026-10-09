// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package ideplugins

import (
	"os"

	"golang.org/x/sys/unix"
)

// openNonblocking opens path read-only without blocking on a FIFO, and
// without following a final link unless follow is set.
func openNonblocking(path string, follow bool) (*os.File, error) {
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

// resolvesToItself is the Windows check for a path whose parent folders the
// scan may not stat; a Unix scan never needs it.
func resolvesToItself(string) bool { return false }
