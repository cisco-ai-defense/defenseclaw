// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"syscall"
)

// openHostFileForInspection opens a hook-named host file for reading
// without blocking: a FIFO swapped in after the caller's Lstat would
// otherwise park the hook goroutine in open(2) until a writer appears. The
// caller must still check that the opened file is the regular file it
// expected. O_NONBLOCK does not change reads of a regular file.
func openHostFileForInspection(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0) // #nosec G304 -- callers pass a validated, hook-derived path.
}
