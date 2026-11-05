// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"syscall"
)

// openCoworkActivityRecord opens the Cowork activity record for reading
// without following a final link and without blocking: a FIFO swapped in
// after the caller's Lstat would otherwise park the hook goroutine in
// open(2). The caller still checks that the opened file is the regular file
// it inspected.
func openCoworkActivityRecord(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW|syscall.O_NONBLOCK, 0) // #nosec G304 -- <data_dir>/cowork/gateway-activity.json.
}
