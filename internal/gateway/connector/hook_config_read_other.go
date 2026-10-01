// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"syscall"
)

// openHookConfigForRead opens a vendor hook config without blocking, so a
// named pipe in its place opens at once and is refused by the regular-file
// check instead of waiting for a writer.
func openHookConfigForRead(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_NONBLOCK, 0)
}
