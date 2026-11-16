// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"

	"golang.org/x/sys/windows"
)

// fsctlSetSparse is FSCTL_SET_SPARSE (winioctl.h).
const fsctlSetSparse = 0x000900c4

// makeSparseFile marks path sparse and sets its size, so NTFS reports a size
// it allocates no clusters for, the way an account would.
func makeSparseFile(path string, size int64) error {
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		return err
	}
	defer file.Close()
	var returned uint32
	if err := windows.DeviceIoControl(windows.Handle(file.Fd()), fsctlSetSparse, nil, 0, nil, 0, &returned, nil); err != nil {
		return err
	}
	return file.Truncate(size)
}
