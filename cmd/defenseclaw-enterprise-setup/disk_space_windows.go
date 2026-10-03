// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import "golang.org/x/sys/windows"

func platformFreeDiskBytes(dir string) (uint64, bool, error) {
	path, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, false, err
	}
	var available uint64
	if err := windows.GetDiskFreeSpaceEx(path, &available, nil, nil); err != nil {
		return 0, false, err
	}
	return available, true, nil
}
