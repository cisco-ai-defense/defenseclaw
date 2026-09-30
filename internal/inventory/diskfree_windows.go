// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package inventory

import "golang.org/x/sys/windows"

// diskFreeBytes returns the bytes available to the calling user on the
// volume holding dir.
func diskFreeBytes(dir string) (uint64, bool) {
	path, err := windows.UTF16PtrFromString(dir)
	if err != nil {
		return 0, false
	}
	var avail, total, totalFree uint64
	if err := windows.GetDiskFreeSpaceEx(path, &avail, &total, &totalFree); err != nil {
		return 0, false
	}
	return avail, true
}
