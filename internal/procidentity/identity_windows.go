// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package procidentity

import (
	"strconv"

	"golang.org/x/sys/windows"
)

func of(pid int) (string, bool) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return "", false
	}
	defer windows.CloseHandle(process)
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(process, &creation, &exit, &kernel, &user); err != nil {
		return "", false
	}
	ticks := uint64(creation.HighDateTime)<<32 | uint64(creation.LowDateTime)
	if ticks == 0 {
		return "", false
	}
	// An exited process stays an object while any other process holds a
	// handle to it, and GetProcessTimes still answers, with its exit time
	// set. It names no process (GAP-2325), as on Linux and macOS.
	if exit.HighDateTime != 0 || exit.LowDateTime != 0 {
		return "", false
	}
	return strconv.FormatUint(ticks, 10), true
}
