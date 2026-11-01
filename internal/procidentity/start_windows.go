// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package procidentity

import (
	"time"

	"golang.org/x/sys/windows"
)

func startTime(pid int) (time.Time, bool) {
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return time.Time{}, false
	}
	defer windows.CloseHandle(process)
	var creation, exit, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(process, &creation, &exit, &kernel, &user); err != nil {
		return time.Time{}, false
	}
	if creation.HighDateTime == 0 && creation.LowDateTime == 0 {
		return time.Time{}, false
	}
	return time.Unix(0, creation.Nanoseconds()), true
}
