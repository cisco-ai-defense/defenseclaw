// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"errors"

	"golang.org/x/sys/windows"
)

// installLockOwnerGone reports a pid that names no process: Windows refuses
// to open it as an unknown process (ERROR_INVALID_PARAMETER), or it opens a
// process that has exited. Access denied or any other answer keeps the lock.
func installLockOwnerGone(pid int) bool {
	const stillActive = 259
	process, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err != nil {
		return errors.Is(err, windows.ERROR_INVALID_PARAMETER)
	}
	defer windows.CloseHandle(process)
	var code uint32
	if err := windows.GetExitCodeProcess(process, &code); err != nil {
		return false
	}
	return code != stillActive
}
