// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package attach

import (
	"errors"

	"golang.org/x/sys/windows"
)

// pidAlive reports whether the process pid still runs. os.FindProcess is no
// use on Windows: it succeeds while any handle to a dead process is open, so
// a child the bridge already killed and waited for still "exists". This opens
// a handle and waits on it with a zero timeout: signaled means exited.
func pidAlive(pid int) bool {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION|windows.SYNCHRONIZE, false, uint32(pid))
	if err != nil {
		// No such process: gone. Anything else (access denied) means it exists.
		return !errors.Is(err, windows.ERROR_INVALID_PARAMETER)
	}
	defer windows.CloseHandle(h)
	ev, err := windows.WaitForSingleObject(h, 0)
	return err == nil && ev == uint32(windows.WAIT_TIMEOUT)
}
