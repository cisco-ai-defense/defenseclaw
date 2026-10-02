// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package daemon

import (
	"errors"

	"golang.org/x/sys/windows"
)

// ForeignListenerPID returns the PID of the process listening on the loopback
// API port host:port when it belongs to another account: it is not the
// gateway recorded in dataDir's gateway.pid and this account may not open it.
// A per-user hook or CLI then sends that listener no token (GAP-1343). It
// returns 0 when the port is free, the holder is this account's, or the
// owner cannot be told.
func ForeignListenerPID(host string, port int, dataDir string) int {
	pid, err := listenerOwnerPID(host, port)
	if err != nil || pid <= 0 {
		return 0
	}
	if info, err := New(dataDir).readPIDInfo(); err == nil && info.PID == pid {
		return 0
	}
	handle, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, uint32(pid))
	if err == nil {
		_ = windows.CloseHandle(handle)
		return 0
	}
	if errors.Is(err, windows.ERROR_ACCESS_DENIED) {
		return pid
	}
	return 0
}
