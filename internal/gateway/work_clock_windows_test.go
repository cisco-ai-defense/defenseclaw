// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"syscall"
	"time"
)

// processCPUTime is the CPU time this process has used so far.
func processCPUTime() (time.Duration, bool) {
	handle, err := syscall.GetCurrentProcess()
	if err != nil {
		return 0, false
	}
	var created, exited, kernel, user syscall.Filetime
	if err := syscall.GetProcessTimes(handle, &created, &exited, &kernel, &user); err != nil {
		return 0, false
	}
	hundredNanos := func(ft syscall.Filetime) int64 {
		return int64(uint64(ft.HighDateTime)<<32|uint64(ft.LowDateTime)) * 100
	}
	return time.Duration(hundredNanos(kernel) + hundredNanos(user)), true
}
