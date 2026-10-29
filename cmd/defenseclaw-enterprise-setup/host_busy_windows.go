// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package main

import (
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var procGetSystemTimes = windows.NewLazySystemDLL("kernel32.dll").NewProc("GetSystemTimes")

func systemTimes() (idle, kernel, user uint64, ok bool) {
	var idleTime, kernelTime, userTime windows.Filetime
	result, _, _ := procGetSystemTimes.Call(uintptr(unsafe.Pointer(&idleTime)),
		uintptr(unsafe.Pointer(&kernelTime)), uintptr(unsafe.Pointer(&userTime)))
	if result == 0 {
		return 0, 0, 0, false
	}
	value := func(f windows.Filetime) uint64 { return uint64(f.HighDateTime)<<32 | uint64(f.LowDateTime) }
	return value(idleTime), value(kernelTime), value(userTime), true
}

// platformHostIdlePercent is the idle share of all processors over window:
// GetSystemTimes counts idle time inside kernel time.
func platformHostIdlePercent(window time.Duration) (int, bool) {
	idle0, kernel0, user0, ok := systemTimes()
	if !ok {
		return 0, false
	}
	time.Sleep(window)
	idle1, kernel1, user1, ok := systemTimes()
	if !ok || idle1 < idle0 || kernel1 < kernel0 || user1 < user0 {
		return 0, false
	}
	total := (kernel1 - kernel0) + (user1 - user0)
	if total == 0 {
		return 0, false
	}
	return int((idle1 - idle0) * 100 / total), true
}
