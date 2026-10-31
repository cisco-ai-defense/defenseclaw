// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// hookFloodWorkingSet is the process working set and private bytes on
// Windows, where the flood probe has no /proc (rel-1-0-3 GAP-0244 measures
// the idle release there too).
func hookFloodWorkingSet() string {
	var counters struct {
		cb                         uint32
		pageFaultCount             uint32
		peakWorkingSetSize         uintptr
		workingSetSize             uintptr
		quotaPeakPagedPoolUsage    uintptr
		quotaPagedPoolUsage        uintptr
		quotaPeakNonPagedPoolUsage uintptr
		quotaNonPagedPoolUsage     uintptr
		pagefileUsage              uintptr
		peakPagefileUsage          uintptr
	}
	counters.cb = uint32(unsafe.Sizeof(counters))
	proc := windows.NewLazySystemDLL("kernel32.dll").NewProc("K32GetProcessMemoryInfo")
	if ok, _, _ := proc.Call(uintptr(windows.CurrentProcess()), uintptr(unsafe.Pointer(&counters)), uintptr(counters.cb)); ok == 0 {
		return ""
	}
	return fmt.Sprintf(" workingset=%dKiB private=%dKiB", counters.workingSetSize>>10, counters.pagefileUsage>>10)
}
