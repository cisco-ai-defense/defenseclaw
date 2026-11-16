// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package devicekeys

import "golang.org/x/sys/windows"

// werFaultReportingFlagNoHeap is WER_FAULT_REPORTING_FLAG_NOHEAP (werapi.h).
const werFaultReportingFlagNoHeap = 1

var procWerSetFlags = windows.NewLazySystemDLL("kernel32.dll").NewProc("WerSetFlags")

// disableCrashDumps asks Windows Error Reporting to collect no heap for a
// crash of this process (WerSetFlags NOHEAP), so a report it sends holds
// no secret. A full LocalDumps configuration is set by an administrator.
func disableCrashDumps() {
	if procWerSetFlags.Find() == nil {
		_, _, _ = procWerSetFlags.Call(werFaultReportingFlagNoHeap)
	}
}
