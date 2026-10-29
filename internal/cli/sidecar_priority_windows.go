// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import "golang.org/x/sys/windows"

// sidecarAnswerAtHookPriority runs a Windows gateway at the above-normal
// priority class of the hooks it answers (cmd/internal/
// hookpriority). A hook raises itself to above normal before its packages
// initialize, so a burst of hook processes (a Claude Code turn that reads 60
// files at once starts 60) took the whole CPU ahead of a normal-priority
// gateway, and one started by a lifecycle run or a scheduled task inherited
// below normal (windowsLifecycleYieldToHooks). The calls those hooks had
// already sent waited for the gateway until the burst's start-up work was
// done: on 8 processors 43-88% of a 60-way burst of benign reads passed the
// answer budget and were blocked as a gateway no-answer (GAP-0050). At the
// hooks' class the gateway shares the CPU with them and answers within the
// budget. A gateway spends its CPU on hook answers and on bounded upkeep;
// Windows does not pass the above-normal class to a program the gateway
// starts (scanners, agents), so those keep the normal class. A class already
// above normal (high, realtime) is kept.
func sidecarAnswerAtHookPriority() {
	process := windows.CurrentProcess()
	current, err := windows.GetPriorityClass(process)
	if err != nil {
		return
	}
	if !sidecarRaisesPriorityClass(current) {
		return
	}
	_ = windows.SetPriorityClass(process, windows.ABOVE_NORMAL_PRIORITY_CLASS)
}

// sidecarRaisesPriorityClass reports whether a gateway at class is raised to
// above normal: every class below it is.
func sidecarRaisesPriorityClass(class uint32) bool {
	switch class {
	case windows.ABOVE_NORMAL_PRIORITY_CLASS, windows.HIGH_PRIORITY_CLASS, windows.REALTIME_PRIORITY_CLASS:
		return false
	}
	return true
}
