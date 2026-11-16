// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import "golang.org/x/sys/windows"

// windowsLifecycleYieldToHooks lowers the CPU priority class of a Windows
// lifecycle run (install, upgrade, repair, ensure) to below normal before it
// works. The installer, the PowerShell module and the other programs it
// starts take that class too (Windows passes a below-normal or idle class to
// a child process). An attestation repair filled the CPU of a small host
// while the hooks of the signed-in users, at normal priority, still had to
// answer each tool call within the answer budget (GAP-0155, GAP-0167); the
// lifecycle now takes only the CPU they leave. It is the Windows counterpart
// of the lifecycle nice value on Linux and macOS (internal/enterpriseunix).
// The gateway and guardian services are started by the service manager and
// keep their own class. A class already lower (idle) is kept.
func windowsLifecycleYieldToHooks() {
	process := windows.CurrentProcess()
	current, err := windows.GetPriorityClass(process)
	if err != nil {
		return
	}
	switch current {
	case windows.IDLE_PRIORITY_CLASS, windows.BELOW_NORMAL_PRIORITY_CLASS:
		return
	}
	_ = windows.SetPriorityClass(process, windows.BELOW_NORMAL_PRIORITY_CLASS)
}

// windowsEnterpriseLifecycleYield is windowsLifecycleYieldToHooks; the
// package's tests replace it, so a lifecycle test does not lower the class
// of the test binary, and of every test and program after it (GAP-0079).
var windowsEnterpriseLifecycleYield = windowsLifecycleYieldToHooks
