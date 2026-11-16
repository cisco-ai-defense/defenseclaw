// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpriority

import (
	"os"

	"golang.org/x/sys/windows"
)

// The hook process raises its priority class here, in a package init, so
// the raise comes before the initialization of the CLI's packages (about
// 150 ms of CPU and 85 MB of allocations on a fast core, a second or more
// on a small host whose CPU is full). Go initializes this package as soon
// as golang.org/x/sys/windows is, within the first milliseconds.
func init() { raiseForHook(os.Args[1:]) }

// raiseForHook raises a hook process (`defenseclaw-hook hook ...`) to the
// above-normal priority class, so its work and its answer deadline run ahead
// of the normal-priority work that fills a small host's CPU while Setup
// ensures, upgrades or repairs the deployment and the gateway service starts
// (GAP-0155, GAP-0167, GAP-0171). At normal priority the hook shared the CPU
// with that work: calls whose answer was due 4 s after the hook started gave
// it 1.1 to 1.75 s late, so the agent waited more than 5 s for its block.
//
// A hook call is short and mostly waits on the gateway; its answer
// watchdog ends it at the answer deadline whatever it is doing, so the raise
// is bounded by the deadline. Windows does not pass the above-normal class
// to a process the hook starts (a gateway cold start runs at normal
// priority). A class already above normal is kept. It reports whether it
// raised the class.
//
// The launcher guard (`launcher-guard <defenseclaw-hook.exe> hook ...`, the
// Windows Claude Code PreToolUse handler of the one-line install and of a
// packaged install) starts the hook, so it is raised too. At normal priority
// it waited behind the above-normal hooks and gateway of the calls already
// running: in a 60-way parallel read the guards started the hooks 1 to 4 s
// late and the answers came 3 to 5 s after the call (GAP-0050).
func raiseForHook(args []string) bool {
	if len(args) == 0 || (args[0] != "hook" && args[0] != LauncherGuardSubcommand) {
		return false
	}
	process := windows.CurrentProcess()
	current, err := windows.GetPriorityClass(process)
	if err != nil {
		return false
	}
	switch current {
	case windows.ABOVE_NORMAL_PRIORITY_CLASS, windows.HIGH_PRIORITY_CLASS, windows.REALTIME_PRIORITY_CLASS:
		return false
	}
	return windows.SetPriorityClass(process, windows.ABOVE_NORMAL_PRIORITY_CLASS) == nil
}
