// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package processutil

import (
	"context"
	"os/exec"
	"syscall"

	"golang.org/x/sys/windows"
)

// priorityClassFlags are the CreateProcess priority-class flags; a process
// is created with at most one.
const priorityClassFlags = windows.IDLE_PRIORITY_CLASS | windows.BELOW_NORMAL_PRIORITY_CLASS |
	windows.NORMAL_PRIORITY_CLASS | windows.ABOVE_NORMAL_PRIORITY_CLASS |
	windows.HIGH_PRIORITY_CLASS | windows.REALTIME_PRIORITY_CLASS

// withScannerPriority creates the scan in the below-normal priority class, so
// that it does not take the CPU the gateway needs to answer hook calls (see
// lowerScannerPriority for Linux and macOS, rel-1-0-10 GAP-0251).
// A process that a below-normal process creates without a class of its own
// is below normal too, so the scanner runtime and its helpers keep it.
func withScannerPriority(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.CreationFlags = cmd.SysProcAttr.CreationFlags&^priorityClassFlags | windows.BELOW_NORMAL_PRIORITY_CLASS
}

// RunTreeIsolated runs an MCP scan with RunTree, below the normal priority
// class.
func RunTreeIsolated(_ context.Context, cmd *exec.Cmd) error {
	withScannerPriority(cmd)
	return RunTree(cmd)
}
