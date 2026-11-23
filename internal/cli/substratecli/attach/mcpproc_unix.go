// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package attach

import (
	"os/exec"
	"syscall"
)

// prepareMCPCmd puts the command in its own process group, so one signal
// reaches the command and what it started (npx starts node).
func prepareMCPCmd(cmd *exec.Cmd) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
}

// terminateMCP asks the command's process group to end (SIGTERM).
func terminateMCP(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGTERM)
	}
}

// killMCP ends the command's process group at once (SIGKILL).
func killMCP(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL)
		_ = cmd.Process.Kill()
	}
}
