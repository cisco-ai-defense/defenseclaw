// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package attach

import (
	"os/exec"
	"syscall"
)

// mcpProc is a started command in its own process group.
type mcpProc struct{ cmd *exec.Cmd }

// startMCP puts the command in its own process group, so one signal reaches
// the command and what it started (npx starts node), and starts it.
func startMCP(cmd *exec.Cmd) (*mcpProc, error) {
	cmd.SysProcAttr = &syscall.SysProcAttr{Setpgid: true}
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &mcpProc{cmd: cmd}, nil
}

// terminate asks the command's process group to end (SIGTERM).
func (p *mcpProc) terminate() {
	_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGTERM)
}

// kill ends the command's process group at once (SIGKILL).
func (p *mcpProc) kill() {
	_ = syscall.Kill(-p.cmd.Process.Pid, syscall.SIGKILL)
	_ = p.cmd.Process.Kill()
}

// release runs once cmd.Wait has returned; a process group needs nothing.
func (p *mcpProc) release() {}
