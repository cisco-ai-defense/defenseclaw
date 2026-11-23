// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !unix && !windows

package attach

import "os/exec"

// mcpProc is a started command; this platform has no process tree to end.
type mcpProc struct{ cmd *exec.Cmd }

func startMCP(cmd *exec.Cmd) (*mcpProc, error) {
	if err := cmd.Start(); err != nil {
		return nil, err
	}
	return &mcpProc{cmd: cmd}, nil
}

func (p *mcpProc) terminate() { p.kill() }

func (p *mcpProc) kill() { _ = p.cmd.Process.Kill() }

func (p *mcpProc) release() {}
