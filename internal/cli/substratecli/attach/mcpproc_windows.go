// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package attach

import (
	"os/exec"

	"github.com/defenseclaw/defenseclaw/internal/processutil"
)

// mcpProc is a started command and the kill-on-close Job Object that holds
// it and everything it starts: `npx ...` runs npx.cmd under cmd.exe, which
// starts node.exe, so ending only the direct process left node running
// (GAP-1008). If the launcher dies, Windows closes the job and ends the tree.
type mcpProc struct {
	cmd  *exec.Cmd
	tree *processutil.Tree
}

// startMCP starts cmd inside its job (created suspended, assigned, resumed).
func startMCP(cmd *exec.Cmd) (*mcpProc, error) {
	tree, err := processutil.StartTree(cmd)
	if err != nil {
		return nil, err
	}
	return &mcpProc{cmd: cmd, tree: tree}, nil
}

// terminate and kill both end the whole job: Windows has no SIGTERM for a
// console-less child.
func (p *mcpProc) terminate() { p.kill() }

func (p *mcpProc) kill() {
	p.tree.Kill()
	_ = p.cmd.Process.Kill()
}

// release runs once cmd.Wait has returned: it ends what the command left
// running and waits until it is gone, so the presence record is removed
// only after the whole tree.
func (p *mcpProc) release() { p.tree.Close() }
