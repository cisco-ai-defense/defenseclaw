// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package attach

import "os/exec"

func prepareMCPCmd(*exec.Cmd) {}

// terminateMCP and killMCP both end the process: Windows has no SIGTERM for
// a console-less child.
func terminateMCP(cmd *exec.Cmd) { killMCP(cmd) }

func killMCP(cmd *exec.Cmd) {
	if cmd.Process != nil {
		_ = cmd.Process.Kill()
	}
}
