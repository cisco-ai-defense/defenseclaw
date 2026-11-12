// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !unix

package relay

import (
	"os"
	"os/exec"
)

// The actor is Linux; elsewhere the command is stopped without its
// children (the relay's file routes are exercised only for development).
func setProcessGroup(*exec.Cmd) {}

func killProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}

func exitCodeOf(ps *os.ProcessState) int {
	if c := ps.ExitCode(); c >= 0 {
		return c
	}
	return 1
}
