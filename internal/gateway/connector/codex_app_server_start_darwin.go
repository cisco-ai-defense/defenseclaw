// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import (
	"os/exec"
	"syscall"
)

func configureCodexAppServerCommandPlatform(*exec.Cmd) {}

func startCodexAppServerProcess(command *exec.Cmd, expectedDigest string) error {
	return startProtectedDarwinAgentCommand(command, "codex", expectedDigest)
}

func terminateCodexAppServerProcess(command *exec.Cmd) error {
	if command.SysProcAttr != nil && command.SysProcAttr.Setpgid && command.Process != nil {
		return protectedDarwinKill(-command.Process.Pid, syscall.SIGKILL)
	}
	return command.Process.Kill()
}
