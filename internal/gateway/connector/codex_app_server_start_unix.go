// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !darwin && !windows

package connector

import "os/exec"

func configureCodexAppServerCommandPlatform(*exec.Cmd) {}

func startCodexAppServerProcess(command *exec.Cmd, _ string) error {
	return command.Start()
}

func terminateCodexAppServerProcess(command *exec.Cmd) error {
	return command.Process.Kill()
}
