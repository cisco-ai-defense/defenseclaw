// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package relay

import (
	"os"
	"syscall"
)

func processAlive(pid int) bool    { return syscall.Kill(pid, 0) == nil }
func signalRecreateSocket(pid int) { _ = syscall.Kill(pid, syscall.SIGUSR1) }

// terminalSignals are caught by the run-agent wrapper (RunAgentCommand).
var terminalSignals = []os.Signal{syscall.SIGINT, syscall.SIGQUIT, syscall.SIGTSTP, syscall.SIGTTIN, syscall.SIGTTOU,
	syscall.SIGHUP, syscall.SIGTERM, syscall.SIGWINCH}
