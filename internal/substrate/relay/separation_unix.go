// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build unix

package relay

import (
	"os/exec"
	"syscall"
)

type agentCred = *syscall.Credential

// asAgent makes cmd run as the agent's user. It keeps the other process
// attributes the caller set.
func (sp *separation) asAgent(cmd *exec.Cmd) {
	if sp == nil || sp.cred == nil {
		return
	}
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Credential = sp.cred
}
