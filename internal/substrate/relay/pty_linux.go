// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package relay

import (
	"os"
	"os/exec"
	"syscall"

	"golang.org/x/sys/unix"
)

// startPTY starts cmd on a new pseudo-terminal of cols x rows and returns
// its master side.
func startPTY(cmd *exec.Cmd, cols, rows uint16) (*os.File, error) {
	var cred agentCred
	if cmd.SysProcAttr != nil {
		cred = cmd.SysProcAttr.Credential
	}
	master, slave, err := openPTY(cred)
	if err != nil {
		return nil, err
	}
	defer slave.Close()
	if err := setSize(master, cols, rows); err != nil {
		master.Close()
		return nil, err
	}
	cmd.Stdin, cmd.Stdout, cmd.Stderr = slave, slave, slave
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setsid, cmd.SysProcAttr.Setctty, cmd.SysProcAttr.Ctty = true, true, 0
	if err := cmd.Start(); err != nil {
		master.Close()
		return nil, err
	}
	return master, nil
}

func setSize(f *os.File, cols, rows uint16) error {
	return unix.IoctlSetWinsize(int(f.Fd()), unix.TIOCSWINSZ, &unix.Winsize{Col: cols, Row: rows})
}
