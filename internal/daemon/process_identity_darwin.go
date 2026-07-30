// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package daemon

import (
	"fmt"
	"os/exec"
	"strconv"
	"strings"

	"golang.org/x/sys/unix"
)

const darwinPSPath = "/bin/ps"

func darwinProcessStartIdentity(pid int) (string, error) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return "", err
	}
	start := info.Proc.P_starttime
	return fmt.Sprintf("%d.%06d", start.Sec, start.Usec), nil
}

func darwinProcessInspectionCommand(pid int) *exec.Cmd {
	cmd := exec.Command(darwinPSPath, "-p", strconv.Itoa(pid), "-o", "comm=")
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	cmd.Dir = "/"
	return cmd
}

func processExecutableDarwin(pid int) (string, error) {
	out, err := darwinProcessInspectionCommand(pid).Output()
	if err != nil {
		return "", err
	}
	comm := strings.TrimSpace(string(out))
	if comm == "" {
		return "", fmt.Errorf("daemon: %s returned empty command for pid %d", darwinPSPath, pid)
	}
	return comm, nil
}
