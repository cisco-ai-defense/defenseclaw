// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package daemon

import (
	"context"
	"fmt"
	"os/exec"
	"strconv"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

const (
	darwinPSPath    = "/bin/ps"
	darwinPSTimeout = 2 * time.Second
)

func darwinProcessStartIdentity(pid int) (string, error) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return "", err
	}
	start := info.Proc.P_starttime
	return fmt.Sprintf("%d.%06d", start.Sec, start.Usec), nil
}

func darwinProcessInspectionCommand(ctx context.Context, pid int) *exec.Cmd {
	cmd := exec.CommandContext(ctx, darwinPSPath, "-p", strconv.Itoa(pid), "-o", "comm=")
	cmd.Env = []string{"LANG=C", "LC_ALL=C"}
	cmd.Dir = "/"
	return cmd
}

func processExecutableDarwin(pid int) (string, error) {
	ctx, cancel := context.WithTimeout(context.Background(), darwinPSTimeout)
	defer cancel()
	out, err := darwinProcessInspectionCommand(ctx, pid).Output()
	if err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return "", fmt.Errorf("daemon: %s inspection for pid %d: %w", darwinPSPath, pid, ctxErr)
		}
		return "", err
	}
	comm := strings.TrimSpace(string(out))
	if comm == "" {
		return "", fmt.Errorf("daemon: %s returned empty command for pid %d", darwinPSPath, pid)
	}
	return comm, nil
}
