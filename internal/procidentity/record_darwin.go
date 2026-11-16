// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package procidentity

import (
	"fmt"

	"golang.org/x/sys/unix"
)

func recorded(pid int) (string, bool) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || info == nil || int(info.Proc.P_pid) != pid {
		return "", false
	}
	start := info.Proc.P_starttime
	return fmt.Sprintf("%d.%06d", start.Sec, start.Usec), true
}
