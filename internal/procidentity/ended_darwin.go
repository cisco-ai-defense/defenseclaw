// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package procidentity

import "golang.org/x/sys/unix"

// sZomb is XNU's SZOMB process state (sys/proc.h).
const sZomb = 5

func ended(pid int) bool {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	return err == nil && info != nil && int(info.Proc.P_pid) == pid && info.Proc.P_stat == sZomb
}
