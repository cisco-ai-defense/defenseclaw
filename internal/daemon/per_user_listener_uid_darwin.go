// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package daemon

import "golang.org/x/sys/unix"

func gatewayProcessUID(pid int) (int, error) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil {
		return -1, err
	}
	return int(info.Eproc.Ucred.Uid), nil
}
