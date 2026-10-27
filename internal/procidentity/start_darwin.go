// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package procidentity

import (
	"time"

	"golang.org/x/sys/unix"
)

func startTime(pid int) (time.Time, bool) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", pid)
	if err != nil || info == nil || int(info.Proc.P_pid) != pid {
		return time.Time{}, false
	}
	return time.Unix(int64(info.Proc.P_starttime.Sec), int64(info.Proc.P_starttime.Usec)*1000), true
}
