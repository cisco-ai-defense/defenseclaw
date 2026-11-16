// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package hookexec

import (
	"os"
	"time"

	"golang.org/x/sys/unix"
)

// processStartTimeKnown reports a system that names the process start.
const processStartTimeKnown = true

func processStartTime(time.Time) (time.Time, bool) {
	info, err := unix.SysctlKinfoProc("kern.proc.pid", os.Getpid())
	if err != nil {
		return time.Time{}, false
	}
	started := info.Proc.P_starttime
	return time.Unix(int64(started.Sec), int64(started.Usec)*int64(time.Microsecond)), true
}
