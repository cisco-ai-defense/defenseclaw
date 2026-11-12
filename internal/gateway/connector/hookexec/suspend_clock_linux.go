// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookexec

import (
	"time"

	"golang.org/x/sys/unix"
)

// platformSuspendClock reads CLOCK_BOOTTIME: CLOCK_MONOTONIC (Go's timers and
// monotonic readings) plus the time the system was suspended. It is the
// clock the kernel counts the process start on (procStatStartTime).
func platformSuspendClock() (time.Duration, bool) {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_BOOTTIME, &now); err != nil {
		return 0, false
	}
	return time.Duration(now.Nano()), true
}
