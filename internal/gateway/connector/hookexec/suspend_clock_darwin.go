// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package hookexec

import (
	"time"

	"golang.org/x/sys/unix"
)

// platformSuspendClock reads CLOCK_MONOTONIC_RAW, which libSystem computes
// from mach_continuous_time: it keeps counting while the Mac sleeps and no
// time adjustment moves it. Go's timers and monotonic readings use
// mach_absolute_time (CLOCK_UPTIME_RAW), which stops during sleep.
// clock_gettime is reached through libSystem by x/sys/unix, with no cgo and
// no new assembly; calling mach_continuous_time directly would need both.
// CLOCK_MONOTONIC counts sleep too, but in microsecond steps and following
// the adjusted wall clock.
func platformSuspendClock() (time.Duration, bool) {
	var now unix.Timespec
	if err := unix.ClockGettime(unix.CLOCK_MONOTONIC_RAW, &now); err != nil {
		return 0, false
	}
	return time.Duration(now.Nano()), true
}
