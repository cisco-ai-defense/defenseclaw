// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package hookpaths

import (
	"time"

	"golang.org/x/sys/unix"
)

// filesystemClockNow is the clock the kernel stamps change and modification
// times with: its coarse real-time clock, which moves one tick (a few
// milliseconds) at a time and never runs ahead of a time it will stamp later.
// A timestamp read from a path that is strictly older than this value was
// written in an earlier tick, so any later change of the path gets a later
// stamp (activeStateSettleLimit). ok is false when the clock cannot be read.
func filesystemClockNow() (time.Time, bool) {
	var now unix.Timespec
	if unix.ClockGettime(unix.CLOCK_REALTIME_COARSE, &now) != nil {
		return time.Time{}, false
	}
	return time.Unix(now.Unix()), true
}
