// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookexec

import (
	"time"

	"golang.org/x/sys/windows"
)

// platformSuspendClock reads GetTickCount64 (windows.DurationSinceBoot): the
// milliseconds since boot, sleep and hibernation included (Microsoft points
// to QueryUnbiasedInterruptTime for the working time only). It is in
// kernel32 on every supported Windows; its 10-16 ms steps are inside
// suspendClockSlack. A WaitForSingleObject timeout does not count sleep on
// Windows 8 and later, which is why the waiter looks at this clock again.
func platformSuspendClock() (time.Duration, bool) {
	return windows.DurationSinceBoot(), true
}
