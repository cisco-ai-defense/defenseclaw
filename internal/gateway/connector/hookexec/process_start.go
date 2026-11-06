// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import "time"

// hookProcessInit is when this package was initialized, the fallback for
// ProcessStartTime.
var hookProcessInit = time.Now()

// ProcessStartTime is when the operating system created this process, so a
// hook's time budgets count the launch and the runtime resolution that come
// before Run (they took seconds on a busy Windows host during an
// attestation repair, GAP-0155). A process that ran late keeps that start
// at any age: its budget is spent, and it is never given a new one. Before,
// a start more than 30 s old was taken for a clock problem and the call got
// a fresh budget from this package's initialization, so a hook the host
// froze for a minute during Setup /repair asked its gateway again and gave
// a verdict 73 s after the agent started it (rel-1-0-6 GAP-0648). Only a
// start in the future (the clock stepped back) falls back to the package's
// initialization, as does a system that does not say.
func ProcessStartTime() time.Time {
	now := time.Now()
	started, ok := processStartTime(now)
	return hookCallStart(started, ok, now)
}

// hookCallStart is the start of a hook call the system created at started
// (ok: the system said), seen at now.
func hookCallStart(started time.Time, ok bool, now time.Time) time.Time {
	if ok && !started.After(now) {
		return started
	}
	return hookProcessInit
}
