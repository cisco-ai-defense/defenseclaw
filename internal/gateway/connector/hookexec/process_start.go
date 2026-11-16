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
// initialization, as does a system that does not say. A Secure Client hook
// uses SecureClientProcessStartTime.
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

// secureClientMaxProcessStartAge bounds the process start a Secure Client
// hook accepts from the operating system; an older one (or one in the
// future) gives the call a fresh budget from the package's initialization.
const secureClientMaxProcessStartAge = 30 * time.Second

// SecureClientProcessStartTime is the start of a Secure Client hook call:
// ProcessStartTime as 1.0.8 had it. Secure Client hooks stay unchanged in
// 1.0.9 (they were not reviewed or tested for it): its hook held more than
// 30 s still asks the gateway with a fresh budget, where ProcessStartTime
// would spend it and give the Secure Client fail mode's answer without
// asking (an allow when that mode is open). Kept until the Secure Client
// round takes the one start of ProcessStartTime.
func SecureClientProcessStartTime() time.Time {
	now := time.Now()
	started, ok := processStartTime(now)
	return secureClientCallStart(started, ok, now, hookProcessInit)
}

// secureClientCallStart is the start of a Secure Client hook call the system
// created at started (ok: the system said), seen at now, in a process
// initialized at init.
func secureClientCallStart(started time.Time, ok bool, now, init time.Time) time.Time {
	if ok {
		if age := now.Sub(started); age >= 0 && age <= secureClientMaxProcessStartAge {
			return started
		}
	}
	return init
}
