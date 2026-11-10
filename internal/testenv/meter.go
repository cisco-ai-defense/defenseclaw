// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import "time"

// MaxStretch is the most a Meter ever lets a time exceed its bound: a time
// over this many bounds fails whatever the host did, so the budget a test
// guards stays detectable.
const MaxStretch = 3.0

// busyShare is the part of a Meter interval a thread must have been ready to
// run, running or not, to count as busy: a thread that mostly sleeps is not
// waiting for the host.
const busyShare = 0.10

// threadTimes is what the kernel reports of one thread: the time it ran and
// the time it was ready to run and had no CPU.
type threadTimes struct{ run, wait time.Duration }

// deniedBetween is the time, over an interval of wall time, that the most
// kept-waiting busy thread of the process was ready to run and had no CPU: the
// longest wait among the threads present in both readings that ran or waited
// for at least busyShare of the interval. A call runs on one thread at a time,
// so the longest wait is what the host can have cost it; the mean would hide
// it behind the threads that only helped. A process that only sleeps has no
// busy thread and reads 0, whatever the host does around it.
func deniedBetween(before, after map[int]threadTimes, wall time.Duration) time.Duration {
	if wall <= 0 {
		return 0
	}
	var longest time.Duration
	for tid, then := range before {
		now, ok := after[tid]
		if !ok {
			continue
		}
		run, wait := now.run-then.run, now.wait-then.wait
		if run < 0 || wait < 0 || float64(run+wait) < busyShare*float64(wall) {
			continue
		}
		longest = max(longest, min(wait, wall))
	}
	return longest
}

// Meter measures, over the interval between StartMeter and a later reading,
// how long the host kept this process from the CPU it was ready to use. It
// is made for one timed call: start it just before the call and ask it when
// the call has ended, so the reading is of the call's own interval. A host
// that does not report it (anything but Linux with scheduler statistics)
// reads 0, and the bound stays the product value.
type Meter struct {
	started time.Time
	before  map[int]threadTimes
}

// StartMeter starts a Meter now.
func StartMeter() *Meter {
	return &Meter{started: time.Now(), before: readThreadTimes()}
}

// Denied is the time since StartMeter that the process was ready to run and
// had no CPU (0 on an idle host and for a call that only waited).
func (m *Meter) Denied() time.Duration {
	if m == nil || m.before == nil {
		return 0
	}
	after := readThreadTimes()
	if after == nil {
		return 0
	}
	return deniedBetween(m.before, after, time.Since(m.started))
}

// Within reports whether a call that took took, measured from StartMeter to
// its end, stayed inside bound once the time the host denied it the CPU is
// taken off, and never took more than MaxStretch times the bound. A call
// inside bound costs no reading.
func (m *Meter) Within(took, bound time.Duration) bool {
	if took <= bound {
		return true
	}
	if float64(took) > MaxStretch*float64(bound) {
		return false
	}
	return took-m.Denied() <= bound
}
