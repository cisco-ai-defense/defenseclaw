// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"runtime"
	"time"
)

// Two meters tell a test what the host did to it, so a test of a time budget
// can tell a slow product from a slow host. Neither moves a bound or pays one
// call with the time another thread lost. Measure is for one call that runs on
// the calling goroutine: it reads the thread that ran it, and only that
// thread. Window is for a load measurement, many calls whose work passes
// between goroutines on every thread of the process: no thread can be named
// for such a call (holding each call on a thread of its own changes the
// schedule being measured), so a Window excuses nothing; it says whether the
// host let the measurement run at all.

// MaxStretch is the most a time ever exceeds its bound and still passes: a
// time over this many bounds fails whatever the host did, so the budget a test
// guards stays detectable.
const MaxStretch = 3.0

// StarvedShare is the part of a Window the host must have kept a busy thread
// of the process from the CPU, for the window to count as one the host did not
// let run. A quarter leaves the process three quarters of its CPUs, which
// stretches a time by a third; a load measurement that misses a bound by far
// more than that has not been slowed by the host alone.
const StarvedShare = 0.25

// busyShare is the part of a Window a thread must have been ready to run,
// running or not, to count as busy: a thread that mostly sleeps is not
// waiting for the host.
const busyShare = 0.10

// Call is the reading of one timed call: how long the host kept the thread
// that ran it from the CPU while the call was in progress.
type Call struct {
	denied time.Duration
}

// Measure runs call on this goroutine, on an operating-system thread held for
// the call alone, and reads what the host did to that thread: the time it was
// ready to run and had no CPU between the start and the end of the call. It is
// the thread the timed call executes on, so the time it was kept waiting is
// time the call itself lost; a call that sleeps or blocks is not ready to run,
// so it reads only the short waits at its own wake-ups, and it cannot be
// excused by time other threads of the process (a load generator, another
// call) were kept waiting. Use it for a call that runs on the calling
// goroutine and does not hand its work to others for long: a call that waits
// on other goroutines keeps the time it waited for them. A host that does not
// report scheduler statistics (anything but Linux) reads 0, and the bound
// stays the product value.
func Measure(call func()) Call {
	runtime.LockOSThread()
	defer runtime.UnlockOSThread()
	before, ok := threadWaited()
	started := time.Now()
	call()
	if !ok {
		return Call{}
	}
	after, ok := threadWaited()
	if !ok || after < before {
		return Call{}
	}
	return Call{denied: min(after-before, time.Since(started))}
}

// Denied is the time the thread that ran the call was ready to run and had no
// CPU while the call was in progress.
func (c Call) Denied() time.Duration { return c.denied }

// Within reports whether a call that took took stayed inside bound once the
// time the host denied its thread the CPU is taken off, and never took more
// than MaxStretch times the bound. A call inside bound passes on its wall time.
func (c Call) Within(took, bound time.Duration) bool {
	if took <= bound {
		return true
	}
	if float64(took) > MaxStretch*float64(bound) {
		return false
	}
	return took-c.denied <= bound
}

// threadTimes is what the kernel reports of one thread: the time it ran and
// the time it was ready to run and had no CPU.
type threadTimes struct{ run, wait time.Duration }

// starvedBetween reports whether, over an interval of wall time, some busy
// thread of the process (one that ran or waited for at least busyShare of the
// interval, present in both readings) was ready to run and had no CPU for at
// least StarvedShare of it. A process that only sleeps has no busy thread and
// is never starved, whatever the host does around it.
func starvedBetween(before, after map[int]threadTimes, wall time.Duration) bool {
	if wall <= 0 {
		return false
	}
	for tid, then := range before {
		now, ok := after[tid]
		if !ok {
			continue
		}
		run, wait := now.run-then.run, now.wait-then.wait
		if run < 0 || wait < 0 || float64(run+wait) < busyShare*float64(wall) {
			continue
		}
		if float64(wait) >= StarvedShare*float64(wall) {
			return true
		}
	}
	return false
}

// Window watches the host over one interval, from StartWindow to a later
// question. It is made for a load measurement: many calls, in flight together,
// whose work moves between goroutines and threads, so no call has a thread to
// be read (see the package comment). It answers only whether the host let the
// process run; the caller does not subtract anything from a time with it.
type Window struct {
	started time.Time
	before  map[int]threadTimes
}

// StartWindow starts a Window now.
func StartWindow() *Window {
	return &Window{started: time.Now(), before: readThreadTimes()}
}

// Starved reports whether the host kept a busy thread of this process from
// the CPU for at least StarvedShare of the time since StartWindow. A host that
// reports no scheduler statistics is never starved, and its measurement is
// judged as it stands.
func (w *Window) Starved() bool {
	if w == nil || w.before == nil {
		return false
	}
	after := readThreadTimes()
	if after == nil {
		return false
	}
	return starvedBetween(w.before, after, time.Since(w.started))
}
