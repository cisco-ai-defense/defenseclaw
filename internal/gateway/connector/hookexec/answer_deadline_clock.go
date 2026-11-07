// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"sync"
	"time"
)

// The answer deadline of a managed call outside Secure Client counts the
// time the computer slept. The watchdog waits on timers that stop while it
// sleeps: Go's timers run on CLOCK_MONOTONIC on Linux and on
// mach_absolute_time on macOS, and a WaitForSingleObject timeout on Windows
// 8 and later does not count low-power time. On Linux the deadline also kept
// the monotonic reading of the process start, so a suspend after the start
// was read did not count at all. A managed call the computer slept through
// woke with its budget seemingly left, and a gateway verdict read first
// reached the agent past the budget through the 1 s lateAnswerWait
// (rel-1-0-6 GAP-0648 review F4). Such a deadline is now also kept on a
// clock that counts sleep (platformSuspendClock): the watchdog looks at it
// each time it wakes, at least every suspendCheckInterval, and the call's
// own answer is given only before it (lateAnswerDue). Per-user calls keep
// their deadline as it was; Secure Client calls have none.

// clockAnchor pairs a reading of the clock time.Now() compares on with one of
// the sleep-counting clock, taken together, so a time can be placed on the
// sleep-counting clock.
type clockAnchor struct {
	at      time.Time
	suspend time.Duration
	ok      bool
}

// hookClockAnchor is taken when the package initializes: a hook's whole call
// comes after it.
var hookClockAnchor = readClockAnchor()

func readClockAnchor() clockAnchor {
	suspend, ok := platformSuspendClock()
	return clockAnchor{at: time.Now(), suspend: suspend, ok: ok}
}

// place is t on the sleep-counting clock. t.Sub uses the monotonic readings
// when t has one (a Linux process start, a test), else the wall clock (a
// macOS or Windows process start): either way t keeps its distance from the
// anchor.
func (a clockAnchor) place(t time.Time) time.Duration { return a.suspend + t.Sub(a.at) }

// suspendClockSlack is how far the sleep-counting clock must be past a
// deadline before it ends the wait: more than the steps of the coarsest one
// (GetTickCount64, 10-16 ms), so a call that did not sleep keeps its
// deadline on the awake clock, to the same precision as before.
const suspendClockSlack = 50 * time.Millisecond

// suspendCheckInterval bounds each wait of a watchdog whose deadline counts
// sleep, so it looks at the sleep-counting clock soon after a wake.
const suspendCheckInterval = 200 * time.Millisecond

// deadlineState is the answer deadline an answerDeadlineWaiter waits for.
// The deadline only moves later (extendTo, after the gateway reported that it
// waits on a remote scanner).
type deadlineState struct {
	mu       sync.Mutex
	deadline time.Time
	// sleepClock, once set (countSleep), is the clock that counts sleep the
	// deadline is also kept on, at sleepAt.
	sleepClock func() (time.Duration, bool)
	sleepAt    time.Duration
}

// countSleep makes the deadline count the time the computer sleeps, read
// from clock. A system with no sleep-counting clock keeps the awake clock.
func (s *deadlineState) countSleep(clock func() (time.Duration, bool)) {
	if !hookClockAnchor.ok || clock == nil {
		return
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.sleepClock = clock
	if !s.deadline.IsZero() {
		s.sleepAt = hookClockAnchor.place(s.deadline)
	}
}

// extendTo moves the deadline to t when t is later.
func (s *deadlineState) extendTo(t time.Time) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if t.After(s.deadline) {
		s.deadline = t
		s.sleepAt = hookClockAnchor.place(t)
	}
}

func (s *deadlineState) current() time.Time {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.deadline
}

// passed reports a deadline that is set and has come, on the awake clock or,
// for one that counts sleep, on the sleep-counting clock.
func (s *deadlineState) passed() bool {
	return !s.current().IsZero() && s.next() <= 0
}

// next is how long to wait before looking at the deadline again; zero or
// less once it has come.
func (s *deadlineState) next() time.Duration {
	s.mu.Lock()
	deadline, clock, sleepAt := s.deadline, s.sleepClock, s.sleepAt
	s.mu.Unlock()
	left := time.Until(deadline)
	if clock == nil || left <= 0 {
		return left
	}
	if now, ok := clock(); ok {
		left = min(left, sleepAt+suspendClockSlack-now)
	}
	if left <= 0 {
		return left
	}
	return min(left, suspendCheckInterval)
}
