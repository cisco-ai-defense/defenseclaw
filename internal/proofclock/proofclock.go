// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package proofclock is the time source of the post-deadline proofs of a
// per-user hook call (rel-1-0-6 GAP-0295, GAP-0781): the budgets that bound
// how far a call may run past its deadline, and the age of the gateway
// process a fresh-start proof reads.
//
// Those proofs read every process of the account, so what they cost follows
// the host. A test that wants a positive proof must not race the host for
// it, and must not widen the product budget either: it installs a clock it
// controls (proofclocktest), asserts the budget the product asked for, and
// decides when, if ever, a budget is spent. A release build always runs the
// system clock.
package proofclock

import (
	"context"
	"sync/atomic"
	"time"
)

// Clock is a source of time and of timers.
type Clock interface {
	Now() time.Time
	// NewTimer returns a channel that receives once d has passed on this
	// clock, and a function that stops the timer.
	NewTimer(d time.Duration) (<-chan time.Time, func())
}

type clockBox struct{ clock Clock }

// active is nil for the system clock.
var active atomic.Pointer[clockBox]

// heldTimersBake is empty in every release build. A test builds the hook
// helper it runs as a separate process with it set to "1" (-ldflags -X), so
// that helper never spends a proof budget on a timer and reads time as of
// its start: a proof then ends on its own result, never on the speed of the
// host. Like outageAccountHomeBake
// in internal/cli, no environment variable, file or flag can set it.
var heldTimersBake string

func init() {
	if heldTimersBake == "1" {
		active.Store(&clockBox{clock: heldTimers{at: time.Now()}})
	}
}

// Use makes c the clock of every proof until the returned function runs. A
// nil c is the system clock. Only tests call it.
func Use(c Clock) (restore func()) {
	var next *clockBox
	if c != nil {
		next = &clockBox{clock: c}
	}
	previous := active.Swap(next)
	return func() { active.Store(previous) }
}

// Now is the current time.
func Now() time.Time {
	if box := active.Load(); box != nil {
		return box.clock.Now()
	}
	return time.Now()
}

// Since is the time elapsed since t.
func Since(t time.Time) time.Duration { return Now().Sub(t) }

// Until is the time left until t.
func Until(t time.Time) time.Duration { return t.Sub(Now()) }

// NewTimer returns a channel that receives after d and a function that stops
// the timer.
func NewTimer(d time.Duration) (<-chan time.Time, func()) {
	if box := active.Load(); box != nil {
		return box.clock.NewTimer(d)
	}
	timer := time.NewTimer(d)
	return timer.C, func() { timer.Stop() }
}

// WithTimeout is context.WithTimeout on the proof clock.
func WithTimeout(parent context.Context, d time.Duration) (context.Context, context.CancelFunc) {
	box := active.Load()
	if box == nil {
		return context.WithTimeout(parent, d)
	}
	ctx, cancel := context.WithCancelCause(parent)
	expired, stop := box.clock.NewTimer(d)
	done := make(chan struct{})
	go func() {
		select {
		case <-expired:
			cancel(context.DeadlineExceeded)
		case <-ctx.Done():
		case <-done:
		}
	}()
	return &timeoutContext{Context: ctx, deadline: box.clock.Now().Add(d)}, func() {
		stop()
		cancel(context.Canceled)
		close(done)
	}
}

// timeoutContext reports the deadline on the proof clock, and
// context.DeadlineExceeded when the timer ended it.
type timeoutContext struct {
	context.Context
	deadline time.Time
}

func (c *timeoutContext) Deadline() (time.Time, bool) { return c.deadline, true }

func (c *timeoutContext) Err() error {
	if err := c.Context.Err(); err != nil {
		if cause := context.Cause(c.Context); cause == context.DeadlineExceeded {
			return cause
		}
		return err
	}
	return nil
}

// heldTimers is the clock of a helper built with heldTimersBake: its timers
// never end, and time stands at the start of the process, so the age of a
// gateway process read by a proof is its age when the helper started, not
// after the call it made.
type heldTimers struct{ at time.Time }

func (h heldTimers) Now() time.Time { return h.at }

func (heldTimers) NewTimer(time.Duration) (<-chan time.Time, func()) {
	return nil, func() {}
}
