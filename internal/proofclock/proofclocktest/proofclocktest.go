// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package proofclocktest is a proofclock.Clock that a test controls: time
// stands still until the test moves it, and a timer ends only when the test
// moves time past it. It records the duration of every timer the product
// asked for, so a test can assert the real budget while it decides whether
// that budget is spent. Only test files import it.
package proofclocktest

import (
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/proofclock"
)

// Clock is a manual proofclock.Clock.
type Clock struct {
	mu       sync.Mutex
	now      time.Time
	timers   []*timer
	requests []time.Duration
	stops    int
}

type timer struct {
	due     time.Time
	c       chan time.Time
	stopped bool
	fired   bool
}

// Install makes a new Clock, standing at the system time of the call, the
// clock of every proof until the test ends.
func Install(t testing.TB) *Clock {
	t.Helper()
	c := &Clock{now: time.Now()}
	t.Cleanup(proofclock.Use(c))
	return c
}

// Now is the time the clock stands at.
func (c *Clock) Now() time.Time {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.now
}

// NewTimer starts a timer of d. It ends when the clock is moved d forward.
func (c *Clock) NewTimer(d time.Duration) (<-chan time.Time, func()) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.requests = append(c.requests, d)
	t := &timer{due: c.now.Add(d), c: make(chan time.Time, 1)}
	if d <= 0 {
		t.fired = true
		t.c <- c.now
	}
	c.timers = append(c.timers, t)
	return t.c, func() {
		c.mu.Lock()
		defer c.mu.Unlock()
		if !t.stopped {
			c.stops++
		}
		t.stopped = true
	}
}

// Set moves the clock to t and ends every timer that is due by then.
func (c *Clock) Set(t time.Time) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.now = t
	for _, tm := range c.timers {
		if !tm.stopped && !tm.fired && !tm.due.After(t) {
			tm.fired = true
			tm.c <- t
		}
	}
}

// Advance moves the clock d forward.
func (c *Clock) Advance(d time.Duration) { c.Set(c.Now().Add(d)) }

// Requested lists the duration of every timer started so far, in order.
func (c *Clock) Requested() []time.Duration {
	c.mu.Lock()
	defer c.mu.Unlock()
	return append([]time.Duration(nil), c.requests...)
}

// Stopped counts the timers that were stopped so far. The product stops the
// timer of a bounded read when the read ends, so a test that holds time still
// can wait on that event instead of on the speed of the host.
func (c *Clock) Stopped() int {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.stops
}
