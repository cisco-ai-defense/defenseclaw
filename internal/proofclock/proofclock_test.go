// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package proofclock_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/proofclock"
	"github.com/defenseclaw/defenseclaw/internal/proofclock/proofclocktest"
)

// A timeout on the proof clock ends when the clock reaches it, not before,
// and reports the deadline on that clock.
func TestWithTimeoutEndsWhenTheProofClockReachesIt(t *testing.T) {
	clock := proofclocktest.Install(t)
	ctx, cancel := proofclock.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	deadline, ok := ctx.Deadline()
	if !ok || proofclock.Until(deadline) != 300*time.Millisecond {
		t.Fatalf("deadline %v %v, want 300ms ahead on the proof clock", deadline, ok)
	}
	clock.Advance(300*time.Millisecond - time.Nanosecond)
	if err := ctx.Err(); err != nil {
		t.Fatalf("ended just inside its budget: %v", err)
	}
	clock.Advance(time.Nanosecond)
	<-ctx.Done()
	if err := ctx.Err(); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("ended with %v, want a deadline", err)
	}
	if got := clock.Requested(); len(got) != 1 || got[0] != 300*time.Millisecond {
		t.Fatalf("timers %v, want one of 300ms", got)
	}
}

// A stopped timeout and a canceled parent leave the clock alone.
func TestWithTimeoutCanceledBeforeItsBudgetIsNoDeadline(t *testing.T) {
	clock := proofclocktest.Install(t)
	ctx, cancel := proofclock.WithTimeout(context.Background(), time.Second)
	cancel()
	clock.Advance(time.Hour)
	if err := ctx.Err(); !errors.Is(err, context.Canceled) {
		t.Fatalf("canceled timeout ended with %v, want canceled", err)
	}
}

// A timer of zero or less has ended already; a timer that was stopped never
// ends.
func TestNewTimerOnTheProofClock(t *testing.T) {
	clock := proofclocktest.Install(t)
	zero, _ := proofclock.NewTimer(0)
	select {
	case <-zero:
	default:
		t.Fatal("a timer of zero has not ended")
	}
	stopped, stop := proofclock.NewTimer(time.Second)
	stop()
	clock.Advance(time.Hour)
	select {
	case <-stopped:
		t.Fatal("a stopped timer ended")
	default:
	}
}

// Without a test clock the proofs run on the system clock.
func TestSystemClockIsTheDefault(t *testing.T) {
	before := time.Now()
	if now := proofclock.Now(); now.Before(before) {
		t.Fatalf("Now %v is before %v", now, before)
	}
	expired, stop := proofclock.NewTimer(time.Millisecond)
	defer stop()
	<-expired
}
