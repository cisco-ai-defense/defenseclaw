// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"errors"
	"sync/atomic"
	"testing"
	"time"
)

// W2B-G-enum review loop 2: a lookup that never returned was counted against
// one limit shared by every account, and each pass started it again, so one
// account whose directory never answered stopped the lookups of all the
// others after four passes. A lookup still running now holds only its own
// account; the others run on every pass.
func TestIdentityLookupGateHoldsOnlyTheStalledAccount(t *testing.T) {
	var gate identityLookupGate
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	var stalledCalls, otherCalls atomic.Int32
	stalled := func(context.Context) (string, error) {
		stalledCalls.Add(1)
		<-release // a native call that ignores its deadline
		return "late", nil
	}
	other := func(context.Context) (string, error) {
		otherCalls.Add(1)
		return "fresh", nil
	}
	for pass := 1; pass <= 8; pass++ {
		ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
		_, errA := identityLookupGated(ctx, &gate, "A", stalled)
		cancel()
		want := errIdentityLookupStillRunning
		if pass == 1 {
			want = context.DeadlineExceeded
		}
		if !errors.Is(errA, want) {
			t.Fatalf("pass %d: stalled account err = %v, want %v", pass, errA, want)
		}
		got, errB := identityLookupGated(context.Background(), &gate, "B", other)
		if errB != nil || got != "fresh" {
			t.Fatalf("pass %d: the other account = %q, %v; want it looked up", pass, got, errB)
		}
	}
	if stalledCalls.Load() != 1 || otherCalls.Load() != 8 {
		t.Fatalf("lookups started: stalled %d, other %d; want 1 and 8", stalledCalls.Load(), otherCalls.Load())
	}
	if !gate.isLate("A") || gate.isLate("B") {
		t.Fatalf("late: A %v, B %v; want only the stalled account late", gate.isLate("A"), gate.isLate("B"))
	}
}

// Once the stalled lookup returns, the account is looked up again, and an
// answer in time clears its lateness.
func TestIdentityLookupGateRetriesAnAccountAfterItsLookupReturns(t *testing.T) {
	var gate identityLookupGate
	release := make(chan struct{})
	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if _, err := identityLookupGated(ctx, &gate, "A", func(context.Context) (int, error) {
		<-release
		return 0, nil
	}); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the wait ended by its context", err)
	}
	close(release)
	for deadline := time.Now().Add(5 * time.Second); gate.runningLookups() != 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Fatal("the returned lookup is still counted as running")
		}
	}
	if !gate.isLate("A") {
		t.Fatal("an account whose last lookup did not answer in time must stay late until one does")
	}
	got, err := identityLookupGated(context.Background(), &gate, "A", func(context.Context) (int, error) { return 7, nil })
	if err != nil || got != 7 || gate.isLate("A") {
		t.Fatalf("retry = %d, %v, late %v; want the answer and the lateness cleared", got, err, gate.isLate("A"))
	}
}

// runningLookups counts the lookups of g that have not returned.
func (g *identityLookupGate) runningLookups() int {
	g.mu.Lock()
	defer g.mu.Unlock()
	n := 0
	for _, count := range g.running {
		n += count
	}
	return n
}

// waitIdentityLookupGateIdle waits until every lookup of g has returned, and
// forgets which accounts were late, so one test's lookups never reach the
// next test.
func waitIdentityLookupGateIdle(t *testing.T, g *identityLookupGate) {
	t.Helper()
	for deadline := time.Now().Add(5 * time.Second); g.runningLookups() != 0; time.Sleep(time.Millisecond) {
		if time.Now().After(deadline) {
			t.Errorf("%d identity lookups are still running", g.runningLookups())
			return
		}
	}
	g.mu.Lock()
	g.late = nil
	g.mu.Unlock()
}
