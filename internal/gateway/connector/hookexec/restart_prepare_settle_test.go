// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"context"
	"errors"
	"slices"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/proofclock/proofclocktest"
)

// The deadline reads the restart answer of a call after the contact of the
// call and its background preparation are over, when a test asks for it
// (GAP-0859). A release build never waits: the read at the deadline is as
// fast as before.
func TestRestartAnswerReadHoldsForTheBackgroundPreparation(t *testing.T) {
	stubRestartWindowProof(t, false)
	sp, _ := specFor("claudecode")
	arm := func(t *testing.T, scan func() bool) (*answerWatchdog, Options) {
		t.Helper()
		opts := perUserRestartOptions(t.TempDir(), "open", false, newClaimedStopWriter(), newClaimedStopWriter(), func(int) {})
		opts.lateOrdinary = scan
		return prepareAnswerWatchdog(&opts, sp, "open", time.Time{}), opts
	}
	t.Run("held until the scan and the rendering are over", func(t *testing.T) {
		release := make(chan struct{})
		w, opts := arm(t, func() bool { <-release; return true })
		w.restartWindowContact(opts, sp, "open", &perUserPeerCheck{})
		select {
		case <-w.contactSettled:
			t.Fatal("the contact was settled while the scan was still running")
		default:
		}
		close(release)
		<-w.contactSettled
		w.mu.Lock()
		prepared := w.restart != nil
		w.mu.Unlock()
		if !prepared {
			t.Fatal("the contact was settled before the outage answer was ready")
		}
	})
	t.Run("a call with nothing to prepare is settled at once", func(t *testing.T) {
		w, opts := arm(t, func() bool { return true })
		w.restartWindowContact(opts, sp, "open", nil)
		<-w.contactSettled
	})
	t.Run("a release build does not wait", func(t *testing.T) {
		release := make(chan struct{})
		defer close(release)
		w, opts := arm(t, func() bool { <-release; return true })
		w.restartWindowContact(opts, sp, "open", &perUserPeerCheck{})
		if w.awaitSettled != nil {
			t.Fatal("a watchdog armed with no test seam holds its deadline read")
		}
		w.awaitContactSettled()
	})
}

// A call that reconnects after an outage runs the contact again: the
// deadline reads wait for the scan of that later try as well, not only for
// the first (GAP-0859 review 3).
func TestRestartAnswerReadHoldsForALaterTryScan(t *testing.T) {
	stubRestartWindowProof(t, false)
	previous := holdForRestartPrepare
	holdForRestartPrepare = func(settled <-chan struct{}) { <-settled }
	t.Cleanup(func() { holdForRestartPrepare = previous })
	sp, _ := specFor("claudecode")
	opts := perUserRestartOptions(t.TempDir(), "open", false, newClaimedStopWriter(), newClaimedStopWriter(), func(int) {})
	var scans atomic.Int32
	secondStarted := make(chan struct{})
	releaseSecond := make(chan struct{})
	opts.lateOrdinary = func() bool {
		if scans.Add(1) == 1 {
			return false
		}
		close(secondStarted)
		<-releaseSecond
		return true
	}
	w := prepareAnswerWatchdog(&opts, sp, "open", time.Time{})
	w.restartWindowContact(opts, sp, "open", &perUserPeerCheck{})
	<-w.contactSettled
	w.awaitContactSettled() // the first scan is over: nothing to wait for
	w.restartWindowContact(opts, sp, "open", &perUserPeerCheck{})
	<-secondStarted
	read := make(chan struct{})
	go func() {
		w.awaitContactSettled()
		close(read)
	}()
	select {
	case <-read:
		t.Fatal("the deadline read passed while the later try was still scanning")
	case <-time.After(50 * time.Millisecond): // a pause that can only hide a failure, never cause one
	}
	close(releaseSecond)
	<-read
	w.mu.Lock()
	prepared := w.restart != nil
	w.mu.Unlock()
	if !prepared {
		t.Fatal("the deadline read passed before the outage answer of the later try was ready")
	}
}

// The service watch bounds one state read on the proof clock: a read the test
// holds is not known only once the production bound is spent (GAP-0859).
func TestManagedServiceStateReadIsBoundedOnTheProofClock(t *testing.T) {
	clock := proofclocktest.Install(t)
	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	type state struct{ up, known bool }
	got := make(chan state, 1)
	go func() {
		up, known := serviceRunningWithin(func() (bool, bool) { <-release; return true, true }, managedGatewayServiceStateWait)
		got <- state{up, known}
	}()
	for !slices.Equal(clock.Requested(), []time.Duration{managedGatewayServiceStateWait}) {
		time.Sleep(time.Millisecond)
	}
	select {
	case s := <-got:
		t.Fatalf("the read ended before its %s bound was spent: %+v", managedGatewayServiceStateWait, s)
	default:
	}
	clock.Advance(managedGatewayServiceStateWait)
	if s := <-got; s.up || s.known {
		t.Fatalf("a read past its bound is %+v, want not known", s)
	}
}

// The service watch spends its restart budget on the proof clock too: a stop
// read at the budget ends the call once the test moves the clock to it, not
// when a loaded host gets round to a real timer, and the repoll is the
// production one (GAP-0859).
func TestManagedServiceWatchSpendsItsBudgetOnTheProofClock(t *testing.T) {
	clock := proofclocktest.Install(t)
	const budget = time.Hour
	ctx, stop, release := watchManagedGatewayService(context.Background(), func() (bool, bool) { return false, true },
		time.Now().Add(budget), managedGatewayServiceWatchInterval)
	defer release()
	defer stop()
	gotConn(ctx)
	for hang := time.Now().Add(time.Minute); len(clock.Requested()) == 0; time.Sleep(time.Millisecond) {
		if time.Now().After(hang) { // a hang guard, not a timing assertion
			t.Fatal("the watch asked the proof clock for no timer")
		}
	}
	if first := clock.Requested()[0]; first > budget || first < budget-time.Minute {
		t.Fatalf("the watch asked for a timer of %s, want the budget of %s", first, budget)
	}
	select {
	case <-ctx.Done():
		t.Fatal("the watch ended the call before its budget was spent")
	case <-time.After(20 * time.Millisecond): // a pause that can only hide a failure, never cause one
	}
	clock.Advance(budget)
	select {
	case <-ctx.Done():
		if !errors.Is(context.Cause(ctx), errGatewayRestarting) {
			t.Fatalf("the watch ended the call with %v, want errGatewayRestarting", context.Cause(ctx))
		}
	case <-time.After(time.Minute): // a hang guard, not a timing assertion
		t.Fatal("the watch did not end the call once its budget was spent")
	}
}
