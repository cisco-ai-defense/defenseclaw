// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"slices"
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
