// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookexec

import (
	"sync/atomic"
	"testing"
	"time"
)

// S8 b2 review P2-2: a late ordinary call reads the account outage tier
// once, shared by its restart and its ordinary answer, started a second
// before the deadline while the call is still unanswered, with one budget
// (lateOrdinaryTierWait) measured from the deadline.

// lateOrdinaryWatchdog is a late ordinary per-user call whose restart-window
// and ordinary answers are both prepared, reading its tier with tier.
func lateOrdinaryWatchdog(t *testing.T, tier func() string) (*answerWatchdog, chan int, *claimedStopWriter) {
	t.Helper()
	sp, _ := specFor("claudecode")
	stdout, stderr := newClaimedStopWriter(), newClaimedStopWriter()
	exited := make(chan int, 1)
	opts := perUserRestartOptions(t.TempDir(), "open", false, stdout, stderr, func(code int) { exited <- code })
	opts.OutageFailModeNow = tier
	opts.lateOrdinary = func() bool { return true }
	opts.failurePayload = []byte(gap0268Ordinary)
	w := prepareAnswerWatchdog(&opts, sp, "open", time.Time{})
	w.noDecisionPending()
	w.mu.Lock()
	w.lookGen++
	gen := w.lookGen
	w.mu.Unlock()
	w.startOrdinaryLook(gen, opts, sp, "open")
	w.restartWindowContact(opts, sp, "open", &perUserPeerCheck{})
	for deadline := time.Now().Add(5 * time.Second); ; time.Sleep(5 * time.Millisecond) {
		w.mu.Lock()
		ready := w.ordinary != nil && w.restartChoice != nil
		w.mu.Unlock()
		if ready {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("late answers never prepared")
		}
	}
	return w, exited, stdout
}

func awaitExit(t *testing.T, exited chan int) int {
	t.Helper()
	select {
	case code := <-exited:
		return code
	case <-time.After(10 * time.Second):
		t.Fatal("no answer")
		return 0
	}
}

// A stalled tier read (2 s) holds the deadline answer for one budget, not
// one per answer: about 250 ms, and the answer stays closed.
func TestB2ReviewStalledTierHoldsTheAnswerOneBudget(t *testing.T) {
	var reads atomic.Int32
	w, exited, stdout := lateOrdinaryWatchdog(t, func() string { reads.Add(1); time.Sleep(2 * time.Second); return "open" })
	deadline := time.Now()
	go w.watch(deadline)
	code := awaitExit(t, exited)
	late := time.Since(deadline)
	if late > 400*time.Millisecond {
		t.Fatalf("answer %v after the deadline with a stalled tier read, want one budget (%v)", late, lateOrdinaryTierWait)
	}
	if !nativeAnswerBlocks(code, stdout.String()) {
		t.Fatalf("stalled tier read gave exit %d %q, want the closed answer", code, stdout.String())
	}
	if n := reads.Load(); n != 1 {
		t.Fatalf("%d tier reads, want one shared read", n)
	}
}

// The read starts a second before the deadline while the call is
// unanswered, so a read of 600 ms is done when the deadline comes and the
// open tier applies at once.
func TestB2ReviewTierReadStartsBeforeTheDeadline(t *testing.T) {
	var started atomic.Int64
	w, exited, stdout := lateOrdinaryWatchdog(t, func() string {
		started.CompareAndSwap(0, time.Now().UnixNano())
		time.Sleep(600 * time.Millisecond)
		return "open"
	})
	deadline := time.Now().Add(1300 * time.Millisecond)
	go w.watch(deadline)
	code := awaitExit(t, exited)
	late := time.Since(deadline)
	if nativeAnswerBlocks(code, stdout.String()) {
		t.Fatalf("exit %d %q: the open tier read before the deadline did not apply", code, stdout.String())
	}
	if at := time.Unix(0, started.Load()); started.Load() == 0 || !at.Before(deadline.Add(-500*time.Millisecond)) {
		t.Fatalf("tier read started %v before the deadline, want about a second", deadline.Sub(at))
	}
	if late > 200*time.Millisecond {
		t.Fatalf("answer %v after the deadline, want at once", late)
	}
}

// A call the gateway answers before the prepare lead never reads the tier.
func TestB2ReviewAnsweredBeforeTheLeadReadsNoTier(t *testing.T) {
	var reads atomic.Int32
	w, _, _ := lateOrdinaryWatchdog(t, func() string { reads.Add(1); return "open" })
	deadline := time.Now().Add(1500 * time.Millisecond)
	done := make(chan struct{})
	go func() { w.watch(deadline); close(done) }()
	time.Sleep(100 * time.Millisecond)
	w.finish(0)
	<-done
	time.Sleep(1600 * time.Millisecond)
	if n := reads.Load(); n != 0 {
		t.Fatalf("a call answered in time read the tier %d times", n)
	}
}
