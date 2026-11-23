// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// GAP-0402: retention ran every six hours, and a size cap was only checked
// then; under about 15 actors audit.db and its WAL filled the gateway's
// volume well before that, and every hook failed closed. With a cap the
// controller checks the store every 30 seconds (substrate-1:GAP-0570: 50
// actors write about 75 MiB a minute); without one it keeps the six-hour
// cadence.
func TestRetentionControllerChecksASizeCapEvery30Seconds(t *testing.T) {
	for _, c := range []struct {
		capMB int64
		want  time.Duration
	}{
		{capMB: 1024, want: 30 * time.Second},
		{capMB: 0, want: audit.RetentionScheduleInterval},
	} {
		reaper := &cappedFakeRetentionReaper{fakeRetentionReaper: newFakeRetentionReaper(7)}
		scheduler := newScriptedRetentionScheduler()
		controller, err := newRetentionController(reaper, RetentionControllerOptions{Scheduler: scheduler})
		if err != nil {
			t.Fatal(err)
		}
		controller.lifecycleMu.Lock()
		err = controller.applyPolicyLocked(7, c.capMB)
		controller.lifecycleMu.Unlock()
		if err != nil {
			t.Fatal(err)
		}
		if err := controller.Start(t.Context()); err != nil {
			t.Fatal(err)
		}
		receiveRetentionTest(t, reaper.started)
		reaper.responses <- fakeRetentionResponse{result: successfulRetentionResult()}
		if wait := receiveRetentionTest(t, scheduler.waits); wait != c.want {
			t.Fatalf("cap %d MiB: wait after a run = %s, want %s", c.capMB, wait, c.want)
		}
		stopRetentionControllerTest(t, controller)
	}
}

// checkingFakeRetentionReaper is a capped fake reaper with the page-count
// size check.
type checkingFakeRetentionReaper struct {
	*cappedFakeRetentionReaper
	over   atomic.Bool
	checks atomic.Int64
}

func (reaper *checkingFakeRetentionReaper) StoreOverCapStart(context.Context) (bool, error) {
	reaper.checks.Add(1)
	return reaper.over.Load(), nil
}

// substrate-1:GAP-0538 (b): a size-check tick under the cap only reads the
// page counts; the full pass runs when the store is near the cap or the
// six-hour pass is due. After a pass that left the store over the cap with
// nothing it could delete, the checks wait RetentionSizeCapShortfallInterval before another pass.
func TestRetentionControllerSizeCheckRunsAPassOnlyNearTheCapOrWhenDue(t *testing.T) {
	reaper := &checkingFakeRetentionReaper{cappedFakeRetentionReaper: &cappedFakeRetentionReaper{
		fakeRetentionReaper: newFakeRetentionReaper(7),
	}}
	reaper.maxStoreMB.Store(1024)
	scheduler := newScriptedRetentionScheduler()
	var clockMu sync.Mutex
	now := time.Date(2026, 11, 17, 21, 0, 0, 0, time.UTC)
	advance := func(by time.Duration) {
		clockMu.Lock()
		now = now.Add(by)
		clockMu.Unlock()
	}
	controller, err := newRetentionController(reaper, RetentionControllerOptions{
		Scheduler: scheduler, Clock: func() time.Time {
			clockMu.Lock()
			defer clockMu.Unlock()
			return now
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer stopRetentionControllerTest(t, controller)
	runs := func() int {
		count, _, _, _ := reaper.snapshot()
		return count
	}
	tick := func() time.Duration {
		advance(RetentionSizeCapCheckInterval)
		scheduler.commands <- retentionSchedulerCommand{wake: audit.RetentionScheduleTick}
		return receiveRetentionTest(t, scheduler.waits)
	}
	receiveRetentionTest(t, reaper.started)
	reaper.responses <- fakeRetentionResponse{result: successfulRetentionResult()}
	receiveRetentionTest(t, scheduler.waits)

	// Under the cap: checks, no pass.
	for range 3 {
		if wait := tick(); wait != RetentionSizeCapCheckInterval {
			t.Fatalf("wait after a size check = %s", wait)
		}
	}
	if got, checks := runs(), reaper.checks.Load(); got != 1 || checks != 3 {
		t.Fatalf("under the cap: %d passes and %d checks, want 1 and 3", got, checks)
	}

	// Near the cap: the next check runs the pass.
	reaper.over.Store(true)
	advance(RetentionSizeCapCheckInterval)
	scheduler.commands <- retentionSchedulerCommand{wake: audit.RetentionScheduleTick}
	receiveRetentionTest(t, reaper.started)
	reaper.responses <- fakeRetentionResponse{result: audit.RetentionRunResult{
		CompletedAt: now, CapNotReached: true, StoreSizeBytes: 1100 << 20,
		StoreCapBytes: 1024 << 20, CapReason: audit.RetentionCapActiveCorrelation,
	}}
	receiveRetentionTest(t, scheduler.waits)
	if got := runs(); got != 2 {
		t.Fatalf("near the cap: %d passes, want 2", got)
	}

	// That pass could not meet the cap: the checks wait RetentionSizeCapShortfallInterval.
	checks := reaper.checks.Load()
	for elapsed := RetentionSizeCapCheckInterval; elapsed < RetentionSizeCapShortfallInterval; elapsed += RetentionSizeCapCheckInterval {
		tick()
	}
	if got := runs(); got != 2 || reaper.checks.Load() != checks {
		t.Fatalf("after a shortfall: %d passes, %d new checks; want no pass and no check for RetentionSizeCapShortfallInterval",
			got, reaper.checks.Load()-checks)
	}
	advance(RetentionSizeCapCheckInterval)
	scheduler.commands <- retentionSchedulerCommand{wake: audit.RetentionScheduleTick}
	receiveRetentionTest(t, reaper.started)
	reaper.responses <- fakeRetentionResponse{result: successfulRetentionResult()}
	receiveRetentionTest(t, scheduler.waits)

	// Under the cap again, the six-hour pass still runs when due.
	reaper.over.Store(false)
	advance(audit.RetentionScheduleInterval - RetentionSizeCapCheckInterval)
	advance(RetentionSizeCapCheckInterval)
	scheduler.commands <- retentionSchedulerCommand{wake: audit.RetentionScheduleTick}
	receiveRetentionTest(t, reaper.started)
	reaper.responses <- fakeRetentionResponse{result: successfulRetentionResult()}
	receiveRetentionTest(t, scheduler.waits)
	if got := runs(); got != 4 {
		t.Fatalf("six-hour pass: %d passes, want 4", got)
	}
}

// Secure Client keeps the six-hour cadence and no size checks, cap or not.
func TestRetentionControllerSecureClientKeepsTheSixHourCadenceWithACap(t *testing.T) {
	reaper := &checkingFakeRetentionReaper{cappedFakeRetentionReaper: &cappedFakeRetentionReaper{
		fakeRetentionReaper: newFakeRetentionReaper(7),
	}}
	reaper.maxStoreMB.Store(1024)
	scheduler := newScriptedRetentionScheduler()
	controller, err := newRetentionController(reaper, RetentionControllerOptions{SecureClient: true, Scheduler: scheduler})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer stopRetentionControllerTest(t, controller)
	receiveRetentionTest(t, reaper.started)
	reaper.responses <- fakeRetentionResponse{result: successfulRetentionResult()}
	if wait := receiveRetentionTest(t, scheduler.waits); wait != audit.RetentionScheduleInterval {
		t.Fatalf("Secure Client wait with a cap = %s, want %s", wait, audit.RetentionScheduleInterval)
	}
	scheduler.commands <- retentionSchedulerCommand{wake: audit.RetentionScheduleTick}
	receiveRetentionTest(t, reaper.started)
	reaper.responses <- fakeRetentionResponse{result: successfulRetentionResult()}
	receiveRetentionTest(t, scheduler.waits)
	if checks := reaper.checks.Load(); checks != 0 {
		t.Fatalf("Secure Client ran %d size checks", checks)
	}
}

// CLOSE-RET review (P3): a store that sits past nine tenths of its cap with
// nothing a pass may delete (open correlation state) used to run a full,
// empty pass on every 30-second check, since the pass ended under the cap and
// so was no shortfall. Such a pass now waits RetentionSizeCapShortfallInterval
// too.
func TestRetentionControllerWaitsAfterAnEmptyCappedPassPastTheStart(t *testing.T) {
	reaper := &checkingFakeRetentionReaper{cappedFakeRetentionReaper: &cappedFakeRetentionReaper{
		fakeRetentionReaper: newFakeRetentionReaper(7),
	}}
	reaper.maxStoreMB.Store(1024)
	scheduler := newScriptedRetentionScheduler()
	var clockMu sync.Mutex
	now := time.Date(2026, 11, 18, 1, 0, 0, 0, time.UTC)
	advance := func(by time.Duration) {
		clockMu.Lock()
		now = now.Add(by)
		clockMu.Unlock()
	}
	controller, err := newRetentionController(reaper, RetentionControllerOptions{
		Scheduler: scheduler, Clock: func() time.Time {
			clockMu.Lock()
			defer clockMu.Unlock()
			return now
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer stopRetentionControllerTest(t, controller)
	runs := func() int {
		count, _, _, _ := reaper.snapshot()
		return count
	}
	receiveRetentionTest(t, reaper.started)
	reaper.responses <- fakeRetentionResponse{result: successfulRetentionResult()}
	receiveRetentionTest(t, scheduler.waits)

	// Past the start: the check runs a capped pass that deletes nothing.
	reaper.over.Store(true)
	advance(RetentionSizeCapCheckInterval)
	scheduler.commands <- retentionSchedulerCommand{wake: audit.RetentionScheduleTick}
	receiveRetentionTest(t, reaper.started)
	reaper.responses <- fakeRetentionResponse{result: audit.RetentionRunResult{CompletedAt: now, SizeCapped: true}}
	receiveRetentionTest(t, scheduler.waits)
	if got := runs(); got != 2 {
		t.Fatalf("past the start: %d passes, want 2", got)
	}
	for elapsed := RetentionSizeCapCheckInterval; elapsed < RetentionSizeCapShortfallInterval; elapsed += RetentionSizeCapCheckInterval {
		advance(RetentionSizeCapCheckInterval)
		scheduler.commands <- retentionSchedulerCommand{wake: audit.RetentionScheduleTick}
		receiveRetentionTest(t, scheduler.waits)
	}
	if got := runs(); got != 2 {
		t.Fatalf("after an empty capped pass past the start: %d passes within %s, want none", got-2, RetentionSizeCapShortfallInterval)
	}
	advance(RetentionSizeCapCheckInterval)
	scheduler.commands <- retentionSchedulerCommand{wake: audit.RetentionScheduleTick}
	receiveRetentionTest(t, reaper.started)
	reaper.responses <- fakeRetentionResponse{result: successfulRetentionResult()}
	receiveRetentionTest(t, scheduler.waits)
	if got := runs(); got != 3 {
		t.Fatalf("after the wait: %d passes, want 3", got)
	}
}
