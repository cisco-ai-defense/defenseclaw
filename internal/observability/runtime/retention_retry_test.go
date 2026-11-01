// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// rel-1-0-6:GAP-0263 (dc-float2, managed RHEL rc23): the first size-capped
// run on a 2.6 GB audit.db failed, and retention stayed degraded/run_failed
// for minutes, through the removal of the cap, until a gateway restart. A
// failed run is now tried again a minute later, then two minutes, and a
// policy change after a failure runs at once, so the state shown is that of
// the policy now in force.
func TestRetentionControllerRetriesAFailedRunSoonAndOnAPolicyChange(t *testing.T) {
	reaper := newFakeRetentionReaper(7)
	scheduler := newScriptedRetentionScheduler()
	reporter := &recordingRetentionReporter{statuses: make(chan RetentionControllerStatus, 16)}
	controller, err := newRetentionController(reaper, RetentionControllerOptions{Scheduler: scheduler, Reporter: reporter})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	receiveRetentionTest(t, reaper.started)
	reaper.responses <- fakeRetentionResponse{err: errors.New("database is locked")}
	if failed := receiveRetentionTest(t, reporter.statuses); failed.State != RetentionStateDegraded || failed.Failure != RetentionFailureRun {
		t.Fatalf("first run: %#v", failed)
	}
	if wait := receiveRetentionTest(t, scheduler.waits); wait != audit.RetentionFollowUpInterval {
		t.Fatalf("wait after a failed run = %s, want %s", wait, audit.RetentionFollowUpInterval)
	}
	scheduler.commands <- retentionSchedulerCommand{wake: audit.RetentionScheduleTick}
	receiveRetentionTest(t, reaper.started)
	reaper.responses <- fakeRetentionResponse{err: errors.New("database is locked")}
	receiveRetentionTest(t, reporter.statuses)
	if wait := receiveRetentionTest(t, scheduler.waits); wait != 2*audit.RetentionFollowUpInterval {
		t.Fatalf("wait after two failed runs = %s, want %s", wait, 2*audit.RetentionFollowUpInterval)
	}
	// A looser policy (the cap removed, a longer age) asks for no run on a
	// healthy store; after a failure it runs, and its success clears the state.
	if err := controller.ApplyPolicy(30); err != nil {
		t.Fatal(err)
	}
	receiveRetentionTest(t, reaper.started)
	reaper.responses <- fakeRetentionResponse{result: successfulRetentionResult()}
	if healthy := receiveRetentionTest(t, reporter.statuses); healthy.State != RetentionStateHealthy || healthy.Failure != RetentionFailureNone ||
		healthy.RunCount != 3 || healthy.FailureCount != 2 {
		t.Fatalf("after the policy change: %#v", healthy)
	}
	if wait := receiveRetentionTest(t, scheduler.waits); wait != audit.RetentionScheduleInterval {
		t.Fatalf("wait after a success = %s, want %s", wait, audit.RetentionScheduleInterval)
	}
	// Healthy again: a looser policy runs nothing and only republishes.
	if err := controller.ApplyPolicy(60); err != nil {
		t.Fatal(err)
	}
	if again := receiveRetentionTest(t, reporter.statuses); again.State != RetentionStateHealthy || again.RunCount != 3 {
		t.Fatalf("looser policy while healthy: %#v", again)
	}
	if runs, _, _, _ := reaper.snapshot(); runs != 3 {
		t.Fatalf("runs = %d, want 3", runs)
	}
	if err := controller.Stop(lifecycleTestContext(t)); err != nil {
		t.Fatal(err)
	}
}

// Review of rel-1-0-6:GAP-0263: Secure Client keeps its cadence after a
// failed run, and a looser policy then runs nothing, as documented.
func TestRetentionControllerSecureClientKeepsItsCadenceAfterAFailedRun(t *testing.T) {
	reaper := newFakeRetentionReaper(7)
	scheduler := newScriptedRetentionScheduler()
	reporter := &recordingRetentionReporter{statuses: make(chan RetentionControllerStatus, 16)}
	controller, err := newRetentionController(reaper, RetentionControllerOptions{Scheduler: scheduler, Reporter: reporter, SecureClient: true})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	receiveRetentionTest(t, reaper.started)
	reaper.responses <- fakeRetentionResponse{err: errors.New("database is locked")}
	receiveRetentionTest(t, reporter.statuses)
	if wait := receiveRetentionTest(t, scheduler.waits); wait != audit.RetentionScheduleInterval {
		t.Fatalf("Secure Client wait after a failed run = %s, want %s", wait, audit.RetentionScheduleInterval)
	}
	if err := controller.ApplyPolicy(30); err != nil {
		t.Fatal(err)
	}
	if again := receiveRetentionTest(t, reporter.statuses); again.State != RetentionStateDegraded || again.RunCount != 1 {
		t.Fatalf("Secure Client looser policy after a failure: %#v", again)
	}
	if runs, _, _, _ := reaper.snapshot(); runs != 1 {
		t.Fatalf("runs = %d, want 1", runs)
	}
	if err := controller.Stop(lifecycleTestContext(t)); err != nil {
		t.Fatal(err)
	}
}
