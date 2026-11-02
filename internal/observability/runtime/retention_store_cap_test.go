// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"errors"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// cappedFakeRetentionReaper is a fake reaper with the opt-in size cap.
type cappedFakeRetentionReaper struct {
	*fakeRetentionReaper
	maxStoreMB atomic.Int64
}

func (reaper *cappedFakeRetentionReaper) MaxStoreMB() int64 { return reaper.maxStoreMB.Load() }

func (reaper *cappedFakeRetentionReaper) UpdateMaxStoreMB(mb int64) error {
	if mb < 0 {
		return errors.New("invalid fake size cap")
	}
	reaper.maxStoreMB.Store(mb)
	return nil
}

// #1384: a size cap alone (retention_days 0) keeps the reaper running; with
// neither the controller reports retention disabled, as before.
func TestRetentionControllerRunsForASizeCapAlone(t *testing.T) {
	reaper := &cappedFakeRetentionReaper{fakeRetentionReaper: newFakeRetentionReaper(0)}
	scheduler := newScriptedRetentionScheduler()
	controller, err := newRetentionController(reaper, RetentionControllerOptions{Scheduler: scheduler})
	if err != nil {
		t.Fatal(err)
	}
	controller.lifecycleMu.Lock()
	err = controller.applyPolicyLocked(0, 2048)
	controller.lifecycleMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if !controller.enabled() || reaper.MaxStoreMB() != 2048 {
		t.Fatalf("enabled %t, cap %d; want a run for the size cap", controller.enabled(), reaper.MaxStoreMB())
	}
	// The status the health reports carries the cap (GAP-0141).
	if got := controller.Status().MaxStoreMB; got != 2048 {
		t.Fatalf("status cap = %d, want 2048", got)
	}
	if err := controller.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	receiveRetentionTest(t, reaper.started)
	reaper.responses <- fakeRetentionResponse{result: successfulRetentionResult()}
	if interval := receiveRetentionTest(t, scheduler.waits); interval == 0 {
		t.Fatal("no cadence for a size cap alone")
	}
	stopRetentionControllerTest(t, controller)

	off := &cappedFakeRetentionReaper{fakeRetentionReaper: newFakeRetentionReaper(0)}
	controller, err = newRetentionController(off, RetentionControllerOptions{Scheduler: newScriptedRetentionScheduler()})
	if err != nil {
		t.Fatal(err)
	}
	if controller.enabled() {
		t.Fatal("retention enabled with no age and no size cap")
	}
	// A reaper without the size cap refuses one.
	plain, err := newRetentionController(newFakeRetentionReaper(7), RetentionControllerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	plain.lifecycleMu.Lock()
	err = plain.applyPolicyLocked(7, 2048)
	plain.lifecycleMu.Unlock()
	if err == nil {
		t.Fatal("a reaper without a size cap accepted one")
	}
}

// A size cap set back to 0 (or any looser policy that needs no prompt run) is
// still published, so gateway status stops showing the old cap without a
// restart.
func TestRetentionControllerPublishesALooserPolicyWithoutARun(t *testing.T) {
	reaper := &cappedFakeRetentionReaper{fakeRetentionReaper: newFakeRetentionReaper(7)}
	reaper.maxStoreMB.Store(128)
	scheduler := newScriptedRetentionScheduler()
	reporter := &recordingRetentionReporter{statuses: make(chan RetentionControllerStatus, 16)}
	controller, err := newRetentionController(reaper, RetentionControllerOptions{
		Scheduler: scheduler, Reporter: reporter,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	receiveRetentionTest(t, reaper.started)
	reaper.responses <- fakeRetentionResponse{result: successfulRetentionResult()}
	if got := receiveRetentionTest(t, reporter.statuses); got.MaxStoreMB != 128 {
		t.Fatalf("startup status cap = %d, want 128", got.MaxStoreMB)
	}
	receiveRetentionTest(t, scheduler.waits)

	controller.lifecycleMu.Lock()
	err = controller.applyPolicyLocked(7, 0)
	controller.lifecycleMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	got := receiveRetentionTest(t, reporter.statuses)
	if got.MaxStoreMB != 0 || got.RetentionDays != 7 {
		t.Fatalf("status after the cap was lowered to 0 = %#v, want cap 0 and 7 days", got)
	}
	if runs, _, _, _ := reaper.snapshot(); runs != 1 {
		t.Fatalf("a looser policy started a run: %d runs, want 1", runs)
	}
	stopRetentionControllerTest(t, controller)
}

func TestRetentionControllerWarnsForUnmetCapAndClearsWhenMet(t *testing.T) {
	reaper := &cappedFakeRetentionReaper{fakeRetentionReaper: newFakeRetentionReaper(7)}
	reaper.maxStoreMB.Store(1)
	reporter := &recordingRetentionReporter{statuses: make(chan RetentionControllerStatus, 4)}
	controller, err := newRetentionController(reaper, RetentionControllerOptions{Reporter: reporter})
	if err != nil {
		t.Fatal(err)
	}
	reaper.responses <- fakeRetentionResponse{result: audit.RetentionRunResult{
		CompletedAt: time.Now().UTC(), CapNotReached: true, StoreSizeBytes: 2 << 20,
		StoreCapBytes: 1 << 20, CapReason: audit.RetentionCapRetainedHistory,
	}}
	if !controller.runOnce(t.Context()) {
		t.Fatal("cap pass did not finish")
	}
	warning := receiveRetentionTest(t, reporter.statuses)
	if warning.State != RetentionStateWarning || warning.Failure != RetentionFailureNone ||
		warning.CapReason != audit.RetentionCapRetainedHistory || warning.StoreSizeBytes != 2<<20 ||
		warning.StoreCapBytes != 1<<20 || warning.FailureCount != 0 {
		t.Fatalf("shortfall status = %+v", warning)
	}
	controller.lifecycleMu.Lock()
	err = controller.applyPolicyLocked(7, 0)
	controller.lifecycleMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	if cleared := controller.Status(); cleared.State != RetentionStateHealthy ||
		cleared.StoreSizeBytes != 0 || cleared.CapReason != "" || cleared.MaxStoreMB != 0 {
		t.Fatalf("warning after cap removed = %+v", cleared)
	}
	controller.lifecycleMu.Lock()
	err = controller.applyPolicyLocked(7, 1)
	controller.lifecycleMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	reaper.responses <- fakeRetentionResponse{result: successfulRetentionResult()}
	if !controller.runOnce(t.Context()) {
		t.Fatal("follow-up cap pass did not finish")
	}
	healthy := receiveRetentionTest(t, reporter.statuses)
	if healthy.State != RetentionStateHealthy || healthy.CapReason != "" ||
		healthy.StoreSizeBytes != 0 || healthy.StoreCapBytes != 0 {
		t.Fatalf("met-cap status = %+v", healthy)
	}
}

func TestRetentionControllerRerunsWhenWarningCapIsRaisedButStillUnmet(t *testing.T) {
	reaper := &cappedFakeRetentionReaper{fakeRetentionReaper: newFakeRetentionReaper(7)}
	reaper.maxStoreMB.Store(1)
	scheduler := newScriptedRetentionScheduler()
	reporter := &recordingRetentionReporter{statuses: make(chan RetentionControllerStatus, 4)}
	controller, err := newRetentionController(reaper, RetentionControllerOptions{
		Scheduler: scheduler, Reporter: reporter,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	defer stopRetentionControllerTest(t, controller)
	receiveRetentionTest(t, reaper.started)
	reaper.responses <- fakeRetentionResponse{result: audit.RetentionRunResult{
		CompletedAt: time.Now().UTC(), CapNotReached: true, StoreSizeBytes: 3 << 20,
		StoreCapBytes: 1 << 20, CapReason: audit.RetentionCapRetainedHistory,
	}}
	if got := receiveRetentionTest(t, reporter.statuses); got.State != RetentionStateWarning {
		t.Fatalf("initial cap status = %+v, want warning", got)
	}
	receiveRetentionTest(t, scheduler.waits)

	controller.lifecycleMu.Lock()
	err = controller.applyPolicyLocked(7, 2)
	controller.lifecycleMu.Unlock()
	if err != nil {
		t.Fatal(err)
	}
	receiveRetentionTest(t, reaper.started)
	reaper.responses <- fakeRetentionResponse{result: audit.RetentionRunResult{
		CompletedAt: time.Now().UTC(), CapNotReached: true, StoreSizeBytes: 3 << 20,
		StoreCapBytes: 2 << 20, CapReason: audit.RetentionCapRetainedHistory,
	}}
	if got := receiveRetentionTest(t, reporter.statuses); got.State != RetentionStateWarning ||
		got.MaxStoreMB != 2 || got.StoreSizeBytes != 3<<20 || got.StoreCapBytes != 2<<20 ||
		got.RunCount != 2 {
		t.Fatalf("status after a pass with the raised cap = %+v, want measured warning", got)
	}
}
