// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

type fakeRetentionResponse struct {
	result audit.RetentionRunResult
	err    error
}

type fakeRetentionReaper struct {
	mu            sync.Mutex
	days          int64
	runs          int
	active        int
	maxActive     int
	updates       []int64
	started       chan struct{}
	responses     chan fakeRetentionResponse
	stop          <-chan struct{}
	updateStarted chan int64
	updateRelease <-chan struct{}
}

func newFakeRetentionReaper(days int64) *fakeRetentionReaper {
	return &fakeRetentionReaper{
		days: days, started: make(chan struct{}, 16),
		responses: make(chan fakeRetentionResponse, 16),
	}
}

func (reaper *fakeRetentionReaper) RetentionDays() int64 {
	reaper.mu.Lock()
	defer reaper.mu.Unlock()
	return reaper.days
}

func (reaper *fakeRetentionReaper) UpdateRetentionDays(days int64) error {
	if days < 0 || days > math.MaxInt64/int64(24*time.Hour) {
		return errors.New("invalid fake retention age")
	}
	reaper.mu.Lock()
	started := reaper.updateStarted
	release := reaper.updateRelease
	reaper.mu.Unlock()
	if started != nil {
		started <- days
	}
	if release != nil {
		<-release
	}
	reaper.mu.Lock()
	reaper.days = days
	reaper.updates = append(reaper.updates, days)
	reaper.mu.Unlock()
	return nil
}

func (reaper *fakeRetentionReaper) gateUpdates(started chan int64, release <-chan struct{}) {
	reaper.mu.Lock()
	reaper.updateStarted = started
	reaper.updateRelease = release
	reaper.mu.Unlock()
}

func (reaper *fakeRetentionReaper) updateSnapshot() []int64 {
	reaper.mu.Lock()
	defer reaper.mu.Unlock()
	return append([]int64(nil), reaper.updates...)
}

func (reaper *fakeRetentionReaper) Run(ctx context.Context) (audit.RetentionRunResult, error) {
	reaper.mu.Lock()
	reaper.runs++
	reaper.active++
	if reaper.active > reaper.maxActive {
		reaper.maxActive = reaper.active
	}
	reaper.mu.Unlock()
	select {
	case reaper.started <- struct{}{}:
	case <-ctx.Done():
	}
	var response fakeRetentionResponse
	select {
	case response = <-reaper.responses:
	case <-reaper.stop:
		response.result = successfulRetentionResult()
	case <-ctx.Done():
		response.err = ctx.Err()
	}
	reaper.mu.Lock()
	reaper.active--
	reaper.mu.Unlock()
	return response.result, response.err
}

func (reaper *fakeRetentionReaper) snapshot() (runs, active, maxActive int, days int64) {
	reaper.mu.Lock()
	defer reaper.mu.Unlock()
	return reaper.runs, reaper.active, reaper.maxActive, reaper.days
}

type retentionSchedulerCommand struct {
	wake audit.RetentionScheduleWake
	err  error
}

type scriptedRetentionScheduler struct {
	waits    chan time.Duration
	commands chan retentionSchedulerCommand
}

func newScriptedRetentionScheduler() *scriptedRetentionScheduler {
	return &scriptedRetentionScheduler{
		waits: make(chan time.Duration, 16), commands: make(chan retentionSchedulerCommand, 16),
	}
}

func (scheduler *scriptedRetentionScheduler) Wait(
	ctx context.Context,
	interval time.Duration,
	reload <-chan struct{},
) (audit.RetentionScheduleWake, error) {
	select {
	case scheduler.waits <- interval:
	case <-ctx.Done():
		return 0, ctx.Err()
	}
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-reload:
		return audit.RetentionScheduleReload, nil
	case command := <-scheduler.commands:
		return command.wake, command.err
	}
}

type recordingRetentionReporter struct {
	statuses chan RetentionControllerStatus
}

func (reporter *recordingRetentionReporter) ReportRetentionController(status RetentionControllerStatus) {
	reporter.statuses <- status
}

func TestRetentionControllerWaitsForReadinessRunsOnCadenceAndStopsCleanly(t *testing.T) {
	reaper := newFakeRetentionReaper(90)
	scheduler := newScriptedRetentionScheduler()
	ready := make(chan struct{})
	attemptedAt := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	controller, err := newRetentionController(reaper, RetentionControllerOptions{
		Ready: ready, Scheduler: scheduler, Clock: func() time.Time { return attemptedAt },
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	if status := controller.Status(); status.State != RetentionStateWaiting {
		t.Fatalf("pre-readiness status=%#v", status)
	}
	if err := controller.ApplyPolicy(30); err != nil {
		t.Fatal(err)
	}
	if runs, _, _, _ := reaper.snapshot(); runs != 0 {
		t.Fatalf("reaper ran %d times before readiness", runs)
	}

	close(ready)
	receiveRetentionTest(t, reaper.started)
	firstCompleted := attemptedAt.Add(time.Second)
	reaper.responses <- fakeRetentionResponse{result: audit.RetentionRunResult{
		CompletedAt: firstCompleted, Duration: time.Second, BatchCount: 1,
		RowsDeleted: map[audit.RetentionTableClass]int64{audit.RetentionAuditEvents: 2},
	}}
	if interval := receiveRetentionTest(t, scheduler.waits); interval != audit.RetentionScheduleInterval {
		t.Fatalf("initial cadence=%s want %s", interval, audit.RetentionScheduleInterval)
	}
	status := controller.Status()
	if status.State != RetentionStateHealthy || status.RetentionDays != 30 || status.RunCount != 1 ||
		status.LastRowsDeleted != 2 || !status.LastAttemptAt.Equal(attemptedAt) ||
		!status.LastSuccessAt.Equal(firstCompleted) {
		t.Fatalf("initial status=%#v", status)
	}

	scheduler.commands <- retentionSchedulerCommand{wake: audit.RetentionScheduleTick}
	receiveRetentionTest(t, reaper.started)
	reaper.responses <- fakeRetentionResponse{result: audit.RetentionRunResult{
		CompletedAt: firstCompleted.Add(time.Hour), BatchCount: 0,
		RowsDeleted: map[audit.RetentionTableClass]int64{},
	}}
	if interval := receiveRetentionTest(t, scheduler.waits); interval != audit.RetentionScheduleInterval {
		t.Fatalf("periodic cadence=%s", interval)
	}
	if err := controller.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
	if status := controller.Status(); status.State != RetentionStateStopped {
		t.Fatalf("stopped status=%#v", status)
	}
	if err := controller.Start(t.Context()); err == nil {
		t.Fatal("stopped controller restarted")
	}
}

func TestRetentionControllerAppliesPolicyWithoutReplacingOrOverlappingReaper(t *testing.T) {
	reaper := newFakeRetentionReaper(90)
	scheduler := newScriptedRetentionScheduler()
	controller, err := newRetentionController(reaper, RetentionControllerOptions{Scheduler: scheduler})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	receiveRetentionTest(t, reaper.started)
	if err := controller.ApplyPolicy(30); err != nil {
		t.Fatal(err)
	}
	if _, active, maxActive, days := reaper.snapshot(); active != 1 || maxActive != 1 || days != 30 {
		t.Fatalf("policy during run active=%d max=%d days=%d", active, maxActive, days)
	}
	reaper.responses <- fakeRetentionResponse{result: successfulRetentionResult()}
	if interval := receiveRetentionTest(t, scheduler.waits); interval != audit.RetentionScheduleInterval {
		t.Fatalf("post-run interval=%s", interval)
	}
	// The shorter policy wake was buffered while the initial run was active.
	receiveRetentionTest(t, reaper.started)
	if _, active, maxActive, _ := reaper.snapshot(); active != 1 || maxActive != 1 {
		t.Fatalf("prompt run overlap active=%d max=%d", active, maxActive)
	}
	reaper.responses <- fakeRetentionResponse{result: successfulRetentionResult()}
	receiveRetentionTest(t, scheduler.waits)

	if err := controller.ApplyPolicy(0); err != nil {
		t.Fatal(err)
	}
	if interval := receiveRetentionTest(t, scheduler.waits); interval != 0 {
		t.Fatalf("disabled interval=%s want 0", interval)
	}
	if status := controller.Status(); status.State != RetentionStateDisabled || status.RetentionDays != 0 {
		t.Fatalf("disabled status=%#v", status)
	}
	if err := controller.ApplyPolicy(60); err != nil {
		t.Fatal(err)
	}
	receiveRetentionTest(t, reaper.started)
	reaper.responses <- fakeRetentionResponse{result: successfulRetentionResult()}
	receiveRetentionTest(t, scheduler.waits)
	if err := controller.ApplyPolicy(-1); err == nil {
		t.Fatal("invalid policy was accepted")
	}
	if _, _, maxActive, days := reaper.snapshot(); maxActive != 1 || days != 60 {
		t.Fatalf("invalid policy changed process reaper max=%d days=%d", maxActive, days)
	}
	if err := controller.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestRetentionControllerPublishesOnlyBoundedFailureOutcomesAndRecovers(t *testing.T) {
	reaper := newFakeRetentionReaper(90)
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
	reaper.responses <- fakeRetentionResponse{err: errors.New("secret database path and retained body")}
	failed := receiveRetentionTest(t, reporter.statuses)
	if failed.State != RetentionStateDegraded || failed.Failure != RetentionFailureRun ||
		failed.FailureCount != 1 || failed.RunCount != 1 {
		t.Fatalf("bounded failure status=%#v", failed)
	}
	receiveRetentionTest(t, scheduler.waits)
	scheduler.commands <- retentionSchedulerCommand{wake: audit.RetentionScheduleTick}
	receiveRetentionTest(t, reaper.started)
	reaper.responses <- fakeRetentionResponse{result: successfulRetentionResult()}
	recovered := receiveRetentionTest(t, reporter.statuses)
	if recovered.State != RetentionStateHealthy || recovered.Failure != RetentionFailureNone ||
		recovered.FailureCount != 1 || recovered.RunCount != 2 {
		t.Fatalf("recovered status=%#v", recovered)
	}
	receiveRetentionTest(t, scheduler.waits)
	scheduler.commands <- retentionSchedulerCommand{err: errors.New("secret scheduler internals")}
	schedulerFailure := receiveRetentionTest(t, reporter.statuses)
	if schedulerFailure.State != RetentionStateDegraded ||
		schedulerFailure.Failure != RetentionFailureScheduler || schedulerFailure.FailureCount != 2 {
		t.Fatalf("scheduler failure status=%#v", schedulerFailure)
	}
	if err := controller.Stop(t.Context()); err != nil {
		t.Fatal(err)
	}
}

func TestRetentionControllerStopDrainsAndWaitsForActiveRun(t *testing.T) {
	reaper := newFakeRetentionReaper(90)
	controller, err := newRetentionController(reaper, RetentionControllerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.Start(t.Context()); err != nil {
		t.Fatal(err)
	}
	receiveRetentionTest(t, reaper.started)
	stopDone := make(chan error, 1)
	go func() { stopDone <- controller.Stop(t.Context()) }()
	select {
	case err := <-stopDone:
		t.Fatalf("stop returned before the active retention run drained: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	reaper.responses <- fakeRetentionResponse{result: successfulRetentionResult()}
	if err := receiveRetentionTest(t, stopDone); err != nil {
		t.Fatal(err)
	}
	if _, active, maxActive, _ := reaper.snapshot(); active != 0 || maxActive != 1 {
		t.Fatalf("stop returned with reaper active=%d max=%d", active, maxActive)
	}
	if err := controller.ApplyPolicy(30); err == nil {
		t.Fatal("stopped controller accepted a policy")
	}
}

func successfulRetentionResult() audit.RetentionRunResult {
	completed := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	return audit.RetentionRunResult{
		CompletedAt: completed, Duration: time.Second,
		RowsDeleted: map[audit.RetentionTableClass]int64{},
	}
}

func receiveRetentionTest[T any](t *testing.T, channel <-chan T) T {
	t.Helper()
	select {
	case value := <-channel:
		return value
	case <-time.After(5 * time.Second):
		var zero T
		t.Fatal("timed out waiting for retention controller test handshake")
		return zero
	}
}
