// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
)

func TestRuntimeStartsRetentionOnceAfterInitialGraphReadiness(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 45, nil)
	missingController := dependencies.options()
	missingController.RetentionController = nil
	if _, err := New(
		t.Context(), runtimegraph.ConfigFromPlan(plan, false), missingController,
	); err == nil {
		t.Fatal("runtime accepted a missing process retention controller")
	}
	runtime := newRuntimeForTest(t, dependencies, plan, false)
	receiveRetentionTest(t, dependencies.retentionReaper.started)
	if runtime.Active() == nil || runtime.Active().RetentionDays() != 45 ||
		runtime.retention != dependencies.retentionController {
		t.Fatal("runtime returned before the initial retention policy graph was ready")
	}
	lease, err := runtime.manager.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	lease.Release()
	dependencies.retentionReaper.responses <- fakeRetentionResponse{result: successfulRetentionResult()}
	if interval := receiveRetentionTest(t, dependencies.retentionScheduler.waits); interval != 6*time.Hour {
		t.Fatalf("retention cadence=%s want 6h", interval)
	}
	if runs, _, maxActive, days := dependencies.retentionReaper.snapshot(); runs != 1 || maxActive != 1 || days != 45 {
		t.Fatalf("startup runs=%d max=%d days=%d", runs, maxActive, days)
	}
}

func TestRuntimeOwnershipRejectsDirectControllerLifecycleMutation(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90, nil)
	runtime := newRuntimeForTest(t, dependencies, plan, false)
	receiveRetentionTest(t, dependencies.retentionReaper.started)

	if err := dependencies.retentionController.ApplyPolicy(30); err == nil {
		t.Fatal("runtime-owned controller accepted a direct policy mutation")
	}
	if err := dependencies.retentionController.Start(t.Context()); err == nil {
		t.Fatal("runtime-owned controller accepted a direct start")
	}
	if err := dependencies.retentionController.Stop(t.Context()); err == nil {
		t.Fatal("runtime-owned controller accepted a direct stop")
	}
	if _, _, _, days := dependencies.retentionReaper.snapshot(); days != 90 {
		t.Fatalf("direct controller call changed active graph policy to %d", days)
	}
	if runtime.Active() == nil || dependencies.retentionController.Status().State == RetentionStateStopped {
		t.Fatal("direct controller call stopped the active runtime")
	}
}

func TestRuntimeRetentionReloadActivatesSameControllerBeforeGraphAcquisition(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	initial := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90, nil)
	runtime := newRuntimeForTest(t, dependencies, initial, false)
	receiveRetentionTest(t, dependencies.retentionReaper.started)
	dependencies.retentionReaper.responses <- fakeRetentionResponse{result: successfulRetentionResult()}
	receiveRetentionTest(t, dependencies.retentionScheduler.waits)

	shorter := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 30, nil)
	result, reloadErr := runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(shorter, false))
	if reloadErr != nil || result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("shorter reload status=%s err=%v", result.Status(), reloadErr)
	}
	if runtime.retention != dependencies.retentionController {
		t.Fatal("retention reload replaced the process controller")
	}
	if _, _, _, days := dependencies.retentionReaper.snapshot(); days != 30 {
		t.Fatalf("new graph became ready before retention policy activation: days=%d", days)
	}
	lease, err := runtime.manager.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if lease.Graph() != result.ActiveGraph() || lease.Graph().RetentionDays() != 30 {
		t.Fatal("acquired graph does not match synchronously activated retention policy")
	}
	lease.Release()
	// The shorter policy requests exactly one prompt run on the same worker.
	receiveRetentionTest(t, dependencies.retentionReaper.started)
	dependencies.retentionReaper.responses <- fakeRetentionResponse{result: successfulRetentionResult()}
	receiveRetentionTest(t, dependencies.retentionScheduler.waits)

	disabled := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 0, nil)
	result, reloadErr = runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(disabled, false))
	if reloadErr != nil || result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("disable reload status=%s err=%v", result.Status(), reloadErr)
	}
	if interval := receiveRetentionTest(t, dependencies.retentionScheduler.waits); interval != 0 {
		t.Fatalf("disabled retention interval=%s want zero", interval)
	}
	if status := dependencies.retentionController.Status(); status.State != RetentionStateDisabled || status.RetentionDays != 0 {
		t.Fatalf("disabled retention status=%#v", status)
	}
}

func TestRuntimeRejectedCandidatesLeaveRetentionPolicyAndReservationUnchanged(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	initial := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90, nil)
	runtime := newRuntimeForTest(t, dependencies, initial, false)
	old := runtime.Active()

	buildFailure := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 30,
		func(source *config.ObservabilityV8Source) {
			source.Destinations = []config.ObservabilityV8DestinationSource{{
				Name: "console", Kind: config.ObservabilityV8DestinationConsole,
			}}
		},
	)
	result, reloadErr := runtime.Reload(
		t.Context(), runtimegraph.ConfigFromPlan(buildFailure, false),
	)
	if reloadErr == nil || result.Status() != runtimegraph.ReloadRejected || result.ActiveGraph() != old {
		t.Fatalf("build failure status=%s err=%v", result.Status(), reloadErr)
	}
	if _, _, _, days := dependencies.retentionReaper.snapshot(); days != 90 {
		t.Fatalf("rejected build mutated retention days to %d", days)
	}

	restart := runtimeTestPlan(
		t, filepath.Join(filepath.Dir(dependencies.storePath), "replacement.db"),
		dependencies.judgePath, 30, nil,
	)
	result, reloadErr = runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(restart, false))
	if reloadErr == nil || reloadErr.Code() != runtimegraph.ErrorRestartRequired ||
		result.Status() != runtimegraph.ReloadRejected {
		t.Fatalf("restart reload status=%s err=%v", result.Status(), reloadErr)
	}
	if _, _, _, days := dependencies.retentionReaper.snapshot(); days != 90 {
		t.Fatalf("restart rejection mutated retention days to %d", days)
	}

	// A valid reload after both failures proves candidate cleanup released the
	// reservation rather than stranding the process controller lock.
	valid := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 30, nil)
	result, reloadErr = runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(valid, false))
	if reloadErr != nil || result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("post-rejection valid reload status=%s err=%v", result.Status(), reloadErr)
	}
	if _, _, _, days := dependencies.retentionReaper.snapshot(); days != 30 {
		t.Fatalf("valid activation days=%d want 30", days)
	}
}

func TestRetentionPolicyContextFailureReleasesReservationWithoutMutation(t *testing.T) {
	reaper := newFakeRetentionReaper(90)
	controller, err := newRetentionController(reaper, RetentionControllerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if err := controller.claimRuntimeOwnership(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(controller.releaseRuntimeOwnership)
	directory := t.TempDir()
	initialPlan := runtimeTestPlan(
		t, filepath.Join(directory, "audit.db"), filepath.Join(directory, "judge.db"), 90, nil,
	)
	failureFactory := &cancelCandidateFactory{}
	manager, managerErr := runtimegraph.New(
		t.Context(), runtimegraph.ConfigFromPlan(initialPlan, false),
		[]runtimegraph.ComponentFactory{
			&retentionPolicyFactory{controller: controller}, failureFactory,
		},
		runtimegraph.DefaultOptions(&discardGraphReporter{}),
	)
	if managerErr != nil {
		t.Fatal(managerErr)
	}
	t.Cleanup(func() { _ = manager.Close(context.Background()) })

	failureFactory.failNext.Store(true)
	reloadContext, cancel := context.WithCancel(t.Context())
	failureFactory.cancel = cancel
	candidatePlan := runtimeTestPlan(
		t, filepath.Join(directory, "audit.db"), filepath.Join(directory, "judge.db"), 30, nil,
	)
	result, reloadErr := manager.Reload(
		reloadContext, runtimegraph.ConfigFromPlan(candidatePlan, false),
	)
	if reloadErr == nil || result.Status() != runtimegraph.ReloadRejected {
		t.Fatalf("context failure status=%s err=%v", result.Status(), reloadErr)
	}
	if _, _, _, days := reaper.snapshot(); days != 90 {
		t.Fatalf("context failure activated candidate retention days=%d", days)
	}
	result, reloadErr = manager.Reload(
		t.Context(), runtimegraph.ConfigFromPlan(candidatePlan, false),
	)
	if reloadErr != nil || result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("post-context reload status=%s err=%v", result.Status(), reloadErr)
	}
	if _, _, _, days := reaper.snapshot(); days != 30 {
		t.Fatalf("post-context activation days=%d", days)
	}
}

func TestRuntimeConcurrentReloadAndCloseNeverActivateAfterControllerStop(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	initial := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90, nil)
	runtime := newRuntimeForTest(t, dependencies, initial, false)
	updateStarted := make(chan int64, 1)
	allowUpdate := make(chan struct{})
	dependencies.retentionReaper.gateUpdates(updateStarted, allowUpdate)
	candidate := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 30, nil)
	type reloadOutcome struct {
		result runtimegraph.ReloadResult
		err    *runtimegraph.Error
	}
	reloadDone := make(chan reloadOutcome, 1)
	go func() {
		result, err := runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(candidate, false))
		reloadDone <- reloadOutcome{result: result, err: err}
	}()
	if days := receiveRetentionTest(t, updateStarted); days != 30 {
		t.Fatalf("gated activation days=%d", days)
	}
	closeStarted := make(chan struct{})
	closeDone := make(chan error, 1)
	go func() {
		close(closeStarted)
		closeDone <- runtime.Close(t.Context())
	}()
	<-closeStarted
	close(allowUpdate)
	reloaded := receiveRetentionTest(t, reloadDone)
	if reloaded.err != nil || reloaded.result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("serialized reload status=%s err=%v", reloaded.result.Status(), reloaded.err)
	}
	if closeErr := receiveRetentionTest(t, closeDone); closeErr != nil {
		t.Fatal(closeErr)
	}
	if status := dependencies.retentionController.Status(); status.State != RetentionStateStopped {
		t.Fatalf("controller status after close=%#v", status)
	}
	if !dependencies.store.Ready() || runtime.store != dependencies.store ||
		runtime.retention != dependencies.retentionController {
		t.Fatal("runtime close changed process-stable controller/store identity")
	}
	updatesBefore := len(dependencies.retentionReaper.updateSnapshot())
	dependencies.retentionReaper.gateUpdates(nil, nil)
	afterClose := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 60, nil)
	result, reloadErr := runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(afterClose, false))
	if reloadErr == nil || result.Status() != runtimegraph.ReloadRejected {
		t.Fatalf("post-close reload status=%s err=%v", result.Status(), reloadErr)
	}
	if updates := dependencies.retentionReaper.updateSnapshot(); len(updates) != updatesBefore {
		t.Fatalf("policy activated after controller stop: before=%d after=%d", updatesBefore, len(updates))
	}
}

func TestRuntimeCloseDeadlineFailureIsBoundedAndRetryWaitsForRetention(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	blockingReporter := &blockingRetentionReporter{
		entered: make(chan struct{}), release: make(chan struct{}),
	}
	t.Cleanup(func() {
		select {
		case <-blockingReporter.release:
		default:
			close(blockingReporter.release)
		}
	})
	reaper := newFakeRetentionReaper(90)
	scheduler := newScriptedRetentionScheduler()
	controller, err := newRetentionController(reaper, RetentionControllerOptions{
		Scheduler: scheduler, Reporter: blockingReporter,
	})
	if err != nil {
		t.Fatal(err)
	}
	dependencies.retentionReaper = reaper
	dependencies.retentionScheduler = scheduler
	dependencies.retentionController = controller
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90, nil)
	runtime := newRuntimeForTest(t, dependencies, plan, false)
	receiveRetentionTest(t, reaper.started)
	reaper.responses <- fakeRetentionResponse{result: successfulRetentionResult()}
	receiveRetentionTest(t, blockingReporter.entered)

	expired, cancel := context.WithDeadline(t.Context(), time.Now().Add(-time.Second))
	defer cancel()
	closeErr := runtime.Close(expired)
	var runtimeErr *Error
	if !errors.As(closeErr, &runtimeErr) || runtimeErr.Code() != ErrorShutdown {
		t.Fatalf("expired close error=%v", closeErr)
	}
	if !runtime.destinationObserver.stopped.Load() {
		t.Fatal("degraded close skipped the process-stable destination observer")
	}
	if runtime.Active() != nil {
		t.Fatal("expired close did not attempt graph shutdown")
	}
	if !dependencies.store.Ready() {
		t.Fatal("degraded close closed the caller-owned store")
	}
	if status := controller.Status(); status.State == RetentionStateStopped {
		t.Fatal("degraded close claimed retention had stopped while reporter was blocked")
	}

	close(blockingReporter.release)
	if err := runtime.Close(t.Context()); err != nil {
		t.Fatalf("retry close failed: %v", err)
	}
	if status := controller.Status(); status.State != RetentionStateStopped {
		t.Fatalf("retry close returned before retention stopped: %#v", status)
	}
	if !dependencies.store.Ready() {
		t.Fatal("successful retry closed the caller-owned store")
	}
}

type blockingRetentionReporter struct {
	once    sync.Once
	entered chan struct{}
	release chan struct{}
}

func (reporter *blockingRetentionReporter) ReportRetentionController(RetentionControllerStatus) {
	reporter.once.Do(func() {
		close(reporter.entered)
		<-reporter.release
	})
}

type cancelCandidateFactory struct {
	failNext atomic.Bool
	cancel   context.CancelFunc
}

func (*cancelCandidateFactory) Name() string { return "cancel-candidate" }

func (factory *cancelCandidateFactory) Prepare(
	ctx context.Context,
	input runtimegraph.BuildInput,
	_ *runtimegraph.Acquisitions,
) (runtimegraph.Component, error) {
	if factory.failNext.CompareAndSwap(true, false) {
		if factory.cancel != nil {
			factory.cancel()
		}
		return nil, ctx.Err()
	}
	return &noOpGenerationComponent{generation: input.Generation}, nil
}

type noOpGenerationComponent struct{ generation uint64 }

func (*noOpGenerationComponent) Activate()                        {}
func (*noOpGenerationComponent) StopIntake(context.Context) error { return nil }
func (*noOpGenerationComponent) Drain(context.Context) error      { return nil }
func (*noOpGenerationComponent) Close(context.Context) error      { return nil }
