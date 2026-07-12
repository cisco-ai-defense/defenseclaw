// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// Package runtime owns process-stable observability services whose lifetime is
// longer than any one immutable runtime graph generation.
package runtime

import (
	"context"
	"errors"
	"math"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

// RetentionControllerState is a bounded lifecycle/health label. It never
// contains a database error, path, SQL text, or retained record content.
type RetentionControllerState string

const (
	RetentionStateWaiting  RetentionControllerState = "waiting_for_readiness"
	RetentionStateHealthy  RetentionControllerState = "healthy"
	RetentionStateDegraded RetentionControllerState = "degraded"
	RetentionStateDisabled RetentionControllerState = "disabled"
	RetentionStateStopped  RetentionControllerState = "stopped"
)

// RetentionControllerFailure is a stable low-cardinality failure label.
type RetentionControllerFailure string

const (
	RetentionFailureNone      RetentionControllerFailure = ""
	RetentionFailureRun       RetentionControllerFailure = "run_failed"
	RetentionFailureScheduler RetentionControllerFailure = "scheduler_failed"
)

// RetentionControllerStatus is an immutable bounded snapshot suitable for
// readiness, health, and metric adapters. It intentionally omits raw errors.
type RetentionControllerStatus struct {
	State              RetentionControllerState
	Failure            RetentionControllerFailure
	RetentionDays      int64
	LastAttemptAt      time.Time
	LastSuccessAt      time.Time
	RunCount           uint64
	FailureCount       uint64
	LastRowsDeleted    int64
	LastBatchCount     int64
	LastRunDuration    time.Duration
	LastRunCompletedAt time.Time
}

// RetentionControllerReporter receives bounded status changes. Implementations
// must return promptly; reporting occurs after a reaper run has released its
// database and lifecycle ownership.
type RetentionControllerReporter interface {
	ReportRetentionController(RetentionControllerStatus)
}

// RetentionControllerOptions supplies process lifecycle seams. Ready may be
// nil when Start is called only after store readiness; otherwise the initial
// run waits until Ready is closed or receives a value. Scheduler and Clock have
// production defaults and are injectable for deterministic tests.
type RetentionControllerOptions struct {
	Ready     <-chan struct{}
	Scheduler audit.RetentionScheduler
	Clock     func() time.Time
	Reporter  RetentionControllerReporter
}

type retentionReaper interface {
	RetentionDays() int64
	UpdateRetentionDays(int64) error
	Run(context.Context) (audit.RetentionRunResult, error)
}

// RetentionController owns exactly one audit reaper for the process lifetime.
// Runtime graph activation changes policy through ApplyPolicy; it never swaps
// or closes the reaper or its stores.
type RetentionController struct {
	reaper    retentionReaper
	ready     <-chan struct{}
	scheduler audit.RetentionScheduler
	clock     func() time.Time
	reporter  RetentionControllerReporter

	lifecycleMu  sync.Mutex
	started      bool
	stopped      bool
	runtimeOwned bool
	cancel       context.CancelFunc
	done         chan struct{}
	policyWake   chan struct{}
	promptRun    bool

	statusMu sync.Mutex
	status   atomic.Pointer[RetentionControllerStatus]
}

// NewRetentionController creates a process owner around an existing reaper.
// The caller retains responsibility for starting it after (or gating it on)
// store readiness and stopping it before either SQLite store is closed.
func NewRetentionController(
	reaper *audit.RetentionReaper,
	options RetentionControllerOptions,
) (*RetentionController, error) {
	if reaper == nil {
		return nil, errors.New("observability retention controller requires a reaper")
	}
	return newRetentionController(reaper, options)
}

func newRetentionController(
	reaper retentionReaper,
	options RetentionControllerOptions,
) (*RetentionController, error) {
	if reaper == nil {
		return nil, errors.New("observability retention controller requires a reaper")
	}
	scheduler := options.Scheduler
	if scheduler == nil {
		scheduler = audit.TimerRetentionScheduler{}
	}
	clock := options.Clock
	if clock == nil {
		clock = time.Now
	}
	controller := &RetentionController{
		reaper: reaper, ready: options.Ready, scheduler: scheduler,
		clock: clock, reporter: options.Reporter,
		done: make(chan struct{}), policyWake: make(chan struct{}, 1),
	}
	controller.storeStatus(RetentionControllerStatus{
		State: RetentionStateWaiting, RetentionDays: reaper.RetentionDays(),
	})
	return controller, nil
}

// Start launches the one process worker. It is intentionally non-blocking;
// readiness gating and the initial run happen in that worker.
func (controller *RetentionController) Start(parent context.Context) error {
	return controller.start(parent, false)
}

func (controller *RetentionController) startRuntime(parent context.Context) error {
	return controller.start(parent, true)
}

func (controller *RetentionController) start(parent context.Context, runtimeOwner bool) error {
	if controller == nil {
		return errors.New("observability retention controller is not initialized")
	}
	if parent == nil {
		return errors.New("observability retention controller context is required")
	}
	controller.lifecycleMu.Lock()
	defer controller.lifecycleMu.Unlock()
	if controller.runtimeOwned != runtimeOwner {
		return errors.New("observability retention controller lifecycle is owned elsewhere")
	}
	if controller.stopped {
		return errors.New("observability retention controller is stopped")
	}
	if controller.started {
		return errors.New("observability retention controller is already started")
	}
	ctx, cancel := context.WithCancel(parent)
	controller.cancel = cancel
	controller.started = true
	go controller.run(ctx)
	return nil
}

// ApplyPolicy atomically activates the next graph generation's one global
// retention age on the existing reaper. Zero disables startup/cadence runs. A
// transition from zero or to a shorter positive age requests one prompt run.
func (controller *RetentionController) ApplyPolicy(retentionDays int64) error {
	if controller == nil {
		return errors.New("observability retention controller is not initialized")
	}
	controller.lifecycleMu.Lock()
	defer controller.lifecycleMu.Unlock()
	if controller.runtimeOwned {
		return errors.New("observability retention policy is runtime-owned")
	}
	if controller.stopped {
		return errors.New("observability retention controller is stopped")
	}
	return controller.applyPolicyLocked(retentionDays)
}

func (controller *RetentionController) applyPolicyLocked(retentionDays int64) error {
	previous := controller.reaper.RetentionDays()
	if err := controller.reaper.UpdateRetentionDays(retentionDays); err != nil {
		return errors.New("observability retention policy is invalid")
	}
	if retentionDays > 0 && (previous == 0 || retentionDays < previous) {
		controller.promptRun = true
	}
	if controller.started {
		select {
		case controller.policyWake <- struct{}{}:
		default:
		}
	}
	return nil
}

// Status returns a copy of the latest bounded controller outcome. The active
// age is read from the reaper so a successful ApplyPolicy is immediately
// visible even before the worker consumes its wake-up.
func (controller *RetentionController) Status() RetentionControllerStatus {
	if controller == nil {
		return RetentionControllerStatus{State: RetentionStateStopped}
	}
	status := controller.status.Load()
	if status == nil {
		return RetentionControllerStatus{
			State: RetentionStateWaiting, RetentionDays: controller.reaper.RetentionDays(),
		}
	}
	copyStatus := *status
	copyStatus.RetentionDays = controller.reaper.RetentionDays()
	return copyStatus
}

// Stop cancels the scheduler and any active reaper run, then waits for all
// controller work to release store ownership. Call it before closing stores.
func (controller *RetentionController) Stop(ctx context.Context) error {
	return controller.stop(ctx, false)
}

func (controller *RetentionController) stopRuntime(ctx context.Context) error {
	return controller.stop(ctx, true)
}

func (controller *RetentionController) stop(ctx context.Context, runtimeOwner bool) error {
	if controller == nil {
		return nil
	}
	if ctx == nil {
		return errors.New("observability retention stop context is required")
	}
	controller.lifecycleMu.Lock()
	if controller.runtimeOwned != runtimeOwner {
		controller.lifecycleMu.Unlock()
		return errors.New("observability retention controller lifecycle is owned elsewhere")
	}
	if !controller.started {
		publishStopped := false
		if !controller.stopped {
			controller.stopped = true
			close(controller.done)
			publishStopped = true
		}
		done := controller.done
		controller.lifecycleMu.Unlock()
		if publishStopped {
			controller.publishStatus(RetentionControllerStatus{
				State: RetentionStateStopped, RetentionDays: controller.reaper.RetentionDays(),
			})
		}
		select {
		case <-done:
			return nil
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	if controller.cancel != nil {
		controller.cancel()
	}
	done := controller.done
	controller.lifecycleMu.Unlock()
	select {
	case <-done:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

func (controller *RetentionController) run(ctx context.Context) {
	defer func() {
		if ctx.Err() != nil {
			controller.publishStatus(controller.nextStatus(
				RetentionStateStopped, RetentionFailureNone, nil,
			))
		}
		controller.lifecycleMu.Lock()
		controller.stopped = true
		close(controller.done)
		controller.lifecycleMu.Unlock()
	}()

	if controller.ready != nil {
		select {
		case <-ctx.Done():
			return
		case <-controller.ready:
		}
	}
	// Policy activations received while readiness was pending are already
	// reflected in the reaper's atomic age. The one startup run applies the
	// latest such policy, so discard their coalesced prompt to avoid a duplicate
	// immediate run. An activation racing after this point queues normally.
	controller.consumePreReadinessPolicy()
	if controller.reaper.RetentionDays() == 0 {
		controller.publishStatus(controller.nextStatus(
			RetentionStateDisabled, RetentionFailureNone, nil,
		))
	} else if !controller.runOnce(ctx) {
		return
	}

	for {
		interval := audit.RetentionScheduleInterval
		if controller.reaper.RetentionDays() == 0 {
			interval = 0
		}
		wake, err := controller.scheduler.Wait(ctx, interval, controller.policyWake)
		if err != nil {
			if ctx.Err() != nil || errors.Is(err, context.Canceled) ||
				errors.Is(err, context.DeadlineExceeded) {
				return
			}
			controller.publishStatus(controller.nextStatus(
				RetentionStateDegraded, RetentionFailureScheduler,
				func(status *RetentionControllerStatus) {
					status.FailureCount = saturatingIncrement(status.FailureCount)
				},
			))
			return
		}
		switch wake {
		case audit.RetentionScheduleTick:
			if controller.reaper.RetentionDays() > 0 && !controller.runOnce(ctx) {
				return
			}
		case audit.RetentionScheduleReload:
			prompt := controller.consumePromptRun()
			if controller.reaper.RetentionDays() == 0 {
				controller.publishStatus(controller.nextStatus(
					RetentionStateDisabled, RetentionFailureNone, nil,
				))
			} else if prompt && !controller.runOnce(ctx) {
				return
			}
		default:
			controller.publishStatus(controller.nextStatus(
				RetentionStateDegraded, RetentionFailureScheduler,
				func(status *RetentionControllerStatus) {
					status.FailureCount = saturatingIncrement(status.FailureCount)
				},
			))
			return
		}
	}
}

func (controller *RetentionController) consumePreReadinessPolicy() {
	controller.lifecycleMu.Lock()
	defer controller.lifecycleMu.Unlock()
	controller.promptRun = false
	select {
	case <-controller.policyWake:
	default:
	}
}

func (controller *RetentionController) consumePromptRun() bool {
	controller.lifecycleMu.Lock()
	defer controller.lifecycleMu.Unlock()
	prompt := controller.promptRun
	controller.promptRun = false
	return prompt
}

func (controller *RetentionController) runOnce(ctx context.Context) bool {
	if ctx.Err() != nil {
		return false
	}
	attemptedAt := controller.clock().UTC()
	result, err := controller.reaper.Run(ctx)
	if ctx.Err() != nil {
		return false
	}
	status := controller.Status()
	status.LastAttemptAt = attemptedAt
	status.RunCount = saturatingIncrement(status.RunCount)
	status.LastRowsDeleted = sumRowsDeleted(result.RowsDeleted)
	status.LastBatchCount = result.BatchCount
	status.LastRunDuration = result.Duration
	status.LastRunCompletedAt = result.CompletedAt
	if err != nil {
		status.State = RetentionStateDegraded
		status.Failure = RetentionFailureRun
		status.FailureCount = saturatingIncrement(status.FailureCount)
		controller.publishStatus(status)
		return true
	}
	status.State = RetentionStateHealthy
	status.Failure = RetentionFailureNone
	status.LastSuccessAt = result.CompletedAt
	if status.LastSuccessAt.IsZero() {
		status.LastSuccessAt = controller.clock().UTC()
	}
	controller.publishStatus(status)
	return true
}

func (controller *RetentionController) nextStatus(
	state RetentionControllerState,
	failure RetentionControllerFailure,
	mutate func(*RetentionControllerStatus),
) RetentionControllerStatus {
	status := controller.Status()
	status.State = state
	status.Failure = failure
	if mutate != nil {
		mutate(&status)
	}
	return status
}

func (controller *RetentionController) storeStatus(status RetentionControllerStatus) {
	copyStatus := status
	controller.status.Store(&copyStatus)
}

func (controller *RetentionController) publishStatus(status RetentionControllerStatus) {
	controller.statusMu.Lock()
	controller.storeStatus(status)
	reporter := controller.reporter
	controller.statusMu.Unlock()
	if reporter != nil {
		reporter.ReportRetentionController(status)
	}
}

func sumRowsDeleted(rows map[audit.RetentionTableClass]int64) int64 {
	var total int64
	for _, count := range rows {
		if count <= 0 {
			continue
		}
		if total > math.MaxInt64-count {
			return math.MaxInt64
		}
		total += count
	}
	return total
}

func saturatingIncrement(value uint64) uint64 {
	if value == math.MaxUint64 {
		return value
	}
	return value + 1
}
