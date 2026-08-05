// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package delivery

import (
	"context"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

const (
	maxQueueItems = 65_536
	maxQueueBytes = 256 * 1024 * 1024
	maxBatchItems = 8_192
	maxBatchBytes = 64 * 1024 * 1024
	maxAttempts   = 32
)

type atomicCounters struct {
	accepted  atomic.Uint64
	delivered atomic.Uint64
	retried   atomic.Uint64
	dropped   atomic.Uint64
	rejected  atomic.Uint64
	failed    atomic.Uint64
}

// Dispatcher is one destination's generation-owned queue and worker. NewDispatcher
// performs no I/O and starts no goroutine; Activate publishes intake and starts
// the worker after the containing runtime graph becomes active.
type Dispatcher struct {
	config  Config
	adapter Adapter

	rootContext context.Context
	cancelRoot  context.CancelFunc

	lifecycleMu     sync.Mutex
	activated       bool
	accepting       bool
	intakeStopped   bool
	closeStarted    bool
	workerStarted   bool
	observerStarted bool

	queueMu       sync.Mutex
	pending       []Payload
	chargedItems  int
	chargedBytes  int
	inFlightItems int
	inFlightBytes int
	wake          chan struct{}
	flushNotify   chan struct{}

	workerDone     chan struct{}
	workerDoneOnce sync.Once

	healthMu            sync.Mutex
	health              HealthState
	healthReason        HealthReason
	circuitState        CircuitState
	consecutiveFailures uint64
	circuitOpenUntil    time.Time
	lastFailureClass    FailureClass
	lastSuccess         time.Time
	lastFailure         time.Time
	healthSequence      uint64
	pendingTransition   *HealthTransition
	healthNotify        chan struct{}
	observerStop        chan struct{}
	observerDone        chan struct{}
	observerStopOnce    sync.Once
	observerDoneOnce    sync.Once

	counters  atomicCounters
	completed atomic.Uint64
	now       func() time.Time
}

// NewDispatcher validates limits and snapshots configuration without touching
// the destination. Enabled dispatchers begin in initializing; disabled ones
// remain disabled and own no worker.
func NewDispatcher(config Config, adapter Adapter) (*Dispatcher, error) {
	if !observability.IsStableToken(config.Destination) || config.ObserverInterval < 0 ||
		(config.Signal != "" && !observability.IsSignal(observability.Signal(config.Signal))) {
		return nil, newError(ErrorInvalidConfig)
	}
	circuit, ok := normalizedCircuitPolicy(config.Circuit)
	if !ok {
		return nil, newError(ErrorInvalidConfig)
	}
	config.Circuit = circuit
	if config.Enabled && !validEnabledConfig(config, adapter) {
		return nil, newError(ErrorInvalidConfig)
	}
	rootContext, cancelRoot := context.WithCancel(context.Background())
	health := HealthDisabled
	if config.Enabled {
		health = HealthInitializing
	}
	return &Dispatcher{
		config: config, adapter: adapter,
		rootContext: rootContext, cancelRoot: cancelRoot,
		wake: make(chan struct{}, 1), flushNotify: make(chan struct{}, 1),
		workerDone: make(chan struct{}),
		health:     health, circuitState: CircuitClosed, healthNotify: make(chan struct{}, 1),
		observerStop: make(chan struct{}), observerDone: make(chan struct{}),
		now: time.Now,
	}, nil
}

func validEnabledConfig(config Config, adapter Adapter) bool {
	return adapter != nil &&
		config.MaxQueueItems > 0 && config.MaxQueueItems <= maxQueueItems &&
		config.MaxQueueBytes > 0 && config.MaxQueueBytes <= maxQueueBytes &&
		config.MaxBatchItems > 0 && config.MaxBatchItems <= maxBatchItems &&
		config.MaxBatchItems <= config.MaxQueueItems &&
		config.MaxBatchBytes > 0 && config.MaxBatchBytes <= maxBatchBytes &&
		config.ScheduledDelay >= 0 && config.AttemptTimeout > 0 &&
		config.Retry.MaxAttempts > 0 && config.Retry.MaxAttempts <= maxAttempts &&
		config.Retry.InitialBackoff >= 0 && config.Retry.MaxBackoff >= 0 &&
		config.Retry.InitialBackoff <= config.Retry.MaxBackoff
}

// Activate implements runtimegraph.Component. It is infallible, nonblocking,
// and idempotent. All adapter initialization belongs in its factory/Prepare.
func (dispatcher *Dispatcher) Activate() {
	if dispatcher == nil {
		return
	}
	dispatcher.lifecycleMu.Lock()
	if dispatcher.activated || dispatcher.closeStarted {
		dispatcher.lifecycleMu.Unlock()
		return
	}
	dispatcher.activated = true
	if !dispatcher.config.Enabled {
		dispatcher.lifecycleMu.Unlock()
		return
	}
	dispatcher.accepting = !dispatcher.intakeStopped
	dispatcher.workerStarted = true
	dispatcher.observerStarted = true
	dispatcher.lifecycleMu.Unlock()

	// Publish the initial state before either worker can observe queued work.
	// Otherwise an immediate delivery failure can transition to failing and then
	// be overwritten by the later activated transition.
	if dispatcher.intakeIsStopped() {
		dispatcher.setHealth(HealthDraining, HealthReasonIntakeStopped)
	} else {
		dispatcher.setOperationalHealth(HealthHealthy, HealthReasonActivated)
	}
	go dispatcher.observeHealth()
	go dispatcher.run()
}

// Enqueue snapshots no producer object and performs no destination I/O. It
// accepts or rejects under a short queue lock, then wakes the destination-owned
// worker through a nonblocking signal.
func (dispatcher *Dispatcher) Enqueue(payload Payload) EnqueueResult {
	if dispatcher == nil || !payload.valid() {
		if dispatcher != nil {
			dispatcher.counters.rejected.Add(1)
			dispatcher.recordFailure(dispatcher.nowUTC())
		}
		return EnqueueResult{Disposition: EnqueueRejected, Reason: ReasonInvalidPayload}
	}
	identity := payload.identity
	if identity.OriginDestination != "" && identity.OriginDestination == dispatcher.config.Destination {
		dispatcher.counters.rejected.Add(1)
		dispatcher.recordFailure(dispatcher.nowUTC())
		dispatcher.setOperationalHealth(HealthDegraded, HealthReasonOriginLoop)
		return EnqueueResult{Disposition: EnqueueRejected, Reason: ReasonOriginLoop}
	}

	dispatcher.lifecycleMu.Lock()
	active := dispatcher.activated && dispatcher.config.Enabled && !dispatcher.closeStarted
	accepting := dispatcher.accepting
	if !active || !accepting {
		dispatcher.lifecycleMu.Unlock()
		dispatcher.counters.rejected.Add(1)
		reason := ReasonInactive
		if active || dispatcher.intakeIsStopped() {
			reason = ReasonIntakeStopped
		}
		return EnqueueResult{Disposition: EnqueueRejected, Reason: reason}
	}

	dispatcher.queueMu.Lock()
	countFull := dispatcher.chargedItems >= dispatcher.config.MaxQueueItems
	byteFull := payload.Size() > dispatcher.config.MaxQueueBytes-dispatcher.chargedBytes
	if countFull || byteFull {
		dispatcher.queueMu.Unlock()
		dispatcher.lifecycleMu.Unlock()
		dispatcher.counters.dropped.Add(1)
		dispatcher.recordFailure(dispatcher.nowUTC())
		dispatcher.setOperationalHealth(HealthDegraded, HealthReasonQueueFull)
		reason := ReasonCountLimit
		if countFull && byteFull {
			reason = ReasonCountAndByteLimit
		} else if byteFull {
			reason = ReasonByteLimit
		}
		return EnqueueResult{Disposition: EnqueueDropped, Reason: reason}
	}
	admitted, halfOpen := dispatcher.admitCircuit(dispatcher.nowUTC())
	if !admitted {
		dispatcher.queueMu.Unlock()
		dispatcher.lifecycleMu.Unlock()
		dispatcher.counters.rejected.Add(1)
		return EnqueueResult{Disposition: EnqueueRejected, Reason: ReasonCircuitOpen}
	}
	dispatcher.pending = append(dispatcher.pending, payload)
	dispatcher.chargedItems++
	dispatcher.chargedBytes += payload.Size()
	dispatcher.counters.accepted.Add(1)
	if halfOpen {
		dispatcher.setOperationalHealth(HealthDegraded, HealthReasonCircuitHalfOpen)
	}
	dispatcher.queueMu.Unlock()
	dispatcher.lifecycleMu.Unlock()
	dispatcher.signalWorker()
	return EnqueueResult{Disposition: EnqueueAccepted, Reason: ReasonNone}
}

// StopIntake closes producer admission without waiting for delivery.
func (dispatcher *Dispatcher) StopIntake(context.Context) error {
	if dispatcher == nil {
		return nil
	}
	dispatcher.lifecycleMu.Lock()
	dispatcher.intakeStopped = true
	dispatcher.accepting = false
	activated := dispatcher.activated
	enabled := dispatcher.config.Enabled
	closed := dispatcher.closeStarted
	dispatcher.lifecycleMu.Unlock()
	if activated && enabled && !closed {
		dispatcher.setHealth(HealthDraining, HealthReasonIntakeStopped)
	}
	dispatcher.signalWorker()
	return nil
}

// Flush waits until every payload accepted before this call reaches a terminal
// delivery, rejection, or drop disposition. Unlike Drain it keeps intake open,
// so generation-owned trace processors can implement ForceFlush without making
// the destination unusable for subsequent spans.
func (dispatcher *Dispatcher) Flush(ctx context.Context) error {
	if dispatcher == nil {
		return nil
	}
	if ctx == nil {
		return newError(ErrorInvalidContext)
	}
	target := dispatcher.counters.accepted.Load()
	for dispatcher.completed.Load() < target {
		select {
		case <-dispatcher.flushNotify:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	return nil
}

// Drain stops intake and waits for accepted records and bounded retries. A
// deadline does not silently discard work: callers may retry Drain or call
// Close, which cancels the active attempt and releases retained memory.
func (dispatcher *Dispatcher) Drain(ctx context.Context) error {
	if dispatcher == nil {
		return nil
	}
	if ctx == nil {
		return newError(ErrorInvalidContext)
	}
	_ = dispatcher.StopIntake(ctx)
	dispatcher.lifecycleMu.Lock()
	started := dispatcher.workerStarted
	dispatcher.lifecycleMu.Unlock()
	if !started {
		return nil
	}
	select {
	case <-dispatcher.workerDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Close is bounded by ctx, idempotent, and retryable. Its first call cancels
// destination work; a timed-out caller can invoke Close again to observe the
// same worker and observer reaching stopped.
func (dispatcher *Dispatcher) Close(ctx context.Context) error {
	if dispatcher == nil {
		return nil
	}
	if ctx == nil {
		return newError(ErrorInvalidContext)
	}
	_ = dispatcher.StopIntake(ctx)
	dispatcher.lifecycleMu.Lock()
	first := !dispatcher.closeStarted
	dispatcher.closeStarted = true
	dispatcher.accepting = false
	started := dispatcher.workerStarted
	observerStarted := dispatcher.observerStarted
	dispatcher.lifecycleMu.Unlock()
	if first {
		dispatcher.cancelRoot()
		dispatcher.signalWorker()
	}
	if !started {
		dispatcher.finishWorker()
	}
	select {
	case <-dispatcher.workerDone:
	case <-ctx.Done():
		return ctx.Err()
	}

	dispatcher.setHealth(HealthStopped, HealthReasonClosed)
	if observerStarted {
		dispatcher.observerStopOnce.Do(func() { close(dispatcher.observerStop) })
	} else {
		dispatcher.finishObserver()
	}
	select {
	case <-dispatcher.observerDone:
		return nil
	case <-ctx.Done():
		return ctx.Err()
	}
}

// Health returns the current exact destination state.
func (dispatcher *Dispatcher) Health() HealthState {
	if dispatcher == nil {
		return HealthStopped
	}
	dispatcher.healthMu.Lock()
	defer dispatcher.healthMu.Unlock()
	return dispatcher.health
}

// Counters returns an atomic content-free snapshot.
func (dispatcher *Dispatcher) Counters() Counters {
	if dispatcher == nil {
		return Counters{}
	}
	return Counters{
		Accepted: dispatcher.counters.accepted.Load(), Delivered: dispatcher.counters.delivered.Load(),
		Retried: dispatcher.counters.retried.Load(), Dropped: dispatcher.counters.dropped.Load(),
		Rejected: dispatcher.counters.rejected.Load(), Failed: dispatcher.counters.failed.Load(),
	}
}

// QueueUsage includes the in-flight batch because its immutable bytes remain
// charged until a terminal disposition.
func (dispatcher *Dispatcher) QueueUsage() (items, projectedBytes, inFlightItems, inFlightBytes int) {
	if dispatcher == nil {
		return 0, 0, 0, 0
	}
	dispatcher.queueMu.Lock()
	defer dispatcher.queueMu.Unlock()
	return dispatcher.chargedItems, dispatcher.chargedBytes,
		dispatcher.inFlightItems, dispatcher.inFlightBytes
}

// DeliveryHealthSnapshot returns a detached, generation-bound view. It never
// exposes queued payloads or the adapter. Sequential locks avoid coupling the
// queue hot path to health observation while still returning values that were
// all actually observed by this dispatcher.
func (dispatcher *Dispatcher) DeliveryHealthSnapshot() HealthSnapshot {
	if dispatcher == nil {
		return HealthSnapshot{State: HealthStopped}
	}
	dispatcher.healthMu.Lock()
	state := dispatcher.health
	reason := dispatcher.healthReason
	circuitState := dispatcher.circuitState
	consecutiveFailures := dispatcher.consecutiveFailures
	circuitOpenUntil := dispatcher.circuitOpenUntil
	lastFailureClass := dispatcher.lastFailureClass
	lastSuccess := dispatcher.lastSuccess
	lastFailure := dispatcher.lastFailure
	dispatcher.healthMu.Unlock()
	items, bytes, inFlightItems, inFlightBytes := dispatcher.QueueUsage()
	return HealthSnapshot{
		Destination:         dispatcher.config.Destination,
		Generation:          dispatcher.config.Generation,
		Signal:              dispatcher.config.Signal,
		State:               state,
		Reason:              string(reason),
		CircuitState:        circuitState,
		ConsecutiveFailures: consecutiveFailures,
		CircuitOpenUntil:    circuitOpenUntil,
		LastFailureClass:    lastFailureClass,
		Queue: &QueueSnapshot{
			Items: items, Bytes: bytes,
			InFlightItems: inFlightItems, InFlightBytes: inFlightBytes,
			MaxItems: dispatcher.config.MaxQueueItems, MaxBytes: dispatcher.config.MaxQueueBytes,
		},
		Counters: dispatcher.Counters(), LastSuccess: lastSuccess, LastFailure: lastFailure,
	}
}

func (dispatcher *Dispatcher) nowUTC() time.Time {
	if dispatcher == nil || dispatcher.now == nil {
		return time.Now().UTC()
	}
	return dispatcher.now().UTC()
}

func (dispatcher *Dispatcher) recordSuccess(at time.Time) {
	if dispatcher == nil || at.IsZero() {
		return
	}
	dispatcher.healthMu.Lock()
	dispatcher.lastSuccess = at.UTC()
	dispatcher.healthMu.Unlock()
}

func (dispatcher *Dispatcher) recordFailure(at time.Time) {
	if dispatcher == nil || at.IsZero() {
		return
	}
	dispatcher.healthMu.Lock()
	dispatcher.lastFailure = at.UTC()
	dispatcher.healthMu.Unlock()
}

type circuitDeliveryMode uint8

const (
	circuitDeliveryNormal circuitDeliveryMode = iota
	circuitDeliveryBlocked
	circuitDeliveryProbe
)

// admitCircuit runs while Enqueue owns the lifecycle and queue locks. This
// makes the first post-cooldown record the sole half-open probe without
// reserving a slot that can subsequently fail the queue-capacity check.
func (dispatcher *Dispatcher) admitCircuit(now time.Time) (admitted, halfOpen bool) {
	dispatcher.healthMu.Lock()
	defer dispatcher.healthMu.Unlock()
	switch dispatcher.circuitState {
	case CircuitClosed:
		return true, false
	case CircuitOpen:
		if now.Before(dispatcher.circuitOpenUntil) {
			return false, false
		}
		dispatcher.circuitState = CircuitHalfOpen
		return true, true
	case CircuitHalfOpen:
		return false, false
	default:
		return false, false
	}
}

func (dispatcher *Dispatcher) circuitMode(now time.Time) (circuitDeliveryMode, bool) {
	dispatcher.healthMu.Lock()
	defer dispatcher.healthMu.Unlock()
	switch dispatcher.circuitState {
	case CircuitClosed:
		return circuitDeliveryNormal, false
	case CircuitOpen:
		if now.Before(dispatcher.circuitOpenUntil) {
			return circuitDeliveryBlocked, false
		}
		dispatcher.circuitState = CircuitHalfOpen
		return circuitDeliveryProbe, true
	case CircuitHalfOpen:
		return circuitDeliveryProbe, false
	default:
		return circuitDeliveryBlocked, false
	}
}

func (dispatcher *Dispatcher) recordCircuitSuccess() {
	dispatcher.healthMu.Lock()
	dispatcher.circuitState = CircuitClosed
	dispatcher.consecutiveFailures = 0
	dispatcher.circuitOpenUntil = time.Time{}
	dispatcher.healthMu.Unlock()
}

func (dispatcher *Dispatcher) abortCircuitProbe() bool {
	dispatcher.healthMu.Lock()
	defer dispatcher.healthMu.Unlock()
	if dispatcher.circuitState != CircuitHalfOpen {
		return false
	}
	dispatcher.circuitState = CircuitOpen
	return true
}

func (dispatcher *Dispatcher) recordCircuitFailure(class FailureClass, at time.Time) bool {
	dispatcher.healthMu.Lock()
	defer dispatcher.healthMu.Unlock()
	if dispatcher.consecutiveFailures < ^uint64(0) {
		dispatcher.consecutiveFailures++
	}
	dispatcher.lastFailureClass = class
	immediateFailure := class == FailureClassAuthentication ||
		class == FailureClassUnsafeEndpoint
	shouldOpen := dispatcher.circuitState == CircuitHalfOpen ||
		immediateFailure ||
		dispatcher.consecutiveFailures >= uint64(dispatcher.config.Circuit.TransientFailureThreshold)
	if !shouldOpen {
		return false
	}
	dispatcher.circuitState = CircuitOpen
	openDuration := dispatcher.config.Circuit.OpenDuration
	if immediateFailure {
		openDuration = immediateCircuitOpenDuration
	}
	dispatcher.circuitOpenUntil = at.UTC().Add(openDuration)
	return true
}

func (dispatcher *Dispatcher) run() {
	defer dispatcher.finishWorker()
	for {
		if dispatcher.rootContext.Err() != nil {
			dispatcher.abortCircuitProbe()
			dispatcher.abandonPending()
			return
		}
		if !dispatcher.waitForPending() {
			return
		}
		mode, enteredHalfOpen := dispatcher.circuitMode(dispatcher.nowUTC())
		if enteredHalfOpen {
			dispatcher.setOperationalHealth(HealthDegraded, HealthReasonCircuitHalfOpen)
		}
		if mode == circuitDeliveryBlocked {
			payloads := dispatcher.takeCircuitRejectedBatch()
			if len(payloads) > 0 {
				dispatcher.counters.rejected.Add(uint64(len(payloads)))
				dispatcher.release(payloads)
			}
			continue
		}
		if mode == circuitDeliveryNormal && !dispatcher.waitScheduledDelay() {
			dispatcher.abandonPending()
			return
		}
		payloads, encodedSize, oversized := dispatcher.takeBatch()
		if len(payloads) == 0 {
			if mode == circuitDeliveryProbe {
				dispatcher.abortCircuitProbe()
			}
			continue
		}
		if oversized {
			dispatcher.counters.failed.Add(1)
			dispatcher.counters.rejected.Add(uint64(len(payloads)))
			now := dispatcher.nowUTC()
			dispatcher.recordFailure(now)
			reason := HealthReasonDeliveryFailed
			if dispatcher.recordCircuitFailure(FailureClassPermanentPayload, now) {
				reason = HealthReasonCircuitOpen
			}
			dispatcher.setOperationalHealth(HealthFailing, reason)
			dispatcher.release(payloads)
			continue
		}
		if !dispatcher.deliver(payloads, encodedSize, mode == circuitDeliveryProbe) {
			dispatcher.abortCircuitProbe()
			dispatcher.abandonPending()
			return
		}
	}
}

func (dispatcher *Dispatcher) waitForPending() bool {
	for {
		dispatcher.lifecycleMu.Lock()
		dispatcher.queueMu.Lock()
		hasPending := len(dispatcher.pending) > 0
		stopped := dispatcher.intakeStopped || dispatcher.closeStarted
		dispatcher.queueMu.Unlock()
		dispatcher.lifecycleMu.Unlock()
		if hasPending {
			return true
		}
		if stopped {
			return false
		}
		select {
		case <-dispatcher.rootContext.Done():
			return false
		case <-dispatcher.wake:
		}
	}
}

func (dispatcher *Dispatcher) waitScheduledDelay() bool {
	delay := dispatcher.config.ScheduledDelay
	if delay <= 0 || dispatcher.intakeIsStopped() {
		return dispatcher.rootContext.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	for {
		select {
		case <-dispatcher.rootContext.Done():
			return false
		case <-timer.C:
			return true
		case <-dispatcher.wake:
			if dispatcher.intakeIsStopped() {
				return true
			}
		}
	}
}

// takeCircuitRejectedBatch removes already-accepted work without consulting
// the adapter's estimator. Open-circuit suppression therefore cannot block on
// destination code and does not increment the failed-operation counter.
func (dispatcher *Dispatcher) takeCircuitRejectedBatch() []Payload {
	dispatcher.queueMu.Lock()
	defer dispatcher.queueMu.Unlock()
	limit := len(dispatcher.pending)
	if limit > dispatcher.config.MaxBatchItems {
		limit = dispatcher.config.MaxBatchItems
	}
	if limit == 0 {
		return nil
	}
	payloads := append([]Payload(nil), dispatcher.pending[:limit]...)
	remaining := copy(dispatcher.pending, dispatcher.pending[limit:])
	clear(dispatcher.pending[remaining:])
	dispatcher.pending = dispatcher.pending[:remaining]
	if remaining == 0 {
		dispatcher.pending = nil
	}
	dispatcher.inFlightItems = len(payloads)
	dispatcher.inFlightBytes = 0
	for _, payload := range payloads {
		dispatcher.inFlightBytes += payload.Size()
	}
	return payloads
}

func (dispatcher *Dispatcher) takeBatch() (payloads []Payload, encodedSize int, oversized bool) {
	dispatcher.queueMu.Lock()
	limit := len(dispatcher.pending)
	if limit > dispatcher.config.MaxBatchItems {
		limit = dispatcher.config.MaxBatchItems
	}
	candidates := append([]Payload(nil), dispatcher.pending[:limit]...)
	dispatcher.queueMu.Unlock()

	sizes := make([]int, 0, limit)
	selected := 0
	projectedSize := 0
	for selected < limit {
		nextSize := candidates[selected].Size()
		if projectedSize > intMax-nextSize {
			if selected == 0 {
				selected = 1
				oversized = true
			}
			break
		}
		projectedSize += nextSize
		sizes = append(sizes, nextSize)
		estimate, ok := dispatcher.encodedSize(sizes)
		if !ok || estimate < projectedSize || estimate > dispatcher.config.MaxBatchBytes {
			sizes = sizes[:len(sizes)-1]
			if selected == 0 {
				selected = 1
				oversized = true
			}
			break
		}
		encodedSize = estimate
		selected++
	}
	if selected == 0 {
		return nil, 0, false
	}
	payloads = append([]Payload(nil), candidates[:selected]...)
	dispatcher.queueMu.Lock()
	remaining := copy(dispatcher.pending, dispatcher.pending[selected:])
	clear(dispatcher.pending[remaining:])
	dispatcher.pending = dispatcher.pending[:remaining]
	if remaining == 0 {
		dispatcher.pending = nil
	}
	dispatcher.inFlightItems = selected
	dispatcher.inFlightBytes = 0
	for _, payload := range payloads {
		dispatcher.inFlightBytes += payload.Size()
	}
	dispatcher.queueMu.Unlock()
	return payloads, encodedSize, oversized
}

func (dispatcher *Dispatcher) deliver(payloads []Payload, encodedSize int, halfOpen bool) bool {
	items := make([]BatchItem, len(payloads))
	for index := range payloads {
		items[index] = BatchItem{payload: payloads[index]}
	}
	batch := Batch{destination: dispatcher.config.Destination, items: items, encodedSize: encodedSize}
	maxAttempts := dispatcher.config.Retry.MaxAttempts
	if halfOpen {
		maxAttempts = 1
	}
	for attempt := 1; attempt <= maxAttempts; attempt++ {
		attemptContext, cancelAttempt := context.WithTimeout(dispatcher.rootContext, dispatcher.config.AttemptTimeout)
		result := dispatcher.callAdapter(attemptContext, batch)
		cancelAttempt()
		if dispatcher.rootContext.Err() != nil {
			dispatcher.counters.dropped.Add(uint64(len(payloads)))
			dispatcher.release(payloads)
			return false
		}
		switch result.Outcome {
		case OutcomeDelivered:
			if result.DeliveredItems != 0 || result.RejectedItems != 0 {
				dispatcher.rejectMalformedResult(payloads)
				return true
			}
			dispatcher.counters.delivered.Add(uint64(len(payloads)))
			dispatcher.recordSuccess(dispatcher.nowUTC())
			dispatcher.recordCircuitSuccess()
			dispatcher.release(payloads)
			dispatcher.setOperationalHealth(HealthHealthy, HealthReasonRecovered)
			return true
		case OutcomePartial:
			if !validPartialResult(result, len(payloads)) {
				dispatcher.rejectMalformedResult(payloads)
				return true
			}
			dispatcher.counters.delivered.Add(uint64(result.DeliveredItems))
			dispatcher.counters.rejected.Add(uint64(result.RejectedItems))
			dispatcher.counters.failed.Add(1)
			now := dispatcher.nowUTC()
			dispatcher.recordSuccess(now)
			dispatcher.recordFailure(now)
			dispatcher.recordCircuitSuccess()
			dispatcher.setOperationalHealth(HealthDegraded, HealthReasonPartial)
			dispatcher.release(payloads)
			return true
		case OutcomeTransient, OutcomeAmbiguous:
			if result.DeliveredItems != 0 || result.RejectedItems != 0 {
				dispatcher.rejectMalformedResult(payloads)
				return true
			}
			dispatcher.counters.failed.Add(1)
			if attempt == maxAttempts {
				now := dispatcher.nowUTC()
				dispatcher.recordFailure(now)
				dispatcher.counters.rejected.Add(uint64(len(payloads)))
				reason := HealthReasonDeliveryFailed
				if dispatcher.recordCircuitFailure(FailureClassTransient, now) {
					reason = HealthReasonCircuitOpen
				}
				dispatcher.setOperationalHealth(HealthFailing, reason)
				dispatcher.release(payloads)
				return true
			}
			dispatcher.counters.retried.Add(uint64(len(payloads)))
			dispatcher.setOperationalHealth(HealthDegraded, HealthReasonRetryable)
			if !dispatcher.waitBackoff(attempt) {
				dispatcher.counters.dropped.Add(uint64(len(payloads)))
				dispatcher.release(payloads)
				return false
			}
		case OutcomeAuthentication, OutcomePermanentPayload, OutcomeUnsafeEndpoint:
			if result.DeliveredItems != 0 || result.RejectedItems != 0 {
				dispatcher.rejectMalformedResult(payloads)
				return true
			}
			dispatcher.counters.rejected.Add(uint64(len(payloads)))
			dispatcher.counters.failed.Add(1)
			now := dispatcher.nowUTC()
			dispatcher.recordFailure(now)
			reason := HealthReasonDeliveryFailed
			if dispatcher.recordCircuitFailure(failureClassForOutcome(result.Outcome), now) {
				reason = HealthReasonCircuitOpen
			}
			dispatcher.setOperationalHealth(HealthFailing, reason)
			dispatcher.release(payloads)
			return true
		default:
			dispatcher.counters.rejected.Add(uint64(len(payloads)))
			dispatcher.counters.failed.Add(1)
			now := dispatcher.nowUTC()
			dispatcher.recordFailure(now)
			reason := HealthReasonDeliveryFailed
			if dispatcher.recordCircuitFailure(FailureClassPermanentPayload, now) {
				reason = HealthReasonCircuitOpen
			}
			dispatcher.setOperationalHealth(HealthFailing, reason)
			dispatcher.release(payloads)
			return true
		}
	}
	return true
}

func failureClassForOutcome(outcome DeliveryOutcome) FailureClass {
	switch outcome {
	case OutcomeTransient, OutcomeAmbiguous:
		return FailureClassTransient
	case OutcomeAuthentication:
		return FailureClassAuthentication
	case OutcomeUnsafeEndpoint:
		return FailureClassUnsafeEndpoint
	default:
		return FailureClassPermanentPayload
	}
}

func validPartialResult(result DeliveryResult, batchItems int) bool {
	return batchItems > 1 && result.DeliveredItems > 0 && result.RejectedItems > 0 &&
		result.DeliveredItems <= batchItems && result.RejectedItems <= batchItems-result.DeliveredItems &&
		result.DeliveredItems+result.RejectedItems == batchItems
}

func (dispatcher *Dispatcher) rejectMalformedResult(payloads []Payload) {
	dispatcher.counters.failed.Add(1)
	dispatcher.counters.rejected.Add(uint64(len(payloads)))
	now := dispatcher.nowUTC()
	dispatcher.recordFailure(now)
	reason := HealthReasonDeliveryFailed
	if dispatcher.recordCircuitFailure(FailureClassPermanentPayload, now) {
		reason = HealthReasonCircuitOpen
	}
	dispatcher.setOperationalHealth(HealthFailing, reason)
	dispatcher.release(payloads)
}

func (dispatcher *Dispatcher) encodedSize(sizes []int) (size int, ok bool) {
	defer func() {
		if recover() != nil {
			size, ok = 0, false
		}
	}()
	return dispatcher.adapter.EncodedSize(sizes)
}

func (dispatcher *Dispatcher) callAdapter(ctx context.Context, batch Batch) (result DeliveryResult) {
	result = DeliveryResult{Outcome: OutcomePermanentPayload}
	defer func() { _ = recover() }()
	return dispatcher.adapter.Deliver(ctx, batch)
}

func (dispatcher *Dispatcher) waitBackoff(attempt int) bool {
	delay := boundedBackoff(dispatcher.config.Retry, attempt)
	if delay <= 0 {
		return dispatcher.rootContext.Err() == nil
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-dispatcher.rootContext.Done():
		return false
	case <-timer.C:
		return true
	}
}

func boundedBackoff(policy RetryPolicy, attempt int) time.Duration {
	delay := policy.InitialBackoff
	for current := 1; current < attempt; current++ {
		if delay > policy.MaxBackoff/2 {
			delay = policy.MaxBackoff
			break
		}
		delay *= 2
	}
	if delay > policy.MaxBackoff {
		delay = policy.MaxBackoff
	}
	if policy.Jitter != nil {
		delay = safeJitter(policy.Jitter, delay, attempt)
	} else if delay > 0 {
		// Full jitter avoids synchronized retry waves and is still bounded.
		delay = time.Duration(rand.Float64() * float64(delay))
	}
	if delay < 0 {
		return 0
	}
	if delay > policy.MaxBackoff {
		return policy.MaxBackoff
	}
	return delay
}

func safeJitter(function func(time.Duration, int) time.Duration, delay time.Duration, attempt int) (result time.Duration) {
	result = delay
	defer func() { _ = recover() }()
	return function(delay, attempt)
}

// release marks payloads complete and may wake Flush. Callers must publish the
// terminal counters and health state before calling it.
func (dispatcher *Dispatcher) release(payloads []Payload) {
	dispatcher.queueMu.Lock()
	for _, payload := range payloads {
		dispatcher.chargedItems--
		dispatcher.chargedBytes -= payload.Size()
	}
	dispatcher.inFlightItems = 0
	dispatcher.inFlightBytes = 0
	dispatcher.queueMu.Unlock()
	dispatcher.completed.Add(uint64(len(payloads)))
	dispatcher.signalFlush()
}

func (dispatcher *Dispatcher) abandonPending() {
	dispatcher.queueMu.Lock()
	dropped := len(dispatcher.pending)
	for _, payload := range dispatcher.pending {
		dispatcher.chargedItems--
		dispatcher.chargedBytes -= payload.Size()
	}
	dispatcher.pending = nil
	dispatcher.queueMu.Unlock()
	if dropped > 0 {
		dispatcher.counters.dropped.Add(uint64(dropped))
		dispatcher.completed.Add(uint64(dropped))
		dispatcher.signalFlush()
	}
}

func (dispatcher *Dispatcher) signalWorker() {
	select {
	case dispatcher.wake <- struct{}{}:
	default:
	}
}

func (dispatcher *Dispatcher) signalFlush() {
	select {
	case dispatcher.flushNotify <- struct{}{}:
	default:
	}
}

func (dispatcher *Dispatcher) intakeIsStopped() bool {
	dispatcher.lifecycleMu.Lock()
	defer dispatcher.lifecycleMu.Unlock()
	return dispatcher.intakeStopped || dispatcher.closeStarted
}

func (dispatcher *Dispatcher) finishWorker() {
	dispatcher.workerDoneOnce.Do(func() { close(dispatcher.workerDone) })
}

func (dispatcher *Dispatcher) finishObserver() {
	dispatcher.observerDoneOnce.Do(func() { close(dispatcher.observerDone) })
}
