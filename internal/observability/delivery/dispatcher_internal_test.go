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
	"fmt"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type circuitTestAdapter struct {
	mu            sync.Mutex
	outcomes      []DeliveryOutcome
	calls         int
	started       chan int
	firstRelease  <-chan struct{}
	encodedCalls  atomic.Uint64
	encodedPrefix int
}

type circuitProbeCancelAdapter struct {
	calls        atomic.Uint64
	probeStarted chan struct{}
}

func (*circuitProbeCancelAdapter) EncodedSize(sizes []int) (int, bool) {
	return DelimitedEncodedSize(sizes, 0, 0, 0)
}

func (adapter *circuitProbeCancelAdapter) Deliver(ctx context.Context, _ Batch) DeliveryResult {
	if adapter.calls.Add(1) == 1 {
		return DeliveryResult{Outcome: OutcomeAuthentication}
	}
	select {
	case adapter.probeStarted <- struct{}{}:
	default:
	}
	<-ctx.Done()
	return DeliveryResult{Outcome: OutcomeTransient}
}

type circuitPartialAdapter struct{}

func (*circuitPartialAdapter) EncodedSize(sizes []int) (int, bool) {
	return DelimitedEncodedSize(sizes, 0, 0, 0)
}

func (*circuitPartialAdapter) Deliver(context.Context, Batch) DeliveryResult {
	return DeliveryResult{Outcome: OutcomePartial, DeliveredItems: 1, RejectedItems: 1}
}

func (adapter *circuitTestAdapter) EncodedSize(sizes []int) (int, bool) {
	adapter.encodedCalls.Add(1)
	return DelimitedEncodedSize(sizes, adapter.encodedPrefix, 0, 0)
}

func (adapter *circuitTestAdapter) Deliver(ctx context.Context, _ Batch) DeliveryResult {
	adapter.mu.Lock()
	index := adapter.calls
	adapter.calls++
	outcome := OutcomeDelivered
	if index < len(adapter.outcomes) {
		outcome = adapter.outcomes[index]
	}
	adapter.mu.Unlock()
	if adapter.started != nil {
		adapter.started <- index
	}
	if index == 0 && adapter.firstRelease != nil {
		select {
		case <-adapter.firstRelease:
		case <-ctx.Done():
			return DeliveryResult{Outcome: OutcomeTransient}
		}
	}
	return DeliveryResult{Outcome: outcome}
}

func (adapter *circuitTestAdapter) callCount() int {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	return adapter.calls
}

func circuitTestConfig(generation uint64) Config {
	return Config{
		Destination: "circuit-test", Generation: generation, Signal: "logs", Enabled: true,
		MaxQueueItems: 64, MaxQueueBytes: 4 * 1024,
		MaxBatchItems: 1, MaxBatchBytes: 4 * 1024,
		AttemptTimeout: time.Second,
		Retry:          RetryPolicy{MaxAttempts: 1},
		Circuit: CircuitPolicy{
			TransientFailureThreshold: 3,
			OpenDuration:              time.Minute,
		},
	}
}

func circuitTestPayload(t *testing.T, id string) Payload {
	t.Helper()
	payload, err := NewPayload([]byte(`{"projected":true}`), RoutingIdentity{
		RecordID: id, Bucket: "model.io", Signal: "logs", EventName: "model.response",
	})
	if err != nil {
		t.Fatal(err)
	}
	return payload
}

func waitForCircuitSnapshot(t *testing.T, dispatcher *Dispatcher, predicate func(HealthSnapshot) bool) HealthSnapshot {
	t.Helper()
	deadline := time.Now().Add(time.Second)
	for {
		snapshot := dispatcher.DeliveryHealthSnapshot()
		if predicate(snapshot) {
			return snapshot
		}
		if time.Now().After(deadline) {
			t.Fatalf("circuit condition not reached; snapshot=%+v", snapshot)
		}
		time.Sleep(time.Millisecond)
	}
}

func closeCircuitTestDispatcher(t *testing.T, dispatcher *Dispatcher) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := dispatcher.Drain(ctx); err != nil {
		t.Fatalf("drain circuit dispatcher: %v", err)
	}
	if err := dispatcher.Close(ctx); err != nil {
		t.Fatalf("close circuit dispatcher: %v", err)
	}
}

func TestHealthVocabularyHasExactlySevenStates(t *testing.T) {
	states := []HealthState{
		HealthDisabled, HealthInitializing, HealthHealthy, HealthDegraded,
		HealthFailing, HealthDraining, HealthStopped,
	}
	if got, want := fmt.Sprint(states), "[disabled initializing healthy degraded failing draining stopped]"; got != want {
		t.Fatalf("states=%s want=%s", got, want)
	}
}

func TestBoundedBackoffExponentAndJitterClamp(t *testing.T) {
	policy := RetryPolicy{
		InitialBackoff: 10 * time.Millisecond,
		MaxBackoff:     25 * time.Millisecond,
		Jitter:         func(delay time.Duration, _ int) time.Duration { return delay },
	}
	for _, test := range []struct {
		attempt int
		want    time.Duration
	}{{1, 10 * time.Millisecond}, {2, 20 * time.Millisecond}, {3, 25 * time.Millisecond}, {31, 25 * time.Millisecond}} {
		if got := boundedBackoff(policy, test.attempt); got != test.want {
			t.Fatalf("attempt %d delay=%s want=%s", test.attempt, got, test.want)
		}
	}
	policy.Jitter = func(time.Duration, int) time.Duration { return time.Hour }
	if got := boundedBackoff(policy, 1); got != policy.MaxBackoff {
		t.Fatalf("large jitter=%s", got)
	}
	policy.Jitter = func(time.Duration, int) time.Duration { return -time.Second }
	if got := boundedBackoff(policy, 1); got != 0 {
		t.Fatalf("negative jitter=%s", got)
	}
	policy.Jitter = func(time.Duration, int) time.Duration { panic("jitter panic") }
	if got := boundedBackoff(policy, 1); got != policy.InitialBackoff {
		t.Fatalf("panic fallback=%s", got)
	}
}

func TestCircuitPolicyDefaultsAreBounded(t *testing.T) {
	policy, ok := normalizedCircuitPolicy(CircuitPolicy{})
	if !ok || policy.TransientFailureThreshold != 3 ||
		policy.OpenDuration != 30*time.Second ||
		immediateCircuitOpenDuration != 24*time.Hour {
		t.Fatalf("default policy=%+v immediate-open=%s ok=%v",
			policy, immediateCircuitOpenDuration, ok)
	}
}

func TestCircuitFailureClassesOpenAtBoundedThresholds(t *testing.T) {
	at := time.Date(2026, time.July, 30, 12, 0, 0, 0, time.UTC)
	tests := []struct {
		name         string
		class        FailureClass
		failures     int
		wantOpen     bool
		wantFailures uint64
		wantDuration time.Duration
	}{
		{name: "transient-before-threshold", class: FailureClassTransient, failures: 2, wantFailures: 2},
		{name: "transient-at-threshold", class: FailureClassTransient, failures: 3, wantOpen: true, wantFailures: 3, wantDuration: time.Minute},
		{name: "authentication", class: FailureClassAuthentication, failures: 1, wantOpen: true, wantFailures: 1, wantDuration: 24 * time.Hour},
		{name: "permanent-payload-before-threshold", class: FailureClassPermanentPayload, failures: 2, wantFailures: 2},
		{name: "permanent-payload-at-threshold", class: FailureClassPermanentPayload, failures: 3, wantOpen: true, wantFailures: 3, wantDuration: time.Minute},
		{name: "unsafe-endpoint", class: FailureClassUnsafeEndpoint, failures: 1, wantOpen: true, wantFailures: 1, wantDuration: 24 * time.Hour},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			dispatcher, err := NewDispatcher(circuitTestConfig(1), &circuitTestAdapter{})
			if err != nil {
				t.Fatal(err)
			}
			opened := false
			for index := 0; index < test.failures; index++ {
				opened = dispatcher.recordCircuitFailure(test.class, at)
			}
			snapshot := dispatcher.DeliveryHealthSnapshot()
			if opened != test.wantOpen ||
				snapshot.ConsecutiveFailures != test.wantFailures ||
				snapshot.LastFailureClass != test.class {
				t.Fatalf("opened=%v snapshot=%+v", opened, snapshot)
			}
			if test.wantOpen {
				if snapshot.CircuitState != CircuitOpen ||
					!snapshot.CircuitOpenUntil.Equal(at.Add(test.wantDuration)) {
					t.Fatalf("open snapshot=%+v", snapshot)
				}
			} else if snapshot.CircuitState != CircuitClosed || !snapshot.CircuitOpenUntil.IsZero() {
				t.Fatalf("closed snapshot=%+v", snapshot)
			}
		})
	}
}

func TestSinglePermanentPayloadFailureDoesNotSuppressNextValidRecord(t *testing.T) {
	adapter := &circuitTestAdapter{outcomes: []DeliveryOutcome{
		OutcomePermanentPayload,
		OutcomeDelivered,
	}}
	dispatcher, err := NewDispatcher(circuitTestConfig(40), adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	if result := dispatcher.Enqueue(circuitTestPayload(t, "bad-shape")); !result.Accepted() {
		t.Fatalf("first enqueue=%+v", result)
	}
	waitForCircuitSnapshot(t, dispatcher, func(snapshot HealthSnapshot) bool {
		return snapshot.CircuitState == CircuitClosed &&
			snapshot.ConsecutiveFailures == 1 &&
			snapshot.Counters.Rejected == 1
	})
	if result := dispatcher.Enqueue(circuitTestPayload(t, "valid-shape")); !result.Accepted() {
		t.Fatalf("second enqueue=%+v", result)
	}
	snapshot := waitForCircuitSnapshot(t, dispatcher, func(snapshot HealthSnapshot) bool {
		return snapshot.CircuitState == CircuitClosed &&
			snapshot.ConsecutiveFailures == 0 &&
			snapshot.Counters.Delivered == 1
	})
	if adapter.callCount() != 2 || snapshot.LastFailureClass != FailureClassPermanentPayload {
		t.Fatalf("adapter calls=%d snapshot=%+v", adapter.callCount(), snapshot)
	}
	closeCircuitTestDispatcher(t, dispatcher)
}

func TestCircuitCooldownHalfOpenRecoveryAndGenerationReset(t *testing.T) {
	start := time.Date(2026, time.July, 30, 13, 0, 0, 0, time.UTC)
	config := circuitTestConfig(41)
	first, err := NewDispatcher(config, &circuitTestAdapter{})
	if err != nil {
		t.Fatal(err)
	}
	if !first.recordCircuitFailure(FailureClassAuthentication, start) {
		t.Fatal("authentication failure did not open circuit")
	}
	successorConfig := config
	successorConfig.Generation = 42
	recreated, err := NewDispatcher(successorConfig, &circuitTestAdapter{})
	if err != nil {
		t.Fatal(err)
	}
	recreatedSnapshot := recreated.DeliveryHealthSnapshot()
	if recreatedSnapshot.Generation != 42 || recreatedSnapshot.CircuitState != CircuitClosed ||
		recreatedSnapshot.ConsecutiveFailures != 0 || !recreatedSnapshot.CircuitOpenUntil.IsZero() ||
		recreatedSnapshot.LastFailureClass != "" {
		t.Fatalf("recreated snapshot retained prior generation: %+v", recreatedSnapshot)
	}
	immediateOpenUntil := start.Add(immediateCircuitOpenDuration)
	if admitted, halfOpen := first.admitCircuit(immediateOpenUntil.Add(-time.Nanosecond)); admitted || halfOpen {
		t.Fatalf("admission before cooldown=(%v,%v)", admitted, halfOpen)
	}
	if admitted, halfOpen := first.admitCircuit(immediateOpenUntil); !admitted || !halfOpen {
		t.Fatalf("admission at cooldown=(%v,%v)", admitted, halfOpen)
	}
	if admitted, halfOpen := first.admitCircuit(immediateOpenUntil); admitted || halfOpen {
		t.Fatalf("second half-open admission=(%v,%v)", admitted, halfOpen)
	}
	reopenedAt := immediateOpenUntil
	if !first.recordCircuitFailure(FailureClassTransient, reopenedAt) {
		t.Fatal("failed half-open probe did not immediately reopen circuit")
	}
	snapshot := first.DeliveryHealthSnapshot()
	if snapshot.CircuitState != CircuitOpen || snapshot.ConsecutiveFailures != 2 ||
		snapshot.LastFailureClass != FailureClassTransient ||
		!snapshot.CircuitOpenUntil.Equal(reopenedAt.Add(config.Circuit.OpenDuration)) {
		t.Fatalf("reopened snapshot=%+v", snapshot)
	}
	mode, transitioned := first.circuitMode(snapshot.CircuitOpenUntil)
	if mode != circuitDeliveryProbe || !transitioned {
		t.Fatalf("post-cooldown mode=%v transitioned=%v", mode, transitioned)
	}
	first.recordCircuitSuccess()
	snapshot = first.DeliveryHealthSnapshot()
	if snapshot.CircuitState != CircuitClosed || snapshot.ConsecutiveFailures != 0 ||
		!snapshot.CircuitOpenUntil.IsZero() ||
		snapshot.LastFailureClass != FailureClassTransient {
		t.Fatalf("recovered snapshot=%+v", snapshot)
	}
}

func TestTransientCircuitPersistsAcrossBatchesAndFailsFastWhileOpen(t *testing.T) {
	adapter := &circuitTestAdapter{outcomes: []DeliveryOutcome{
		OutcomeTransient, OutcomeTransient, OutcomeTransient, OutcomeDelivered,
	}}
	circuitTransition := make(chan HealthTransition, 1)
	config := circuitTestConfig(1)
	config.Observer = ObserverFunc(func(transition HealthTransition) {
		if transition.Reason == HealthReasonCircuitOpen {
			select {
			case circuitTransition <- transition:
			default:
			}
		}
	})
	dispatcher, err := NewDispatcher(config, adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	for index := 1; index <= 3; index++ {
		result := dispatcher.Enqueue(circuitTestPayload(t, fmt.Sprintf("failure-%d", index)))
		if !result.Accepted() {
			t.Fatalf("failure %d enqueue=%+v", index, result)
		}
		snapshot := waitForCircuitSnapshot(t, dispatcher, func(snapshot HealthSnapshot) bool {
			return snapshot.ConsecutiveFailures == uint64(index)
		})
		if index < 3 {
			if snapshot.CircuitState != CircuitClosed || snapshot.State != HealthFailing ||
				snapshot.Reason != string(HealthReasonDeliveryFailed) {
				t.Fatalf("failure %d snapshot=%+v", index, snapshot)
			}
		} else if snapshot.CircuitState != CircuitOpen || snapshot.State != HealthFailing ||
			snapshot.Reason != string(HealthReasonCircuitOpen) {
			t.Fatalf("threshold snapshot=%+v", snapshot)
		}
	}
	select {
	case transition := <-circuitTransition:
		if transition.Previous != HealthFailing || transition.Current != HealthFailing {
			t.Fatalf("circuit transition=%+v", transition)
		}
	case <-time.After(time.Second):
		t.Fatal("same-state circuit-open health transition was not observed")
	}
	for index := 0; index < 20; index++ {
		result := dispatcher.Enqueue(circuitTestPayload(t, fmt.Sprintf("blocked-%d", index)))
		if result.Disposition != EnqueueRejected || result.Reason != ReasonCircuitOpen {
			t.Fatalf("blocked enqueue %d=%+v", index, result)
		}
	}
	if got := adapter.callCount(); got != 3 {
		t.Fatalf("open circuit touched adapter %d times", got)
	}
	counters := dispatcher.Counters()
	if counters.Accepted != 3 || counters.Rejected != 23 || counters.Failed != 3 ||
		counters.Retried != 0 || counters.Delivered != 0 {
		t.Fatalf("counters=%+v", counters)
	}
	closeCircuitTestDispatcher(t, dispatcher)
}

func TestOpenCircuitRejectsAcceptedBacklogWithoutAdapterWork(t *testing.T) {
	release := make(chan struct{})
	adapter := &circuitTestAdapter{
		outcomes:     []DeliveryOutcome{OutcomeAuthentication},
		started:      make(chan int, 1),
		firstRelease: release,
	}
	dispatcher, err := NewDispatcher(circuitTestConfig(1), adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	if result := dispatcher.Enqueue(circuitTestPayload(t, "in-flight")); !result.Accepted() {
		t.Fatalf("first enqueue=%+v", result)
	}
	select {
	case index := <-adapter.started:
		if index != 0 {
			t.Fatalf("first adapter index=%d", index)
		}
	case <-time.After(time.Second):
		t.Fatal("first adapter call did not start")
	}
	for _, id := range []string{"queued-one", "queued-two"} {
		if result := dispatcher.Enqueue(circuitTestPayload(t, id)); !result.Accepted() {
			t.Fatalf("%s enqueue=%+v", id, result)
		}
	}
	close(release)
	snapshot := waitForCircuitSnapshot(t, dispatcher, func(snapshot HealthSnapshot) bool {
		return snapshot.CircuitState == CircuitOpen &&
			snapshot.Counters.Rejected == 3 &&
			snapshot.Queue != nil && snapshot.Queue.Items == 0
	})
	if adapter.callCount() != 1 || adapter.encodedCalls.Load() != 1 ||
		snapshot.Counters.Accepted != 3 || snapshot.Counters.Failed != 1 {
		t.Fatalf("adapter calls=%d encoded=%d snapshot=%+v",
			adapter.callCount(), adapter.encodedCalls.Load(), snapshot)
	}
	closeCircuitTestDispatcher(t, dispatcher)
}

func TestCircuitRejectedBatchResetsInFlightByteSnapshot(t *testing.T) {
	config := circuitTestConfig(2)
	config.MaxBatchItems = 2
	dispatcher, err := NewDispatcher(config, &circuitTestAdapter{})
	if err != nil {
		t.Fatal(err)
	}
	defer dispatcher.cancelRoot()
	first := circuitTestPayload(t, "first-rejected")
	second := circuitTestPayload(t, "second-rejected")
	dispatcher.pending = []Payload{first, second}
	dispatcher.inFlightBytes = 1_000_000
	payloads := dispatcher.takeCircuitRejectedBatch()
	if len(payloads) != 2 || dispatcher.inFlightItems != 2 ||
		dispatcher.inFlightBytes != first.Size()+second.Size() {
		t.Fatalf("payloads=%d in-flight=(%d,%d) want=(2,%d)",
			len(payloads), dispatcher.inFlightItems, dispatcher.inFlightBytes,
			first.Size()+second.Size())
	}
}

func TestPartialDeliveryResetsTerminalFailureStreak(t *testing.T) {
	config := circuitTestConfig(3)
	config.Circuit.TransientFailureThreshold = 2
	dispatcher, err := NewDispatcher(config, &circuitPartialAdapter{})
	if err != nil {
		t.Fatal(err)
	}
	defer dispatcher.cancelRoot()
	at := time.Date(2026, time.July, 30, 13, 15, 0, 0, time.UTC)
	if dispatcher.recordCircuitFailure(FailureClassTransient, at) {
		t.Fatal("first terminal failure unexpectedly opened circuit")
	}
	first := circuitTestPayload(t, "partial-one")
	second := circuitTestPayload(t, "partial-two")
	dispatcher.chargedItems = 2
	dispatcher.chargedBytes = first.Size() + second.Size()
	dispatcher.inFlightItems = 2
	dispatcher.inFlightBytes = dispatcher.chargedBytes
	if !dispatcher.deliver([]Payload{first, second}, dispatcher.chargedBytes, false) {
		t.Fatal("partial delivery stopped dispatcher")
	}
	snapshot := dispatcher.DeliveryHealthSnapshot()
	if snapshot.CircuitState != CircuitClosed ||
		snapshot.ConsecutiveFailures != 0 ||
		snapshot.LastFailureClass != FailureClassTransient ||
		snapshot.State != HealthDegraded ||
		snapshot.Reason != string(HealthReasonPartial) {
		t.Fatalf("partial delivery circuit=%+v", snapshot)
	}
	if snapshot.Counters.Delivered != 1 || snapshot.Counters.Rejected != 1 ||
		snapshot.Counters.Failed != 1 {
		t.Fatalf("partial delivery counters=%+v", snapshot.Counters)
	}
}

func TestCanceledHalfOpenProbeReturnsCircuitToOpen(t *testing.T) {
	start := time.Date(2026, time.July, 30, 13, 45, 0, 0, time.UTC)
	var clock atomic.Int64
	clock.Store(start.UnixNano())
	adapter := &circuitProbeCancelAdapter{probeStarted: make(chan struct{}, 1)}
	config := circuitTestConfig(4)
	dispatcher, err := NewDispatcher(config, adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.now = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
	dispatcher.Activate()
	if result := dispatcher.Enqueue(circuitTestPayload(t, "authentication")); !result.Accepted() {
		t.Fatalf("authentication enqueue=%+v", result)
	}
	opened := waitForCircuitSnapshot(t, dispatcher, func(snapshot HealthSnapshot) bool {
		return snapshot.CircuitState == CircuitOpen
	})
	clock.Store(opened.CircuitOpenUntil.UnixNano())
	if result := dispatcher.Enqueue(circuitTestPayload(t, "canceled-probe")); !result.Accepted() {
		t.Fatalf("probe enqueue=%+v", result)
	}
	select {
	case <-adapter.probeStarted:
	case <-time.After(time.Second):
		t.Fatal("half-open probe did not start")
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := dispatcher.Close(ctx); err != nil {
		t.Fatal(err)
	}
	snapshot := dispatcher.DeliveryHealthSnapshot()
	if snapshot.CircuitState != CircuitOpen ||
		!snapshot.CircuitOpenUntil.Equal(opened.CircuitOpenUntil) ||
		snapshot.State != HealthStopped {
		t.Fatalf("canceled probe circuit=%+v", snapshot)
	}
}

func TestHealthObserverCanReenterDispatcherWithoutLockInversion(t *testing.T) {
	type observation struct {
		snapshot HealthSnapshot
		enqueue  EnqueueResult
	}
	observed := make(chan observation, 1)
	reentryPayload := circuitTestPayload(t, "observer-reentry")
	var dispatcher *Dispatcher
	config := circuitTestConfig(5)
	config.Observer = ObserverFunc(func(transition HealthTransition) {
		if transition.Reason != HealthReasonActivated {
			return
		}
		observed <- observation{
			snapshot: dispatcher.DeliveryHealthSnapshot(),
			enqueue:  dispatcher.Enqueue(reentryPayload),
		}
	})
	var err error
	dispatcher, err = NewDispatcher(config, &circuitTestAdapter{})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	select {
	case result := <-observed:
		if result.snapshot.State != HealthHealthy || !result.enqueue.Accepted() {
			t.Fatalf("reentrant observation=%+v enqueue=%+v", result.snapshot, result.enqueue)
		}
	case <-time.After(time.Second):
		t.Fatal("reentrant health observer blocked")
	}
	waitForCircuitSnapshot(t, dispatcher, func(snapshot HealthSnapshot) bool {
		return snapshot.Counters.Delivered == 1
	})
	closeCircuitTestDispatcher(t, dispatcher)
}

func TestRepeatedPermanentBatchShapeFailuresOpenAtBoundedThreshold(t *testing.T) {
	start := time.Date(2026, time.July, 30, 13, 30, 0, 0, time.UTC)
	var clock atomic.Int64
	clock.Store(start.UnixNano())
	config := circuitTestConfig(3)
	adapter := &circuitTestAdapter{encodedPrefix: config.MaxBatchBytes}
	dispatcher, err := NewDispatcher(config, adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.now = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
	dispatcher.Activate()
	for _, id := range []string{"oversized-one", "oversized-two", "oversized-three"} {
		if result := dispatcher.Enqueue(circuitTestPayload(t, id)); !result.Accepted() {
			t.Fatalf("%s enqueue=%+v", id, result)
		}
	}
	snapshot := waitForCircuitSnapshot(t, dispatcher, func(snapshot HealthSnapshot) bool {
		return snapshot.CircuitState == CircuitOpen
	})
	if snapshot.LastFailureClass != FailureClassPermanentPayload ||
		snapshot.ConsecutiveFailures != 3 ||
		!snapshot.CircuitOpenUntil.Equal(start.Add(config.Circuit.OpenDuration)) ||
		adapter.callCount() != 0 || adapter.encodedCalls.Load() != 3 {
		t.Fatalf("adapter calls=%d encoded=%d snapshot=%+v",
			adapter.callCount(), adapter.encodedCalls.Load(), snapshot)
	}
	closeCircuitTestDispatcher(t, dispatcher)
}

func TestHalfOpenProbeUsesOneAttemptThenRecoversAfterNextCooldown(t *testing.T) {
	start := time.Date(2026, time.July, 30, 14, 0, 0, 0, time.UTC)
	var clock atomic.Int64
	clock.Store(start.UnixNano())
	adapter := &circuitTestAdapter{outcomes: []DeliveryOutcome{
		OutcomeAuthentication, OutcomeTransient, OutcomeDelivered,
	}}
	config := circuitTestConfig(7)
	config.Retry = RetryPolicy{MaxAttempts: 3}
	dispatcher, err := NewDispatcher(config, adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.now = func() time.Time { return time.Unix(0, clock.Load()).UTC() }
	dispatcher.Activate()
	if result := dispatcher.Enqueue(circuitTestPayload(t, "authentication")); !result.Accepted() {
		t.Fatalf("authentication enqueue=%+v", result)
	}
	firstOpen := waitForCircuitSnapshot(t, dispatcher, func(snapshot HealthSnapshot) bool {
		return snapshot.CircuitState == CircuitOpen
	})
	if firstOpen.LastFailureClass != FailureClassAuthentication ||
		!firstOpen.CircuitOpenUntil.Equal(start.Add(immediateCircuitOpenDuration)) {
		t.Fatalf("first open=%+v", firstOpen)
	}

	clock.Store(firstOpen.CircuitOpenUntil.UnixNano())
	if result := dispatcher.Enqueue(circuitTestPayload(t, "failed-probe")); !result.Accepted() {
		t.Fatalf("half-open enqueue=%+v", result)
	}
	secondOpen := waitForCircuitSnapshot(t, dispatcher, func(snapshot HealthSnapshot) bool {
		return snapshot.CircuitState == CircuitOpen &&
			snapshot.LastFailureClass == FailureClassTransient
	})
	if adapter.callCount() != 2 || secondOpen.ConsecutiveFailures != 2 ||
		!secondOpen.CircuitOpenUntil.Equal(firstOpen.CircuitOpenUntil.Add(config.Circuit.OpenDuration)) {
		t.Fatalf("failed probe calls=%d snapshot=%+v", adapter.callCount(), secondOpen)
	}
	if counters := dispatcher.Counters(); counters.Retried != 0 || counters.Failed != 2 {
		t.Fatalf("half-open probe retried: %+v", counters)
	}

	clock.Store(secondOpen.CircuitOpenUntil.UnixNano())
	if result := dispatcher.Enqueue(circuitTestPayload(t, "successful-probe")); !result.Accepted() {
		t.Fatalf("recovery probe enqueue=%+v", result)
	}
	recovered := waitForCircuitSnapshot(t, dispatcher, func(snapshot HealthSnapshot) bool {
		return snapshot.CircuitState == CircuitClosed && snapshot.Counters.Delivered == 1
	})
	if adapter.callCount() != 3 || recovered.ConsecutiveFailures != 0 ||
		!recovered.CircuitOpenUntil.IsZero() ||
		recovered.LastFailureClass != FailureClassTransient {
		t.Fatalf("recovered calls=%d snapshot=%+v", adapter.callCount(), recovered)
	}
	closeCircuitTestDispatcher(t, dispatcher)
}
