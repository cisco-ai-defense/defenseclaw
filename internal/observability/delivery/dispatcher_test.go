// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package delivery_test

import (
	"bytes"
	"context"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
)

var _ runtimegraph.Component = (*delivery.Dispatcher)(nil)

type attempt struct {
	ids         []string
	payloads    [][]byte
	encodedSize int
}

type fakeAdapter struct {
	mu                        sync.Mutex
	outcomes                  []delivery.DeliveryOutcome
	attempts                  []attempt
	started                   chan struct{}
	release                   <-chan struct{}
	ignoreContext             bool
	prefix, separator, suffix int
	deliverCalls              atomic.Uint64
}

type panicAdapter struct {
	panicSize    bool
	panicDeliver bool
}

func (adapter panicAdapter) EncodedSize(sizes []int) (int, bool) {
	if adapter.panicSize {
		panic("estimator panic")
	}
	return delivery.DelimitedEncodedSize(sizes, 0, 0, 0)
}

func (adapter panicAdapter) Deliver(context.Context, delivery.Batch) delivery.DeliveryResult {
	if adapter.panicDeliver {
		panic("delivery panic")
	}
	return delivery.DeliveryResult{Outcome: delivery.OutcomeDelivered}
}

type undercountingAdapter struct{ calls atomic.Uint64 }

func (*undercountingAdapter) EncodedSize([]int) (int, bool) { return 0, true }
func (adapter *undercountingAdapter) Deliver(context.Context, delivery.Batch) delivery.DeliveryResult {
	adapter.calls.Add(1)
	return delivery.DeliveryResult{Outcome: delivery.OutcomeDelivered}
}

type fixedResultAdapter struct{ result delivery.DeliveryResult }

func (*fixedResultAdapter) EncodedSize(sizes []int) (int, bool) {
	return delivery.DelimitedEncodedSize(sizes, 0, 0, 0)
}

func (adapter *fixedResultAdapter) Deliver(context.Context, delivery.Batch) delivery.DeliveryResult {
	return adapter.result
}

type blockingSizerAdapter struct {
	entered chan struct{}
	release <-chan struct{}
}

type cancelAwareAdapter struct {
	started  chan struct{}
	canceled chan struct{}
	release  <-chan struct{}
}

func (*cancelAwareAdapter) EncodedSize(sizes []int) (int, bool) {
	return delivery.DelimitedEncodedSize(sizes, 0, 0, 0)
}

func (adapter *cancelAwareAdapter) Deliver(ctx context.Context, _ delivery.Batch) delivery.DeliveryResult {
	select {
	case adapter.started <- struct{}{}:
	default:
	}
	<-ctx.Done()
	select {
	case adapter.canceled <- struct{}{}:
	default:
	}
	<-adapter.release
	return delivery.DeliveryResult{Outcome: delivery.OutcomeTransient}
}

func (adapter *blockingSizerAdapter) EncodedSize(sizes []int) (int, bool) {
	select {
	case adapter.entered <- struct{}{}:
	default:
	}
	<-adapter.release
	return delivery.DelimitedEncodedSize(sizes, 0, 0, 0)
}

func (*blockingSizerAdapter) Deliver(context.Context, delivery.Batch) delivery.DeliveryResult {
	return delivery.DeliveryResult{Outcome: delivery.OutcomeDelivered}
}

func (adapter *fakeAdapter) EncodedSize(sizes []int) (int, bool) {
	return delivery.DelimitedEncodedSize(sizes, adapter.prefix, adapter.separator, adapter.suffix)
}

func (adapter *fakeAdapter) Deliver(ctx context.Context, batch delivery.Batch) delivery.DeliveryResult {
	adapter.deliverCalls.Add(1)
	items := batch.Items()
	captured := attempt{encodedSize: batch.EncodedSize()}
	for _, item := range items {
		captured.ids = append(captured.ids, item.RecordID())
		captured.payloads = append(captured.payloads, item.Bytes())
	}
	adapter.mu.Lock()
	index := len(adapter.attempts)
	adapter.attempts = append(adapter.attempts, captured)
	adapter.mu.Unlock()
	if adapter.started != nil {
		select {
		case adapter.started <- struct{}{}:
		default:
		}
	}
	if adapter.release != nil {
		if adapter.ignoreContext {
			<-adapter.release
		} else {
			select {
			case <-adapter.release:
			case <-ctx.Done():
				return delivery.DeliveryResult{Outcome: delivery.OutcomeTransient}
			}
		}
	}
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	if index < len(adapter.outcomes) {
		return delivery.DeliveryResult{Outcome: adapter.outcomes[index]}
	}
	return delivery.DeliveryResult{Outcome: delivery.OutcomeDelivered}
}

func (adapter *fakeAdapter) snapshot() []attempt {
	adapter.mu.Lock()
	defer adapter.mu.Unlock()
	result := make([]attempt, len(adapter.attempts))
	copy(result, adapter.attempts)
	return result
}

func testConfig(name string) delivery.Config {
	return delivery.Config{
		Destination: name, Enabled: true,
		MaxQueueItems: 16, MaxQueueBytes: 1024,
		MaxBatchItems: 4, MaxBatchBytes: 1024,
		ScheduledDelay: 0, AttemptTimeout: time.Second,
		Retry: delivery.RetryPolicy{
			MaxAttempts: 3, InitialBackoff: time.Millisecond,
			MaxBackoff: time.Millisecond,
			Jitter:     func(delay time.Duration, _ int) time.Duration { return delay },
		},
	}
}

func payload(t *testing.T, id, body string) delivery.Payload {
	t.Helper()
	result, err := delivery.NewPayload([]byte(body), delivery.RoutingIdentity{
		RecordID: id, Bucket: "model.io", Signal: "logs", EventName: "model.response",
	})
	if err != nil {
		t.Fatal(err)
	}
	return result
}

func closeDispatcher(t *testing.T, dispatcher *delivery.Dispatcher) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := dispatcher.Drain(ctx); err != nil {
		t.Fatalf("drain: %v", err)
	}
	if err := dispatcher.Close(ctx); err != nil {
		t.Fatalf("close: %v", err)
	}
}

func waitFor(t *testing.T, condition func() bool) {
	t.Helper()
	deadline := time.Now().Add(2 * time.Second)
	for !condition() {
		if time.Now().After(deadline) {
			t.Fatal("condition did not become true")
		}
		time.Sleep(time.Millisecond)
	}
}

func TestPayloadIsImmutableBoundedAndUninterpreted(t *testing.T) {
	original := []byte(`{"prompt":"alice@example.test","secret":"raw"}`)
	projection, err := delivery.NewPayload(original, delivery.RoutingIdentity{
		RecordID: "record-1", Bucket: "model.io", Signal: "logs", EventName: "model.response",
	})
	if err != nil {
		t.Fatal(err)
	}
	original[0] = '!'
	first := projection.Bytes()
	first[1] = '!'
	if got, want := string(projection.Bytes()), `{"prompt":"alice@example.test","secret":"raw"}`; got != want {
		t.Fatalf("payload changed or was redacted: got %q want %q", got, want)
	}
	if projection.Size() != len(projection.Bytes()) {
		t.Fatalf("size=%d bytes=%d", projection.Size(), len(projection.Bytes()))
	}

	badIdentities := []delivery.RoutingIdentity{
		{RecordID: "", Bucket: "model.io", Signal: "logs", EventName: "model.response"},
		{RecordID: "record", Bucket: "UPPER", Signal: "logs", EventName: "model.response"},
		{RecordID: "record", Bucket: "model.io", Signal: "future", EventName: "model.response"},
		{RecordID: "record", Bucket: "model.io", Signal: "logs", EventName: "unknown.event"},
		{RecordID: "record\nforged", Bucket: "model.io", Signal: "logs", EventName: "model.response"},
		{RecordID: "record", Bucket: "model.io", Signal: "logs", EventName: "model.response", OriginDestination: strings.Repeat("x", observability.MaxStableTokenBytes+1)},
	}
	for _, identity := range badIdentities {
		if _, err := delivery.NewPayload([]byte(`{}`), identity); !delivery.IsError(err, delivery.ErrorInvalidIdentity) {
			t.Fatalf("identity %#v error=%v", identity, err)
		}
	}
	if _, err := delivery.NewPayload(nil, delivery.RoutingIdentity{}); !delivery.IsError(err, delivery.ErrorInvalidPayload) {
		t.Fatalf("empty payload error=%v", err)
	}
	if _, err := delivery.NewPayload(make([]byte, delivery.MaxPayloadBytes+1), delivery.RoutingIdentity{
		RecordID: "record", Bucket: "model.io", Signal: "logs", EventName: "model.response",
	}); !delivery.IsError(err, delivery.ErrorInvalidPayload) {
		t.Fatalf("oversized payload error=%v", err)
	}
}

func TestDispatcherRejectsInvalidCapacityBeforeStartingWorker(t *testing.T) {
	valid := testConfig("validation")
	mutations := []func(*delivery.Config){
		func(config *delivery.Config) { config.Destination = "INVALID" },
		func(config *delivery.Config) { config.Signal = "future" },
		func(config *delivery.Config) { config.MaxQueueItems = 0 },
		func(config *delivery.Config) { config.MaxQueueItems = 65_537 },
		func(config *delivery.Config) { config.MaxQueueBytes = 256*1024*1024 + 1 },
		func(config *delivery.Config) { config.MaxBatchItems = config.MaxQueueItems + 1 },
		func(config *delivery.Config) { config.MaxBatchBytes = 64*1024*1024 + 1 },
		func(config *delivery.Config) { config.AttemptTimeout = 0 },
		func(config *delivery.Config) { config.Retry.MaxAttempts = 0 },
		func(config *delivery.Config) {
			config.Retry.InitialBackoff = 2 * time.Second
			config.Retry.MaxBackoff = time.Second
		},
		func(config *delivery.Config) { config.ObserverInterval = -1 },
	}
	for index, mutate := range mutations {
		config := valid
		mutate(&config)
		if _, err := delivery.NewDispatcher(config, &fakeAdapter{}); !delivery.IsError(err, delivery.ErrorInvalidConfig) {
			t.Fatalf("mutation %d error=%v", index, err)
		}
	}
}

func TestQueueDropsNewestAtCountLimitWhileInflightRemainsCharged(t *testing.T) {
	release := make(chan struct{})
	adapter := &fakeAdapter{started: make(chan struct{}, 1), release: release}
	config := testConfig("count-limited")
	config.MaxQueueItems = 2
	config.MaxBatchItems = 2
	dispatcher, err := delivery.NewDispatcher(config, adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	if got := dispatcher.Enqueue(payload(t, "a", "aaa")); !got.Accepted() {
		t.Fatalf("A=%+v", got)
	}
	<-adapter.started
	if got := dispatcher.Enqueue(payload(t, "b", "bbb")); !got.Accepted() {
		t.Fatalf("B=%+v", got)
	}
	if got := dispatcher.Enqueue(payload(t, "c", "ccc")); got.Disposition != delivery.EnqueueDropped || got.Reason != delivery.ReasonCountLimit {
		t.Fatalf("C=%+v", got)
	}
	items, size, inFlight, inFlightBytes := dispatcher.QueueUsage()
	if items != 2 || size != 6 || inFlight != 1 || inFlightBytes != 3 {
		t.Fatalf("usage=(%d,%d,%d,%d)", items, size, inFlight, inFlightBytes)
	}
	failureSnapshot := dispatcher.DeliveryHealthSnapshot()
	if failureSnapshot.LastFailure.IsZero() || failureSnapshot.State != delivery.HealthDegraded ||
		failureSnapshot.Reason != string(delivery.HealthReasonQueueFull) {
		t.Fatalf("queue-full health=%+v", failureSnapshot)
	}
	close(release)
	closeDispatcher(t, dispatcher)
	if got := dispatcher.Counters(); got.Accepted != 2 || got.Delivered != 2 || got.Dropped != 1 {
		t.Fatalf("counters=%+v", got)
	}
	completed := dispatcher.DeliveryHealthSnapshot()
	if completed.LastSuccess.IsZero() || completed.LastSuccess.Before(failureSnapshot.LastFailure) {
		t.Fatalf("completed health=%+v failure=%+v", completed, failureSnapshot)
	}
	attempts := adapter.snapshot()
	if len(attempts) != 2 || attempts[0].ids[0] != "a" || attempts[1].ids[0] != "b" {
		t.Fatalf("FIFO attempts=%#v", attempts)
	}
}

func TestQueueExactByteBoundaryAndBothLimitResult(t *testing.T) {
	release := make(chan struct{})
	adapter := &fakeAdapter{started: make(chan struct{}, 1), release: release}
	config := testConfig("byte-limited")
	config.MaxQueueItems = 2
	config.MaxBatchItems = 2
	config.MaxQueueBytes = 6
	dispatcher, err := delivery.NewDispatcher(config, adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	if !dispatcher.Enqueue(payload(t, "a", "abc")).Accepted() {
		t.Fatal("A rejected")
	}
	<-adapter.started
	if !dispatcher.Enqueue(payload(t, "b", "def")).Accepted() {
		t.Fatal("exact byte boundary rejected")
	}
	if got := dispatcher.Enqueue(payload(t, "c", "z")); got.Reason != delivery.ReasonCountAndByteLimit {
		t.Fatalf("boundary+1 result=%+v", got)
	}
	close(release)
	closeDispatcher(t, dispatcher)
}

func TestStalledDestinationDoesNotBlockIndependentDispatcher(t *testing.T) {
	release := make(chan struct{})
	stalledAdapter := &fakeAdapter{started: make(chan struct{}, 1), release: release}
	stalled, err := delivery.NewDispatcher(testConfig("stalled"), stalledAdapter)
	if err != nil {
		t.Fatal(err)
	}
	fastAdapter := &fakeAdapter{}
	fast, err := delivery.NewDispatcher(testConfig("fast"), fastAdapter)
	if err != nil {
		t.Fatal(err)
	}
	stalled.Activate()
	fast.Activate()
	if !stalled.Enqueue(payload(t, "slow", "slow")).Accepted() || !fast.Enqueue(payload(t, "fast", "fast")).Accepted() {
		t.Fatal("enqueue failed")
	}
	<-stalledAdapter.started
	waitFor(t, func() bool { return fast.Counters().Delivered == 1 })
	if stalled.Counters().Delivered != 0 {
		t.Fatal("stalled destination unexpectedly delivered")
	}
	close(release)
	closeDispatcher(t, stalled)
	closeDispatcher(t, fast)
}

func TestEnqueueNeverCallsAdapterOnProducerGoroutine(t *testing.T) {
	release := make(chan struct{})
	adapter := &fakeAdapter{started: make(chan struct{}, 1), release: release}
	dispatcher, err := delivery.NewDispatcher(testConfig("async"), adapter)
	if err != nil {
		t.Fatal(err)
	}
	if got := dispatcher.Enqueue(payload(t, "before", "value")); got.Reason != delivery.ReasonInactive {
		t.Fatalf("pre-activation=%+v", got)
	}
	if adapter.deliverCalls.Load() != 0 {
		t.Fatal("constructor or inactive enqueue called adapter")
	}
	dispatcher.Activate()
	returned := make(chan delivery.EnqueueResult, 1)
	go func() { returned <- dispatcher.Enqueue(payload(t, "active", "value")) }()
	select {
	case result := <-returned:
		if !result.Accepted() {
			t.Fatalf("enqueue=%+v", result)
		}
	case <-time.After(time.Second):
		t.Fatal("enqueue waited for adapter I/O")
	}
	<-adapter.started
	close(release)
	closeDispatcher(t, dispatcher)
}

func TestFlushWaitsForAcceptedPayloadWithoutStoppingIntake(t *testing.T) {
	release := make(chan struct{})
	adapter := &fakeAdapter{started: make(chan struct{}, 1), release: release}
	dispatcher, err := delivery.NewDispatcher(testConfig("flush"), adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	if got := dispatcher.Enqueue(payload(t, "before-flush", "value")); !got.Accepted() {
		t.Fatalf("enqueue before flush=%+v", got)
	}
	<-adapter.started

	flushDone := make(chan error, 1)
	go func() { flushDone <- dispatcher.Flush(context.Background()) }()
	select {
	case err := <-flushDone:
		t.Fatalf("flush returned before terminal disposition: %v", err)
	case <-time.After(20 * time.Millisecond):
	}

	close(release)
	select {
	case err := <-flushDone:
		if err != nil {
			t.Fatalf("flush: %v", err)
		}
	case <-time.After(time.Second):
		t.Fatal("flush did not observe terminal disposition")
	}
	if got := dispatcher.Enqueue(payload(t, "after-flush", "value")); !got.Accepted() {
		t.Fatalf("flush stopped intake: %+v", got)
	}
	closeDispatcher(t, dispatcher)
	if got := dispatcher.Counters(); got.Accepted != 2 || got.Delivered != 2 {
		t.Fatalf("counters=%+v", got)
	}
}

func TestFlushCancellationDoesNotStopIntake(t *testing.T) {
	release := make(chan struct{})
	adapter := &fakeAdapter{started: make(chan struct{}, 1), release: release}
	dispatcher, err := delivery.NewDispatcher(testConfig("flush-cancel"), adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	if got := dispatcher.Enqueue(payload(t, "blocked", "value")); !got.Accepted() {
		t.Fatalf("enqueue=%+v", got)
	}
	<-adapter.started

	ctx, cancel := context.WithTimeout(context.Background(), 20*time.Millisecond)
	defer cancel()
	if err := dispatcher.Flush(ctx); err != context.DeadlineExceeded {
		t.Fatalf("flush cancellation=%v", err)
	}
	if got := dispatcher.Enqueue(payload(t, "still-open", "value")); !got.Accepted() {
		t.Fatalf("canceled flush stopped intake: %+v", got)
	}
	close(release)
	if err := dispatcher.Flush(context.Background()); err != nil {
		t.Fatalf("second flush: %v", err)
	}
	closeDispatcher(t, dispatcher)
}

func TestFlushValidatesContextAndHandlesNilDispatcher(t *testing.T) {
	dispatcher, err := delivery.NewDispatcher(testConfig("flush-context"), &fakeAdapter{})
	if err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.Flush(nil); !delivery.IsError(err, delivery.ErrorInvalidContext) {
		t.Fatalf("nil context error=%v", err)
	}
	var nilDispatcher *delivery.Dispatcher
	if err := nilDispatcher.Flush(context.Background()); err != nil {
		t.Fatalf("nil dispatcher flush=%v", err)
	}
	closeDispatcher(t, dispatcher)
}

func TestEnqueueDoesNotWaitForAdapterBatchEstimator(t *testing.T) {
	release := make(chan struct{})
	adapter := &blockingSizerAdapter{entered: make(chan struct{}, 1), release: release}
	dispatcher, err := delivery.NewDispatcher(testConfig("slow-estimator"), adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	if !dispatcher.Enqueue(payload(t, "first", "value")).Accepted() {
		t.Fatal("first enqueue failed")
	}
	<-adapter.entered
	returned := make(chan delivery.EnqueueResult, 1)
	go func() { returned <- dispatcher.Enqueue(payload(t, "second", "value")) }()
	select {
	case result := <-returned:
		if !result.Accepted() {
			t.Fatalf("second enqueue=%+v", result)
		}
	case <-time.After(100 * time.Millisecond):
		t.Fatal("enqueue waited for adapter estimator")
	}
	close(release)
	closeDispatcher(t, dispatcher)
}

func TestRetryUsesExactImmutableBytesAndIdentity(t *testing.T) {
	adapter := &fakeAdapter{outcomes: []delivery.DeliveryOutcome{
		delivery.OutcomeTransient, delivery.OutcomeAmbiguous, delivery.OutcomeDelivered,
	}}
	dispatcher, err := delivery.NewDispatcher(testConfig("retry"), adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	want := []byte(`{"password":"still-projected"}`)
	if !dispatcher.Enqueue(payload(t, "stable-id", string(want))).Accepted() {
		t.Fatal("enqueue failed")
	}
	closeDispatcher(t, dispatcher)
	attempts := adapter.snapshot()
	if len(attempts) != 3 {
		t.Fatalf("attempts=%d", len(attempts))
	}
	for index, got := range attempts {
		if len(got.ids) != 1 || got.ids[0] != "stable-id" || !bytes.Equal(got.payloads[0], want) {
			t.Fatalf("attempt %d=%#v", index, got)
		}
	}
	if got := dispatcher.Counters(); got.Accepted != 1 || got.Delivered != 1 || got.Retried != 2 || got.Rejected != 0 {
		t.Fatalf("counters=%+v", got)
	}
}

func TestOnlyTransientAndAmbiguousOutcomesRetry(t *testing.T) {
	for _, outcome := range []delivery.DeliveryOutcome{
		delivery.OutcomeAuthentication, delivery.OutcomePermanentPayload, delivery.OutcomeUnsafeEndpoint,
	} {
		t.Run(string(outcome), func(t *testing.T) {
			adapter := &fakeAdapter{outcomes: []delivery.DeliveryOutcome{outcome, delivery.OutcomeDelivered}}
			dispatcher, err := delivery.NewDispatcher(testConfig("terminal-"+string(outcome)), adapter)
			if err != nil {
				t.Fatal(err)
			}
			dispatcher.Activate()
			dispatcher.Enqueue(payload(t, "record", "value"))
			closeDispatcher(t, dispatcher)
			if got := len(adapter.snapshot()); got != 1 {
				t.Fatalf("attempts=%d", got)
			}
			if got := dispatcher.Counters(); got.Rejected != 1 || got.Retried != 0 {
				t.Fatalf("counters=%+v", got)
			}
		})
	}
}

func TestPartialOutcomeAccountsExactTerminalSplitWithoutRetry(t *testing.T) {
	adapter := &fixedResultAdapter{result: delivery.DeliveryResult{
		Outcome: delivery.OutcomePartial, DeliveredItems: 1, RejectedItems: 1,
	}}
	config := testConfig("partial")
	config.ScheduledDelay = 25 * time.Millisecond
	dispatcher, err := delivery.NewDispatcher(config, adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	for _, id := range []string{"accepted", "rejected"} {
		if result := dispatcher.Enqueue(payload(t, id, "value")); !result.Accepted() {
			t.Fatalf("enqueue %q = %+v", id, result)
		}
	}
	waitFor(t, func() bool {
		counters := dispatcher.Counters()
		return counters.Delivered == 1 && counters.Rejected == 1
	})
	if got := dispatcher.Counters(); got.Accepted != 2 || got.Delivered != 1 || got.Rejected != 1 || got.Retried != 0 {
		t.Fatalf("partial counters = %+v", got)
	}
	if got := dispatcher.Health(); got != delivery.HealthDegraded {
		t.Fatalf("partial health = %q", got)
	}
	closeDispatcher(t, dispatcher)
}

func TestMalformedAdapterItemCountsFailClosedWithoutRetry(t *testing.T) {
	tests := []struct {
		name   string
		result delivery.DeliveryResult
	}{
		{name: "partial-missing-delivered", result: delivery.DeliveryResult{Outcome: delivery.OutcomePartial, RejectedItems: 2}},
		{name: "partial-missing-rejected", result: delivery.DeliveryResult{Outcome: delivery.OutcomePartial, DeliveredItems: 2}},
		{name: "partial-under-count", result: delivery.DeliveryResult{Outcome: delivery.OutcomePartial, DeliveredItems: 1, RejectedItems: 1}},
		{name: "partial-over-count", result: delivery.DeliveryResult{Outcome: delivery.OutcomePartial, DeliveredItems: 2, RejectedItems: 2}},
		{name: "delivered-with-counts", result: delivery.DeliveryResult{Outcome: delivery.OutcomeDelivered, DeliveredItems: 3}},
		{name: "retry-with-counts", result: delivery.DeliveryResult{Outcome: delivery.OutcomeTransient, RejectedItems: 3}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			adapter := &fixedResultAdapter{result: test.result}
			config := testConfig("malformed-" + test.name)
			config.ScheduledDelay = 25 * time.Millisecond
			dispatcher, err := delivery.NewDispatcher(config, adapter)
			if err != nil {
				t.Fatal(err)
			}
			dispatcher.Activate()
			for _, id := range []string{"one", "two", "three"} {
				if result := dispatcher.Enqueue(payload(t, id, "value")); !result.Accepted() {
					t.Fatalf("enqueue %q = %+v", id, result)
				}
			}
			waitFor(t, func() bool {
				return dispatcher.Counters().Rejected == 3 && dispatcher.Health() == delivery.HealthFailing
			})
			if got := dispatcher.Counters(); got.Accepted != 3 || got.Delivered != 0 || got.Rejected != 3 || got.Retried != 0 {
				t.Fatalf("malformed counters = %+v", got)
			}
			if got := dispatcher.Health(); got != delivery.HealthFailing {
				t.Fatalf("malformed health = %q", got)
			}
			closeDispatcher(t, dispatcher)
		})
	}
}

func TestBatchPackingHonorsCountAndFullyEncodedByteCeilings(t *testing.T) {
	adapter := &fakeAdapter{prefix: 2, separator: 1, suffix: 2}
	config := testConfig("packing")
	config.MaxBatchItems = 2
	config.MaxBatchBytes = 11 // two three-byte payloads: 2+3+1+3+2
	config.ScheduledDelay = time.Hour
	dispatcher, err := delivery.NewDispatcher(config, adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	for index := 0; index < 5; index++ {
		if !dispatcher.Enqueue(payload(t, fmt.Sprintf("id-%d", index), "abc")).Accepted() {
			t.Fatalf("enqueue %d failed", index)
		}
	}
	closeDispatcher(t, dispatcher)
	attempts := adapter.snapshot()
	if len(attempts) != 3 {
		t.Fatalf("batches=%d %#v", len(attempts), attempts)
	}
	for index, got := range attempts {
		if len(got.ids) > 2 || got.encodedSize > 11 {
			t.Fatalf("batch %d count=%d encoded=%d", index, len(got.ids), got.encodedSize)
		}
	}
	if len(attempts[0].ids) != 2 || len(attempts[1].ids) != 2 || len(attempts[2].ids) != 1 {
		t.Fatalf("batch counts=%d,%d,%d", len(attempts[0].ids), len(attempts[1].ids), len(attempts[2].ids))
	}
}

func TestSingleProjectionWhoseWrapperExceedsBatchCeilingIsRejectedWithoutAllocation(t *testing.T) {
	adapter := &fakeAdapter{prefix: 100}
	config := testConfig("oversized-wrapper")
	config.MaxBatchBytes = 10
	dispatcher, err := delivery.NewDispatcher(config, adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	dispatcher.Enqueue(payload(t, "record", "x"))
	closeDispatcher(t, dispatcher)
	if got := adapter.deliverCalls.Load(); got != 0 {
		t.Fatalf("delivery calls=%d", got)
	}
	if got := dispatcher.Counters(); got.Rejected != 1 || got.Delivered != 0 {
		t.Fatalf("counters=%+v", got)
	}
}

func TestEstimatorCannotUndercountProjectedBytesAndAdapterPanicsAreContained(t *testing.T) {
	t.Run("undercount", func(t *testing.T) {
		adapter := &undercountingAdapter{}
		dispatcher, err := delivery.NewDispatcher(testConfig("undercount"), adapter)
		if err != nil {
			t.Fatal(err)
		}
		dispatcher.Activate()
		dispatcher.Enqueue(payload(t, "record", "projected"))
		closeDispatcher(t, dispatcher)
		if adapter.calls.Load() != 0 || dispatcher.Counters().Rejected != 1 {
			t.Fatalf("calls=%d counters=%+v", adapter.calls.Load(), dispatcher.Counters())
		}
	})
	for _, test := range []struct {
		name    string
		adapter panicAdapter
	}{
		{name: "estimator", adapter: panicAdapter{panicSize: true}},
		{name: "delivery", adapter: panicAdapter{panicDeliver: true}},
	} {
		t.Run(test.name, func(t *testing.T) {
			dispatcher, err := delivery.NewDispatcher(testConfig("panic-"+test.name), test.adapter)
			if err != nil {
				t.Fatal(err)
			}
			dispatcher.Activate()
			dispatcher.Enqueue(payload(t, "record", "projected"))
			closeDispatcher(t, dispatcher)
			if dispatcher.Counters().Rejected != 1 || dispatcher.Health() != delivery.HealthStopped {
				t.Fatalf("counters=%+v health=%s", dispatcher.Counters(), dispatcher.Health())
			}
		})
	}
}

func TestOriginDestinationCannotRecursivelyExport(t *testing.T) {
	adapter := &fakeAdapter{}
	dispatcher, err := delivery.NewDispatcher(testConfig("collector-a"), adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	projection, err := delivery.NewPayload([]byte(`{}`), delivery.RoutingIdentity{
		RecordID: "loop", Bucket: "telemetry.ingest", Signal: "logs", EventName: "telemetry.batch.accepted",
		OriginDestination: "collector-a",
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := dispatcher.Enqueue(projection); got.Reason != delivery.ReasonOriginLoop || got.Disposition != delivery.EnqueueRejected {
		t.Fatalf("loop=%+v", got)
	}
	closeDispatcher(t, dispatcher)
	if adapter.deliverCalls.Load() != 0 {
		t.Fatal("recursive payload reached adapter")
	}
}

func TestDrainAndCloseTimeoutsAreRetryable(t *testing.T) {
	t.Run("drain", func(t *testing.T) {
		release := make(chan struct{})
		adapter := &fakeAdapter{started: make(chan struct{}, 1), release: release, ignoreContext: true}
		dispatcher, err := delivery.NewDispatcher(testConfig("drain-timeout"), adapter)
		if err != nil {
			t.Fatal(err)
		}
		dispatcher.Activate()
		dispatcher.Enqueue(payload(t, "record", "value"))
		<-adapter.started
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		defer cancel()
		if err := dispatcher.Drain(ctx); err != context.DeadlineExceeded {
			t.Fatalf("drain error=%v", err)
		}
		close(release)
		closeDispatcher(t, dispatcher)
	})

	t.Run("close", func(t *testing.T) {
		release := make(chan struct{})
		adapter := &fakeAdapter{started: make(chan struct{}, 1), release: release, ignoreContext: true}
		dispatcher, err := delivery.NewDispatcher(testConfig("close-timeout"), adapter)
		if err != nil {
			t.Fatal(err)
		}
		dispatcher.Activate()
		dispatcher.Enqueue(payload(t, "record", "value"))
		<-adapter.started
		ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
		if err := dispatcher.Close(ctx); err != context.DeadlineExceeded {
			t.Fatalf("first close error=%v", err)
		}
		cancel()
		close(release)
		ctx, cancel = context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		if err := dispatcher.Close(ctx); err != nil {
			t.Fatalf("retry close: %v", err)
		}
		if dispatcher.Health() != delivery.HealthStopped {
			t.Fatalf("health=%s", dispatcher.Health())
		}
	})
}

func TestLifecycleRejectsNilContextWithoutChangingIntake(t *testing.T) {
	dispatcher, err := delivery.NewDispatcher(testConfig("nil-context"), &fakeAdapter{})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	if err := dispatcher.Drain(nil); !delivery.IsError(err, delivery.ErrorInvalidContext) {
		t.Fatalf("drain error=%v", err)
	}
	if err := dispatcher.Close(nil); !delivery.IsError(err, delivery.ErrorInvalidContext) {
		t.Fatalf("close error=%v", err)
	}
	if got := dispatcher.Enqueue(payload(t, "still-active", "value")); !got.Accepted() {
		t.Fatalf("nil lifecycle call changed intake: %+v", got)
	}
	closeDispatcher(t, dispatcher)
}

func TestAttemptDeadlineBoundsCooperativeAdapter(t *testing.T) {
	never := make(chan struct{})
	adapter := &fakeAdapter{release: never}
	config := testConfig("attempt-deadline")
	config.AttemptTimeout = 2 * time.Millisecond
	config.Retry.InitialBackoff = 0
	config.Retry.MaxBackoff = 0
	dispatcher, err := delivery.NewDispatcher(config, adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	dispatcher.Enqueue(payload(t, "record", "projected"))
	closeDispatcher(t, dispatcher)
	if got := adapter.deliverCalls.Load(); got != uint64(config.Retry.MaxAttempts) {
		t.Fatalf("attempts=%d", got)
	}
	if got := dispatcher.Counters(); got.Retried != 2 || got.Rejected != 1 || got.Delivered != 0 {
		t.Fatalf("counters=%+v", got)
	}
}

func TestCloseTimeoutIncludesObserverAndCanBeRetried(t *testing.T) {
	release := make(chan struct{})
	entered := make(chan struct{}, 1)
	observer := delivery.ObserverFunc(func(transition delivery.HealthTransition) {
		if transition.Current == delivery.HealthHealthy {
			select {
			case entered <- struct{}{}:
			default:
			}
			<-release
		}
	})
	config := testConfig("observer-timeout")
	config.Observer = observer
	dispatcher, err := delivery.NewDispatcher(config, &fakeAdapter{})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	<-entered
	ctx, cancel := context.WithTimeout(context.Background(), time.Millisecond)
	if err := dispatcher.Close(ctx); err != context.DeadlineExceeded {
		t.Fatalf("first close error=%v", err)
	}
	cancel()
	close(release)
	ctx, cancel = context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := dispatcher.Close(ctx); err != nil {
		t.Fatalf("retry close: %v", err)
	}
}

func TestCloseCancellationReleasesInflightAndPendingCharges(t *testing.T) {
	release := make(chan struct{})
	adapter := &cancelAwareAdapter{
		started: make(chan struct{}, 1), canceled: make(chan struct{}, 1), release: release,
	}
	config := testConfig("close-release")
	config.MaxBatchItems = 1
	dispatcher, err := delivery.NewDispatcher(config, adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	dispatcher.Enqueue(payload(t, "inflight", "one"))
	<-adapter.started
	dispatcher.Enqueue(payload(t, "pending", "two"))

	done := make(chan error, 1)
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		done <- dispatcher.Close(ctx)
	}()
	<-adapter.canceled
	close(release)
	if err := <-done; err != nil {
		t.Fatal(err)
	}
	items, retained, inFlight, inFlightBytes := dispatcher.QueueUsage()
	if items != 0 || retained != 0 || inFlight != 0 || inFlightBytes != 0 {
		t.Fatalf("retained=(%d,%d,%d,%d)", items, retained, inFlight, inFlightBytes)
	}
	if got := dispatcher.Counters(); got.Accepted != 2 || got.Dropped != 2 || got.Delivered != 0 {
		t.Fatalf("counters=%+v", got)
	}
}

func TestHealthTransitionsRecoveryAndCoalescing(t *testing.T) {
	var mu sync.Mutex
	var transitions []delivery.HealthTransition
	healthyObserved := make(chan struct{})
	observer := delivery.ObserverFunc(func(transition delivery.HealthTransition) {
		mu.Lock()
		transitions = append(transitions, transition)
		mu.Unlock()
		if transition.Current == delivery.HealthHealthy && transition.Reason == delivery.HealthReasonActivated {
			select {
			case healthyObserved <- struct{}{}:
			default:
			}
		}
	})
	adapter := &fakeAdapter{outcomes: []delivery.DeliveryOutcome{delivery.OutcomeTransient, delivery.OutcomeDelivered}}
	config := testConfig("health")
	config.Observer = observer
	config.ObserverInterval = 0
	dispatcher, err := delivery.NewDispatcher(config, adapter)
	if err != nil {
		t.Fatal(err)
	}
	if dispatcher.Health() != delivery.HealthInitializing {
		t.Fatalf("initial health=%s", dispatcher.Health())
	}
	dispatcher.Activate()
	<-healthyObserved
	dispatcher.Enqueue(payload(t, "record", "value"))
	waitFor(t, func() bool { return dispatcher.Counters().Delivered == 1 })
	if dispatcher.Health() != delivery.HealthHealthy {
		t.Fatalf("recovered health=%s", dispatcher.Health())
	}
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(transitions) > 0 && transitions[len(transitions)-1].Reason == delivery.HealthReasonRecovered
	})
	_ = dispatcher.StopIntake(context.Background())
	waitFor(t, func() bool {
		mu.Lock()
		defer mu.Unlock()
		return len(transitions) > 0 && transitions[len(transitions)-1].Current == delivery.HealthDraining
	})
	closeDispatcher(t, dispatcher)
	mu.Lock()
	defer mu.Unlock()
	states := make([]delivery.HealthState, 0, len(transitions))
	for _, transition := range transitions {
		states = append(states, transition.Current)
		if transition.Destination != "health" {
			t.Fatalf("transition disclosed unexpected destination=%q", transition.Destination)
		}
	}
	want := []delivery.HealthState{
		delivery.HealthHealthy, delivery.HealthDegraded, delivery.HealthHealthy,
		delivery.HealthDraining, delivery.HealthStopped,
	}
	if fmt.Sprint(states) != fmt.Sprint(want) {
		t.Fatalf("states=%v want=%v transitions=%+v", states, want, transitions)
	}

	// Same-state failures are coalesced at the state machine boundary rather
	// than producing one mandatory health event per dropped record.
	release := make(chan struct{})
	var queueFull atomic.Uint64
	coalescingObserver := delivery.ObserverFunc(func(transition delivery.HealthTransition) {
		if transition.Reason == delivery.HealthReasonQueueFull {
			queueFull.Add(1)
		}
	})
	coalescingConfig := testConfig("coalescing")
	coalescingConfig.MaxQueueItems = 1
	coalescingConfig.MaxBatchItems = 1
	coalescingConfig.Observer = coalescingObserver
	coalescing := &fakeAdapter{started: make(chan struct{}, 1), release: release}
	second, err := delivery.NewDispatcher(coalescingConfig, coalescing)
	if err != nil {
		t.Fatal(err)
	}
	second.Activate()
	second.Enqueue(payload(t, "held", "x"))
	<-coalescing.started
	for index := 0; index < 100; index++ {
		second.Enqueue(payload(t, fmt.Sprintf("drop-%d", index), "x"))
	}
	waitFor(t, func() bool { return queueFull.Load() == 1 })
	close(release)
	closeDispatcher(t, second)
	if queueFull.Load() != 1 {
		t.Fatalf("queue-full health transitions=%d", queueFull.Load())
	}
}

func TestHealthObserverRateLimitCoalescesRapidFlappingToLatestState(t *testing.T) {
	transitions := make(chan delivery.HealthTransition, 8)
	config := testConfig("rate-limited")
	config.ObserverInterval = 40 * time.Millisecond
	config.Observer = delivery.ObserverFunc(func(transition delivery.HealthTransition) {
		transitions <- transition
	})
	dispatcher, err := delivery.NewDispatcher(config, &fakeAdapter{})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	first := <-transitions
	if first.Current != delivery.HealthHealthy {
		t.Fatalf("first=%+v", first)
	}
	loop, err := delivery.NewPayload([]byte(`{}`), delivery.RoutingIdentity{
		RecordID: "loop", Bucket: "telemetry.ingest", Signal: "logs", EventName: "telemetry.batch.accepted",
		OriginDestination: "rate-limited",
	})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Enqueue(loop)
	dispatcher.Enqueue(payload(t, "recovery", "projected"))
	waitFor(t, func() bool { return dispatcher.Counters().Delivered == 1 })
	select {
	case transition := <-transitions:
		t.Fatalf("transition escaped rate limit: %+v", transition)
	case <-time.After(15 * time.Millisecond):
	}
	select {
	case latest := <-transitions:
		if latest.Current != delivery.HealthHealthy || latest.Reason != delivery.HealthReasonRecovered {
			t.Fatalf("latest=%+v", latest)
		}
	case <-time.After(time.Second):
		t.Fatal("coalesced recovery transition not emitted")
	}
	closeDispatcher(t, dispatcher)
}

func TestDisabledAndPreparedDispatchersOwnNoWorkers(t *testing.T) {
	disabledConfig := testConfig("disabled")
	disabledConfig.Enabled = false
	disabled, err := delivery.NewDispatcher(disabledConfig, nil)
	if err != nil {
		t.Fatal(err)
	}
	if disabled.Health() != delivery.HealthDisabled {
		t.Fatalf("health=%s", disabled.Health())
	}
	disabled.Activate()
	closeDispatcher(t, disabled)

	prepared, err := delivery.NewDispatcher(testConfig("prepared"), &fakeAdapter{})
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := prepared.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if prepared.Health() != delivery.HealthStopped {
		t.Fatalf("prepared health=%s", prepared.Health())
	}
}

func TestDispatcherWorkersTerminateUnderStress(t *testing.T) {
	baseline := runtime.NumGoroutine()
	const dispatchers = 40
	for index := 0; index < dispatchers; index++ {
		config := testConfig(fmt.Sprintf("worker-%d", index))
		config.MaxQueueItems = 64
		dispatcher, err := delivery.NewDispatcher(config, &fakeAdapter{})
		if err != nil {
			t.Fatal(err)
		}
		dispatcher.Activate()
		var producers sync.WaitGroup
		for producer := 0; producer < 4; producer++ {
			producers.Add(1)
			go func(producer int) {
				defer producers.Done()
				for item := 0; item < 50; item++ {
					dispatcher.Enqueue(payload(t, fmt.Sprintf("%d-%d", producer, item), "value"))
				}
			}(producer)
		}
		producers.Wait()
		closeDispatcher(t, dispatcher)
		items, retained, inFlight, inFlightBytes := dispatcher.QueueUsage()
		if items != 0 || retained != 0 || inFlight != 0 || inFlightBytes != 0 {
			t.Fatalf("dispatcher %d retained (%d,%d,%d,%d), counters=%+v", index, items, retained, inFlight, inFlightBytes, dispatcher.Counters())
		}
	}
	runtime.GC()
	waitFor(t, func() bool { return runtime.NumGoroutine() <= baseline+8 })
}
