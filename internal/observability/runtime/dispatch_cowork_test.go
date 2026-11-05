// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
)

type coworkCollectorAdapter struct {
	available atomic.Bool
	calls     atomic.Int32
	firstCall chan struct{}
}

func (*coworkCollectorAdapter) EncodedSize(sizes []int) (int, bool) {
	return delivery.DelimitedEncodedSize(sizes, 0, 0, 0)
}

func (adapter *coworkCollectorAdapter) Deliver(context.Context, delivery.Batch) delivery.DeliveryResult {
	if adapter.calls.Add(1) == 1 && adapter.firstCall != nil {
		close(adapter.firstCall)
	}
	if !adapter.available.Load() {
		return delivery.DeliveryResult{Outcome: delivery.OutcomeTransient, FailureCode: delivery.FailureCodeConnectionFailed}
	}
	return delivery.DeliveryResult{Outcome: delivery.OutcomeDelivered}
}

func TestCoworkOTLPCircuitCooldownSurvivesNewIntake(t *testing.T) {
	destination := config.ObservabilityV8EffectiveDestination{
		Name: "cowork-cooldown", Kind: config.ObservabilityV8DestinationOTLP,
		Enabled: true, SelectedSignals: []observability.Signal{observability.SignalLogs},
		Transport: config.ObservabilityV8TransportPlan{
			Batch: &config.ObservabilityV8BatchSource{MaxQueueSize: 2, MaxQueueBytes: 4096},
		},
	}
	compiled, ok := CompiledDispatcherConfigForProfile(destination, 1, observability.SignalLogs, nil, false)
	if !ok {
		t.Fatal("OTLP dispatcher did not compile")
	}
	compiled.Retry = delivery.RetryPolicy{MaxAttempts: 1, InitialBackoff: time.Millisecond, MaxBackoff: time.Millisecond}
	compiled.Circuit = delivery.CircuitPolicy{TransientFailureThreshold: 1, OpenDuration: 2 * time.Second}
	adapter := &coworkCollectorAdapter{firstCall: make(chan struct{})}
	dispatcher, err := delivery.NewDispatcher(compiled, adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = dispatcher.Close(ctx)
	})
	payload := func(id string) delivery.Payload {
		item, err := delivery.NewPayload([]byte("record"), delivery.RoutingIdentity{
			RecordID: id, Bucket: "model.io", Signal: "logs", EventName: "model.response",
		})
		if err != nil {
			t.Fatal(err)
		}
		return item
	}
	if result := dispatcher.Enqueue(payload("first")); !result.Accepted() {
		t.Fatalf("first enqueue: %+v", result)
	}
	select {
	case <-adapter.firstCall:
	case <-time.After(2 * time.Second):
		t.Fatal("first delivery did not start")
	}
	if result := dispatcher.Enqueue(payload("second")); !result.Accepted() {
		t.Fatalf("second enqueue: %+v", result)
	}
	time.Sleep(40 * time.Millisecond)
	if calls := adapter.calls.Load(); calls != 1 {
		t.Fatalf("open circuit made %d calls before its cooldown elapsed", calls)
	}
}

func TestCoworkOTLPCollectorOutageKeepsBoundedQueue(t *testing.T) {
	destination := config.ObservabilityV8EffectiveDestination{
		Name: "cowork-collector", Kind: config.ObservabilityV8DestinationOTLP,
		Enabled: true, SelectedSignals: []observability.Signal{observability.SignalLogs},
		Transport: config.ObservabilityV8TransportPlan{
			Batch: &config.ObservabilityV8BatchSource{MaxQueueSize: 1, MaxQueueBytes: 4096},
		},
	}
	compiled, ok := CompiledDispatcherConfigForProfile(destination, 1, observability.SignalLogs, nil, false)
	if !ok {
		t.Fatal("OTLP dispatcher did not compile")
	}
	compiled.Retry = delivery.RetryPolicy{MaxAttempts: 2, InitialBackoff: time.Millisecond, MaxBackoff: time.Millisecond}
	compiled.Circuit = delivery.CircuitPolicy{TransientFailureThreshold: 1, OpenDuration: 5 * time.Millisecond}
	adapter := &coworkCollectorAdapter{}
	dispatcher, err := delivery.NewDispatcher(compiled, adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = dispatcher.Close(ctx)
	})
	payload := func(id string) delivery.Payload {
		t.Helper()
		item, err := delivery.NewPayload([]byte("record"), delivery.RoutingIdentity{
			RecordID: id, Bucket: "model.io", Signal: "logs", EventName: "model.response",
		})
		if err != nil {
			t.Fatal(err)
		}
		return item
	}
	if result := dispatcher.Enqueue(payload("first")); !result.Accepted() {
		t.Fatalf("first enqueue: %+v", result)
	}
	deadline := time.Now().Add(2 * time.Second)
	for adapter.calls.Load() < 3 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if calls := adapter.calls.Load(); calls < 3 {
		t.Fatalf("collector outage stopped retries after %d attempts; counters=%+v", calls, dispatcher.Counters())
	}
	if got := dispatcher.Counters(); got.Rejected != 0 || got.Dropped != 0 {
		t.Fatalf("transient outage lost accepted work: %+v", got)
	}
	if result := dispatcher.Enqueue(payload("second")); result.Disposition != delivery.EnqueueDropped {
		t.Fatalf("bounded queue result: %+v", result)
	}
	if got := dispatcher.Counters(); got.Dropped != 1 {
		t.Fatalf("queue overflow drop counter: %+v", got)
	}
	adapter.available.Store(true)
	deadline = time.Now().Add(2 * time.Second)
	for dispatcher.Counters().Delivered != 1 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if got := dispatcher.Counters(); got.Accepted != 1 || got.Delivered != 1 || got.Rejected != 0 || got.Dropped != 1 {
		t.Fatalf("collector recovery counters: %+v", got)
	}
}

func TestCoworkOTLPHealthyCollectorTwin(t *testing.T) {
	adapter := &coworkCollectorAdapter{}
	adapter.available.Store(true)
	destination := config.ObservabilityV8EffectiveDestination{
		Name: "cowork-healthy", Kind: config.ObservabilityV8DestinationOTLP,
		Enabled: true, SelectedSignals: []observability.Signal{observability.SignalLogs},
		Transport: config.ObservabilityV8TransportPlan{
			Batch: &config.ObservabilityV8BatchSource{MaxQueueSize: 1, MaxQueueBytes: 4096},
		},
	}
	compiled, ok := CompiledDispatcherConfigForProfile(destination, 1, observability.SignalLogs, nil, false)
	if !ok {
		t.Fatal("OTLP dispatcher did not compile")
	}
	dispatcher, err := delivery.NewDispatcher(compiled, adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	item, err := delivery.NewPayload([]byte("record"), delivery.RoutingIdentity{
		RecordID: "healthy", Bucket: "model.io", Signal: "logs", EventName: "model.response",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result := dispatcher.Enqueue(item); !result.Accepted() {
		t.Fatalf("healthy enqueue: %+v", result)
	}
	ctx, cancel := context.WithTimeout(context.Background(), time.Second)
	defer cancel()
	if err := dispatcher.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.Close(ctx); err != nil {
		t.Fatal(err)
	}
	if got := dispatcher.Counters(); got.Delivered != 1 || got.Retried != 0 || got.Dropped != 0 || got.Rejected != 0 {
		t.Fatalf("healthy collector counters: %+v", got)
	}
}
