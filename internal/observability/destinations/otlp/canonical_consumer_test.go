// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"bytes"
	"context"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

type otlpCanonicalCaptureAdapter struct {
	deliveries chan [][]byte
	mu         sync.Mutex
	closed     bool
}

func (*otlpCanonicalCaptureAdapter) EncodedSize(sizes []int) (int, bool) {
	total := 1
	for _, size := range sizes {
		if size < 0 {
			return 0, false
		}
		total += size
	}
	return total, true
}

func (adapter *otlpCanonicalCaptureAdapter) Deliver(_ context.Context, batch delivery.Batch) delivery.DeliveryResult {
	items := batch.Items()
	encoded := make([][]byte, len(items))
	for index := range items {
		encoded[index] = items[index].Bytes()
	}
	adapter.deliveries <- encoded
	return delivery.DeliveryResult{Outcome: delivery.OutcomeDelivered}
}

func (adapter *otlpCanonicalCaptureAdapter) Close(context.Context) error {
	adapter.mu.Lock()
	adapter.closed = true
	adapter.mu.Unlock()
	return nil
}

type otlpCanonicalFailureCapture struct {
	mu     sync.Mutex
	events []CanonicalFailure
}

func (capture *otlpCanonicalFailureCapture) ObserveOTLPCanonicalFailure(failure CanonicalFailure) {
	capture.mu.Lock()
	capture.events = append(capture.events, failure)
	capture.mu.Unlock()
}

func (capture *otlpCanonicalFailureCapture) snapshot() []CanonicalFailure {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]CanonicalFailure(nil), capture.events...)
}

func TestCanonicalTraceConsumerRoutesProjectsAndQueuesExactlyOnce(t *testing.T) {
	fixture := newOTLPCanonicalConsumerFixture(t, observability.BucketModelIO, 8)
	record := canonicalProjectionModelRecordForPlan(t, fixture.plan.Digest(), 8)
	if result := fixture.consumer.TryEnqueue(telemetry.V8CanonicalEndedSpan{}); result != telemetry.V8CanonicalSpanEnqueueClosed {
		t.Fatalf("prepared consumer result=%s", result)
	}
	fixture.consumer.Activate()
	if result := fixture.consumer.tryEnqueueRecord(record); result != telemetry.V8CanonicalSpanEnqueueAccepted {
		t.Fatalf("active consumer result=%s", result)
	}
	flushOTLPCanonical(t, fixture.consumer)
	select {
	case batch := <-fixture.adapter.deliveries:
		if len(batch) != 1 {
			t.Fatalf("delivery items=%d", len(batch))
		}
		wire, ok := decodeCanonicalTraceProjection(batch[0])
		if !ok || wire.recordID != record.RecordID() || wire.projection["redaction_profile"] != "none" {
			t.Fatalf("invalid routed projection: %+v", wire)
		}
		if _, ok := wire.otlp(); !ok {
			t.Fatal("queued projection did not satisfy direct OTLP contract")
		}
	case <-time.After(2 * time.Second):
		t.Fatal("timed out waiting for canonical OTLP delivery")
	}
	if counters := fixture.consumer.Counters(); counters.Accepted != 1 || counters.Failed != 0 {
		t.Fatalf("counters=%+v", counters)
	}
	shutdownOTLPCanonical(t, fixture.consumer)
	fixture.adapter.mu.Lock()
	closed := fixture.adapter.closed
	fixture.adapter.mu.Unlock()
	if !closed {
		t.Fatal("adapter was not closed after drain")
	}
}

func TestCanonicalTraceConsumerDropsUnmatchedRouteAndRejectsGenerationMismatch(t *testing.T) {
	unmatched := newOTLPCanonicalConsumerFixture(t, observability.BucketAgentLifecycle, 8)
	record := canonicalProjectionModelRecordForPlan(t, unmatched.plan.Digest(), 8)
	unmatched.consumer.Activate()
	if result := unmatched.consumer.tryEnqueueRecord(record); result != telemetry.V8CanonicalSpanEnqueueDropped {
		t.Fatalf("unmatched result=%s", result)
	}
	if counters := unmatched.consumer.Counters(); counters.RouteDropped != 1 || counters.Accepted != 0 {
		t.Fatalf("unmatched counters=%+v", counters)
	}
	shutdownOTLPCanonical(t, unmatched.consumer)

	wrongGeneration := newOTLPCanonicalConsumerFixture(t, observability.BucketModelIO, 9)
	record = canonicalProjectionModelRecordForPlan(t, wrongGeneration.plan.Digest(), 8)
	wrongGeneration.consumer.Activate()
	if result := wrongGeneration.consumer.tryEnqueueRecord(record); result != telemetry.V8CanonicalSpanEnqueueFailed {
		t.Fatalf("generation mismatch result=%s", result)
	}
	events := wrongGeneration.failures.snapshot()
	if len(events) != 1 || events[0].Code != CanonicalFailureGenerationMismatch {
		t.Fatalf("generation failures=%+v", events)
	}
	shutdownOTLPCanonical(t, wrongGeneration.consumer)
}

func TestGeneralCanonicalDestinationRequiresExactGeneratedOpenInferenceCapability(t *testing.T) {
	t.Parallel()
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Destinations: []config.ObservabilityV8DestinationSource{{
			Name: "general-otlp", Kind: config.ObservabilityV8DestinationOTLP,
			Endpoint: "https://otel.example.test",
			Send: &config.ObservabilityV8SendSource{
				Signals: []observability.Signal{observability.SignalTraces},
				Buckets: []observability.Bucket{"*"}, RedactionProfile: "none",
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	destination, ok := plan.RuntimeDestination("general-otlp")
	if !ok || !validGeneralCanonicalDestination(destination) {
		t.Fatalf("compiled destination capability rejected: %+v", destination.CompatibilityProfiles)
	}

	tests := []struct {
		name   string
		mutate func(*config.ObservabilityV8EffectiveDestination)
	}{
		{"missing", func(value *config.ObservabilityV8EffectiveDestination) { value.CompatibilityProfiles = nil }},
		{"wrong availability", func(value *config.ObservabilityV8EffectiveDestination) {
			value.CompatibilityProfiles[0].Availability = "pending"
		}},
		{"missing family", func(value *config.ObservabilityV8EffectiveDestination) {
			value.CompatibilityProfiles[0].EligibleSpanFamilies = value.CompatibilityProfiles[0].EligibleSpanFamilies[1:]
		}},
		{"bucket drift", func(value *config.ObservabilityV8EffectiveDestination) {
			value.CompatibilityProfiles[0].EligibleSpanFamilies[0].Bucket = observability.BucketDiagnostic
		}},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			mutated := destination
			mutated.CompatibilityProfiles = append(
				[]config.ObservabilityV8EffectiveCompatibilityProfile(nil), destination.CompatibilityProfiles...,
			)
			mutated.CompatibilityProfiles[0].EligibleSpanFamilies = append(
				[]config.ObservabilityV8EffectiveSpanFamily(nil),
				destination.CompatibilityProfiles[0].EligibleSpanFamilies...,
			)
			test.mutate(&mutated)
			if validGeneralCanonicalDestination(mutated) {
				t.Fatal("drifted compatibility capability accepted")
			}
		})
	}
}

type otlpCanonicalConsumerFixture struct {
	consumer *CanonicalTraceConsumer
	adapter  *otlpCanonicalCaptureAdapter
	failures *otlpCanonicalFailureCapture
	plan     *config.ObservabilityV8Plan
}

func newOTLPCanonicalConsumerFixture(
	t *testing.T,
	bucket observability.Bucket,
	generation uint64,
) *otlpCanonicalConsumerFixture {
	t.Helper()
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Destinations: []config.ObservabilityV8DestinationSource{{
			Name: "general-otlp", Kind: config.ObservabilityV8DestinationOTLP,
			Protocol: "http/protobuf", Endpoint: "https://otel.example.test",
			Send: &config.ObservabilityV8SendSource{
				Signals: []observability.Signal{observability.SignalTraces},
				Buckets: []observability.Bucket{bucket}, RedactionProfile: "none",
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	destination, ok := plan.RuntimeDestination("general-otlp")
	if !ok {
		t.Fatal("compiled destination missing")
	}
	evaluator, err := router.New(plan)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := redaction.NewEngine(bytes.Repeat([]byte{0x44}, 32))
	if err != nil {
		t.Fatal(err)
	}
	projection, err := pipeline.NewTraceProjectionPipeline(plan, evaluator, engine)
	if err != nil {
		t.Fatal(err)
	}
	adapter := &otlpCanonicalCaptureAdapter{deliveries: make(chan [][]byte, 2)}
	failures := &otlpCanonicalFailureCapture{}
	consumer, err := NewCanonicalTraceConsumer(CanonicalTraceConsumerOptions{
		Destination: destination, Generation: generation, Pipeline: projection,
		Adapter: adapter, Dispatcher: otlpCanonicalDispatcherConfig("general-otlp"), Observer: failures,
	})
	if err != nil {
		t.Fatal(err)
	}
	return &otlpCanonicalConsumerFixture{consumer: consumer, adapter: adapter, failures: failures, plan: plan}
}

func otlpCanonicalDispatcherConfig(destination string) delivery.Config {
	return delivery.Config{
		Destination: destination, Enabled: true, MaxQueueItems: 4, MaxQueueBytes: 8 * 1024 * 1024,
		MaxBatchItems: 4, MaxBatchBytes: 8 * 1024 * 1024, ScheduledDelay: 0,
		AttemptTimeout: time.Second, Retry: delivery.RetryPolicy{MaxAttempts: 1},
		Observer: delivery.ObserverFunc(func(delivery.HealthTransition) {}),
	}
}

func flushOTLPCanonical(t *testing.T, consumer *CanonicalTraceConsumer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := consumer.ForceFlush(ctx); err != nil {
		t.Fatal(err)
	}
}

func shutdownOTLPCanonical(t *testing.T, consumer *CanonicalTraceConsumer) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	if err := consumer.Shutdown(ctx); err != nil {
		t.Fatal(err)
	}
}
