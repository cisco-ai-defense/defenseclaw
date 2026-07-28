// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

type runtimeCanaryConsumer struct {
	generation uint64
	block      bool
	entered    chan struct{}
	unblock    chan struct{}
	enterOnce  sync.Once

	mu      sync.Mutex
	spans   []telemetry.V8CanonicalEndedSpan
	flushed bool
	ack     atomic.Bool
	closed  atomic.Uint64
}

func newRuntimeCanaryConsumer(generation uint64, block bool) *runtimeCanaryConsumer {
	consumer := &runtimeCanaryConsumer{
		generation: generation, block: block, entered: make(chan struct{}), unblock: make(chan struct{}),
	}
	consumer.ack.Store(true)
	return consumer
}

func (consumer *runtimeCanaryConsumer) TryEnqueue(
	span telemetry.V8CanonicalEndedSpan,
) telemetry.V8CanonicalSpanEnqueueResult {
	consumer.mu.Lock()
	consumer.spans = append(consumer.spans, span)
	consumer.mu.Unlock()
	return telemetry.V8CanonicalSpanEnqueueAccepted
}

func (consumer *runtimeCanaryConsumer) ForceFlush(ctx context.Context) error {
	if consumer.block {
		consumer.enterOnce.Do(func() { close(consumer.entered) })
		select {
		case <-consumer.unblock:
		case <-ctx.Done():
			return ctx.Err()
		}
	}
	consumer.mu.Lock()
	consumer.flushed = true
	consumer.mu.Unlock()
	return nil
}

func (consumer *runtimeCanaryConsumer) Shutdown(context.Context) error {
	consumer.closed.Add(1)
	return nil
}

func (consumer *runtimeCanaryConsumer) acknowledged(destination, traceID string) bool {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	if !consumer.ack.Load() || !consumer.flushed || destination != "otlp-all" || len(consumer.spans) != 2 {
		return false
	}
	var root, child *telemetry.V8CanonicalEndedSpan
	for index := range consumer.spans {
		span := &consumer.spans[index]
		if span.TraceID().String() != traceID ||
			span.Record().Provenance().ConfigGeneration != int64(consumer.generation) {
			return false
		}
		switch span.Record().EventName() {
		case observability.EventName(observability.TelemetryFamilyAgentInvoke):
			root = span
		case observability.EventName(observability.TelemetryFamilyModelChat):
			child = span
		default:
			return false
		}
	}
	if root == nil || child == nil {
		return false
	}
	parent, hasParent := child.ParentSpanID()
	_, rootHasParent := root.ParentSpanID()
	return !rootHasParent && hasParent && parent == root.SpanID()
}

type runtimeCanaryPipelines struct {
	mu        sync.Mutex
	consumers map[uint64]*runtimeCanaryConsumer
}

func (pipelines *runtimeCanaryPipelines) build(
	_ context.Context,
	_ *config.ObservabilityV8Plan,
	generation uint64,
	_ telemetry.V8MetricReaderSpec,
) (telemetry.V8GenerationPipelines, error) {
	consumer := newRuntimeCanaryConsumer(generation, generation == 1)
	pipelines.mu.Lock()
	pipelines.consumers[generation] = consumer
	pipelines.mu.Unlock()
	return telemetry.V8GenerationPipelines{
		SpanPipelines:      []telemetry.V8GenerationSpanPipeline{{Destination: "otlp-all", Canonical: consumer}},
		CanaryAcknowledged: consumer.acknowledged,
	}, nil
}

func (pipelines *runtimeCanaryPipelines) consumer(t *testing.T, generation uint64) *runtimeCanaryConsumer {
	t.Helper()
	pipelines.mu.Lock()
	defer pipelines.mu.Unlock()
	consumer := pipelines.consumers[generation]
	if consumer == nil {
		t.Fatalf("generation %d consumer is unavailable", generation)
	}
	return consumer
}

func runtimeCanaryPlan(
	t *testing.T,
	dependencies runtimeTestDependencies,
	retentionDays int,
) *config.ObservabilityV8Plan {
	t.Helper()
	return runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, retentionDays,
		func(source *config.ObservabilityV8Source) {
			source.TracePolicy.Sampler = "always_off"
			source.Destinations = []config.ObservabilityV8DestinationSource{{
				Name: "otlp-all", Kind: config.ObservabilityV8DestinationOTLP,
				Protocol: "http/protobuf", Endpoint: "https://otel.example.test",
				Send: &config.ObservabilityV8SendSource{
					Signals: []observability.Signal{observability.SignalTraces},
					Buckets: []observability.Bucket{"*"},
				},
			}}
		},
	)
}

func TestRuntimeTraceCanaryPinsGenerationThroughReloadFlushAndAcknowledgement(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	pipelines := &runtimeCanaryPipelines{consumers: make(map[uint64]*runtimeCanaryConsumer)}
	initialPlan := runtimeCanaryPlan(t, dependencies, 90)
	options := dependencies.options()
	options.TelemetryProviderFactory = telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "8.0.0", Environment: "test", ServiceInstanceID: "runtime-canary",
		GenerationPipelines: pipelines.build,
	})
	runtime, err := New(t.Context(), runtimegraph.ConfigFromPlan(initialPlan, false), options)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if closeErr := runtime.Close(ctx); closeErr != nil {
			t.Errorf("close runtime: %v", closeErr)
		}
	})

	type canaryOutcome struct {
		result TraceCanaryResult
		err    error
	}
	canaryDone := make(chan canaryOutcome, 1)
	go func() {
		result, canaryErr := runtime.EmitTraceCanary(t.Context(), "otlp-all")
		canaryDone <- canaryOutcome{result: result, err: canaryErr}
	}()
	first := pipelines.consumer(t, 1)
	select {
	case <-first.entered:
	case <-time.After(5 * time.Second):
		t.Fatal("generation-one canary did not reach its flush boundary")
	}

	reloadDone := make(chan struct {
		result runtimegraph.ReloadResult
		err    *runtimegraph.Error
	}, 1)
	candidate := runtimeCanaryPlan(t, dependencies, 30)
	go func() {
		result, reloadErr := runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(candidate, false))
		reloadDone <- struct {
			result runtimegraph.ReloadResult
			err    *runtimegraph.Error
		}{result: result, err: reloadErr}
	}()

	deadline := time.Now().Add(5 * time.Second)
	for runtime.Active() == nil || runtime.Active().Generation() != 2 {
		if time.Now().After(deadline) {
			t.Fatal("reload did not publish generation two while generation one remained leased")
		}
		time.Sleep(time.Millisecond)
	}
	if first.closed.Load() != 0 {
		t.Fatal("generation one retired before its canary acknowledgement lease was released")
	}
	select {
	case outcome := <-reloadDone:
		t.Fatalf("reload returned before generation-one lease release: %+v", outcome)
	default:
	}

	close(first.unblock)
	canary := <-canaryDone
	if canary.err != nil || !canary.result.Acknowledged || canary.result.Generation != 1 {
		t.Fatalf("generation-one canary=%+v error=%v", canary.result, canary.err)
	}
	reload := <-reloadDone
	if reload.err != nil || reload.result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("reload=%s error=%v", reload.result.Status(), reload.err)
	}
	if first.closed.Load() == 0 {
		t.Fatal("generation one was not retired after acknowledgement and lease release")
	}

	secondResult, secondErr := runtime.EmitTraceCanary(t.Context(), "otlp-all")
	if secondErr != nil || !secondResult.Acknowledged || secondResult.Generation != 2 ||
		secondResult.TraceID == canary.result.TraceID {
		t.Fatalf("generation-two canary=%+v error=%v", secondResult, secondErr)
	}

	// A failed acknowledgement must release its lease too. A subsequent reload
	// proves the failed call did not pin generation two indefinitely.
	second := pipelines.consumer(t, 2)
	second.ack.Store(false)
	failed, failedErr := runtime.EmitTraceCanary(t.Context(), "otlp-all")
	if failedErr == nil || failed.Acknowledged || failed.Generation != 2 || failed.TraceID == "" {
		t.Fatalf("unacknowledged canary=%+v error=%v", failed, failedErr)
	}
	second.ack.Store(true)
	thirdPlan := runtimeCanaryPlan(t, dependencies, 15)
	reloadContext, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	thirdReload, thirdErr := runtime.Reload(
		reloadContext, runtimegraph.ConfigFromPlan(thirdPlan, false),
	)
	if thirdErr != nil || thirdReload.Status() != runtimegraph.ReloadApplied || runtime.Active().Generation() != 3 {
		t.Fatalf("post-failure reload=%s error=%v generation=%d", thirdReload.Status(), thirdErr, runtime.Active().Generation())
	}
}

func TestRuntimeTraceCanaryValidatesInputWithoutPanicking(t *testing.T) {
	var runtime *Runtime
	if _, err := runtime.EmitTraceCanary(t.Context(), "otlp-all"); err == nil {
		t.Fatal("nil runtime accepted canary")
	}
}
