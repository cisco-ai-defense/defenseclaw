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

const generatedMetricFamily = observability.EventName("defenseclaw.connector.hook.latency")
const generatedMetricBatchFamily = observability.EventName("defenseclaw.connector.hook.invocations")

type runtimeMetricSink struct {
	started      chan struct{}
	release      chan struct{}
	block        atomic.Bool
	records      atomic.Int64
	shutdown     atomic.Int64
	startOnce    sync.Once
	shutdownOnce sync.Once
}

func (sink *runtimeMetricSink) RecordMetric(context.Context, telemetry.V8ProjectedMetric) error {
	sink.records.Add(1)
	if sink.block.Load() {
		sink.startOnce.Do(func() { close(sink.started) })
		<-sink.release
	}
	return nil
}
func (*runtimeMetricSink) ForceFlush(context.Context) error { return nil }
func (sink *runtimeMetricSink) Shutdown(context.Context) error {
	sink.shutdownOnce.Do(func() { sink.shutdown.Add(1) })
	return nil
}

type runtimeMetricPipelines struct {
	mu    sync.Mutex
	sinks map[uint64]*runtimeMetricSink
}

func (pipelines *runtimeMetricPipelines) build(
	_ context.Context,
	plan *config.ObservabilityV8Plan,
	generation uint64,
	_ telemetry.V8MetricReaderSpec,
) (telemetry.V8GenerationPipelines, error) {
	collected := false
	for _, bucket := range plan.Snapshot().Buckets {
		collected = collected || bucket.Collect.Metrics
	}
	if !collected {
		return telemetry.V8GenerationPipelines{}, nil
	}
	sink := &runtimeMetricSink{started: make(chan struct{}), release: make(chan struct{})}
	pipelines.mu.Lock()
	pipelines.sinks[generation] = sink
	pipelines.mu.Unlock()
	return telemetry.V8GenerationPipelines{MetricPipelines: []telemetry.V8GenerationMetricPipeline{{
		Destination: "capture", Projection: telemetry.V8MetricProjectionCanonical,
		SelectedFamilies: []observability.EventName{generatedMetricFamily, generatedMetricBatchFamily}, Sink: sink,
	}}}, nil
}

func (pipelines *runtimeMetricPipelines) sink(t *testing.T, generation uint64) *runtimeMetricSink {
	t.Helper()
	pipelines.mu.Lock()
	defer pipelines.mu.Unlock()
	sink := pipelines.sinks[generation]
	if sink == nil {
		t.Fatalf("generation %d metric sink missing", generation)
	}
	return sink
}

func runtimeGeneratedMetricPlan(
	t *testing.T,
	dependencies runtimeTestDependencies,
	metricBucket observability.Bucket,
) *config.ObservabilityV8Plan {
	t.Helper()
	return runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 30,
		func(source *config.ObservabilityV8Source) {
			no, yes := false, true
			source.Defaults.Collect.Metrics = &no
			source.Buckets = map[observability.Bucket]config.ObservabilityV8BucketPolicySource{}
			if metricBucket != "" {
				source.Buckets[metricBucket] = config.ObservabilityV8BucketPolicySource{
					Collect: config.ObservabilityV8CollectSource{Metrics: &yes},
				}
			}
		})
}

func runtimeGeneratedMetricRecord(
	t *testing.T,
	snapshot EmitContext,
) (observability.Record, error) {
	t.Helper()
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return time.Unix(200, 0).UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return "runtime-metric-1", nil }),
	)
	if err != nil {
		return observability.Record{}, err
	}
	return builder.BuildMetricDefenseClawConnectorHookLatency(
		observability.MetricDefenseClawConnectorHookLatencyInput{
			Envelope: observability.FamilyEnvelopeInput{
				Source: "gateway",
				Provenance: observability.FamilyProvenanceInput{
					Producer: "defenseclaw", BinaryVersion: "8.0.0",
					ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
				},
			},
			Value: 5, DefenseClawConnectorSource: observability.Present("codex"),
			DefenseClawMetricEventType: observability.Present("prompt"),
			DefenseClawMetricReason:    observability.Present("allow"),
			DefenseClawMetricResult:    observability.Present("ok"),
		},
	)
}

func runtimeGeneratedMetricBatchRecord(
	t *testing.T,
	snapshot EmitContext,
) (observability.Record, error) {
	t.Helper()
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return time.Unix(201, 0).UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return "runtime-metric-2", nil }),
	)
	if err != nil {
		return observability.Record{}, err
	}
	return builder.BuildMetricDefenseClawConnectorHookInvocations(
		observability.MetricDefenseClawConnectorHookInvocationsInput{
			Envelope: observability.FamilyEnvelopeInput{
				Source: "gateway",
				Provenance: observability.FamilyProvenanceInput{
					Producer: "defenseclaw", BinaryVersion: "8.0.0",
					ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
				},
			},
			Value: 1, DefenseClawConnectorSource: observability.Present("codex"),
			DefenseClawMetricEventType: observability.Present("prompt"),
			DefenseClawMetricReason:    observability.Present("allow"),
			DefenseClawMetricResult:    observability.Present("ok"),
		},
	)
}

func TestGeneratedMetricBatchIsLazyBoundedAndGenerationPinned(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	pipelines := &runtimeMetricPipelines{sinks: make(map[uint64]*runtimeMetricSink)}
	options := dependencies.options()
	options.TelemetryProviderFactory = telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "8.0.0", Environment: "test", ServiceInstanceID: "generated-metric-batch",
		GenerationPipelines: pipelines.build,
	})
	disabled := runtimeGeneratedMetricPlan(t, dependencies, "")
	runtime, err := New(t.Context(), runtimegraph.ConfigFromPlan(disabled, false), options)
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
	var builds atomic.Int64
	var generationsMu sync.Mutex
	var generations []uint64
	item := func(family observability.EventName, build GeneratedMetricBuilder) GeneratedMetricBatchItem {
		return GeneratedMetricBatchItem{Family: family, Builder: func(snapshot EmitContext) (observability.Record, error) {
			builds.Add(1)
			generationsMu.Lock()
			generations = append(generations, snapshot.Generation())
			generationsMu.Unlock()
			return build(snapshot)
		}}
	}
	items := []GeneratedMetricBatchItem{
		item(generatedMetricFamily, func(snapshot EmitContext) (observability.Record, error) {
			return runtimeGeneratedMetricRecord(t, snapshot)
		}),
		item(generatedMetricBatchFamily, func(snapshot EmitContext) (observability.Record, error) {
			return runtimeGeneratedMetricBatchRecord(t, snapshot)
		}),
	}
	results, batchErr := runtime.RecordGeneratedMetricBatch(t.Context(), items)
	if batchErr != nil || len(results) != 2 || builds.Load() != 0 {
		t.Fatalf("disabled results=%+v builds=%d err=%v", results, builds.Load(), batchErr)
	}
	enabled := runtimeGeneratedMetricPlan(t, dependencies, observability.BucketAgentLifecycle)
	if result, reloadErr := runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(enabled, false)); reloadErr != nil || result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("enable reload=%s err=%v", result.Status(), reloadErr)
	}
	results, batchErr = runtime.RecordGeneratedMetricBatch(t.Context(), items)
	if batchErr != nil || len(results) != 2 || builds.Load() != 2 {
		t.Fatalf("enabled results=%+v builds=%d err=%v", results, builds.Load(), batchErr)
	}
	for index, result := range results {
		if result != (telemetry.V8MetricRecordResult{Matched: 1, Delivered: 1}) {
			t.Fatalf("result[%d]=%+v", index, result)
		}
	}
	generationsMu.Lock()
	gotGenerations := append([]uint64(nil), generations...)
	generationsMu.Unlock()
	if len(gotGenerations) != 2 || gotGenerations[0] != 2 || gotGenerations[1] != 2 {
		t.Fatalf("batch generations=%v, want [2 2]", gotGenerations)
	}
	if pipelines.sink(t, 2).records.Load() != 2 {
		t.Fatalf("batch sink records=%d, want 2", pipelines.sink(t, 2).records.Load())
	}
	before := builds.Load()
	invalid := items[0]
	invalid.Builder = nil
	if _, err := runtime.RecordGeneratedMetricBatch(t.Context(), []GeneratedMetricBatchItem{invalid}); err == nil || builds.Load() != before {
		t.Fatalf("invalid batch error=%v builds=%d want=%d", err, builds.Load(), before)
	}
	tooLarge := make([]GeneratedMetricBatchItem, MaxGeneratedMetricBatchItems+1)
	for index := range tooLarge {
		tooLarge[index] = items[index%len(items)]
	}
	if _, err := runtime.RecordGeneratedMetricBatch(t.Context(), tooLarge); err == nil || builds.Load() != before {
		t.Fatalf("oversized batch error=%v builds=%d want=%d", err, builds.Load(), before)
	}
}

func TestGeneratedMetricRuntimeGatesBeforeBuilderAndPinsLeaseThroughRecord(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	pipelines := &runtimeMetricPipelines{sinks: make(map[uint64]*runtimeMetricSink)}
	options := dependencies.options()
	options.TelemetryProviderFactory = telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "8.0.0", Environment: "test", ServiceInstanceID: "generated-metric-runtime",
		GenerationPipelines: pipelines.build,
	})
	disabled := runtimeGeneratedMetricPlan(t, dependencies, "")
	runtime, err := New(t.Context(), runtimegraph.ConfigFromPlan(disabled, false), options)
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
	var builds atomic.Int64
	build := func(snapshot EmitContext) (observability.Record, error) {
		builds.Add(1)
		return runtimeGeneratedMetricRecord(t, snapshot)
	}
	unregistered := observability.EventName("defenseclaw.test.unregistered.metric")
	unregisteredResult, recordErr := runtime.RecordGeneratedMetric(t.Context(), unregistered, build)
	metricErr, typed := recordErr.(*GeneratedMetricError)
	if unregisteredResult != (telemetry.V8MetricRecordResult{}) || !typed ||
		metricErr.Code() != GeneratedMetricInvalidInput || builds.Load() != 0 {
		t.Fatalf("unregistered result=%+v builds=%d err=%v", unregisteredResult, builds.Load(), recordErr)
	}
	if result, recordErr := runtime.RecordGeneratedMetric(t.Context(), generatedMetricFamily, build); recordErr != nil ||
		result != (telemetry.V8MetricRecordResult{}) || builds.Load() != 0 {
		t.Fatalf("disabled result=%+v builds=%d err=%v", result, builds.Load(), recordErr)
	}
	enabled := runtimeGeneratedMetricPlan(t, dependencies, observability.BucketAgentLifecycle)
	result, reloadErr := runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(enabled, false))
	if reloadErr != nil || result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("enable reload=%s err=%v", result.Status(), reloadErr)
	}
	if recorded, recordErr := runtime.RecordGeneratedMetric(t.Context(), generatedMetricFamily, build); recordErr != nil ||
		recorded != (telemetry.V8MetricRecordResult{Matched: 1, Delivered: 1}) || builds.Load() != 1 {
		t.Fatalf("enabled result=%+v builds=%d err=%v", recorded, builds.Load(), recordErr)
	}
	second := pipelines.sink(t, 2)
	second.block.Store(true)
	done := make(chan error, 1)
	go func() {
		_, recordErr := runtime.RecordGeneratedMetric(context.Background(), generatedMetricFamily, build)
		done <- recordErr
	}()
	select {
	case <-second.started:
	case <-time.After(5 * time.Second):
		t.Fatal("metric sink did not start")
	}
	third := runtimeGeneratedMetricPlan(t, dependencies, observability.BucketAssetScan)
	type reloadOutcome struct {
		result runtimegraph.ReloadResult
		err    *runtimegraph.Error
	}
	reloaded := make(chan reloadOutcome, 1)
	go func() {
		result, reloadErr := runtime.Reload(context.Background(), runtimegraph.ConfigFromPlan(third, false))
		reloaded <- reloadOutcome{result: result, err: reloadErr}
	}()
	time.Sleep(20 * time.Millisecond)
	if second.shutdown.Load() != 0 {
		t.Fatal("old generation metric sink retired while its record lease was active")
	}
	close(second.release)
	if recordErr := <-done; recordErr != nil {
		t.Fatalf("leased record failed across reload: %v", recordErr)
	}
	select {
	case outcome := <-reloaded:
		if outcome.err != nil || outcome.result.Status() != runtimegraph.ReloadApplied {
			t.Fatalf("third reload=%s err=%v", outcome.result.Status(), outcome.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reload did not finish after metric lease released")
	}
	deadline := time.Now().Add(5 * time.Second)
	for second.shutdown.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if second.shutdown.Load() != 1 || second.records.Load() != 2 {
		t.Fatalf("old generation sink records=%d shutdown=%d", second.records.Load(), second.shutdown.Load())
	}
}
