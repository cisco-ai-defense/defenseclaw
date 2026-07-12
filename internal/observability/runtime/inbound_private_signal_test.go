// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"math/big"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

const (
	inboundTraceTargetID  = "otlp.native.span.v8.span.config.reload.span.config.reload"
	inboundMetricTargetID = "otlp.native.metric.v8.metric.defenseclaw.judge.persist.queue_depth.metric.defenseclaw.judge.persist.queue_depth"
)

func TestInboundPrivateTraceAndMetricCollectionPrecedesBuilderAndSQLite(t *testing.T) {
	traceTarget, metricTarget := inboundRuntimeSignalTargets(t)
	dependencies := newRuntimeTestDependencies(t)
	no := false
	disabledPlan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 30,
		func(source *config.ObservabilityV8Source) {
			source.Defaults.Collect.Traces = &no
			source.Defaults.Collect.Metrics = &no
		})
	disabled := newRuntimeForTest(t, dependencies, disabledPlan, false)
	batch, err := disabled.BeginInboundImportBatch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer batch.Close()
	var builds atomic.Int64
	traceResult, err := batch.ImportTrace(t.Context(), traceTarget, "codex", func(EmitContext) (observability.Record, error) {
		builds.Add(1)
		return observability.Record{}, nil
	})
	if err != nil || traceResult != (telemetry.V8ImportedSpanResult{}) || builds.Load() != 0 {
		t.Fatalf("disabled trace=%+v builds=%d err=%v", traceResult, builds.Load(), err)
	}
	metricResult, err := batch.RecordMetric(t.Context(), metricTarget, "codex", func(EmitContext) (observability.Record, error) {
		builds.Add(1)
		return observability.Record{}, nil
	})
	if err != nil || metricResult != (telemetry.V8MetricRecordResult{}) || builds.Load() != 0 {
		t.Fatalf("disabled metric=%+v builds=%d err=%v", metricResult, builds.Load(), err)
	}
	batch.Close()
	events, err := dependencies.store.ListEvents(16)
	if err != nil || len(events) != 0 {
		t.Fatalf("disabled trace/metric SQLite events=%#v err=%v", events, err)
	}
}

func TestInboundPrivateTraceAndMetricUsePinnedCanonicalPipelinesWithoutSQLite(t *testing.T) {
	traceTarget, metricTarget := inboundRuntimeSignalTargets(t)
	dependencies := newRuntimeTestDependencies(t)
	consumer := &generatedTraceConsumer{}
	metricSink := &runtimeMetricSink{started: make(chan struct{}), release: make(chan struct{})}
	options := dependencies.options()
	options.TelemetryProviderFactory = telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "8.0.0", Environment: "test", ServiceInstanceID: "inbound-private-signals",
		GenerationPipelines: func(
			context.Context,
			*config.ObservabilityV8Plan,
			uint64,
			telemetry.V8MetricReaderSpec,
		) (telemetry.V8GenerationPipelines, error) {
			return telemetry.V8GenerationPipelines{
				SpanPipelines: []telemetry.V8GenerationSpanPipeline{{
					Destination: "capture-traces", Canonical: consumer,
				}},
				MetricPipelines: []telemetry.V8GenerationMetricPipeline{{
					Destination: "capture-metrics", Projection: telemetry.V8MetricProjectionCanonical,
					SelectedFamilies: []observability.EventName{metricTarget.EventName()}, Sink: metricSink,
				}},
			}, nil
		},
	})
	yes, no := true, false
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 30,
		func(source *config.ObservabilityV8Source) {
			source.Defaults.Collect.Traces = &no
			source.Defaults.Collect.Metrics = &no
			source.Buckets = map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
				observability.BucketPlatformHealth: {
					Collect: config.ObservabilityV8CollectSource{Traces: &yes, Metrics: &yes},
				},
			}
			source.Destinations = []config.ObservabilityV8DestinationSource{
				{
					Name: "capture-traces", Kind: config.ObservabilityV8DestinationOTLP,
					Protocol: "http/protobuf", Endpoint: "https://otel.example.test",
					Send: &config.ObservabilityV8SendSource{
						Signals: []observability.Signal{observability.SignalTraces},
						Buckets: []observability.Bucket{observability.BucketPlatformHealth},
					},
				},
				{
					Name: "capture-metrics", Kind: config.ObservabilityV8DestinationOTLP,
					Protocol: "http/protobuf", Endpoint: "https://otel.example.test",
					Send: &config.ObservabilityV8SendSource{
						Signals: []observability.Signal{observability.SignalMetrics},
						Buckets: []observability.Bucket{observability.BucketPlatformHealth},
					},
				},
			}
		})
	runtime, err := New(t.Context(), runtimegraph.ConfigFromPlan(plan, false), options)
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
	batch, err := runtime.BeginInboundImportBatch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer batch.Close()
	var ids atomic.Int64
	traceResult, err := batch.ImportTrace(t.Context(), traceTarget, "codex", func(snapshot EmitContext) (observability.Record, error) {
		return inboundRuntimeTraceRecord(t, snapshot, traceTarget, &ids)
	})
	if err != nil || traceResult != (telemetry.V8ImportedSpanResult{Matched: 1, Delivered: 1}) {
		t.Fatalf("trace result=%+v err=%v", traceResult, err)
	}
	metricResult, err := batch.RecordMetric(t.Context(), metricTarget, "codex", func(snapshot EmitContext) (observability.Record, error) {
		return inboundRuntimeMetricRecord(t, snapshot, metricTarget, &ids)
	})
	if err != nil || metricResult != (telemetry.V8MetricRecordResult{Matched: 1, Delivered: 1}) {
		t.Fatalf("metric result=%+v err=%v", metricResult, err)
	}
	spans := consumer.snapshot()
	if ids.Load() != 2 || len(spans) != 1 || metricSink.records.Load() != 1 {
		t.Fatalf("IDs/traces/metrics = %d/%d/%d", ids.Load(), len(spans), metricSink.records.Load())
	}
	if spans[0].TraceID().String() != "0123456789abcdef0123456789abcdef" ||
		spans[0].SpanID().String() != "0123456789abcdef" ||
		spans[0].Name() != "config.reload" || spans[0].OTLPFlags() != 0x80000001 ||
		spans[0].ResourceDroppedAttributesCount() != 2 {
		t.Fatalf("imported canonical topology/counts = trace=%s span=%s name=%s flags=%#x resource_dropped=%d",
			spans[0].TraceID(), spans[0].SpanID(), spans[0].Name(), spans[0].OTLPFlags(),
			spans[0].ResourceDroppedAttributesCount())
	}
	assertInboundRuntimeTraceComponents(t, spans[0])
	events, err := dependencies.store.ListEvents(16)
	if err != nil || len(events) != 0 {
		t.Fatalf("trace/metric created SQLite audit rows=%#v err=%v", events, err)
	}
}

func TestOTLPInboundReloadGenerationIsolation(t *testing.T) {
	catalog, err := observability.LoadInboundCatalog()
	if err != nil {
		t.Fatal(err)
	}
	target, ok := catalog.Target("otlp.genai.span.operation.v1.span.model.chat.span.model.chat")
	if !ok {
		t.Fatal("external GenAI chat target missing")
	}
	dependencies := newRuntimeTestDependencies(t)
	firstCapture, secondCapture := &generatedTraceConsumer{}, &generatedTraceConsumer{}
	options := dependencies.options()
	options.TelemetryProviderFactory = telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "8.0.0", Environment: "test", ServiceInstanceID: "inbound-resource-reload",
		DefenseClawInstanceID: "inbound-resource-reload",
		GenerationPipelines: func(
			_ context.Context,
			_ *config.ObservabilityV8Plan,
			generation uint64,
			_ telemetry.V8MetricReaderSpec,
		) (telemetry.V8GenerationPipelines, error) {
			consumer := firstCapture
			if generation == 2 {
				consumer = secondCapture
			}
			return telemetry.V8GenerationPipelines{SpanPipelines: []telemetry.V8GenerationSpanPipeline{{
				Destination: "capture", Canonical: consumer,
			}}}, nil
		},
	})
	plan := func(retention int, marker string) *config.ObservabilityV8Plan {
		yes := true
		return runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, retention,
			func(source *config.ObservabilityV8Source) {
				source.Resource.Attributes = map[string]string{"generation.marker": marker}
				source.Buckets = map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
					observability.BucketModelIO: {Collect: config.ObservabilityV8CollectSource{Traces: &yes}},
				}
				source.Destinations = []config.ObservabilityV8DestinationSource{{
					Name: "capture", Kind: config.ObservabilityV8DestinationOTLP,
					Protocol: "http/protobuf", Endpoint: "https://otel.example.test",
					Send: &config.ObservabilityV8SendSource{
						Signals: []observability.Signal{observability.SignalTraces},
						Buckets: []observability.Bucket{observability.BucketModelIO},
					},
				}}
			})
	}
	runtime, err := New(t.Context(), runtimegraph.ConfigFromPlan(plan(30, "one"), false), options)
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

	first, err := runtime.BeginInboundImportBatch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	type reloadOutcome struct {
		result runtimegraph.ReloadResult
		err    *runtimegraph.Error
	}
	reloaded := make(chan reloadOutcome, 1)
	go func() {
		result, reloadErr := runtime.Reload(context.Background(), runtimegraph.ConfigFromPlan(plan(31, "two"), false))
		reloaded <- reloadOutcome{result: result, err: reloadErr}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.Active().Generation() != 2 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if runtime.Active().Generation() != 2 {
		t.Fatal("reload did not publish generation two")
	}

	result, err := first.ImportTrace(t.Context(), target, "codex", func(snapshot EmitContext) (observability.Record, error) {
		if snapshot.Generation() != 1 {
			t.Fatalf("pinned callback generation=%d want=1", snapshot.Generation())
		}
		return inboundExternalResourceRecord(t, snapshot, target, "0000000000000001")
	})
	if err != nil || result != (telemetry.V8ImportedSpanResult{Matched: 1, Delivered: 1}) {
		t.Fatalf("generation-one trace=%+v err=%v", result, err)
	}
	if marker := inboundCapturedResourceMarker(t, firstCapture.snapshot()); marker != "one" {
		t.Fatalf("generation-one resource marker=%q", marker)
	}
	if len(secondCapture.snapshot()) != 0 {
		t.Fatal("pinned trace crossed into generation two")
	}
	first.Close()
	select {
	case outcome := <-reloaded:
		if outcome.err != nil || outcome.result.Status() != runtimegraph.ReloadApplied {
			t.Fatalf("reload result=%s err=%v", outcome.result.Status(), outcome.err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("reload did not retire generation one")
	}

	second, err := runtime.BeginInboundImportBatch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer second.Close()
	result, err = second.ImportTrace(t.Context(), target, "codex", func(snapshot EmitContext) (observability.Record, error) {
		if snapshot.Generation() != 2 {
			t.Fatalf("new callback generation=%d want=2", snapshot.Generation())
		}
		return inboundExternalResourceRecord(t, snapshot, target, "0000000000000002")
	})
	if err != nil || result != (telemetry.V8ImportedSpanResult{Matched: 1, Delivered: 1}) {
		t.Fatalf("generation-two trace=%+v err=%v", result, err)
	}
	if marker := inboundCapturedResourceMarker(t, secondCapture.snapshot()); marker != "two" {
		t.Fatalf("generation-two resource marker=%q", marker)
	}
}

func inboundExternalResourceRecord(
	t *testing.T,
	snapshot EmitContext,
	target observability.InboundTarget,
	spanID string,
) (observability.Record, error) {
	t.Helper()
	localResource, ok := snapshot.InboundLocalTraceResource()
	if !ok {
		t.Fatal("external trace callback omitted local resource")
	}
	provenance, ok := snapshot.InboundLocalProvenance()
	if !ok {
		t.Fatal("external trace callback omitted local provenance")
	}
	instanceID, ok := snapshot.InboundLocalInstanceID()
	if !ok {
		t.Fatal("external trace callback omitted local instance")
	}
	fields := make([]observability.InboundMappedField, 0)
	for _, field := range target.RequiredBooleanInputFields() {
		fields = append(fields, observability.NewInboundMappedBoolean(field, false))
	}
	for key, value := range map[string]string{
		"defenseclaw.content.input.state":  "not_reported",
		"defenseclaw.content.output.state": "not_reported",
		"gen_ai.operation.name":            "chat",
		"gen_ai.request.model":             "gpt-4o",
	} {
		for _, field := range target.Fields() {
			if field.FieldRef() == key {
				fields = append(fields, observability.NewInboundMappedString(field, value))
			}
		}
	}
	receipt := time.Date(2026, 7, 6, 17, 0, 0, 0, time.UTC)
	builder, err := observability.NewInboundImportBuilder(
		observability.ClockFunc(func() time.Time { return time.Time{} }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return "reload-" + spanID, nil }),
	)
	if err != nil {
		return observability.Record{}, err
	}
	return builder.BuildTrace(target, observability.InboundImportedTraceInput{
		ReceiptTime: receipt,
		Correlation: observability.Correlation{
			TraceID: "0123456789abcdef0123456789abcdef", SpanID: spanID,
			SidecarInstanceID: instanceID,
		},
		Provenance: provenance,
		Import: observability.InboundImportProvenanceInput{
			AuthenticatedSource: "codex", UpstreamServiceName: "upstream-service",
		},
		Outcome: observability.Present(observability.OutcomeCompleted), Kind: "CLIENT",
		StartTimeUnixNano: uint64(receipt.Add(-2 * time.Second).UnixNano()),
		EndTimeUnixNano:   uint64(receipt.Add(-time.Second).UnixNano()),
		TraceState:        observability.Absent[string](), Flags: 1,
		Status: observability.NewTraceStatusOK(),
		Resource: observability.InboundTraceResourceInput{
			Custom: observability.Absent[observability.TelemetryCustomResourceAttributes](),
		},
		LocalResource: localResource, Fields: fields,
	})
}

func inboundCapturedResourceMarker(t *testing.T, spans []telemetry.V8CanonicalEndedSpan) string {
	t.Helper()
	if len(spans) != 1 {
		t.Fatalf("captured spans=%d want=1", len(spans))
	}
	body, present := spans[0].Record().Body()
	if !present {
		t.Fatal("captured trace body absent")
	}
	object, err := body.Object()
	if err != nil {
		t.Fatal(err)
	}
	resource := object["resource"].(map[string]any)
	attributes := resource["attributes"].(map[string]any)
	marker, _ := attributes["generation.marker"].(string)
	return marker
}

func TestInboundPrivateSignalsSuppressOnlyAuthenticatedOriginAndSealTerminalHop(t *testing.T) {
	traceTarget, metricTarget := inboundRuntimeSignalTargets(t)
	dependencies := newRuntimeTestDependencies(t)
	originTrace, siblingTrace := &generatedTraceConsumer{}, &generatedTraceConsumer{}
	originMetric := &runtimeMetricSink{started: make(chan struct{}), release: make(chan struct{})}
	siblingMetric := &runtimeMetricSink{started: make(chan struct{}), release: make(chan struct{})}
	options := dependencies.options()
	options.TelemetryProviderFactory = telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "8.0.0", Environment: "test", ServiceInstanceID: "inbound-origin-signals",
		GenerationPipelines: func(
			context.Context,
			*config.ObservabilityV8Plan,
			uint64,
			telemetry.V8MetricReaderSpec,
		) (telemetry.V8GenerationPipelines, error) {
			return telemetry.V8GenerationPipelines{
				SpanPipelines: []telemetry.V8GenerationSpanPipeline{
					{Destination: "upstream-otlp", Canonical: originTrace},
					{Destination: "sibling", Canonical: siblingTrace},
				},
				MetricPipelines: []telemetry.V8GenerationMetricPipeline{
					{Destination: "upstream-otlp", Projection: telemetry.V8MetricProjectionCanonical,
						SelectedFamilies: []observability.EventName{metricTarget.EventName()}, Sink: originMetric},
					{Destination: "sibling", Projection: telemetry.V8MetricProjectionCanonical,
						SelectedFamilies: []observability.EventName{metricTarget.EventName()}, Sink: siblingMetric},
				},
			}, nil
		},
	})
	yes, no := true, false
	plan := runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 30,
		func(source *config.ObservabilityV8Source) {
			source.Defaults.Collect.Traces = &no
			source.Defaults.Collect.Metrics = &no
			source.Buckets = map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
				observability.BucketPlatformHealth: {
					Collect: config.ObservabilityV8CollectSource{Traces: &yes, Metrics: &yes},
				},
			}
			signals := []observability.Signal{observability.SignalTraces, observability.SignalMetrics}
			buckets := []observability.Bucket{observability.BucketPlatformHealth}
			source.Destinations = []config.ObservabilityV8DestinationSource{
				{Name: "upstream-otlp", Kind: config.ObservabilityV8DestinationOTLP,
					Protocol: "http/protobuf", Endpoint: "https://origin.example.test",
					Send: &config.ObservabilityV8SendSource{Signals: signals, Buckets: buckets}},
				{Name: "sibling", Kind: config.ObservabilityV8DestinationOTLP,
					Protocol: "http/protobuf", Endpoint: "https://sibling.example.test",
					Send: &config.ObservabilityV8SendSource{Signals: signals, Buckets: buckets}},
			}
		})
	runtime, err := New(t.Context(), runtimegraph.ConfigFromPlan(plan, false), options)
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
	batch, err := runtime.BeginInboundImportBatch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	defer batch.Close()
	originPolicy, err := NewInboundOriginDestination("upstream-otlp")
	if err != nil {
		t.Fatal(err)
	}
	var ids atomic.Int64

	traceResult, err := batch.ImportTraceWithPolicy(
		t.Context(), traceTarget, "codex", originPolicy,
		func(snapshot EmitContext) (observability.Record, error) {
			return inboundRuntimeTraceRecord(t, snapshot, traceTarget, &ids)
		},
	)
	if err != nil || traceResult != (telemetry.V8ImportedSpanResult{
		Matched: 1, Delivered: 1, Suppressed: 1,
	}) {
		t.Fatalf("origin trace=%+v err=%v", traceResult, err)
	}
	metricResult, err := batch.RecordMetricWithPolicy(
		t.Context(), metricTarget, "codex", originPolicy,
		func(snapshot EmitContext) (observability.Record, error) {
			return inboundRuntimeMetricRecord(t, snapshot, metricTarget, &ids)
		},
	)
	if err != nil || metricResult != (telemetry.V8MetricRecordResult{
		Matched: 1, Delivered: 1, Suppressed: 1,
	}) {
		t.Fatalf("origin metric=%+v err=%v", metricResult, err)
	}
	if len(originTrace.snapshot()) != 0 || len(siblingTrace.snapshot()) != 1 ||
		originMetric.records.Load() != 0 || siblingMetric.records.Load() != 1 {
		t.Fatalf("origin fanout traces=%d/%d metrics=%d/%d",
			len(originTrace.snapshot()), len(siblingTrace.snapshot()),
			originMetric.records.Load(), siblingMetric.records.Load())
	}

	// Identical last_hop_destination provenance is foreign input and cannot
	// suppress anything without the local authenticated policy.
	traceResult, err = batch.ImportTrace(
		t.Context(), traceTarget, "codex",
		func(snapshot EmitContext) (observability.Record, error) {
			return inboundRuntimeTraceRecord(t, snapshot, traceTarget, &ids)
		},
	)
	if err != nil || traceResult != (telemetry.V8ImportedSpanResult{Matched: 2, Delivered: 2}) {
		t.Fatalf("foreign trace=%+v err=%v", traceResult, err)
	}
	metricResult, err = batch.RecordMetric(
		t.Context(), metricTarget, "codex",
		func(snapshot EmitContext) (observability.Record, error) {
			return inboundRuntimeMetricRecord(t, snapshot, metricTarget, &ids)
		},
	)
	if err != nil || metricResult != (telemetry.V8MetricRecordResult{Matched: 2, Delivered: 2}) {
		t.Fatalf("foreign metric=%+v err=%v", metricResult, err)
	}

	beforeTerminal := ids.Load()
	traceResult, err = batch.ImportTraceWithPolicy(
		t.Context(), traceTarget, "codex", SuppressAllInboundOptionalExport(),
		func(snapshot EmitContext) (observability.Record, error) {
			return inboundRuntimeTraceRecord(t, snapshot, traceTarget, &ids)
		},
	)
	if err != nil || traceResult != (telemetry.V8ImportedSpanResult{Suppressed: 2}) {
		t.Fatalf("terminal trace=%+v err=%v", traceResult, err)
	}
	metricResult, err = batch.RecordMetricWithPolicy(
		t.Context(), metricTarget, "codex", SuppressAllInboundOptionalExport(),
		func(snapshot EmitContext) (observability.Record, error) {
			return inboundRuntimeMetricRecord(t, snapshot, metricTarget, &ids)
		},
	)
	if err != nil || metricResult != (telemetry.V8MetricRecordResult{Suppressed: 2}) ||
		ids.Load() != beforeTerminal+2 {
		t.Fatalf("terminal metric=%+v ids=%d before=%d err=%v",
			metricResult, ids.Load(), beforeTerminal, err)
	}
	if len(originTrace.snapshot()) != 1 || len(siblingTrace.snapshot()) != 2 ||
		originMetric.records.Load() != 1 || siblingMetric.records.Load() != 2 {
		t.Fatalf("terminal leaked traces=%d/%d metrics=%d/%d",
			len(originTrace.snapshot()), len(siblingTrace.snapshot()),
			originMetric.records.Load(), siblingMetric.records.Load())
	}

	beforeCanceled := ids.Load()
	canceledContext, cancelCanceledContext := context.WithCancel(t.Context())
	cancelCanceledContext()
	if _, err := batch.ImportTrace(
		canceledContext, traceTarget, "codex",
		func(snapshot EmitContext) (observability.Record, error) {
			return inboundRuntimeTraceRecord(t, snapshot, traceTarget, &ids)
		},
	); !errors.Is(err, context.Canceled) || ids.Load() != beforeCanceled {
		t.Fatalf("pre-canceled trace ids=%d before=%d err=%v", ids.Load(), beforeCanceled, err)
	}

	boundaryContext, cancelBoundaryContext := context.WithCancel(t.Context())
	defer cancelBoundaryContext()
	if _, err := batch.ImportTrace(
		boundaryContext, traceTarget, "codex",
		func(snapshot EmitContext) (observability.Record, error) {
			record, buildErr := inboundRuntimeTraceRecord(t, snapshot, traceTarget, &ids)
			cancelBoundaryContext()
			return record, buildErr
		},
	); !errors.Is(err, context.Canceled) || ids.Load() != beforeCanceled+1 ||
		len(originTrace.snapshot()) != 1 || len(siblingTrace.snapshot()) != 2 {
		t.Fatalf("builder-canceled trace ids=%d before=%d traces=%d/%d err=%v",
			ids.Load(), beforeCanceled, len(originTrace.snapshot()), len(siblingTrace.snapshot()), err)
	}

	beforeInvalid := ids.Load()
	invalid := InboundOptionalExportPolicy{originDestination: "not a stable token"}
	if _, err := batch.ImportTraceWithPolicy(
		t.Context(), traceTarget, "codex", invalid,
		func(snapshot EmitContext) (observability.Record, error) {
			return inboundRuntimeTraceRecord(t, snapshot, traceTarget, &ids)
		},
	); err == nil || ids.Load() != beforeInvalid {
		t.Fatalf("invalid trace ids=%d before=%d err=%v", ids.Load(), beforeInvalid, err)
	}
	if _, err := batch.RecordMetricWithPolicy(
		t.Context(), metricTarget, "codex", invalid,
		func(snapshot EmitContext) (observability.Record, error) {
			return inboundRuntimeMetricRecord(t, snapshot, metricTarget, &ids)
		},
	); err == nil || ids.Load() != beforeInvalid {
		t.Fatalf("invalid metric ids=%d before=%d err=%v", ids.Load(), beforeInvalid, err)
	}
	events, err := dependencies.store.ListEvents(16)
	if err != nil || len(events) != 0 {
		t.Fatalf("signal policies created SQLite rows=%#v err=%v", events, err)
	}
}

func inboundRuntimeSignalTargets(t *testing.T) (observability.InboundTarget, observability.InboundTarget) {
	t.Helper()
	catalog, err := observability.LoadInboundCatalog()
	if err != nil {
		t.Fatal(err)
	}
	traceTarget, ok := catalog.Target(inboundTraceTargetID)
	if !ok {
		t.Fatalf("missing target %s", inboundTraceTargetID)
	}
	metricTarget, ok := catalog.Target(inboundMetricTargetID)
	if !ok {
		t.Fatalf("missing target %s", inboundMetricTargetID)
	}
	return traceTarget, metricTarget
}

func inboundRuntimeTraceRecord(
	t *testing.T,
	snapshot EmitContext,
	target observability.InboundTarget,
	ids *atomic.Int64,
) (observability.Record, error) {
	t.Helper()
	builder, err := observability.NewInboundImportBuilder(
		observability.ClockFunc(func() time.Time { return time.Time{} }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			ids.Add(1)
			return "inbound-runtime-trace", nil
		}),
	)
	if err != nil {
		return observability.Record{}, err
	}
	resource := map[string]string{
		"service.name": "upstream-service", "service.namespace": "upstream",
		"service.instance.id":         "upstream-service-instance",
		"deployment.environment.name": "test", "defenseclaw.instance.id": "upstream-instance",
	}
	resourceFields := make([]observability.InboundMappedField, 0, len(resource))
	for key, value := range resource {
		resourceFields = append(resourceFields,
			observability.NewInboundMappedString(inboundRuntimeResourceField(t, target, key), value))
	}
	receipt := time.Date(2026, 7, 6, 15, 0, 0, 0, time.UTC)
	var eventTarget observability.InboundTraceEventTarget
	for _, candidate := range target.TraceEvents() {
		if candidate.Name() == "exception" {
			eventTarget = candidate
			break
		}
	}
	eventTime := uint64(receipt.Add(-1500 * time.Millisecond).UnixNano())
	event, err := observability.NewInboundTraceEvent(
		eventTarget, eventTime, observability.Present[uint32](6), nil,
	)
	if err != nil {
		return observability.Record{}, err
	}
	link, err := observability.NewInboundTraceLink(
		target, observability.InboundTraceLinkDerivedFrom,
		"fedcba9876543210fedcba9876543210", "fedcba9876543210",
		observability.Present("lk=import"), observability.Present[uint32](7),
	)
	if err != nil {
		return observability.Record{}, err
	}
	return builder.BuildTrace(target, observability.InboundImportedTraceInput{
		ReceiptTime: receipt,
		Correlation: observability.Correlation{
			TraceID: "0123456789abcdef0123456789abcdef", SpanID: "0123456789abcdef",
		},
		Provenance: observability.InboundLocalProvenanceInput{
			BinaryVersion: "8.0.0", ConfigGeneration: int64(snapshot.Generation()),
			ConfigDigest: snapshot.Digest(),
		},
		Import: observability.InboundImportProvenanceInput{
			AuthenticatedSource: "codex", UpstreamInstanceID: "upstream-instance",
			UpstreamRecordID: "upstream-span", IngressHopCount: 1,
			LastHopInstanceID: "forwarder-instance", LastHopDestination: "upstream-otlp",
		},
		Outcome: observability.Present(observability.OutcomeApplied), Kind: "INTERNAL",
		NativeSpanName:    observability.Present("config.reload"),
		StartTimeUnixNano: uint64(receipt.Add(-2 * time.Second).UnixNano()),
		EndTimeUnixNano:   uint64(receipt.Add(-time.Second).UnixNano()),
		ParentSpanID:      observability.Absent[string](), TraceState: observability.Present("dc=import"),
		Flags: 0x80000001, Status: observability.NewTraceStatusOK(),
		Resource: observability.InboundTraceResourceInput{
			Fields:                 resourceFields,
			DroppedAttributesCount: observability.Present[uint32](2),
			Custom:                 observability.Absent[observability.TelemetryCustomResourceAttributes](),
		},
		ScopeDroppedCount: observability.Present[uint32](1), Fields: nil,
		Events: []observability.TraceEventInput{event}, DroppedEventsCount: observability.Present[uint32](3),
		Links: []observability.TraceLinkInput{link}, DroppedLinksCount: observability.Present[uint32](4),
		DroppedAttributesCount: observability.Present[uint32](5),
	})
}

func assertInboundRuntimeTraceComponents(t *testing.T, span telemetry.V8CanonicalEndedSpan) {
	t.Helper()
	record := span.Record()
	body, present := record.Body()
	if !present {
		t.Fatal("handed-off imported trace omitted body")
	}
	object, err := body.Object()
	if err != nil {
		t.Fatal(err)
	}
	events, ok := object["events"].([]any)
	if !ok || len(events) != 1 {
		t.Fatalf("handed-off events = %#v", object["events"])
	}
	event, ok := events[0].(map[string]any)
	if !ok || event["name"] != "exception" ||
		inboundRuntimeUint64(t, event["time_unix_nano"]) != 1783349998500000000 ||
		inboundRuntimeUint64(t, event["dropped_attributes_count"]) != 6 {
		t.Fatalf("handed-off event = %#v", events[0])
	}
	if attributes, ok := event["attributes"].(map[string]any); !ok || len(attributes) != 0 {
		t.Fatalf("handed-off event attributes = %#v", event["attributes"])
	}
	links, ok := object["links"].([]any)
	if !ok || len(links) != 1 {
		t.Fatalf("handed-off links = %#v", object["links"])
	}
	link, ok := links[0].(map[string]any)
	if !ok || link["trace_id"] != "fedcba9876543210fedcba9876543210" ||
		link["span_id"] != "fedcba9876543210" || link["trace_state"] != "lk=import" ||
		inboundRuntimeUint64(t, link["dropped_attributes_count"]) != 7 {
		t.Fatalf("handed-off link = %#v", links[0])
	}
	attributes, ok := link["attributes"].(map[string]any)
	if !ok || attributes["defenseclaw.link.relation"] != "derived_from" {
		t.Fatalf("handed-off link attributes = %#v", link["attributes"])
	}
	if inboundRuntimeUint64(t, object["dropped_events_count"]) != 3 ||
		inboundRuntimeUint64(t, object["dropped_links_count"]) != 4 ||
		inboundRuntimeUint64(t, object["dropped_attributes_count"]) != 5 {
		t.Fatalf("handed-off dropped counts = events:%v links:%v attrs:%v",
			object["dropped_events_count"], object["dropped_links_count"], object["dropped_attributes_count"])
	}
	encoded, err := record.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	for _, fragment := range [][]byte{
		[]byte(`"name":"exception"`), []byte(`"time_unix_nano":1.7833499985e18`),
		[]byte(`"defenseclaw.link.relation":"derived_from"`),
		[]byte(`"trace_id":"fedcba9876543210fedcba9876543210"`),
		[]byte(`"trace_state":"lk=import"`),
	} {
		if !bytes.Contains(encoded, fragment) {
			t.Fatalf("serialized imported trace lacks %s", fragment)
		}
	}
}

func inboundRuntimeUint64(t *testing.T, value any) uint64 {
	t.Helper()
	number, ok := value.(json.Number)
	if !ok {
		t.Fatalf("canonical count/time type = %T, want json.Number", value)
	}
	rational, ok := new(big.Rat).SetString(number.String())
	if !ok || !rational.IsInt() || !rational.Num().IsUint64() {
		t.Fatalf("canonical count/time = %q, want uint64", number)
	}
	return rational.Num().Uint64()
}

func inboundRuntimeMetricRecord(
	t *testing.T,
	snapshot EmitContext,
	target observability.InboundTarget,
	ids *atomic.Int64,
) (observability.Record, error) {
	t.Helper()
	if _, available := snapshot.InboundLocalTraceResource(); available {
		t.Fatal("metric callback acquired a trace-only local-resource capability")
	}
	if _, available := snapshot.InboundLocalProvenance(); !available {
		t.Fatal("metric callback omitted its pinned inbound provenance")
	}
	if _, available := snapshot.InboundLocalInstanceID(); !available {
		t.Fatal("metric callback omitted its pinned local instance")
	}
	builder, err := observability.NewInboundImportBuilder(
		observability.ClockFunc(func() time.Time { return time.Time{} }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			ids.Add(1)
			return "inbound-runtime-metric", nil
		}),
	)
	if err != nil {
		return observability.Record{}, err
	}
	receipt := time.Date(2026, 7, 6, 15, 0, 0, 0, time.UTC)
	return builder.BuildMetric(target, observability.InboundImportedMetricInput{
		Timestamp: receipt.Add(-time.Second), ReceiptTime: receipt,
		Provenance: observability.InboundLocalProvenanceInput{
			BinaryVersion: "8.0.0", ConfigGeneration: int64(snapshot.Generation()),
			ConfigDigest: snapshot.Digest(),
		},
		Import: observability.InboundImportProvenanceInput{
			AuthenticatedSource: "codex", UpstreamInstanceID: "upstream-instance",
			IngressHopCount: 1, LastHopInstanceID: "forwarder-instance",
			LastHopDestination: "upstream-otlp",
		},
		SourcePoint: observability.NewInboundMetricGaugeSource("{item}"),
		Value:       observability.NewInboundMetricInt64Value(7),
	})
}

func inboundRuntimeResourceField(
	t *testing.T,
	target observability.InboundTarget,
	key string,
) observability.InboundTargetField {
	t.Helper()
	for _, field := range target.TraceResourceFields() {
		if field.FieldRef() == key {
			return field
		}
	}
	t.Fatalf("target %s lacks resource field %s", target.ID(), key)
	return observability.InboundTargetField{}
}
