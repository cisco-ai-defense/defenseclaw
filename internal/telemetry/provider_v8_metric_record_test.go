// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"errors"
	"reflect"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

type v8MetricCaptureSink struct {
	mu       sync.Mutex
	records  []V8ProjectedMetric
	flushed  int
	shutdown int
	flushErr error
}

func (sink *v8MetricCaptureSink) RecordMetric(_ context.Context, metric V8ProjectedMetric) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.records = append(sink.records, metric)
	return nil
}
func (sink *v8MetricCaptureSink) ForceFlush(context.Context) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.flushed++
	return sink.flushErr
}

type v8MetricValueSink struct{}

func (v8MetricValueSink) RecordMetric(context.Context, V8ProjectedMetric) error { return nil }
func (v8MetricValueSink) ForceFlush(context.Context) error                      { return nil }
func (v8MetricValueSink) Shutdown(context.Context) error                        { return nil }
func (sink *v8MetricCaptureSink) Shutdown(context.Context) error {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	sink.shutdown++
	return nil
}

func buildV8HookLatencyMetric(t *testing.T, generation int64, digest string) observability.Record {
	t.Helper()
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return time.Unix(100, 0).UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return "metric-record-1", nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	record, err := builder.BuildMetricDefenseClawConnectorHookLatency(
		observability.MetricDefenseClawConnectorHookLatencyInput{
			Envelope: observability.FamilyEnvelopeInput{
				Source: "gateway",
				Provenance: observability.FamilyProvenanceInput{
					Producer: "defenseclaw", BinaryVersion: "8.0.0",
					ConfigGeneration: generation, ConfigDigest: digest,
				},
			},
			Value:                      17.5,
			DefenseClawConnectorSource: observability.Present("codex"),
			DefenseClawMetricEventType: observability.Present("prompt"),
			DefenseClawMetricReason:    observability.Present("allow"),
			DefenseClawMetricResult:    observability.Present("ok"),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func TestGeneratedMetricCatalogPreservesContractsAndBoundaryNull(t *testing.T) {
	descriptors, err := V8MetricDescriptorCatalog()
	if err != nil {
		t.Fatal(err)
	}
	if len(descriptors) == 0 {
		t.Fatal("generated metric descriptor catalog is empty")
	}
	var counter, histogram V8MetricDescriptor
	for _, descriptor := range descriptors {
		if descriptor.CardinalityLimit != 2_048 || descriptor.InstrumentType == "" ||
			descriptor.ValueType == "" || descriptor.Unit == "" || descriptor.Temporality == "" {
			t.Fatalf("incomplete descriptor=%+v", descriptor)
		}
		switch descriptor.Name {
		case "defenseclaw.activity.total":
			counter = descriptor
		case "defenseclaw.activity.diff_entries":
			histogram = descriptor
		}
	}
	if !counter.BoundariesNull || counter.Boundaries != nil || counter.InstrumentType != "counter" ||
		histogram.BoundariesNull || histogram.Boundaries == nil || len(histogram.Boundaries) != 0 ||
		histogram.InstrumentType != "histogram" {
		t.Fatalf("authored boundaries lost: counter=%+v histogram=%+v", counter, histogram)
	}
	// Every returned slice is detached, including an authored empty slice.
	descriptors[0].AllowedLabels = append(descriptors[0].AllowedLabels, "mutated")
	descriptors[0].LocalLabelMapping = append(descriptors[0].LocalLabelMapping, V8MetricLabelMapping{Canonical: "x", Local: "y"})
	fresh, err := V8MetricDescriptorCatalog()
	if err != nil || reflect.DeepEqual(descriptors[0], fresh[0]) {
		t.Fatal("descriptor catalog aliases a caller snapshot")
	}
}

func TestGeneratedMetricDescriptorRejectsAliasCollisionWithUnchangedLabel(t *testing.T) {
	descriptor, ok := v8MetricDescriptorByName("defenseclaw.activity.total")
	if !ok || len(descriptor.LocalLabelMapping) == 0 {
		t.Fatal("activity descriptor or aliases missing")
	}
	descriptor.AllowedLabels = append(descriptor.AllowedLabels, descriptor.LocalLabelMapping[0].Local)
	if err := validateV8MetricDescriptor(
		descriptor, "otel_sdk_metric_v1", observability.RuntimeLocalObservabilityProfile,
	); err == nil {
		t.Fatal("metric descriptor accepted an alias collision with an unchanged canonical label")
	}
}

func TestGeneratedMetricRecorderProjectsCanonicalAndLocalIndependently(t *testing.T) {
	canonical, local := &v8MetricCaptureSink{}, &v8MetricCaptureSink{}
	family := observability.EventName("defenseclaw.connector.hook.latency")
	recorder, err := newV8MetricRecorder(7, "abc123", map[observability.Bucket]bool{
		observability.BucketAgentLifecycle: true,
	}, []V8GenerationMetricPipeline{
		{Destination: "generic-otlp", Projection: V8MetricProjectionCanonical, SelectedFamilies: []observability.EventName{family}, Sink: canonical},
		{Destination: "local-observability", Projection: V8MetricProjectionLocal, SelectedFamilies: []observability.EventName{family}, Sink: local},
	})
	if err != nil {
		t.Fatal(err)
	}
	recorder.setActive(true)
	result, err := recorder.record(context.Background(), buildV8HookLatencyMetric(t, 7, "abc123"))
	if err != nil || result != (V8MetricRecordResult{Matched: 2, Delivered: 2}) {
		t.Fatalf("record result=%+v err=%v", result, err)
	}
	canonicalRecord := canonical.records[0]
	localRecord := local.records[0]
	wantCanonical := map[string]any{
		"defenseclaw.connector.source": "codex", "defenseclaw.metric.event_type": "prompt",
		"defenseclaw.metric.reason": "allow", "defenseclaw.metric.result": "ok",
	}
	wantLocal := map[string]any{
		"connector": "codex", "event_type": "prompt", "reason": "allow", "result": "ok",
	}
	if canonicalRecord.Profile() != "" || localRecord.Profile() != observability.RuntimeLocalObservabilityProfile ||
		!reflect.DeepEqual(canonicalRecord.Attributes(), wantCanonical) ||
		!reflect.DeepEqual(localRecord.Attributes(), wantLocal) {
		t.Fatalf("projection canonical=%v local=%v", canonicalRecord.Attributes(), localRecord.Attributes())
	}
	if value, ok := canonicalRecord.Value().Double(); !ok || value != 17.5 {
		t.Fatalf("canonical value=%v ok=%v", value, ok)
	}
	mutated := localRecord.Attributes()
	mutated["connector"] = "mutated"
	if localRecord.Attributes()["connector"] != "codex" {
		t.Fatal("projected metric attributes are mutable")
	}
	if err := recorder.forceFlush(context.Background()); err != nil || canonical.flushed != 1 || local.flushed != 1 {
		t.Fatalf("flush canonical=%d local=%d err=%v", canonical.flushed, local.flushed, err)
	}
	if err := recorder.close(context.Background()); err != nil || canonical.shutdown != 1 || local.shutdown != 1 {
		t.Fatalf("shutdown canonical=%d local=%d err=%v", canonical.shutdown, local.shutdown, err)
	}
	if err := recorder.close(context.Background()); err != nil || canonical.shutdown != 1 || local.shutdown != 1 {
		t.Fatalf("repeated shutdown canonical=%d local=%d err=%v", canonical.shutdown, local.shutdown, err)
	}
	if _, err := recorder.record(context.Background(), buildV8HookLatencyMetric(t, 7, "abc123")); err == nil {
		t.Fatal("retired metric recorder accepted a record")
	}
}

func TestGeneratedMetricLocalProjectionPreservesUnmappedCanonicalLabels(t *testing.T) {
	descriptor, ok := v8MetricDescriptorByName("defenseclaw.agent.last_seen")
	if !ok {
		t.Fatal("agent last-seen descriptor missing")
	}
	projected, profile, err := projectV8MetricAttributes(descriptor, map[string]any{
		"defenseclaw.connector.source":   "codex",
		"defenseclaw.agent.type":         "root",
		"defenseclaw.agent.lifecycle.id": "lifecycle-1",
		"gen_ai.agent.id":                "agent-1",
	}, V8MetricProjectionLocal)
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"connector":                      "codex",
		"gen_ai.agent.type":              "root",
		"defenseclaw.agent.lifecycle.id": "lifecycle-1",
		"gen_ai.agent.id":                "agent-1",
	}
	if profile != observability.RuntimeLocalObservabilityProfile || !reflect.DeepEqual(projected, want) {
		t.Fatalf("local projection profile=%q got=%v want=%v", profile, projected, want)
	}
}

func TestGeneratedMetricRecorderRejectsDuplicatePipelinesAndGenerationMismatch(t *testing.T) {
	sink := &v8MetricCaptureSink{}
	family := observability.EventName("defenseclaw.connector.hook.latency")
	base := V8GenerationMetricPipeline{
		Destination: "generic", Projection: V8MetricProjectionCanonical,
		SelectedFamilies: []observability.EventName{family}, Sink: sink,
	}
	for name, pipelines := range map[string][]V8GenerationMetricPipeline{
		"destination": {base, base},
		"family":      {{Destination: "generic", Projection: V8MetricProjectionCanonical, SelectedFamilies: []observability.EventName{family, family}, Sink: sink}},
		"sink":        {base, {Destination: "second", Projection: V8MetricProjectionLocal, SelectedFamilies: []observability.EventName{family}, Sink: sink}},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := newV8MetricRecorder(1, "abc", map[observability.Bucket]bool{observability.BucketAgentLifecycle: true}, pipelines); err == nil {
				t.Fatal("duplicate metric pipeline accepted")
			}
		})
	}
	recorder, err := newV8MetricRecorder(1, "abc", map[observability.Bucket]bool{
		observability.BucketAgentLifecycle: true,
	}, []V8GenerationMetricPipeline{base})
	if err != nil {
		t.Fatal(err)
	}
	recorder.setActive(true)
	if _, err := recorder.record(context.Background(), buildV8HookLatencyMetric(t, 2, "def")); err == nil || len(sink.records) != 0 {
		t.Fatal("cross-generation metric reached a destination")
	}
}

func TestGeneratedMetricRecorderRequiresStableSinkIdentityAndIsolatesLifecycle(t *testing.T) {
	family := observability.EventName("defenseclaw.connector.hook.latency")
	if _, err := newV8MetricRecorder(1, "abc", map[observability.Bucket]bool{
		observability.BucketAgentLifecycle: true,
	}, []V8GenerationMetricPipeline{{
		Destination: "value", Projection: V8MetricProjectionCanonical,
		SelectedFamilies: []observability.EventName{family}, Sink: v8MetricValueSink{},
	}}); err == nil {
		t.Fatal("value-type metric sink without stable lifecycle identity was accepted")
	}

	first := &v8MetricCaptureSink{flushErr: errors.New("first failed")}
	second := &v8MetricCaptureSink{}
	recorder, err := newV8MetricRecorder(1, "abc", map[observability.Bucket]bool{
		observability.BucketAgentLifecycle: true,
	}, []V8GenerationMetricPipeline{
		{Destination: "first", Projection: V8MetricProjectionCanonical, SelectedFamilies: []observability.EventName{family}, Sink: first},
		{Destination: "second", Projection: V8MetricProjectionLocal, SelectedFamilies: []observability.EventName{family}, Sink: second},
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := recorder.forceFlush(context.Background()); err == nil || first.flushed != 1 || second.flushed != 1 {
		t.Fatalf("isolated flush first=%d second=%d err=%v", first.flushed, second.flushed, err)
	}

	duplicate := &v8MetricCaptureSink{}
	cleanupV8MetricPipelines([]V8GenerationMetricPipeline{
		{Destination: "first", Sink: duplicate},
		{Destination: "second", Sink: duplicate},
	}, time.Second)
	if duplicate.shutdown != 1 {
		t.Fatalf("rollback shutdown count=%d, want 1", duplicate.shutdown)
	}
}

func TestGeneratedMetricSinkFactoriesBindResourceAndRollbackMaterializedChildrenOnce(t *testing.T) {
	family := observability.EventName("defenseclaw.connector.hook.latency")
	resource := V8ResourceContext{
		schemaURL: "https://opentelemetry.io/schemas/1.42.0",
		values: map[string]string{
			"service.name": "defenseclaw", "service.instance.id": "instance-one",
		},
	}
	first := &v8MetricCaptureSink{}
	var firstResource, secondResource map[string]string
	pipelines := []V8GenerationMetricPipeline{
		{
			Destination: "first", Projection: V8MetricProjectionCanonical,
			SelectedFamilies: []observability.EventName{family},
			SinkFactory: func(_ context.Context, captured V8ResourceContext) (V8CanonicalMetricSink, error) {
				firstResource = captured.Values()
				firstResource["service.name"] = "caller-mutation"
				return first, nil
			},
		},
		{
			Destination: "second", Projection: V8MetricProjectionLocal,
			SelectedFamilies: []observability.EventName{family},
			SinkFactory: func(_ context.Context, captured V8ResourceContext) (V8CanonicalMetricSink, error) {
				secondResource = captured.Values()
				return nil, errors.New("private initialization detail")
			},
		},
	}
	if err := validateV8MetricPipelineDeclarations(pipelines); err != nil {
		t.Fatal(err)
	}
	materialized, err := materializeV8MetricPipelines(context.Background(), resource, pipelines)
	if err == nil || len(materialized) != 2 || materialized[0].Sink != first || materialized[0].SinkFactory != nil ||
		materialized[1].Sink != nil || secondResource["service.name"] != "defenseclaw" ||
		resource.Values()["service.name"] != "defenseclaw" {
		t.Fatalf("materialization result=%+v first=%v second=%v err=%v", materialized, firstResource, secondResource, err)
	}
	cleanupV8MetricPipelines(materialized, time.Second)
	if first.shutdown != 1 {
		t.Fatalf("materialized sink cleanup calls=%d", first.shutdown)
	}
}
