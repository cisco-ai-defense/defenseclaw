// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"encoding/json"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/trace"
)

func generatedTelemetryEnvelope(phase string) observability.FamilyEnvelopeInput {
	return observability.FamilyEnvelopeInput{
		Source: observability.SourceOTelReceiver, Connector: "codex",
		Action: "otel.ingest.logs", Phase: phase,
		Correlation: observability.Correlation{RunID: "run-001", RequestID: "request-001"},
		Provenance:  observability.FamilyProvenanceInput{Producer: "defenseclaw"},
	}
}

func generatedTelemetryReceiveInput(start, end time.Time) observability.SpanTelemetryReceiveInput {
	return observability.SpanTelemetryReceiveInput{
		Envelope: generatedTelemetryEnvelope("receive"),
		Outcome:  observability.OutcomeCompleted, Kind: "SERVER",
		StartTimeUnixNano: generatedTimeNanos(start), EndTimeUnixNano: generatedTimeNanos(end),
		Status:                              observability.NewTraceStatusOK(),
		HTTPRequestMethod:                   "POST",
		HTTPResponseStatusCode:              observability.Present[int64](200),
		NetworkProtocolName:                 observability.Present("http"),
		NetworkProtocolVersion:              observability.Present("1.1"),
		DefenseClawConnectorSource:          observability.Present("codex"),
		DefenseClawRunID:                    observability.Present("run-001"),
		DefenseClawTelemetrySignal:          observability.Present("logs"),
		DefenseClawTelemetryPayloadFormat:   observability.Present("json"),
		DefenseClawTelemetryRecordCount:     observability.Present[int64](2),
		DefenseClawTelemetryResourceCount:   observability.Present[int64](1),
		DefenseClawTelemetryWireBytes:       observability.Present[int64](128),
		DefenseClawTelemetryByteCount:       observability.Present[int64](128),
		DefenseClawTelemetryNormalizedBytes: observability.Present[int64](120),
		DefenseClawTelemetryLatencyMs:       observability.Present[int64](5),
		ConditionConnectorKnown:             true, ConditionOperationTerminal: true,
	}
}

func generatedTelemetryNormalizeInput(start, end time.Time) observability.SpanTelemetryNormalizeInput {
	return observability.SpanTelemetryNormalizeInput{
		Envelope: generatedTelemetryEnvelope("normalization"),
		Outcome:  observability.OutcomeCompleted, Kind: "INTERNAL",
		StartTimeUnixNano: generatedTimeNanos(start), EndTimeUnixNano: generatedTimeNanos(end),
		Status:                              observability.NewTraceStatusOK(),
		DefenseClawConnectorSource:          observability.Present("codex"),
		DefenseClawRunID:                    observability.Present("run-001"),
		DefenseClawTelemetrySignal:          "logs",
		DefenseClawTelemetryPayloadFormat:   observability.Present("json"),
		DefenseClawTelemetryRecordCount:     observability.Present[int64](2),
		DefenseClawTelemetryResourceCount:   observability.Present[int64](1),
		DefenseClawTelemetryWireBytes:       observability.Present[int64](128),
		DefenseClawTelemetryByteCount:       observability.Present[int64](128),
		DefenseClawTelemetryNormalizedBytes: observability.Present[int64](120),
		DefenseClawTelemetryLatencyMs:       observability.Present[int64](4),
		ConditionConnectorKnown:             true, ConditionOperationTerminal: true,
	}
}

func generatedTelemetryCollectionDisabledPlan(
	t *testing.T,
	dependencies runtimeTestDependencies,
) *config.ObservabilityV8Plan {
	t.Helper()
	disabled := false
	return runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 90,
		func(source *config.ObservabilityV8Source) {
			source.TracePolicy.Sampler = "always_on"
			source.Buckets = map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
				observability.BucketTelemetryIngest: {
					Collect: config.ObservabilityV8CollectSource{Traces: &disabled},
				},
			}
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

func TestGeneratedTelemetryTracePreservesHierarchyNamesAndFacts(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	pipelines := &generatedTracePipelines{consumers: make(map[uint64]*generatedTraceConsumer)}
	plan := generatedTracePlan(t, dependencies, 90, "always_on", []observability.Bucket{"*"})
	runtime := newGeneratedTraceRuntime(t, dependencies, pipelines, plan)

	base := time.Now().UTC().Add(-time.Second)
	receiveInput := generatedTelemetryReceiveInput(base, base.Add(500*time.Millisecond))
	_, receive, err := runtime.StartTelemetryReceiveTrace(t.Context(), receiveInput)
	if err != nil || receive == nil || receive.Generation() != 1 {
		t.Fatalf("start receive=%v generation=%d err=%v", receive, receive.Generation(), err)
	}
	normalInput := generatedTelemetryNormalizeInput(base.Add(time.Millisecond), base.Add(400*time.Millisecond))
	normalize, err := receive.StartNormalize(normalInput)
	if err != nil || normalize == nil || normalize.TraceID() != receive.TraceID() {
		t.Fatalf("start normalize=%v err=%v", normalize, err)
	}
	if err := normalize.End(normalInput); err != nil {
		t.Fatal(err)
	}
	if err := receive.End(receiveInput); err != nil {
		t.Fatal(err)
	}

	spans := pipelines.consumer(t, 1).snapshot()
	if len(spans) != 2 {
		t.Fatalf("spans=%d want receive+normalize", len(spans))
	}
	byFamily := make(map[observability.EventName]int, len(spans))
	for index, span := range spans {
		byFamily[span.Record().EventName()] = index
		if span.StatusCode() != codes.Ok || span.Record().Provenance().ConfigGeneration != 1 {
			t.Fatalf("span=%s status=%s provenance=%+v", span.Name(), span.StatusCode(), span.Record().Provenance())
		}
	}
	receiveSpan := spans[byFamily[observability.EventName(observability.TelemetryFamilyTelemetryReceive)]]
	normalizeSpan := spans[byFamily[observability.EventName(observability.TelemetryFamilyTelemetryNormalize)]]
	parent, ok := normalizeSpan.ParentSpanID()
	if receiveSpan.Name() != "POST telemetry" || receiveSpan.Kind() != trace.SpanKindServer ||
		normalizeSpan.Name() != "telemetry.normalize logs" || normalizeSpan.Kind() != trace.SpanKindInternal ||
		!ok || parent != receiveSpan.SpanID() {
		t.Fatalf("hierarchy receive=%s/%s normalize=%s/%s parent=%s/%t",
			receiveSpan.Name(), receiveSpan.Kind(), normalizeSpan.Name(), normalizeSpan.Kind(), parent, ok)
	}
	attributes := generatedTraceRecordAttributes(t, normalizeSpan.Record())
	// End succeeding proves the v1 physical control attribute matched the v1
	// generated canonical record at the synchronous handoff boundary.
	if attributes["defenseclaw.span.family_schema_version"] != float64(1) ||
		attributes["defenseclaw.telemetry.record_count"] != float64(2) ||
		attributes["defenseclaw.telemetry.wire_bytes"] != float64(128) ||
		attributes["defenseclaw.telemetry.normalized_bytes"] != float64(120) {
		t.Fatalf("normalize attributes=%v", attributes)
	}
}

func TestGeneratedTelemetryTraceSamplingCollectionAndReload(t *testing.T) {
	for _, test := range []struct {
		name               string
		sampler            string
		collectionDisabled bool
	}{
		{name: "sampling off", sampler: "always_off"},
		{name: "collection off", sampler: "always_on", collectionDisabled: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dependencies := newRuntimeTestDependencies(t)
			pipelines := &generatedTracePipelines{consumers: make(map[uint64]*generatedTraceConsumer)}
			plan := generatedTracePlan(t, dependencies, 90, test.sampler, []observability.Bucket{"*"})
			if test.collectionDisabled {
				plan = generatedTelemetryCollectionDisabledPlan(t, dependencies)
			}
			runtime := newGeneratedTraceRuntime(t, dependencies, pipelines, plan)
			_, receive, err := runtime.StartTelemetryReceiveTrace(t.Context(), generatedTelemetryReceiveInput(time.Now().UTC(), time.Time{}))
			if err != nil || receive != nil {
				t.Fatalf("receive=%v err=%v", receive, err)
			}
			if spans := pipelines.consumer(t, 1).snapshot(); len(spans) != 0 {
				t.Fatalf("canonical spans=%d", len(spans))
			}
		})
	}

	dependencies := newRuntimeTestDependencies(t)
	pipelines := &generatedTracePipelines{consumers: make(map[uint64]*generatedTraceConsumer)}
	initial := generatedTracePlan(t, dependencies, 90, "always_on", []observability.Bucket{"*"})
	runtime := newGeneratedTraceRuntime(t, dependencies, pipelines, initial)
	base := time.Now().UTC().Add(-time.Second)
	receiveInput := generatedTelemetryReceiveInput(base, base.Add(500*time.Millisecond))
	_, receive, err := runtime.StartTelemetryReceiveTrace(t.Context(), receiveInput)
	if err != nil || receive == nil {
		t.Fatalf("start receive=%v err=%v", receive, err)
	}
	normalInput := generatedTelemetryNormalizeInput(base.Add(time.Millisecond), base.Add(400*time.Millisecond))
	normalize, err := receive.StartNormalize(normalInput)
	if err != nil || normalize == nil {
		t.Fatalf("start normalize=%v err=%v", normalize, err)
	}
	updated := generatedTracePlan(t, dependencies, 91, "always_on", []observability.Bucket{"*"})
	reloadDone := make(chan struct {
		result runtimegraph.ReloadResult
		err    *runtimegraph.Error
	}, 1)
	go func() {
		result, reloadErr := runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(updated, false))
		reloadDone <- struct {
			result runtimegraph.ReloadResult
			err    *runtimegraph.Error
		}{result: result, err: reloadErr}
	}()
	deadline := time.Now().Add(5 * time.Second)
	for runtime.Active() == nil || runtime.Active().Generation() != 2 {
		if time.Now().After(deadline) {
			t.Fatal("reload did not publish generation two")
		}
		time.Sleep(time.Millisecond)
	}
	if receive.Generation() != 1 || normalize.Generation() != 1 {
		t.Fatalf("active hierarchy crossed generation receive=%d normalize=%d", receive.Generation(), normalize.Generation())
	}
	if err := normalize.End(normalInput); err != nil {
		t.Fatal(err)
	}
	if err := receive.End(receiveInput); err != nil {
		t.Fatal(err)
	}
	reload := <-reloadDone
	if reload.err != nil || reload.result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("reload=%s err=%v", reload.result.Status(), reload.err)
	}
	if got := len(pipelines.consumer(t, 1).snapshot()); got != 2 {
		t.Fatalf("generation one spans=%d", got)
	}
	_, next, err := runtime.StartTelemetryReceiveTrace(t.Context(), generatedTelemetryReceiveInput(time.Now().UTC(), time.Time{}))
	if err != nil || next == nil || next.Generation() != 2 {
		t.Fatalf("next receive=%v generation=%d err=%v", next, next.Generation(), err)
	}
	next.Abort()
}

func TestGeneratedTelemetryTraceRejectedStatusIsContentFree(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	pipelines := &generatedTracePipelines{consumers: make(map[uint64]*generatedTraceConsumer)}
	plan := generatedTracePlan(t, dependencies, 90, "always_on", []observability.Bucket{"*"})
	runtime := newGeneratedTraceRuntime(t, dependencies, pipelines, plan)
	base := time.Now().UTC().Add(-time.Second)
	input := generatedTelemetryReceiveInput(base, base.Add(100*time.Millisecond))
	input.Outcome = observability.OutcomeRejected
	input.Status = observability.NewTraceStatusError(observability.Absent[string]())
	input.HTTPResponseStatusCode = observability.Present[int64](413)
	input.DefenseClawTelemetryRecordCount = observability.Absent[int64]()
	input.DefenseClawTelemetryResourceCount = observability.Absent[int64]()
	input.DefenseClawTelemetryNormalizedBytes = observability.Absent[int64]()
	input.DefenseClawTelemetryRejectionReasonClass = observability.Present("body_too_large")
	input.ErrorType = observability.Present("body_too_large")
	_, receive, err := runtime.StartTelemetryReceiveTrace(t.Context(), input)
	if err != nil || receive == nil {
		t.Fatalf("start receive=%v err=%v", receive, err)
	}
	if err := receive.End(input); err != nil {
		t.Fatal(err)
	}
	spans := pipelines.consumer(t, 1).snapshot()
	if len(spans) != 1 || spans[0].StatusCode() != codes.Error || spans[0].StatusDescription() != "" {
		t.Fatalf("rejected spans=%v", spans)
	}
	payload, err := json.Marshal(spans[0].Record())
	if err != nil {
		t.Fatal(err)
	}
	if string(payload) == "" || containsAny(string(payload), "raw-prompt", "secret-value") {
		t.Fatalf("unsafe rejected payload=%s", payload)
	}
}

func containsAny(value string, candidates ...string) bool {
	for _, candidate := range candidates {
		if len(candidate) > 0 && len(value) >= len(candidate) {
			for index := 0; index+len(candidate) <= len(value); index++ {
				if value[index:index+len(candidate)] == candidate {
					return true
				}
			}
		}
	}
	return false
}
