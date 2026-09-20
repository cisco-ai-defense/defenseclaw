// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"context"
	"errors"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

type runtimeCorrelationFixture struct {
	ctx                 context.Context
	semanticEventID     audit.SemanticEventID
	logicalEventID      audit.LogicalEventID
	connectorInstanceID audit.ConnectorInstanceID
}

func newRuntimeCorrelationFixture(
	t *testing.T,
	dependencies runtimeTestDependencies,
	rail audit.CorrelationRail,
) runtimeCorrelationFixture {
	t.Helper()
	repository, err := dependencies.store.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	custody := audit.ConnectorCustodyHookOnly
	if rail == audit.CorrelationRailNativeOTLP {
		custody = audit.ConnectorCustodyDefenseClaw
	}
	instance, err := repository.ResolveConnectorInstance(
		t.Context(), "openai_codex", "runtime-correlation-test-v1", custody,
	)
	if err != nil {
		t.Fatal(err)
	}
	semanticEventID, err := audit.NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	logicalEventID := audit.LogicalEventID(semanticEventID)
	now := time.Now().UTC()
	tx, result, err := repository.BeginOccurrence(t.Context(), audit.CorrelationOccurrenceInput{
		Event: audit.CorrelationEvent{
			SemanticEventID: semanticEventID, LogicalEventID: logicalEventID,
			Connector: "openai_codex", ConnectorInstanceID: instance.ConnectorInstanceID,
			Rail: rail, EventName: "runtime.correlation.test", ReceivedTime: now,
			ProfileVersion: "runtime-correlation-test-v1", Completeness: audit.CorrelationComplete,
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	if result.SemanticEventID != semanticEventID || result.SuppressEmission {
		_ = tx.Rollback()
		t.Fatalf("occurrence result=%+v", result)
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	envelope := audit.CorrelationEnvelope{
		SemanticEventID: string(semanticEventID), LogicalEventID: string(logicalEventID),
		ConnectorInstanceID: string(instance.ConnectorInstanceID),
		RunID:               "run-001", RequestID: "request-001", SessionID: "session-001",
		TurnID: "turn-001", AgentID: "agent-root", AgentInstanceID: "agent-instance-001",
		PolicyID: "policy-001", Connector: "openai_codex",
	}
	return runtimeCorrelationFixture{
		ctx: audit.ContextWithEnvelope(t.Context(), envelope), semanticEventID: semanticEventID,
		logicalEventID: logicalEventID, connectorInstanceID: instance.ConnectorInstanceID,
	}
}

func runtimeCorrelationGraph(
	t *testing.T,
	dependencies runtimeTestDependencies,
	semanticEventID audit.SemanticEventID,
) audit.CorrelationGraph {
	t.Helper()
	repository, err := dependencies.store.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	graph, err := repository.QueryGraph(t.Context(), audit.CorrelationGraphQuery{
		Anchor: audit.CorrelationAnchor{SemanticEventID: semanticEventID},
		Page:   audit.CorrelationPageRequest{Limit: 64},
	})
	if err != nil {
		t.Fatal(err)
	}
	return graph
}

func assertRuntimeCorrelation(
	t *testing.T,
	correlation observability.Correlation,
	fixture runtimeCorrelationFixture,
) {
	t.Helper()
	if correlation.SemanticEventID != string(fixture.semanticEventID) ||
		correlation.LogicalEventID != string(fixture.logicalEventID) ||
		correlation.ConnectorInstanceID != string(fixture.connectorInstanceID) {
		t.Fatalf("correlation occurrence envelope=%+v", correlation)
	}
}

func TestRuntimeLogCommitsStampedCorrelationObservationWithEventHistory(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	runtime := newRuntimeForTest(
		t, dependencies,
		runtimeTestPlan(t, dependencies.storePath, dependencies.judgePath, 30, nil), false,
	)
	fixture := newRuntimeCorrelationFixture(t, dependencies, audit.CorrelationRailHook)
	outcome, err := runtime.Emit(
		fixture.ctx, diagnosticMetadata(t),
		runtimeRecordBuilder("runtime-correlation-log", diagnosticIdentity(), nil),
	)
	if err != nil || !outcome.LocalPersisted() {
		t.Fatalf("log outcome=%+v err=%v", outcome, err)
	}
	graph := runtimeCorrelationGraph(t, dependencies, fixture.semanticEventID)
	if len(graph.Observations) != 1 {
		t.Fatalf("log correlation observations=%+v", graph.Observations)
	}
	observation := graph.Observations[0]
	if observation.RecordID != "runtime-correlation-log" ||
		observation.Signal != audit.CorrelationSignalLogs ||
		observation.Status != audit.CorrelationObservationExportEligible ||
		observation.SessionID != "session-001" || observation.TurnID != "turn-001" {
		t.Fatalf("log observation=%+v", observation)
	}
}

func TestGeneratedTraceSharesOccurrenceAndPersistsBeforeCanonicalHandoff(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	pipelines := &generatedTracePipelines{consumers: make(map[uint64]*generatedTraceConsumer)}
	runtime := newGeneratedTraceRuntime(
		t, dependencies, pipelines,
		generatedTracePlan(t, dependencies, 30, "always_on", []observability.Bucket{"*"}),
	)
	fixture := newRuntimeCorrelationFixture(t, dependencies, audit.CorrelationRailHook)
	base := time.Now().UTC().Add(-time.Second)
	input := generatedAgentInput("root", base, base.Add(500*time.Millisecond))
	_, span, err := runtime.StartAgentTrace(fixture.ctx, input)
	if err != nil || span == nil {
		t.Fatalf("start span=%v err=%v", span, err)
	}
	if err := span.End(input); err != nil {
		t.Fatal(err)
	}
	spans := pipelines.consumer(t, 1).snapshot()
	if len(spans) != 1 {
		t.Fatalf("canonical spans=%d", len(spans))
	}
	record := spans[0].Record()
	assertRuntimeCorrelation(t, record.Correlation(), fixture)
	if record.Correlation().TraceID != spans[0].TraceID().String() ||
		record.Correlation().SpanID != spans[0].SpanID().String() {
		t.Fatalf("generated topology record=%+v span=%s/%s", record.Correlation(), spans[0].TraceID(), spans[0].SpanID())
	}
	graph := runtimeCorrelationGraph(t, dependencies, fixture.semanticEventID)
	if len(graph.Observations) != 1 || graph.Observations[0].Signal != audit.CorrelationSignalTraces ||
		graph.Observations[0].TraceID != spans[0].TraceID().String() ||
		graph.Observations[0].SpanID != spans[0].SpanID().String() ||
		graph.Observations[0].LifecycleID != "lifecycle-001" ||
		graph.Observations[0].ExecutionID != "execution-001" {
		t.Fatalf("trace observations=%+v", graph.Observations)
	}
}

type runtimeCorrelationMetricSink struct {
	mu      sync.Mutex
	metrics []telemetry.V8ProjectedMetric
}

func (sink *runtimeCorrelationMetricSink) RecordMetric(_ context.Context, metric telemetry.V8ProjectedMetric) error {
	sink.mu.Lock()
	sink.metrics = append(sink.metrics, metric)
	sink.mu.Unlock()
	return nil
}

func (*runtimeCorrelationMetricSink) ForceFlush(context.Context) error { return nil }
func (*runtimeCorrelationMetricSink) Shutdown(context.Context) error   { return nil }

func (sink *runtimeCorrelationMetricSink) snapshot() []telemetry.V8ProjectedMetric {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return append([]telemetry.V8ProjectedMetric(nil), sink.metrics...)
}

func TestGeneratedMetricCarriesCanonicalEnvelopeWithoutHighCardinalityLabels(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	sink := &runtimeCorrelationMetricSink{}
	options := dependencies.options()
	options.TelemetryProviderFactory = telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "8.0.0", Environment: "test", ServiceInstanceID: "correlation-metric-runtime",
		GenerationPipelines: func(
			context.Context, *config.ObservabilityV8Plan, uint64, telemetry.V8MetricReaderSpec,
		) (telemetry.V8GenerationPipelines, error) {
			return telemetry.V8GenerationPipelines{MetricPipelines: []telemetry.V8GenerationMetricPipeline{{
				Destination: "capture", Projection: telemetry.V8MetricProjectionCanonical,
				SelectedFamilies: []observability.EventName{generatedMetricFamily}, Sink: sink,
			}}}, nil
		},
	})
	plan := runtimeGeneratedMetricPlan(t, dependencies, observability.BucketAgentLifecycle)
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
	fixture := newRuntimeCorrelationFixture(t, dependencies, audit.CorrelationRailHook)
	result, err := runtime.RecordGeneratedMetric(
		fixture.ctx, generatedMetricFamily,
		func(snapshot EmitContext) (observability.Record, error) {
			return runtimeGeneratedMetricRecord(t, snapshot)
		},
	)
	if err != nil || result != (telemetry.V8MetricRecordResult{Matched: 1, Delivered: 1}) {
		t.Fatalf("metric result=%+v err=%v", result, err)
	}
	metrics := sink.snapshot()
	if len(metrics) != 1 {
		t.Fatalf("metrics=%d", len(metrics))
	}
	assertRuntimeCorrelation(t, metrics[0].CanonicalRecord().Correlation(), fixture)
	attributes := metrics[0].Attributes()
	for _, key := range []string{
		"defenseclaw.semantic_event.id", "defenseclaw.logical_event.id",
		"defenseclaw.connector.instance.id", "defenseclaw.request.id", "defenseclaw.turn.id",
	} {
		if _, present := attributes[key]; present {
			t.Fatalf("high-cardinality correlation key %q became a metric label: %+v", key, attributes)
		}
	}
	graph := runtimeCorrelationGraph(t, dependencies, fixture.semanticEventID)
	if len(graph.Observations) != 1 || graph.Observations[0].Signal != audit.CorrelationSignalMetrics {
		t.Fatalf("metric observations=%+v", graph.Observations)
	}
}

func TestGeneratedMetricDoesNotExportWhenCorrelationCommitFails(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	sink := &runtimeCorrelationMetricSink{}
	options := dependencies.options()
	options.TelemetryProviderFactory = telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "8.0.0", Environment: "test", ServiceInstanceID: "correlation-failure-runtime",
		GenerationPipelines: func(
			context.Context, *config.ObservabilityV8Plan, uint64, telemetry.V8MetricReaderSpec,
		) (telemetry.V8GenerationPipelines, error) {
			return telemetry.V8GenerationPipelines{MetricPipelines: []telemetry.V8GenerationMetricPipeline{{
				Destination: "capture", Projection: telemetry.V8MetricProjectionCanonical,
				SelectedFamilies: []observability.EventName{generatedMetricFamily}, Sink: sink,
			}}}, nil
		},
	})
	plan := runtimeGeneratedMetricPlan(t, dependencies, observability.BucketAgentLifecycle)
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
	semanticEventID, err := audit.NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	connectorInstanceID, err := audit.NewConnectorInstanceID()
	if err != nil {
		t.Fatal(err)
	}
	// The UUIDs are well formed but deliberately have no correlation_events
	// parent. The foreign-key failure must happen before the provider sees the
	// metric, proving that remote export cannot outrun durable occurrence state.
	ctx := audit.ContextWithEnvelope(t.Context(), audit.CorrelationEnvelope{
		SemanticEventID: string(semanticEventID), LogicalEventID: string(semanticEventID),
		ConnectorInstanceID: string(connectorInstanceID),
	})
	result, err := runtime.RecordGeneratedMetric(
		ctx, generatedMetricFamily,
		func(snapshot EmitContext) (observability.Record, error) {
			return runtimeGeneratedMetricRecord(t, snapshot)
		},
	)
	var metricErr *GeneratedMetricError
	if !errors.As(err, &metricErr) || metricErr.Code() != GeneratedMetricRecordFailed ||
		result != (telemetry.V8MetricRecordResult{}) {
		t.Fatalf("metric result=%+v err=%v", result, err)
	}
	if got := len(sink.snapshot()); got != 0 {
		t.Fatalf("provider received %d metrics before correlation commit", got)
	}
}
