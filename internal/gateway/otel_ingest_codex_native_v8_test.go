// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"fmt"
	"math"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"go.opentelemetry.io/otel/trace"
	collectorlogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

type codexNativeOTLPPipelines struct {
	metrics *otlpV8MetricPipelines
	traces  *otlpTracePipelines
}

func (pipelines *codexNativeOTLPPipelines) build(
	ctx context.Context,
	plan *config.ObservabilityV8Plan,
	generation uint64,
	spec telemetry.V8MetricReaderSpec,
) (telemetry.V8GenerationPipelines, error) {
	metrics, err := pipelines.metrics.build(ctx, plan, generation, spec)
	if err != nil {
		return telemetry.V8GenerationPipelines{}, err
	}
	traces, err := pipelines.traces.build(ctx, plan, generation, spec)
	if err != nil {
		return telemetry.V8GenerationPipelines{}, err
	}
	metrics.SpanPipelines = traces.SpanPipelines
	return metrics, nil
}

type codexNativeOTLPFixture struct {
	runtime   *observabilityruntime.Runtime
	path      string
	pipelines *codexNativeOTLPPipelines
}

func newCodexNativeOTLPFixture(t *testing.T) codexNativeOTLPFixture {
	t.Helper()
	previousInstanceID := gatewaylog.SidecarInstanceID()
	gatewaylog.SetSidecarInstanceID("codex-native-otlp-test")
	t.Cleanup(func() { gatewaylog.SetSidecarInstanceID(previousInstanceID) })

	directory := t.TempDir()
	path := filepath.Join(directory, "audit.db")
	judgePath := filepath.Join(directory, "judge-bodies.db")
	store, err := audit.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	engine, err := observabilityredaction.NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	builder, err := observability.NewRecordBuilder(
		observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("codex-native-%d", time.Now().UnixNano()), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	reaper, err := audit.NewRetentionReaper(store, nil, 0, audit.RetentionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	retention, err := observabilityruntime.NewRetentionController(
		reaper, observabilityruntime.RetentionControllerOptions{},
	)
	if err != nil {
		t.Fatal(err)
	}

	collect := true
	retentionDays := 0
	source := &config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{
			Path: path, JudgeBodiesPath: judgePath, RetentionDays: &retentionDays,
		},
		Defaults: config.ObservabilityV8BucketPolicySource{Collect: config.ObservabilityV8CollectSource{
			Logs: &collect, Traces: &collect, Metrics: &collect,
		}},
		TracePolicy: config.ObservabilityV8TracePolicySource{Sampler: "always_on"},
		Destinations: []config.ObservabilityV8DestinationSource{{
			Name: "capture", Kind: config.ObservabilityV8DestinationOTLP,
			Protocol: "http/protobuf", Endpoint: "https://otel.example.test",
			Send: &config.ObservabilityV8SendSource{
				Signals: []observability.Signal{observability.SignalTraces},
				Buckets: []observability.Bucket{"*"}, RedactionProfile: "none",
			},
		}},
	}
	plan, err := config.CompileObservabilityV8(source)
	if err != nil {
		t.Fatal(err)
	}
	pipelines := &codexNativeOTLPPipelines{
		metrics: &otlpV8MetricPipelines{generations: make(map[uint64]otlpV8MetricGenerationSinks)},
		traces:  &otlpTracePipelines{captures: make(map[uint64]*proxyCanonicalCapture), engine: engine},
	}
	providerFactory := telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "8.0.0", Environment: "test", ServiceInstanceID: "codex-native-otlp-test",
		DefenseClawInstanceID: "codex-native-otlp-test", GenerationPipelines: pipelines.build,
	})
	runtime, err := observabilityruntime.New(
		t.Context(), runtimegraph.ConfigFromPlan(plan, false), observabilityruntime.Options{
			Store: store, Engine: engine, RecordBuilder: builder,
			Reporter: &discardSidecarGraphReporter{}, RetentionController: retention,
			TelemetryProviderFactory: providerFactory,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := runtime.Close(ctx); err != nil {
			t.Errorf("close native Codex OTLP runtime: %v", err)
		}
	})
	return codexNativeOTLPFixture{runtime: runtime, path: path, pipelines: pipelines}
}

func TestOTLPInboundRealCodexTurnProjectsOnceAndJoinsHookRoot(t *testing.T) {
	fixture := newCodexNativeOTLPFixture(t)
	const (
		conversationID = "019f4f18-3c1c-7f00-80b2-8248d5894a01"
		agentID        = "agent-a9f5218e67786344"
		turnID         = "019f4f18-4c1c-7a00-90b2-8248d5894a02"
	)
	meta := llmEventMeta{
		Source: "codex", SessionID: conversationID, TurnID: turnID,
		AgentID: agentID, AgentName: "root", AgentType: "codex",
		RootAgentID: agentID, RootSessionID: conversationID, LineageProvenance: "reported",
		LifecycleID: "lifecycle-79134be59e212fc4", ExecutionID: "execution-55b116c308bfda2b",
		Phase: "model", AgentDepth: 0,
	}
	stateKey := hookSessionStateKey(meta)
	api := &APIServer{
		hookSessionStates:     map[string]hookSessionState{stateKey: {meta: meta}},
		hookSessionStateOrder: []string{stateKey},
	}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	now := time.Now().UTC().Truncate(time.Nanosecond)

	responseLog := &collectorlogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			otlpClassifierStringAttribute("service.name", "codex_cli_rs"),
		}},
		ScopeLogs: []*logspb.ScopeLogs{{
			Scope: &commonpb.InstrumentationScope{Name: "codex_cli_rs"},
			LogRecords: []*logspb.LogRecord{{
				TimeUnixNano: uint64(now.Add(-2 * time.Second).UnixNano()),
				Body:         &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "response.completed"}},
				Attributes: []*commonpb.KeyValue{
					otlpClassifierStringAttribute("event.name", "codex.sse_event"),
					otlpClassifierStringAttribute("event.kind", "response.completed"),
					otlpClassifierStringAttribute("conversation.id", conversationID),
					otlpClassifierStringAttribute("model", "gpt-5.4"),
					otlpClassifierStringAttribute("input_token_count", "12770"),
					otlpClassifierStringAttribute("cached_token_count", "2432"),
					otlpClassifierStringAttribute("output_token_count", "19"),
					otlpClassifierStringAttribute("reasoning_token_count", "11"),
				},
			}},
		}},
	}}}
	logAccounting, err := api.importDecodedOTLPRequestV8(
		context.Background(), responseLog, otelSignalLogs, "codex", now,
	)
	if err != nil || !logAccounting.valid() || logAccounting.importedAndDerived != 1 ||
		logAccounting.derivativeRecorded != 1 {
		t.Fatalf("native Codex response accounting=%+v err=%v", logAccounting, err)
	}
	if got := codexNativeStoredEventCount(t, fixture.path, "model.response"); got != 1 {
		t.Fatalf("native Codex response records=%d want=1", got)
	}

	// Codex 0.136 reports the raw SSE poll and the parsed completion under the
	// same event name/kind. The poll carries a string duration_ms but no token
	// counters. It must not import a second model.response or derive duration;
	// the exact session_task.turn span below is the sole duration authority.
	rawSSELog := &collectorlogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			otlpClassifierStringAttribute("service.name", "codex_cli_rs"),
		}},
		ScopeLogs: []*logspb.ScopeLogs{{
			Scope: &commonpb.InstrumentationScope{Name: "codex_cli_rs"},
			LogRecords: []*logspb.LogRecord{{
				TimeUnixNano: uint64(now.Add(-2500 * time.Millisecond).UnixNano()),
				Body:         &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "response.completed"}},
				Attributes: []*commonpb.KeyValue{
					otlpClassifierStringAttribute("event.name", "codex.sse_event"),
					otlpClassifierStringAttribute("event.kind", "response.completed"),
					otlpClassifierStringAttribute("conversation.id", conversationID),
					otlpClassifierStringAttribute("model", "gpt-5.4"),
					otlpClassifierStringAttribute("duration_ms", "1475"),
				},
			}},
		}},
	}}}
	rawAccounting, err := api.importDecodedOTLPRequestV8(
		context.Background(), rawSSELog, otelSignalLogs, "codex", now,
	)
	if err != nil || !rawAccounting.valid() || rawAccounting.unsupportedIdentity != 1 {
		t.Fatalf("raw Codex SSE accounting=%+v err=%v", rawAccounting, err)
	}
	if got := codexNativeStoredEventCount(t, fixture.path, "model.response"); got != 1 {
		t.Fatalf("raw Codex SSE imported %d extra model responses", got-1)
	}

	tokenPoint := func(tokenType string, value float64) *metricspb.HistogramDataPoint {
		return &metricspb.HistogramDataPoint{
			TimeUnixNano: uint64(now.Add(-time.Second).UnixNano()), Count: 1, Sum: &value,
			Attributes: []*commonpb.KeyValue{
				otlpClassifierStringAttribute("token_type", tokenType),
				otlpClassifierStringAttribute("model", "gpt-5.4"),
			},
		}
	}
	metricsRequest := &collectormetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			otlpClassifierStringAttribute("service.name", "codex_cli_rs"),
		}},
		ScopeMetrics: []*metricspb.ScopeMetrics{{
			Scope: &commonpb.InstrumentationScope{Name: "codex_cli_rs"},
			Metrics: []*metricspb.Metric{
				{
					Name: "codex.turn.token_usage", Unit: "",
					Data: &metricspb.Metric_Histogram{Histogram: &metricspb.Histogram{
						AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
						DataPoints: []*metricspb.HistogramDataPoint{
							tokenPoint("total", 12789), tokenPoint("input", 12770),
							tokenPoint("cached_input", 2432), tokenPoint("output", 19),
							tokenPoint("reasoning_output", 11),
						},
					}},
				},
				{
					Name: "codex.turn.e2e_duration_ms", Unit: "ms",
					Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{{
						TimeUnixNano: uint64(now.Add(-time.Second).UnixNano()),
						Value:        &metricspb.NumberDataPoint_AsDouble{AsDouble: 1475},
					}}}},
				},
			},
		}},
	}}}
	metricAccounting, err := api.importDecodedOTLPRequestV8(
		context.Background(), metricsRequest, otelSignalMetrics, "codex", now,
	)
	if err != nil || !metricAccounting.valid() || metricAccounting.decoded != 6 ||
		metricAccounting.derivedOnly != 3 || metricAccounting.unsupportedIdentity != 3 ||
		metricAccounting.derivativeRecorded != 3 {
		t.Fatalf("native Codex metric accounting=%+v err=%v", metricAccounting, err)
	}

	turnSpan := &tracepb.Span{
		TraceId: []byte{0xca, 0x34, 0xa9, 0x9d, 0xb9, 0x82, 0x50, 0x2e, 0x22, 0xc0, 0xd7, 0xd2, 0x8d, 0x29, 0x52, 0xec},
		SpanId:  []byte{0x10, 0x34, 0xa9, 0x9d, 0xb9, 0x82, 0x50, 0x2e},
		Name:    "session_task.turn", Kind: tracepb.Span_SPAN_KIND_INTERNAL,
		StartTimeUnixNano: uint64(now.Add(-1500 * time.Millisecond).UnixNano()),
		EndTimeUnixNano:   uint64(now.UnixNano()),
		Attributes: []*commonpb.KeyValue{
			otlpClassifierStringAttribute("thread.id", conversationID),
			otlpClassifierStringAttribute("turn.id", turnID),
			otlpClassifierStringAttribute("model", "gpt-5.4"),
			otlpClassifierIntAttribute("input_token_count", 12770),
			otlpClassifierIntAttribute("cached_token_count", 2432),
			otlpClassifierIntAttribute("output_token_count", 19),
		},
	}
	traceRequest := &collectortracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			otlpClassifierStringAttribute("service.name", "Codex Desktop"),
		}},
		ScopeSpans: []*tracepb.ScopeSpans{{
			Scope: &commonpb.InstrumentationScope{Name: "Codex Desktop"}, Spans: []*tracepb.Span{turnSpan},
		}},
	}}}
	traceAccounting, err := api.importDecodedOTLPRequestV8(
		context.Background(), traceRequest, otelSignalTraces, "codex", now,
	)
	if err != nil || !traceAccounting.valid() || traceAccounting.importedAndDerived != 1 ||
		traceAccounting.derivativeRecorded != 1 {
		t.Fatalf("native Codex trace accounting=%+v err=%v", traceAccounting, err)
	}

	metrics := fixture.pipelines.metrics.sinks(t, 1).local.snapshot()
	counts := make(map[string]int)
	for _, metric := range metrics {
		counts[metric.Descriptor().Name]++
		if metric.Descriptor().Name != observability.TelemetryInstrumentDefenseClawAgentTokenUsage {
			continue
		}
		attributes := metric.Attributes()
		if attributes["defenseclaw.agent.root.id"] != agentID ||
			attributes["gen_ai.agent.id"] != agentID ||
			attributes["defenseclaw.agent.lifecycle.id"] != meta.LifecycleID ||
			attributes["defenseclaw.agent.execution.id"] != meta.ExecutionID ||
			attributes["connector"] != "codex" || attributes["kind"] == "" {
			t.Fatalf("agent token local labels=%#v", attributes)
		}
		correlation := metric.CanonicalRecord().Correlation()
		if correlation.SessionID != conversationID || correlation.AgentID != agentID || correlation.TurnID != turnID {
			t.Fatalf("agent token correlation=%+v", correlation)
		}
	}
	if counts[observability.TelemetryInstrumentDefenseClawAgentTokenUsage] != 3 ||
		counts[observability.TelemetryInstrumentGenAIClientTokenUsage] != 3 ||
		counts[observability.TelemetryInstrumentGenAIClientOperationDuration] != 1 {
		t.Fatalf("native Codex local metric family counts=%v", counts)
	}

	spans := fixture.pipelines.traces.capture(t, 1).snapshot()
	if len(spans) != 1 || spans[0].Record().EventName() != "span.model.chat" ||
		spans[0].Name() != "chat gpt-5.4" || spans[0].Kind() != trace.SpanKindClient {
		t.Fatalf("native Codex turn spans=%#v", spans)
	}
	spanCorrelation := spans[0].Record().Correlation()
	if spanCorrelation.SessionID != conversationID || spanCorrelation.AgentID != agentID ||
		spanCorrelation.TurnID != turnID {
		t.Fatalf("native Codex turn correlation=%+v", spanCorrelation)
	}
	body, present := spans[0].Record().Body()
	if !present {
		t.Fatal("native Codex turn body absent")
	}
	object, err := body.Object()
	if err != nil {
		t.Fatal(err)
	}
	attributes, ok := object["attributes"].(map[string]any)
	if !ok || attributes["defenseclaw.agent.root.id"] != agentID ||
		attributes["defenseclaw.agent.lifecycle.id"] != meta.LifecycleID ||
		attributes["defenseclaw.agent.execution.id"] != meta.ExecutionID ||
		attributes["defenseclaw.turn.id"] != turnID {
		t.Fatalf("native Codex turn attributes=%#v", object["attributes"])
	}

	wrongName := proto.Clone(turnSpan).(*tracepb.Span)
	wrongName.SpanId = []byte{0x20, 0x34, 0xa9, 0x9d, 0xb9, 0x82, 0x50, 0x2e}
	wrongName.Name = "handle_responses"
	wrongRequest := &collectortracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
		ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{wrongName}}},
	}}}
	wrongAccounting, err := api.importDecodedOTLPRequestV8(
		context.Background(), wrongRequest, otelSignalTraces, "codex", now,
	)
	if err != nil || !wrongAccounting.valid() || wrongAccounting.unsupportedIdentity != 1 {
		t.Fatalf("broad Codex internal span accounting=%+v err=%v", wrongAccounting, err)
	}
	if got := len(fixture.pipelines.traces.capture(t, 1).snapshot()); got != 1 {
		t.Fatalf("broad Codex internal span emitted %d extra spans", got-1)
	}
	if got := len(fixture.pipelines.metrics.sinks(t, 1).local.snapshot()); got != len(metrics) {
		t.Fatalf("broad Codex internal span emitted %d extra metrics", got-len(metrics))
	}
}

func codexNativeStoredEventCount(t *testing.T, path, eventName string) int {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var count int
	if err := database.QueryRow(
		`SELECT COUNT(*) FROM audit_events WHERE event_name = ?`, eventName,
	).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

type codexNativeTokenPoint struct {
	tokenType string
	value     float64
}

func codexNativeTokenHistogramRequest(
	now time.Time,
	points ...codexNativeTokenPoint,
) *collectormetricspb.ExportMetricsServiceRequest {
	dataPoints := make([]*metricspb.HistogramDataPoint, 0, len(points))
	for _, point := range points {
		value := point.value
		dataPoints = append(dataPoints, &metricspb.HistogramDataPoint{
			TimeUnixNano: uint64(now.UnixNano()), Count: 1, Sum: &value,
			Attributes: []*commonpb.KeyValue{
				otlpClassifierStringAttribute("token_type", point.tokenType),
				otlpClassifierStringAttribute("model", "gpt-5.4"),
			},
		})
	}
	return &collectormetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
		Resource: &resourcepb.Resource{Attributes: []*commonpb.KeyValue{
			otlpClassifierStringAttribute("service.name", "codex_cli_rs"),
		}},
		ScopeMetrics: []*metricspb.ScopeMetrics{{
			Scope: &commonpb.InstrumentationScope{Name: "codex_cli_rs"},
			Metrics: []*metricspb.Metric{{
				Name: "codex.turn.token_usage",
				Data: &metricspb.Metric_Histogram{Histogram: &metricspb.Histogram{
					AggregationTemporality: metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA,
					DataPoints:             dataPoints,
				}},
			}},
		}},
	}}}
}

func TestOTLPInboundCodexTokenHistogramZerosAreValidNoObservations(t *testing.T) {
	fixture := newCodexNativeOTLPFixture(t)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	now := time.Now().UTC().Truncate(time.Nanosecond)
	request := codexNativeTokenHistogramRequest(
		now,
		codexNativeTokenPoint{tokenType: "input", value: 17},
		codexNativeTokenPoint{tokenType: "cached_input", value: 0},
		codexNativeTokenPoint{tokenType: "output", value: 0},
	)
	accounting, err := api.importDecodedOTLPRequestV8(
		context.Background(), request, otelSignalMetrics, "codex", now,
	)
	if err != nil || !accounting.valid() || accounting.decoded != 3 ||
		accounting.derivedOnly != 3 || accounting.derivativeRecorded != 1 ||
		accounting.derivativeNoObservation != 2 || accounting.derivativeInvalidRecord != 0 {
		t.Fatalf("mixed Codex token accounting=%+v err=%v", accounting, err)
	}

	metrics := fixture.pipelines.metrics.sinks(t, 1).local.snapshot()
	standardTokens := 0
	for _, metric := range metrics {
		if metric.Descriptor().Name == observability.TelemetryInstrumentGenAIClientTokenUsage {
			standardTokens++
			if got := metric.Attributes()["gen_ai.token.type"]; got != "input" {
				t.Fatalf("zero-token fixture emitted token type %q", got)
			}
		}
	}
	if standardTokens != 1 {
		t.Fatalf("mixed Codex token observations=%d want=1", standardTokens)
	}
}

func TestOTLPInboundCodexTokenHistogramRejectsInvalidSums(t *testing.T) {
	for _, test := range []struct {
		name  string
		value float64
	}{
		{name: "negative", value: -1},
		{name: "nan", value: math.NaN()},
		{name: "positive-infinity", value: math.Inf(1)},
		{name: "negative-infinity", value: math.Inf(-1)},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newCodexNativeOTLPFixture(t)
			api := &APIServer{}
			api.bindOTLPObservabilityRuntime(fixture.runtime)
			now := time.Now().UTC().Truncate(time.Nanosecond)
			request := codexNativeTokenHistogramRequest(
				now, codexNativeTokenPoint{tokenType: "input", value: test.value},
			)
			accounting, err := api.importDecodedOTLPRequestV8(
				context.Background(), request, otelSignalMetrics, "codex", now,
			)
			if err != nil || !accounting.valid() || accounting.invalidRecord != 1 ||
				accounting.derivativeInvalidRecord != 1 || accounting.derivativeRecorded != 0 ||
				accounting.derivativeNoObservation != 0 {
				t.Fatalf("invalid Codex token accounting=%+v err=%v", accounting, err)
			}
			for _, metric := range fixture.pipelines.metrics.sinks(t, 1).local.snapshot() {
				if metric.Descriptor().Name == observability.TelemetryInstrumentGenAIClientTokenUsage {
					t.Fatalf("invalid Codex token sum emitted metric %#v", metric)
				}
			}
		})
	}
}

func TestOTLPInboundCodexHookAuthorityRejectsConflictingBodyIdentity(t *testing.T) {
	fixture := newCodexNativeOTLPFixture(t)
	const (
		conversationID = "conversation-hook-authority"
		agentID        = "agent-hook-authority"
		turnID         = "turn-hook-authority"
	)
	meta := llmEventMeta{
		Source: "codex", SessionID: conversationID, TurnID: turnID,
		AgentID: agentID, AgentName: "root", AgentType: "codex",
		RootAgentID: agentID, RootSessionID: conversationID, LineageProvenance: "reported",
		LifecycleID: "lifecycle-hook-authority", ExecutionID: "execution-hook-authority",
		Phase: "model", AgentDepth: 0,
	}
	stateKey := hookSessionStateKey(meta)
	api := &APIServer{
		hookSessionStates:     map[string]hookSessionState{stateKey: {meta: meta}},
		hookSessionStateOrder: []string{stateKey},
	}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	now := time.Now().UTC().Truncate(time.Nanosecond)

	tests := []struct {
		name      string
		attribute *commonpb.KeyValue
	}{
		{name: "agent", attribute: otlpClassifierStringAttribute("gen_ai.agent.id", "agent-conflict")},
		{name: "root", attribute: otlpClassifierStringAttribute("defenseclaw.agent.root.id", "agent-conflict")},
		{name: "lifecycle", attribute: otlpClassifierStringAttribute("defenseclaw.agent.lifecycle.id", "lifecycle-conflict")},
		{name: "execution", attribute: otlpClassifierStringAttribute("defenseclaw.agent.execution.id", "execution-conflict")},
		{name: "turn", attribute: otlpClassifierStringAttribute("defenseclaw.turn.id", "turn-conflict")},
		{name: "depth", attribute: otlpClassifierIntAttribute("defenseclaw.agent.depth", 1)},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			attributes := []*commonpb.KeyValue{
				otlpClassifierStringAttribute("event.name", "codex.sse_event"),
				otlpClassifierStringAttribute("event.kind", "response.completed"),
				otlpClassifierStringAttribute("conversation.id", conversationID),
				otlpClassifierStringAttribute("model", "gpt-5.4"),
				otlpClassifierStringAttribute("input_token_count", "17"),
				otlpClassifierStringAttribute("output_token_count", "3"),
				test.attribute,
			}
			request := &collectorlogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
				ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{
					TimeUnixNano: uint64(now.Add(time.Duration(index) * time.Nanosecond).UnixNano()),
					Body:         &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "response.completed"}},
					Attributes:   attributes,
				}}}},
			}}}
			accounting, err := api.importDecodedOTLPRequestV8(
				context.Background(), request, otelSignalLogs, "codex", now,
			)
			if err != nil || !accounting.valid() || accounting.invalidMappedField != 1 ||
				accounting.derivativeInvalidRecord != 1 || accounting.derivativeRecorded != 0 {
				t.Fatalf("conflicting %s accounting=%+v err=%v", test.name, accounting, err)
			}
		})
	}
	if got := codexNativeStoredEventCount(t, fixture.path, "model.response"); got != 0 {
		t.Fatalf("conflicting hook identities persisted %d model responses", got)
	}
	for _, metric := range fixture.pipelines.metrics.sinks(t, 1).local.snapshot() {
		if metric.Descriptor().Name == observability.TelemetryInstrumentDefenseClawAgentTokenUsage {
			t.Fatalf("conflicting hook identity emitted root-scoped token metric %#v", metric)
		}
	}
}

func TestCodexSSETokenStringNormalizationIsNarrowAndExact(t *testing.T) {
	classifier := mustOTLPInboundClassifierV8(t)
	match, ok := classifier.catalog.Match("otlp.codex.response_completed.v1.log.model.response")
	if !ok {
		t.Fatal("generated Codex response match missing")
	}
	aliases := make(map[string]observability.InboundAlias)
	for _, alias := range match.Aliases() {
		aliases[alias.ID()] = alias
	}
	for _, test := range []struct {
		name, aliasID, source, raw string
		want                       int64
		ok                         bool
	}{
		{name: "input", aliasID: "input-tokens-v1", source: "codex", raw: "12770", want: 12770, ok: true},
		{name: "cached", aliasID: "cached-input-tokens-v1", source: "codex", raw: "2432", want: 2432, ok: true},
		{name: "zero", aliasID: "output-tokens-v1", source: "codex", raw: "0", want: 0, ok: true},
		{name: "empty", aliasID: "input-tokens-v1", source: "codex", raw: "", ok: false},
		{name: "space", aliasID: "input-tokens-v1", source: "codex", raw: " 1", ok: false},
		{name: "sign", aliasID: "input-tokens-v1", source: "codex", raw: "+1", ok: false},
		{name: "negative", aliasID: "input-tokens-v1", source: "codex", raw: "-1", ok: false},
		{name: "decimal", aliasID: "input-tokens-v1", source: "codex", raw: "1.0", ok: false},
		{name: "overflow", aliasID: "input-tokens-v1", source: "codex", raw: "9223372036854775808", ok: false},
		{name: "other source", aliasID: "input-tokens-v1", source: "claudecode", raw: "1", ok: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			alias, exists := aliases[test.aliasID]
			if !exists {
				t.Fatalf("alias %q missing", test.aliasID)
			}
			value := &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: test.raw}}
			normalized, accepted := normalizeInboundAliasValueV8(value, alias, test.source)
			if accepted != test.ok {
				t.Fatalf("accepted=%t want=%t normalized=%#v", accepted, test.ok, normalized)
			}
			if test.ok {
				integer, ok := normalized.GetValue().(*commonpb.AnyValue_IntValue)
				if !ok || integer.IntValue != test.want {
					t.Fatalf("normalized=%#v want=%d", normalized, test.want)
				}
			}
		})
	}
}

func TestCodexSSETokenAliasesAcceptEqualTypedDuplicateAndRejectConflict(t *testing.T) {
	fixture := newOTLPV8MetricFixture(t)
	api := &APIServer{}
	api.bindOTLPObservabilityRuntime(fixture.runtime)
	now := time.Now().UTC()
	request := func(second int64) *collectorlogspb.ExportLogsServiceRequest {
		return &collectorlogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
			ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{
				TimeUnixNano: uint64(now.UnixNano()),
				Body:         &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "response.completed"}},
				Attributes: []*commonpb.KeyValue{
					otlpClassifierStringAttribute("event.name", "codex.sse_event"),
					otlpClassifierStringAttribute("event.kind", "response.completed"),
					otlpClassifierStringAttribute("conversation.id", "conversation-duplicate"),
					otlpClassifierStringAttribute("model", "gpt-5.4"),
					otlpClassifierStringAttribute("input_token_count", "19"),
					otlpClassifierStringAttribute("output_token_count", "7"),
					otlpClassifierIntAttribute("gen_ai.usage.input_tokens", second),
				},
			}}}},
		}}}
	}
	equal, err := api.importDecodedOTLPRequestV8(
		context.Background(), request(19), otelSignalLogs, "codex", now,
	)
	if err != nil || !equal.valid() || equal.importedAndDerived != 1 ||
		equal.derivativeNoObservation != 1 {
		t.Fatalf("equal token alias accounting=%+v err=%v", equal, err)
	}
	conflict, err := api.importDecodedOTLPRequestV8(
		context.Background(), request(20), otelSignalLogs, "codex", now.Add(time.Nanosecond),
	)
	if err != nil || !conflict.valid() || conflict.invalidMappedField != 1 {
		t.Fatalf("conflicting token alias accounting=%+v err=%v", conflict, err)
	}
}
