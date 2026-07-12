// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"path/filepath"
	"sort"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"github.com/defenseclaw/defenseclaw/internal/version"
	oteltrace "go.opentelemetry.io/otel/trace"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

var hookLifecycleMetricV8Families = []observability.EventName{
	observability.EventName(observability.TelemetryInstrumentDefenseClawAgentLastSeen),
	observability.EventName(observability.TelemetryInstrumentDefenseClawAgentLifecycleTransitions),
	observability.EventName(observability.TelemetryInstrumentDefenseClawAgentPhaseCurrent),
	observability.EventName(observability.TelemetryInstrumentDefenseClawAgentPhaseTransitions),
	observability.EventName(observability.TelemetryInstrumentDefenseClawAgentReportedCost),
}

type hookLifecycleMetricTestSinks struct {
	canonical *otlpV8MetricCaptureSink
	local     *otlpV8MetricCaptureSink
}

type hookLifecycleMetricTestPipelines struct {
	mu          sync.Mutex
	generations map[uint64]hookLifecycleMetricTestSinks
}

func (pipelines *hookLifecycleMetricTestPipelines) build(
	_ context.Context,
	plan *config.ObservabilityV8Plan,
	generation uint64,
	_ telemetry.V8MetricReaderSpec,
) (telemetry.V8GenerationPipelines, error) {
	collected := false
	for _, bucket := range plan.Snapshot().Buckets {
		if bucket.Bucket == observability.BucketAgentLifecycle && bucket.Collect.Metrics {
			collected = true
			break
		}
	}
	if !collected {
		return telemetry.V8GenerationPipelines{}, nil
	}
	sinks := hookLifecycleMetricTestSinks{
		canonical: &otlpV8MetricCaptureSink{}, local: &otlpV8MetricCaptureSink{},
	}
	pipelines.mu.Lock()
	pipelines.generations[generation] = sinks
	pipelines.mu.Unlock()
	return telemetry.V8GenerationPipelines{MetricPipelines: []telemetry.V8GenerationMetricPipeline{
		{
			Destination: "canonical", Projection: telemetry.V8MetricProjectionCanonical,
			SelectedFamilies: append([]observability.EventName(nil), hookLifecycleMetricV8Families...),
			Sink:             sinks.canonical,
		},
		{
			Destination: "local", Projection: telemetry.V8MetricProjectionLocal,
			SelectedFamilies: append([]observability.EventName(nil), hookLifecycleMetricV8Families...),
			Sink:             sinks.local,
		},
	}}, nil
}

func (pipelines *hookLifecycleMetricTestPipelines) sinks(
	t *testing.T,
	generation uint64,
) hookLifecycleMetricTestSinks {
	t.Helper()
	pipelines.mu.Lock()
	defer pipelines.mu.Unlock()
	sinks, ok := pipelines.generations[generation]
	if !ok {
		t.Fatalf("hook lifecycle metric generation %d missing", generation)
	}
	return sinks
}

type hookLifecycleMetricTestFixture struct {
	runtime   *observabilityruntime.Runtime
	pipelines *hookLifecycleMetricTestPipelines
}

type hookLifecycleLogOnlyRuntime struct{}

func (*hookLifecycleLogOnlyRuntime) Emit(
	context.Context,
	router.Metadata,
	observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	return pipeline.LocalLogOutcome{}, nil
}

func newHookLifecycleMetricTestFixture(t *testing.T, collect bool) hookLifecycleMetricTestFixture {
	t.Helper()
	directory := t.TempDir()
	store, err := audit.NewStore(filepath.Join(directory, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	retentionDays := 0
	source := &config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{
			Path:            filepath.Join(directory, "audit.db"),
			JudgeBodiesPath: filepath.Join(directory, "judge.db"), RetentionDays: &retentionDays,
		},
	}
	if !collect {
		disabled := false
		source.Buckets = map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketAgentLifecycle: {
				Collect: config.ObservabilityV8CollectSource{Metrics: &disabled},
			},
		}
	}
	plan, err := config.CompileObservabilityV8(source)
	if err != nil {
		t.Fatal(err)
	}
	engine, err := observabilityredaction.NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	var ids atomic.Uint64
	failureBuilder, err := observability.NewRecordBuilder(
		observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("hook-lifecycle-metric-failure-%d", ids.Add(1)), nil
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
	pipelines := &hookLifecycleMetricTestPipelines{generations: make(map[uint64]hookLifecycleMetricTestSinks)}
	providerFactory := telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "8.0.0", Environment: "test", ServiceInstanceID: "hook-lifecycle-metric-test",
		DefenseClawInstanceID: "hook-lifecycle-metric-test", GenerationPipelines: pipelines.build,
	})
	runtime, err := observabilityruntime.New(
		t.Context(), runtimegraph.ConfigFromPlan(plan, false), observabilityruntime.Options{
			Store: store, Engine: engine, RecordBuilder: failureBuilder,
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
		if closeErr := runtime.Close(ctx); closeErr != nil {
			t.Errorf("close runtime: %v", closeErr)
		}
	})
	return hookLifecycleMetricTestFixture{runtime: runtime, pipelines: pipelines}
}

func richHookLifecycleMetricMeta() llmEventMeta {
	return llmEventMeta{
		Source: "claudecode", Provider: "Anthropic", Model: "claude-4-sonnet",
		SessionID: "session-root", RunID: "run-root", TurnID: "turn-7",
		AgentID: "agent-child", AgentName: "Child Agent", AgentType: "subagent",
		RootAgentID: "agent-root", ParentAgentID: "agent-root", RootSessionID: "session-root",
		LifecycleID: "lifecycle-child", ExecutionID: "execution-child",
		LifecycleEvent: "turn_end", LifecycleState: "completed",
		Phase: "model", PreviousPhase: "planning", AgentDepth: 1,
		ReportedCost: true, ReportedCostUSD: 0.25,
	}
}

func TestHookLifecycleMetricsUseGeneratedV8BatchWithoutLegacyProvider(t *testing.T) {
	fixture := newHookLifecycleMetricTestFixture(t, true)
	previousVersion := version.Current().BinaryVersion
	version.SetBinaryVersion("8.0.0-test")
	t.Cleanup(func() { version.SetBinaryVersion(previousVersion) })
	api := &APIServer{}
	api.bindObservabilityV8Runtimes(fixture.runtime, nil, nil, nil)
	api.recordHookLifecycleMetric(t.Context(), richHookLifecycleMetricMeta())

	sinks := fixture.pipelines.sinks(t, 1)
	canonical := sinks.canonical.snapshot()
	local := sinks.local.snapshot()
	if len(canonical) != 5 || len(local) != 5 {
		t.Fatalf("canonical/local metric counts=%d/%d, want 5/5", len(canonical), len(local))
	}
	wantFamilies := append([]observability.EventName(nil), hookLifecycleMetricV8Families...)
	sort.Slice(wantFamilies, func(i, j int) bool { return wantFamilies[i] < wantFamilies[j] })
	gotFamilies := make([]observability.EventName, 0, len(canonical))
	canonicalByName := make(map[string]telemetry.V8ProjectedMetric, len(canonical))
	localByName := make(map[string]telemetry.V8ProjectedMetric, len(local))
	for _, metric := range canonical {
		name := metric.Descriptor().Name
		gotFamilies = append(gotFamilies, observability.EventName(name))
		canonicalByName[name] = metric
		if metric.Generation() != 1 || metric.Profile() != "" {
			t.Fatalf("canonical %s generation/profile=%d/%q", name, metric.Generation(), metric.Profile())
		}
	}
	for _, metric := range local {
		localByName[metric.Descriptor().Name] = metric
		if metric.Generation() != 1 || metric.Profile() != observability.RuntimeLocalObservabilityProfile {
			t.Fatalf("local %s generation/profile=%d/%q", metric.Descriptor().Name, metric.Generation(), metric.Profile())
		}
	}
	sort.Slice(gotFamilies, func(i, j int) bool { return gotFamilies[i] < gotFamilies[j] })
	if fmt.Sprint(gotFamilies) != fmt.Sprint(wantFamilies) {
		t.Fatalf("generated families=%v want=%v", gotFamilies, wantFamilies)
	}
	transition := canonicalByName[observability.TelemetryInstrumentDefenseClawAgentLifecycleTransitions].Attributes()
	for key, want := range map[string]any{
		"defenseclaw.connector.source":      "claudecode",
		"gen_ai.provider.name":              "anthropic",
		"gen_ai.request.model":              "claude-4",
		"gen_ai.agent.id":                   "agent-child",
		"gen_ai.agent.name":                 "child_agent",
		"defenseclaw.agent.type":            "subagent",
		"defenseclaw.agent.root.id":         "agent-root",
		"defenseclaw.agent.parent.id":       "agent-root",
		"defenseclaw.session.root.id":       "session-root",
		"defenseclaw.agent.lifecycle.id":    "lifecycle-child",
		"defenseclaw.agent.execution.id":    "execution-child",
		"defenseclaw.agent.lifecycle.event": "turn_end",
		"defenseclaw.agent.lifecycle.state": "completed",
		"defenseclaw.agent.depth":           json.Number("1"),
	} {
		if got := transition[key]; got != want {
			t.Errorf("transition %s=%#v want %#v", key, got, want)
		}
	}
	localTransition := localByName[observability.TelemetryInstrumentDefenseClawAgentLifecycleTransitions].Attributes()
	if localTransition["connector"] != "claudecode" || localTransition["gen_ai.agent.type"] != "subagent" {
		t.Fatalf("local compatibility labels=%v", localTransition)
	}
	phaseMetric := canonicalByName[observability.TelemetryInstrumentDefenseClawAgentPhaseCurrent]
	if value, ok := phaseMetric.Value().Int64(); !ok || value != int64(telemetry.AgentPhaseCode("model")) {
		t.Fatalf("phase current value=%d/%v", value, ok)
	}
	costMetric := canonicalByName[observability.TelemetryInstrumentDefenseClawAgentReportedCost]
	if value, ok := costMetric.Value().Double(); !ok || value != 0.25 {
		t.Fatalf("reported cost value=%v/%v", value, ok)
	}
}

func TestHookLifecycleMetricV8DisablementAndMissingCapabilityNeverFallback(t *testing.T) {
	disabled := newHookLifecycleMetricTestFixture(t, false)
	api := &APIServer{}
	api.bindObservabilityV8Runtimes(disabled.runtime, nil, nil, nil)
	api.recordHookLifecycleMetric(t.Context(), richHookLifecycleMetricMeta())

	// A bound log-only test runtime deliberately lacks the batch capability.
	api.bindObservabilityV8Runtimes(&hookLifecycleLogOnlyRuntime{}, nil, nil, nil)
	api.recordHookLifecycleMetric(t.Context(), richHookLifecycleMetricMeta())
	disabled.pipelines.mu.Lock()
	defer disabled.pipelines.mu.Unlock()
	if len(disabled.pipelines.generations) != 0 {
		t.Fatalf("disabled collection prepared metric pipelines: %#v", disabled.pipelines.generations)
	}
}

func TestHookLifecycleTransitionUsesGeneratedRootAndInboundW3CParent(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"traces"})
	meta := richHookLifecycleMetricMeta()
	traceContext := oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
		TraceID: oteltrace.TraceID{1, 2, 3, 4}, SpanID: oteltrace.SpanID{5, 6, 7, 8},
		TraceFlags: oteltrace.FlagsSampled, Remote: true,
	})
	ctx := oteltrace.ContextWithRemoteSpanContext(t.Context(), traceContext)
	api.emitHookLifecycleTransitionSpan(ctx, meta)

	var spans int
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		requests, _ := capture.snapshot()
		spans = len(hookModelV8CapturedSpans(requests))
		if spans == 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if spans != 1 {
		t.Fatalf("generated lifecycle spans=%d want=1", spans)
	}
	requests, _ := capture.snapshot()
	span := hookModelV8CapturedSpans(requests)[0]
	attributes := hookModelV8ProtoAttributes(span)
	for key, want := range map[string]string{
		"defenseclaw.span.family":           observability.TelemetryFamilyAgentTransition,
		"defenseclaw.agent.lifecycle.event": meta.LifecycleEvent,
		"defenseclaw.agent.lifecycle.state": meta.LifecycleState,
		"defenseclaw.agent.lifecycle.id":    meta.LifecycleID,
		"defenseclaw.agent.execution.id":    meta.ExecutionID,
		"gen_ai.conversation.id":            meta.SessionID,
		"gen_ai.agent.id":                   meta.AgentID,
	} {
		if got := attributes[key]; got != want {
			t.Errorf("generated transition %s=%q want=%q attributes=%v", key, got, want, attributes)
		}
	}
	wantTraceID, wantParentID := traceContext.TraceID(), traceContext.SpanID()
	if got := span.GetTraceId(); string(got) != string(wantTraceID[:]) {
		t.Errorf("generated transition trace_id=%x want=%s", got, wantTraceID)
	}
	if got := span.GetParentSpanId(); string(got) != string(wantParentID[:]) {
		t.Errorf("generated transition parent_span_id=%x want=%s", got, wantParentID)
	}
	if span.GetStartTimeUnixNano() != span.GetEndTimeUnixNano() {
		t.Errorf("observed transition fabricated duration start=%d end=%d",
			span.GetStartTimeUnixNano(), span.GetEndTimeUnixNano())
	}
}

func TestHookLifecycleLogSharesGeneratedTransitionTrace(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"logs", "traces"})
	meta := richHookLifecycleMetricMeta()
	correlated := api.emitHookLifecycleTransitionSpan(t.Context(), meta)
	if got := api.emitHookLifecycleEvent(correlated, meta); got != hookLifecycleV8Persisted {
		t.Fatalf("lifecycle emission=%d want persisted", got)
	}

	var transition *tracepb.Span
	var lifecycleTraceID, lifecycleSpanID []byte
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		traceRequests, _ := capture.snapshot()
		for _, span := range hookModelV8CapturedSpans(traceRequests) {
			if gatewayProtoAttribute(span.Attributes, "defenseclaw.span.family") == observability.TelemetryFamilyAgentTransition {
				transition = span
			}
		}
		for _, record := range hookModelV8CapturedLogs(capture.logSnapshot()) {
			if logStringAttribute(record.Attributes, "defenseclaw.event.name") == meta.LifecycleEvent {
				lifecycleTraceID = record.GetTraceId()
				lifecycleSpanID = record.GetSpanId()
			}
		}
		if transition != nil && len(lifecycleTraceID) > 0 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if transition == nil || !bytes.Equal(lifecycleTraceID, transition.TraceId) || !bytes.Equal(lifecycleSpanID, transition.SpanId) {
		t.Fatalf("lifecycle correlation trace=%x span=%x generated=%x/%x", lifecycleTraceID, lifecycleSpanID, transition.GetTraceId(), transition.GetSpanId())
	}
}

func TestHookLifecycleAlwaysOffSamplerKeepsGeneratedCorrelation(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntimeWithSampler(t, "always_off")
	api := &APIServer{}
	api.bindObservabilityV8Runtimes(runtime, nil, nil, runtime)

	correlated := api.emitHookLifecycleTransitionSpan(t.Context(), richHookLifecycleMetricMeta())
	spanContext := oteltrace.SpanContextFromContext(correlated)
	if !spanContext.IsValid() || spanContext.IsSampled() {
		t.Fatalf("always-off correlation valid=%t sampled=%t context=%v", spanContext.IsValid(), spanContext.IsSampled(), spanContext)
	}
	if got := len(capture.snapshot()); got != 0 {
		t.Fatalf("always-off sampler exported %d transition spans, want 0", got)
	}
}

func TestLifecycleOnlySessionStartAndEndEmitGeneratedTransitions(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"traces"})
	for _, event := range []string{"session_start", "session_end"} {
		payload := map[string]interface{}{
			"hook_event_name": event,
			"session_id":      "openhands-lifecycle-only",
			"agent_id":        "openhands-root",
			"agent_type":      "root",
		}
		api.emitAgentHookLLMEvent(
			t.Context(), normalizeAgentHookRequest("openhands", payload), nil,
		)
	}

	var spans []*tracepb.Span
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		requests, _ := capture.snapshot()
		spans = hookModelV8CapturedSpans(requests)
		if len(spans) == 2 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if len(spans) != 2 {
		t.Fatalf("lifecycle-only generated spans=%d want=2", len(spans))
	}
	events := map[string]bool{"session_start": false, "session_end": false}
	for _, span := range spans {
		attributes := hookModelV8ProtoAttributes(span)
		if family := attributes["defenseclaw.span.family"]; family != observability.TelemetryFamilyAgentTransition {
			t.Fatalf("lifecycle-only family=%q want transition; attributes=%v", family, attributes)
		}
		events[attributes["defenseclaw.agent.lifecycle.event"]] = true
	}
	if !events["session_start"] || !events["session_end"] {
		t.Fatalf("lifecycle-only transition events=%v", events)
	}
}
