// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	_ "modernc.org/sqlite"
)

type proxyCanonicalCapture struct {
	mu      sync.Mutex
	spans   []telemetry.V8CanonicalEndedSpan
	metrics []telemetry.V8ProjectedMetric
	closed  atomic.Bool
	store   *audit.Store
}

func (capture *proxyCanonicalCapture) TryEnqueue(span telemetry.V8CanonicalEndedSpan) telemetry.V8CanonicalSpanEnqueueResult {
	if capture.closed.Load() {
		return telemetry.V8CanonicalSpanEnqueueClosed
	}
	capture.mu.Lock()
	capture.spans = append(capture.spans, span)
	capture.mu.Unlock()
	return telemetry.V8CanonicalSpanEnqueueAccepted
}

func (*proxyCanonicalCapture) ForceFlush(context.Context) error { return nil }
func (capture *proxyCanonicalCapture) RecordMetric(_ context.Context, metric telemetry.V8ProjectedMetric) error {
	if capture.closed.Load() {
		return errors.New("proxy canonical capture is closed")
	}
	capture.mu.Lock()
	capture.metrics = append(capture.metrics, metric)
	capture.mu.Unlock()
	return nil
}
func (capture *proxyCanonicalCapture) Shutdown(context.Context) error {
	capture.closed.Store(true)
	return nil
}

func (capture *proxyCanonicalCapture) snapshot() []telemetry.V8CanonicalEndedSpan {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]telemetry.V8CanonicalEndedSpan(nil), capture.spans...)
}

func (capture *proxyCanonicalCapture) metricSnapshot() []telemetry.V8ProjectedMetric {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]telemetry.V8ProjectedMetric(nil), capture.metrics...)
}

func newProxyGeneratedTraceRuntime(t *testing.T) (*observabilityruntime.Runtime, *proxyCanonicalCapture) {
	return newProxyGeneratedTraceRuntimeWithSampler(t, "always_on")
}

func newProxyGeneratedTraceRuntimeWithSampler(
	t *testing.T,
	sampler string,
) (*observabilityruntime.Runtime, *proxyCanonicalCapture) {
	return newProxyGeneratedTraceRuntimeWithSamplerAndDefaults(
		t, sampler, config.ObservabilityV8BucketPolicySource{},
	)
}

func newProxyGeneratedTraceRuntimeWithSamplerAndDefaults(
	t *testing.T,
	sampler string,
	defaults config.ObservabilityV8BucketPolicySource,
) (*observabilityruntime.Runtime, *proxyCanonicalCapture) {
	return newProxyGeneratedTraceRuntimeWithPolicies(t, sampler, defaults, nil)
}

func newProxyGeneratedTraceRuntimeWithPolicies(
	t *testing.T,
	sampler string,
	defaults config.ObservabilityV8BucketPolicySource,
	buckets map[observability.Bucket]config.ObservabilityV8BucketPolicySource,
) (*observabilityruntime.Runtime, *proxyCanonicalCapture) {
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
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{
			Path:            filepath.Join(directory, "audit.db"),
			JudgeBodiesPath: filepath.Join(directory, "judge-bodies.db"), RetentionDays: &retentionDays,
		},
		TracePolicy: config.ObservabilityV8TracePolicySource{Sampler: sampler},
		Defaults:    defaults,
		Buckets:     buckets,
		Destinations: []config.ObservabilityV8DestinationSource{{
			Name: "capture", Kind: config.ObservabilityV8DestinationOTLP,
			Protocol: "http/protobuf", Endpoint: "https://otel.example.test",
			Send: &config.ObservabilityV8SendSource{
				Signals: []observability.Signal{observability.SignalTraces, observability.SignalMetrics},
				Buckets: []observability.Bucket{"*"}, RedactionProfile: "none",
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := redaction.NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	var sequence atomic.Uint64
	builder, err := observability.NewRecordBuilder(
		observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("proxy-trace-failure-%d", sequence.Add(1)), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	reaper, err := audit.NewRetentionReaper(store, nil, 0, audit.RetentionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	retention, err := observabilityruntime.NewRetentionController(reaper, observabilityruntime.RetentionControllerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	capture := &proxyCanonicalCapture{store: store}
	providerFactory := telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "proxy-test", Environment: "test", ServiceInstanceID: "proxy-test",
		GenerationPipelines: func(context.Context, *config.ObservabilityV8Plan, uint64, telemetry.V8MetricReaderSpec) (telemetry.V8GenerationPipelines, error) {
			descriptors, catalogErr := telemetry.V8MetricDescriptorCatalog()
			if catalogErr != nil {
				return telemetry.V8GenerationPipelines{}, catalogErr
			}
			selectedFamilies := make([]observability.EventName, 0, len(descriptors))
			for _, descriptor := range descriptors {
				selectedFamilies = append(selectedFamilies, observability.EventName(descriptor.Name))
			}
			return telemetry.V8GenerationPipelines{
				SpanPipelines: []telemetry.V8GenerationSpanPipeline{{
					Destination: "capture", Canonical: capture,
				}},
				MetricPipelines: []telemetry.V8GenerationMetricPipeline{{
					Destination: "capture", Projection: telemetry.V8MetricProjectionCanonical,
					SelectedFamilies: selectedFamilies,
					Sink:             capture,
				}},
			}, nil
		},
	})
	runtime, err := observabilityruntime.New(t.Context(), runtimegraph.ConfigFromPlan(plan, false), observabilityruntime.Options{
		Store: store, Engine: engine, RecordBuilder: builder,
		Reporter: &discardSidecarGraphReporter{}, RetentionController: retention,
		TelemetryProviderFactory: providerFactory,
	})
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
	return runtime, capture
}

func TestHandleChatCompletionGeneratedTraceRejectsEmptyModelBeforeConstruction(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	provider := &mockProvider{}
	proxy := newTestProxy(t, provider, NewGuardrailInspector("local", nil, nil, ""), "action")
	proxy.SetDefaultAgentName("openclaw")
	proxy.bindObservabilityV8Trace(runtime)
	recorder := postChat(t, proxy, mustJSON(t, map[string]any{
		"messages": []map[string]any{{"role": "user", "content": "hello"}},
	}))
	if recorder.Code != 400 || provider.getLastReq() != nil || len(capture.snapshot()) != 0 {
		t.Fatalf("status=%d provider=%v spans=%d", recorder.Code, provider.getLastReq(), len(capture.snapshot()))
	}
}

func TestHandleChatCompletionGeneratedTraceDoesNotDuplicateLegacySpans(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)

	proxy := newTestProxy(t, &mockProvider{}, NewGuardrailInspector("local", nil, nil, ""), "action")
	proxy.SetDefaultAgentName("openclaw")
	proxy.bindObservabilityV8Trace(runtime)
	recorder := postChat(t, proxy, mustJSON(t, map[string]any{
		"model": "gpt-4", "messages": []map[string]any{{"role": "user", "content": "hello"}},
	}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	spans := capture.snapshot()
	agent, model := assertProxyGeneratedAgentModel(t, spans, observability.OutcomeCompleted, "Ok")
	if got := canonicalTraceEvents(t, agent.Record()); !slices.Equal(got, []string{
		observability.TelemetrySpanEventGuardrailDecision,
	}) {
		t.Fatalf("generated inspector agent overlay events=%v", got)
	}
	if got := canonicalTraceEvents(t, model.Record()); !slices.Equal(got, []string{
		observability.TelemetrySpanEventGuardrailDecision,
	}) {
		t.Fatalf("generated inspector model overlay events=%v", got)
	}
	guardrails := proxyGeneratedSpansForFamily(spans, observability.TelemetryFamilyGuardrailApply)
	if len(guardrails) != 2 {
		t.Fatalf("generated guardrail spans=%d, want prompt + completion", len(guardrails))
	}
	phases := proxyGeneratedSpansForFamily(spans, observability.TelemetryFamilyGuardrailPhase)
	if len(phases) < 2 {
		t.Fatalf("generated guardrail phase spans=%d, want at least prompt + completion regex phases", len(phases))
	}
	guardrailIDs := make(map[string]struct{}, len(guardrails))
	for _, guardrail := range guardrails {
		guardrailIDs[guardrail.SpanID().String()] = struct{}{}
		parent, present := guardrail.ParentSpanID()
		direction, _ := proxyCanonicalAttributes(t, guardrail.Record())["defenseclaw.guardrail.direction"].(string)
		wantParent := model.SpanID()
		if direction == "input" {
			wantParent = agent.SpanID()
		}
		if !present || parent != wantParent || guardrail.TraceID() != agent.TraceID() {
			t.Fatalf("guardrail direction=%q parent=%s/%t want=%s trace=%s/%s",
				direction, parent, present, wantParent, guardrail.TraceID(), agent.TraceID())
		}
	}
	for _, phase := range phases {
		parent, present := phase.ParentSpanID()
		if _, owned := guardrailIDs[parent.String()]; !present || !owned || phase.TraceID() != guardrails[0].TraceID() {
			t.Fatalf("phase %q parent=%s/%t trace=%s guardrails=%v", phase.Name(), parent, present, phase.TraceID(), guardrailIDs)
		}
	}
	metrics := capture.metricSnapshot()
	if len(metrics) == 0 {
		t.Fatal("generated proxy metrics were not recorded")
	}
	for _, metric := range metrics {
		name := metric.Descriptor().Name
		if name != observability.TelemetryInstrumentGenAIClientOperationDuration &&
			name != observability.TelemetryInstrumentGenAIClientTokenUsage {
			continue
		}
		correlation := metric.CanonicalRecord().Correlation()
		if correlation.TraceID != model.TraceID().String() || correlation.SpanID != model.SpanID().String() {
			t.Fatalf(
				"metric %s correlation=%s/%s want model=%s/%s",
				metric.Descriptor().Name, correlation.TraceID, correlation.SpanID,
				model.TraceID(), model.SpanID(),
			)
		}
	}
	rows, err := capture.store.ListEvents(10)
	if err != nil || len(rows) != 4 {
		t.Fatalf("generated proxy evaluation rows=%d err=%v", len(rows), err)
	}
	evaluations, modelLogs := 0, 0
	for _, row := range rows {
		if row.Action == string(gatewaylog.EventLLMPrompt) ||
			row.Action == string(gatewaylog.EventLLMResponse) {
			modelLogs++
			continue
		}
		evaluations++
		if row.Action != string(audit.ActionGuardrailVerdict) ||
			row.Structured["defenseclaw.guardrail.decision"] != "allow" ||
			row.Structured["defenseclaw.guardrail.effective_action"] != "allow" ||
			row.Structured["defenseclaw.guardrail.enforced"] != false ||
			row.Structured["defenseclaw.evaluation.id"] == "" {
			t.Fatalf("generated proxy evaluation row=%+v", row)
		}
	}
	if evaluations != 2 || modelLogs != 2 {
		t.Fatalf("generated proxy evaluation/model rows=%d/%d", evaluations, modelLogs)
	}
}

func TestHandleChatCompletionGeneratedInspectorTraceRecordsAppliedBlock(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	provider := &mockProvider{response: &ChatResponse{
		ID: "chatcmpl-blocked", Model: "gpt-4",
		Choices: []ChatChoice{{
			Index: 0, Message: &ChatMessage{Role: "assistant", Content: "-----BEGIN PRIVATE KEY-----"},
			FinishReason: strPtr("stop"),
		}},
	}}
	proxy := newTestProxy(t, provider, NewGuardrailInspector("local", nil, nil, ""), "action")
	proxy.SetDefaultAgentName("openclaw")
	proxy.store = capture.store
	// Runtime finding persistence is owned by the canonical audit logger, not
	// the legacy proxy.store/Provider fanout. Bind the test proxy to the same
	// runtime generation and SQLite store as its generated traces.
	proxy.logger = audit.NewLogger(capture.store)
	proxy.logger.SetRuntimeV8Emitter(&sidecarOwnedObservabilityV8Runtime{runtime: runtime})
	proxy.bindObservabilityV8Trace(runtime)
	recorder := postChat(t, proxy, mustJSON(t, map[string]any{
		"model": "gpt-4", "messages": []map[string]any{{"role": "user", "content": "hello"}},
	}))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "blocked") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	spans := capture.snapshot()
	_, model := assertProxyGeneratedAgentModel(t, spans, observability.OutcomeBlocked, "Ok")
	output := proxyGeneratedGuardrailSpan(t, spans, "output")
	parent, present := output.ParentSpanID()
	if !present || parent != model.SpanID() || output.TraceID() != model.TraceID() {
		t.Fatalf("output guardrail parent=%s/%t model=%s trace=%s/%s",
			parent, present, model.SpanID(), output.TraceID(), model.TraceID())
	}
	attributes := proxyCanonicalAttributes(t, output.Record())
	if attributes["defenseclaw.guardrail.enforced"] != true ||
		attributes["defenseclaw.guardrail.would_block"] != false ||
		attributes["defenseclaw.guardrail.effective_action"] != "block" ||
		attributes["defenseclaw.enforcement.id"] == "" ||
		attributes["defenseclaw.scan.id"] == "" ||
		attributes["defenseclaw.guardrail.rule_ids"] == nil {
		t.Fatalf("applied block attributes=%v", attributes)
	}
	evaluationID, _ := attributes["defenseclaw.evaluation.id"].(string)
	scanID, _ := attributes["defenseclaw.scan.id"].(string)
	enforcementID, _ := attributes["defenseclaw.enforcement.id"].(string)
	rows, err := capture.store.ListEvents(50)
	if err != nil {
		t.Fatal(err)
	}
	foundEvaluation, foundEnforcement := false, false
	for _, row := range rows {
		if row.Structured["defenseclaw.guardrail.direction"] == "output" {
			foundEvaluation = row.Structured["defenseclaw.evaluation.id"] == evaluationID &&
				row.Structured["defenseclaw.scan.id"] == scanID &&
				row.Structured["defenseclaw.enforcement.id"] == enforcementID && row.TraceID == output.TraceID().String()
		}
		if row.Structured["defenseclaw.enforcement.effective_action"] == "block" &&
			row.Structured["defenseclaw.evaluation.id"] == evaluationID {
			foundEnforcement = row.Structured["defenseclaw.scan.id"] == scanID &&
				row.Structured["defenseclaw.enforcement.id"] == enforcementID && row.TraceID == output.TraceID().String()
		}
	}
	if !foundEvaluation || !foundEnforcement {
		t.Fatalf("joined output evaluation/enforcement=%t/%t rows=%v", foundEvaluation, foundEnforcement, rows)
	}
	database, err := sql.Open("sqlite", capture.store.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	var persisted int
	if err := database.QueryRowContext(t.Context(), "SELECT COUNT(*) FROM scan_results WHERE id = ? AND evaluation_id = ?", scanID, evaluationID).Scan(&persisted); err != nil || persisted != 1 {
		t.Fatalf("persisted scan join count=%d error=%v", persisted, err)
	}
	phaseCount := 0
	for _, phase := range proxyGeneratedSpansForFamily(spans, observability.TelemetryFamilyGuardrailPhase) {
		phaseParent, phaseParentOK := phase.ParentSpanID()
		if phaseParentOK && phaseParent == output.SpanID() {
			phaseCount++
		}
	}
	if phaseCount == 0 {
		t.Fatal("applied output guardrail has no generated phase children")
	}
}

func TestGeneratedInspectorTraceMarksAlreadyDeliveredBlockUnenforced(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
	proxy.bindObservabilityV8Trace(runtime)
	ctx := proxyGuardrailWithoutEnforcement(t.Context())
	started, finish := startProxyGuardrailInspectionV8(
		ctx, runtime, proxy.connectorName(), "regex_only", "completion", "action",
	)
	verdict := &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "already delivered"}
	finish(verdict, 1500*time.Microsecond)
	if !verdict.GeneratedTraceOwned || !verdict.TraceContext.IsValid() || verdict.EnforcementID != "" {
		t.Fatalf("already-delivered verdict ownership=%t trace=%v enforcement=%q",
			verdict.GeneratedTraceOwned, verdict.TraceContext, verdict.EnforcementID)
	}
	proxy.recordTelemetry(started, "completion", "gpt-4", verdict, 1500*time.Microsecond, "action", false)
	output := proxyGeneratedGuardrailSpan(t, capture.snapshot(), "output")
	attributes := proxyCanonicalAttributes(t, output.Record())
	for key, want := range map[string]any{
		"defenseclaw.guardrail.mode":             "enforce",
		"defenseclaw.guardrail.raw_action":       "block",
		"defenseclaw.guardrail.effective_action": "allow",
		"defenseclaw.guardrail.would_block":      true,
		"defenseclaw.guardrail.enforced":         false,
	} {
		if attributes[key] != want {
			t.Errorf("already-delivered %s=%#v want=%#v", key, attributes[key], want)
		}
	}
	if _, fabricated := attributes["defenseclaw.enforcement.id"]; fabricated {
		t.Fatalf("already-delivered trace fabricated enforcement ID: %v", attributes)
	}
}

func TestGeneratedInspectorTraceEndStampsManagedProjectionPolicyOnRootAndPhases(t *testing.T) {
	previousManaged := ManagedEnterpriseActive()
	t.Cleanup(func() { SetManagedEnterpriseActive(previousManaged) })
	falseDirective, trueDirective := false, true
	tests := []struct {
		name      string
		managed   bool
		directive *bool
		want      observability.ProjectionPolicy
	}{
		{
			name: "outside managed stays default", managed: false, directive: &falseDirective,
			want: observability.DefaultProjectionPolicy(),
		},
		{
			name: "managed raw", managed: true, directive: &falseDirective,
			want: observability.RawProjectionPolicy(),
		},
		{
			name: "managed redact", managed: true, directive: &trueDirective,
			want: observability.RedactProjectionPolicy(),
		},
		{
			name: "managed absent fails closed", managed: true, directive: nil,
			want: observability.RedactProjectionPolicy(),
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			SetManagedEnterpriseActive(test.managed)
			runtime, capture := newProxyGeneratedTraceRuntime(t)
			started, finish := startProxyGuardrailInspectionV8(
				t.Context(), runtime, "openclaw", "regex_only", "completion", "action",
			)
			_, endPhase := startProxyGuardrailPhaseV8(started, "regex")
			endPhase("allow", "NONE", 500*time.Microsecond)
			if got := len(capture.snapshot()); got != 0 {
				t.Fatalf("phase escaped before the final projection policy was known: spans=%d", got)
			}
			finish(&ScanVerdict{
				Action: "allow", Severity: "NONE", Reason: "inspection complete",
				RedactionEnabled: test.directive,
			}, time.Millisecond)

			spans := capture.snapshot()
			root := proxyGeneratedSpansForFamily(spans, observability.TelemetryFamilyGuardrailApply)
			phases := proxyGeneratedSpansForFamily(spans, observability.TelemetryFamilyGuardrailPhase)
			if len(root) != 1 || len(phases) != 1 {
				t.Fatalf("root/phases=%d/%d spans=%d", len(root), len(phases), len(spans))
			}
			for name, record := range map[string]observability.Record{
				"root": root[0].Record(), "phase": phases[0].Record(),
			} {
				if got := record.ProjectionPolicy(); got != test.want {
					t.Errorf("%s projection policy=%#v want=%#v", name, got, test.want)
				}
			}
		})
	}
}

func TestGeneratedInspectorTraceInvalidFinalFactsAbortDeferredPhases(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	started, finish := startProxyGuardrailInspectionV8(
		t.Context(), runtime, "openclaw", "regex_only", "completion", "action",
	)
	_, endPhase := startProxyGuardrailPhaseV8(started, "regex")
	endPhase("allow", "NONE", 500*time.Microsecond)
	finish(&ScanVerdict{
		Action: "allow", Severity: "not-a-canonical-severity", Reason: "invalid final facts",
	}, time.Millisecond)
	if spans := capture.snapshot(); len(spans) != 0 {
		t.Fatalf("invalid final facts emitted a partial trace hierarchy: spans=%d", len(spans))
	}
}

func TestGeneratedInspectorTraceNilVerdictAbortsDeferredPhases(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	started, finish := startProxyGuardrailInspectionV8(
		t.Context(), runtime, "openclaw", "regex_only", "completion", "action",
	)
	_, endPhase := startProxyGuardrailPhaseV8(started, "regex")
	endPhase("allow", "NONE", 500*time.Microsecond)
	finish(nil, time.Millisecond)
	if spans := capture.snapshot(); len(spans) != 0 {
		t.Fatalf("nil verdict emitted a partial trace hierarchy: spans=%d", len(spans))
	}
}

func TestGeneratedInspectorTracePhaseEndFailureAbortsRemainingHierarchy(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	started, finish := startProxyGuardrailInspectionV8(
		t.Context(), runtime, "openclaw", "regex_only", "completion", "action",
	)
	_, endPhase := startProxyGuardrailPhaseV8(started, "regex")
	endPhase("allow", "NONE", 500*time.Microsecond)
	operation, _ := started.Value(proxyGuardrailTraceV8ContextKey{}).(*proxyGuardrailTraceV8Operation)
	if operation == nil {
		t.Fatal("generated guardrail operation is missing")
	}
	operation.phaseMu.Lock()
	phaseCount := len(operation.phases)
	if phaseCount != 1 {
		operation.phaseMu.Unlock()
		t.Fatalf("deferred phases=%d want=1", phaseCount)
	}
	// An overflowing end timestamp is rejected by the generated runtime before
	// the canonical phase can register. The root and every other pending phase
	// must then be aborted rather than leaking the generation lease.
	operation.phases[0].input.EndTimeUnixNano = ^uint64(0)
	operation.phaseMu.Unlock()
	verdict := &ScanVerdict{Action: "allow", Severity: "NONE", Reason: "inspection complete"}
	finish(verdict, time.Millisecond)
	if verdict.TraceContext.IsValid() {
		t.Fatal("root trace completed after a deferred phase failed")
	}
	if spans := capture.snapshot(); len(spans) != 0 {
		t.Fatalf("phase failure emitted a partial trace hierarchy: spans=%d", len(spans))
	}
}

func TestGeneratedInspectorPanicMetricDoesNotRequireLegacyProvider(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	inspector := NewGuardrailInspector("local", nil, nil, "")
	proxy := newTestProxy(t, &mockProvider{}, inspector, "action")
	proxy.bindObservabilityV8Trace(runtime)
	inspector.recordRecoveredPanic(t.Context())
	metrics := capture.metricSnapshot()
	if len(metrics) != 1 || metrics[0].Descriptor().Name != observability.TelemetryInstrumentDefenseClawPanicsTotal ||
		metrics[0].Attributes()["defenseclaw.metric.subsystem"] != string(gatewaylog.SubsystemGuardrail) {
		t.Fatalf("generated panic metrics=%v", metrics)
	}
}

func TestHandleChatCompletionGeneratedModelMetricsSurviveTraceSamplingDrop(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntimeWithSampler(t, "always_off")
	provider := &mockProvider{response: &ChatResponse{
		ID: "chatcmpl-metrics", Model: "gpt-4-actual",
		Choices: []ChatChoice{{
			Index: 0, Message: &ChatMessage{Role: "assistant", Content: "Hello!"},
			FinishReason: strPtr("stop"),
		}},
		Usage: &ChatUsage{PromptTokens: 11, CompletionTokens: 7, TotalTokens: 18},
	}}
	proxy := newTestProxy(t, provider, NewGuardrailInspector("local", nil, nil, ""), "action")
	proxy.SetDefaultAgentName("openclaw")
	proxy.bindObservabilityV8Trace(runtime)
	recorder := postChat(t, proxy, mustJSON(t, map[string]any{
		"model": "gpt-4", "messages": []map[string]any{{"role": "user", "content": "hello"}},
	}))
	if recorder.Code != http.StatusOK || len(capture.snapshot()) != 0 {
		t.Fatalf("status=%d sampled spans=%d body=%s", recorder.Code, len(capture.snapshot()), recorder.Body.String())
	}
	metrics := capture.metricSnapshot()
	counts := make(map[string]int)
	tokens := make(map[string]float64)
	for _, metric := range metrics {
		name := metric.Descriptor().Name
		if name != observability.TelemetryInstrumentGenAIClientOperationDuration &&
			name != observability.TelemetryInstrumentGenAIClientTokenUsage {
			continue
		}
		counts[name]++
		attributes := metric.Attributes()
		if attributes["gen_ai.operation.name"] != "chat" ||
			attributes["gen_ai.provider.name"] != "openai" ||
			attributes["gen_ai.request.model"] != "gpt-4" {
			t.Fatalf("generated proxy model metric %s dimensions=%v", name, attributes)
		}
		if name == observability.TelemetryInstrumentGenAIClientTokenUsage {
			tokenType, _ := attributes["gen_ai.token.type"].(string)
			value, ok := metric.Value().Double()
			if !ok {
				t.Fatalf("generated proxy token value arm=%v", metric.Value())
			}
			tokens[tokenType] = value
		}
	}
	if counts[observability.TelemetryInstrumentGenAIClientTokenUsage] != 2 ||
		counts[observability.TelemetryInstrumentGenAIClientOperationDuration] != 1 ||
		len(counts) != 2 || tokens["input"] != 11 || tokens["output"] != 7 {
		t.Fatalf("generated proxy model metric counts=%v tokens=%v", counts, tokens)
	}
	guardrailMetrics := make(map[string]int)
	for _, metric := range metrics {
		name := metric.Descriptor().Name
		if name == observability.TelemetryInstrumentDefenseClawGuardrailEvaluations ||
			name == observability.TelemetryInstrumentDefenseClawGuardrailLatency {
			guardrailMetrics[name]++
		}
	}
	if guardrailMetrics[observability.TelemetryInstrumentDefenseClawGuardrailEvaluations] != 2 ||
		guardrailMetrics[observability.TelemetryInstrumentDefenseClawGuardrailLatency] != 2 {
		t.Fatalf("unsampled guardrail metrics=%v", guardrailMetrics)
	}
	rows, err := capture.store.ListEvents(10)
	if err != nil || len(rows) != 4 {
		t.Fatalf("unsampled guardrail logs=%d err=%v", len(rows), err)
	}
}

func TestHandleChatCompletionGeneratedGuardrailEnforcementCompanion(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	inspector := newMockInspector()
	inspector.setVerdict("completion", &ScanVerdict{
		Action: "block", Severity: "HIGH", Reason: "policy blocked response",
	})
	proxy := newTestProxy(t, &mockProvider{}, inspector, "action")
	proxy.SetDefaultAgentName("openclaw")
	proxy.bindObservabilityV8Trace(runtime)
	recorder := postChat(t, proxy, mustJSON(t, map[string]any{
		"model": "gpt-4", "messages": []map[string]any{{"role": "user", "content": "hello"}},
	}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	spans := capture.snapshot()
	agent, model := assertProxyGeneratedAgentModel(t, spans, observability.OutcomeBlocked, "Ok")
	if got := canonicalTraceEvents(t, agent.Record()); !slices.Equal(got, []string{
		observability.TelemetrySpanEventGuardrailDecision,
	}) {
		t.Fatalf("agent prompt guardrail overlay events=%v", got)
	}
	if got := canonicalTraceEvents(t, model.Record()); !slices.Equal(got, []string{
		observability.TelemetrySpanEventGuardrailDecision,
	}) {
		t.Fatalf("model completion guardrail overlay events=%v", got)
	}
	output := proxyGeneratedGuardrailSpan(t, spans, "output")
	parent, parentOK := output.ParentSpanID()
	if !parentOK || parent != model.SpanID() || output.TraceID() != model.TraceID() {
		t.Fatalf("output guardrail parent=%s/%t model=%s trace=%s/%s", parent, parentOK, model.SpanID(), output.TraceID(), model.TraceID())
	}
	attributes := proxyCanonicalAttributes(t, output.Record())
	for key, want := range map[string]any{
		"defenseclaw.guardrail.decision":         "block",
		"defenseclaw.guardrail.raw_action":       "block",
		"defenseclaw.guardrail.effective_action": "block",
		"defenseclaw.guardrail.mode":             "enforce",
		"defenseclaw.guardrail.would_block":      false,
		"defenseclaw.guardrail.enforced":         true,
		"defenseclaw.security.severity":          "HIGH",
	} {
		if attributes[key] != want {
			t.Errorf("output guardrail %s=%#v want=%#v", key, attributes[key], want)
		}
	}
	enforcementID, _ := attributes["defenseclaw.enforcement.id"].(string)
	evaluationID, _ := attributes["defenseclaw.evaluation.id"].(string)
	if enforcementID == "" || evaluationID == "" {
		t.Fatalf("output guardrail correlation=%v", attributes)
	}
	if got := canonicalTraceEvents(t, output.Record()); !slices.Equal(got, []string{
		observability.TelemetrySpanEventGuardrailDecision,
		observability.TelemetrySpanEventEnforcementRequested,
	}) {
		t.Fatalf("output guardrail events=%v", got)
	}

	rows, err := capture.store.ListEvents(10)
	if err != nil || len(rows) != 5 {
		t.Fatalf("generated enforcement rows=%d err=%v", len(rows), err)
	}
	evaluations, enforcements := 0, 0
	for _, row := range rows {
		switch {
		case row.Structured["defenseclaw.guardrail.decision"] != nil:
			evaluations++
			if row.Structured["defenseclaw.guardrail.direction"] == "output" {
				if row.Structured["defenseclaw.evaluation.id"] != evaluationID ||
					row.Structured["defenseclaw.enforcement.id"] != enforcementID ||
					row.TraceID != output.TraceID().String() {
					t.Fatalf("output evaluation row=%+v", row)
				}
			}
		case row.Structured["defenseclaw.enforcement.effective_action"] != nil:
			enforcements++
			if row.Action != string(audit.ActionBlock) ||
				row.Structured["defenseclaw.evaluation.id"] != evaluationID ||
				row.Structured["defenseclaw.enforcement.id"] != enforcementID ||
				row.Structured["defenseclaw.enforcement.effective_action"] != "block" {
				t.Fatalf("enforcement companion=%+v", row)
			}
		}
	}
	if evaluations != 2 || enforcements != 1 {
		t.Fatalf("evaluation/enforcement rows=%d/%d", evaluations, enforcements)
	}
}

func TestHandleChatCompletionGeneratedGuardrailObserveModeIsNotEnforcement(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	inspector := newMockInspector()
	inspector.setVerdict("completion", &ScanVerdict{
		Action: "block", Severity: "HIGH", Reason: "observe-only finding",
	})
	proxy := newTestProxy(t, &mockProvider{}, inspector, "observe")
	proxy.SetDefaultAgentName("openclaw")
	proxy.bindObservabilityV8Trace(runtime)
	recorder := postChat(t, proxy, mustJSON(t, map[string]any{
		"model": "gpt-4", "messages": []map[string]any{{"role": "user", "content": "hello"}},
	}))
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "Hello!") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	spans := capture.snapshot()
	_, model := assertProxyGeneratedAgentModel(t, spans, observability.OutcomeCompleted, "Ok")
	if got := canonicalTraceEvents(t, model.Record()); !slices.Equal(got, []string{
		observability.TelemetrySpanEventGuardrailDecision,
	}) {
		t.Fatalf("observe model guardrail overlay events=%v", got)
	}
	output := proxyGeneratedGuardrailSpan(t, spans, "output")
	attributes := proxyCanonicalAttributes(t, output.Record())
	for key, want := range map[string]any{
		"defenseclaw.guardrail.decision":         "block",
		"defenseclaw.guardrail.raw_action":       "block",
		"defenseclaw.guardrail.effective_action": "allow",
		"defenseclaw.guardrail.mode":             "observe",
		"defenseclaw.guardrail.would_block":      true,
		"defenseclaw.guardrail.enforced":         false,
	} {
		if attributes[key] != want {
			t.Errorf("observe guardrail %s=%#v want=%#v", key, attributes[key], want)
		}
	}
	if _, fabricated := attributes["defenseclaw.enforcement.id"]; fabricated {
		t.Fatalf("observe guardrail fabricated enforcement ID: %v", attributes)
	}
	if got := canonicalTraceEvents(t, output.Record()); !slices.Equal(got, []string{
		observability.TelemetrySpanEventGuardrailDecision,
	}) {
		t.Fatalf("observe guardrail events=%v", got)
	}
	rows, err := capture.store.ListEvents(10)
	if err != nil || len(rows) != 4 {
		t.Fatalf("observe rows=%d err=%v", len(rows), err)
	}
	for _, row := range rows {
		if row.Structured["defenseclaw.enforcement.effective_action"] != nil || row.Action == string(audit.ActionBlock) {
			t.Fatalf("observe mode emitted enforcement companion: %+v", row)
		}
	}
}

func TestHandleChatCompletionGeneratedEnforcementFloorSurvivesLogCollectionDisablement(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	disabled := false
	retentionDays := 0
	storePath := capture.store.DatabasePath()
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{
			Path: storePath, JudgeBodiesPath: filepath.Join(filepath.Dir(storePath), "judge-bodies.db"),
			RetentionDays: &retentionDays,
		},
		Buckets: map[observability.Bucket]config.ObservabilityV8BucketPolicySource{
			observability.BucketModelIO: {
				Collect: config.ObservabilityV8CollectSource{Logs: &disabled},
			},
			observability.BucketGuardrailEvaluation: {
				Collect: config.ObservabilityV8CollectSource{Logs: &disabled},
			},
			observability.BucketEnforcementAction: {
				Collect: config.ObservabilityV8CollectSource{Logs: &disabled},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	reload, reloadErr := runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(plan, false))
	if reloadErr != nil || reload.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("disable proxy logs: status=%s err=%v", reload.Status(), reloadErr)
	}
	inspector := newMockInspector()
	inspector.setVerdict("completion", &ScanVerdict{
		Action: "block", Severity: "CRITICAL", Reason: "private blocked content",
		RuleIDs: []string{"private-rule"},
	})
	proxy := newTestProxy(t, &mockProvider{}, inspector, "action")
	proxy.SetDefaultAgentName("openclaw")
	proxy.bindObservabilityV8Trace(runtime)
	recorder := postChat(t, proxy, mustJSON(t, map[string]any{
		"model": "gpt-4", "messages": []map[string]any{{"role": "user", "content": "private prompt"}},
	}))
	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}

	reader, err := sql.Open("sqlite", storePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	var eventName, bucket, payload, traceID string
	var mandatory int
	err = reader.QueryRowContext(t.Context(), `
		SELECT COALESCE(event_name,''), COALESCE(bucket,''), COALESCE(mandatory,0),
		       COALESCE(payload_json,''), COALESCE(trace_id,'')
		FROM audit_events`).Scan(&eventName, &bucket, &mandatory, &payload, &traceID)
	if err != nil {
		t.Fatal(err)
	}
	if eventName != observability.TelemetryEventEnforcementBlockApplied ||
		bucket != string(observability.BucketEnforcementAction) || mandatory != 1 || traceID == "" {
		t.Fatalf("floor event=%q bucket=%q mandatory=%d trace=%q", eventName, bucket, mandatory, traceID)
	}
	for _, forbidden := range []string{"private blocked content", "private-rule", "private prompt"} {
		if strings.Contains(payload, forbidden) {
			t.Fatalf("mandatory enforcement floor retained %q: %s", forbidden, payload)
		}
	}
}

func TestHandleChatCompletionGeneratedTraceNonStreamingOutcomes(t *testing.T) {
	toolCalls := json.RawMessage(`[{"id":"call-1","type":"function","function":{"name":"weather","arguments":"{\"city\":\"Austin\"}"}}]`)
	tests := []struct {
		name      string
		provider  *mockProvider
		inspect   func(*mockInspector)
		wantCode  int
		outcome   observability.Outcome
		status    string
		tools     int
		errorType string
	}{
		{name: "completed", provider: &mockProvider{}, wantCode: 200, outcome: observability.OutcomeCompleted, status: "Ok"},
		{name: "upstream failed", provider: &mockProvider{err: errors.New("upstream unavailable")}, wantCode: 502, outcome: observability.OutcomeFailed, status: "Error", errorType: "upstream_error"},
		{name: "output blocked", provider: &mockProvider{}, inspect: func(inspector *mockInspector) {
			inspector.setVerdict("completion", &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "blocked"})
		}, wantCode: 200, outcome: observability.OutcomeBlocked, status: "Ok"},
		{name: "proposed tool call", provider: &mockProvider{response: &ChatResponse{
			ID: "chatcmpl-tool", Model: "gpt-4", Choices: []ChatChoice{{
				Message: &ChatMessage{Role: "assistant", ToolCalls: toolCalls}, FinishReason: strPtr("tool_calls"),
			}},
		}}, wantCode: 200, outcome: observability.OutcomeCompleted, status: "Ok", tools: 1},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime, capture := newProxyGeneratedTraceRuntime(t)
			inspector := newMockInspector()
			if test.inspect != nil {
				test.inspect(inspector)
			}
			proxy := newTestProxy(t, test.provider, inspector, "action")
			proxy.SetDefaultAgentName("openclaw")
			proxy.bindObservabilityV8Trace(runtime)
			recorder := postChat(t, proxy, mustJSON(t, map[string]any{
				"model": "gpt-4", "messages": []map[string]any{{"role": "user", "content": "hello"}},
			}))
			if recorder.Code != test.wantCode {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			agent, model := assertProxyGeneratedAgentModel(t, capture.snapshot(), test.outcome, test.status)
			if model.EndTime().After(agent.EndTime()) {
				t.Fatalf("model ended after agent: model=%s agent=%s", model.EndTime(), agent.EndTime())
			}
			attributes := proxyCanonicalAttributes(t, model.Record())
			toolCount, countErr := attributes["defenseclaw.model.tool_call_count"].(json.Number).Int64()
			if countErr != nil || int(toolCount) != test.tools {
				t.Fatalf("tool count=%d error=%v want=%d", toolCount, countErr, test.tools)
			}
			if test.tools > 0 {
				if _, reported := attributes["gen_ai.output.messages"]; !reported {
					t.Fatal("tool-call-only model output was not represented structurally")
				}
			}
			if test.errorType != "" && attributes["error.type"] != test.errorType {
				t.Fatalf("error.type=%v want=%s", attributes["error.type"], test.errorType)
			}
			if _, fabricated := attributes["gen_ai.conversation.id"]; fabricated || model.Record().Correlation().SessionID != "" {
				t.Fatal("proxy fabricated conversation correlation")
			}
		})
	}
}

func TestHandleChatCompletionGeneratedTraceStreamingOutcomes(t *testing.T) {
	completedChunks := []StreamChunk{
		{ID: "chatcmpl-stream", Model: "gpt-4-actual", Choices: []ChatChoice{{Delta: &ChatMessage{Content: "hello "}}}},
		{ID: "chatcmpl-stream", Model: "gpt-4-actual", Choices: []ChatChoice{{Delta: &ChatMessage{Content: "world"}, FinishReason: strPtr("stop")}}},
	}
	tests := []struct {
		name     string
		provider *mockProvider
		inspect  func(*mockInspector)
		outcome  observability.Outcome
		status   string
	}{
		{name: "completed", provider: &mockProvider{streamChunks: completedChunks}, outcome: observability.OutcomeCompleted, status: "Ok"},
		{name: "upstream failed", provider: &mockProvider{err: errors.New("stream unavailable")}, outcome: observability.OutcomeFailed, status: "Error"},
		{name: "output blocked", provider: &mockProvider{streamChunks: completedChunks}, inspect: func(inspector *mockInspector) {
			inspector.setVerdict("completion", &ScanVerdict{Action: "block", Severity: "HIGH", Reason: "blocked"})
		}, outcome: observability.OutcomeBlocked, status: "Ok"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime, capture := newProxyGeneratedTraceRuntime(t)
			inspector := newMockInspector()
			if test.inspect != nil {
				test.inspect(inspector)
			}
			proxy := newTestProxy(t, test.provider, inspector, "action")
			proxy.SetDefaultAgentName("openclaw")
			proxy.bindObservabilityV8Trace(runtime)
			recorder := postChat(t, proxy, mustJSON(t, map[string]any{
				"model": "gpt-4", "stream": true,
				"messages": []map[string]any{{"role": "user", "content": "hello"}},
			}))
			if recorder.Code != 200 {
				t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
			}
			_, model := assertProxyGeneratedAgentModel(t, capture.snapshot(), test.outcome, test.status)
			attributes := proxyCanonicalAttributes(t, model.Record())
			if streaming, ok := attributes["defenseclaw.model.streaming"].(bool); !ok || !streaming {
				t.Fatalf("streaming=%v", attributes["defenseclaw.model.streaming"])
			}
			streamMetrics := make(map[string][]telemetry.V8ProjectedMetric)
			for _, metric := range capture.metricSnapshot() {
				switch metric.Descriptor().Name {
				case observability.TelemetryInstrumentDefenseClawStreamLifecycle,
					observability.TelemetryInstrumentDefenseClawStreamDurationMs,
					observability.TelemetryInstrumentDefenseClawStreamBytesSent:
					streamMetrics[metric.Descriptor().Name] = append(streamMetrics[metric.Descriptor().Name], metric)
				}
			}
			if len(streamMetrics[observability.TelemetryInstrumentDefenseClawStreamLifecycle]) != 2 ||
				len(streamMetrics[observability.TelemetryInstrumentDefenseClawStreamDurationMs]) != 1 ||
				len(streamMetrics[observability.TelemetryInstrumentDefenseClawStreamBytesSent]) != 1 {
				t.Fatalf("generated stream metrics=%v", streamMetrics)
			}
			transitions := make(map[string]string)
			for _, metric := range streamMetrics[observability.TelemetryInstrumentDefenseClawStreamLifecycle] {
				metricAttributes := metric.Attributes()
				transition, _ := metricAttributes["defenseclaw.metric.transition"].(string)
				outcome, _ := metricAttributes["defenseclaw.outcome"].(string)
				transitions[transition] = outcome
			}
			if transitions["open"] != string(observability.OutcomeAttempted) ||
				transitions["close"] != string(test.outcome) {
				t.Fatalf("generated stream transitions=%v want close=%s", transitions, test.outcome)
			}
			for _, family := range []string{
				observability.TelemetryInstrumentDefenseClawStreamDurationMs,
				observability.TelemetryInstrumentDefenseClawStreamBytesSent,
			} {
				metric := streamMetrics[family][0]
				correlation := metric.CanonicalRecord().Correlation()
				if correlation.TraceID != model.TraceID().String() || correlation.SpanID != model.SpanID().String() ||
					metric.Attributes()["defenseclaw.outcome"] != string(test.outcome) {
					t.Fatalf("stream metric %s correlation/outcome=%+v/%v want model=%s/%s outcome=%s",
						family, correlation, metric.Attributes(), model.TraceID(), model.SpanID(), test.outcome)
				}
			}
		})
	}
}

func TestHandleChatCompletionGeneratedTraceUsesReportedConversationAndHonestModelRoot(t *testing.T) {
	t.Run("reported conversation", func(t *testing.T) {
		runtime, capture := newProxyGeneratedTraceRuntime(t)
		proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
		proxy.SetDefaultAgentName("openclaw")
		proxy.bindObservabilityV8Trace(runtime)
		body := mustJSON(t, map[string]any{
			"model": "gpt-4", "messages": []map[string]any{{"role": "user", "content": "hello"}},
		})
		request := httptest.NewRequest(http.MethodPost, "/v1/chat/completions", bytes.NewReader(body))
		request.RemoteAddr = "127.0.0.1:12345"
		request.Header.Set("X-Conversation-ID", "conversation-reported")
		recorder := httptest.NewRecorder()
		proxy.handleChatCompletion(recorder, request)
		agent, model := assertProxyGeneratedAgentModel(
			t, capture.snapshot(), observability.OutcomeCompleted, "Ok",
		)
		for _, span := range []telemetry.V8CanonicalEndedSpan{agent, model} {
			if span.Record().Correlation().SessionID != "conversation-reported" ||
				proxyCanonicalAttributes(t, span.Record())["gen_ai.conversation.id"] != "conversation-reported" {
				t.Fatalf("family=%s conversation=%+v", span.Record().EventName(), span.Record().Correlation())
			}
		}
	})

	t.Run("no observed agent", func(t *testing.T) {
		runtime, capture := newProxyGeneratedTraceRuntime(t)
		proxy := newTestProxy(t, &mockProvider{}, newMockInspector(), "action")
		proxy.bindObservabilityV8Trace(runtime)
		recorder := postChat(t, proxy, mustJSON(t, map[string]any{
			"model": "gpt-4", "messages": []map[string]any{{"role": "user", "content": "hello"}},
		}))
		spans := capture.snapshot()
		models := proxyGeneratedSpansForFamily(spans, observability.TelemetryFamilyModelChat)
		if recorder.Code != 200 || len(models) != 1 {
			t.Fatalf("status=%d spans=%v", recorder.Code, spans)
		}
		attributes := proxyCanonicalAttributes(t, models[0].Record())
		for _, key := range []string{"gen_ai.agent.id", "gen_ai.agent.name", "defenseclaw.agent.type"} {
			if _, fabricated := attributes[key]; fabricated {
				t.Fatalf("model root fabricated %s", key)
			}
		}
	})
}

func assertProxyGeneratedAgentModel(
	t *testing.T,
	spans []telemetry.V8CanonicalEndedSpan,
	outcome observability.Outcome,
	status string,
) (telemetry.V8CanonicalEndedSpan, telemetry.V8CanonicalEndedSpan) {
	t.Helper()
	var agent, model telemetry.V8CanonicalEndedSpan
	agentCount, modelCount := 0, 0
	for _, span := range spans {
		switch span.Record().EventName() {
		case observability.EventName(observability.TelemetryFamilyAgentInvoke):
			agent = span
			agentCount++
		case observability.EventName(observability.TelemetryFamilyModelChat):
			model = span
			modelCount++
		}
	}
	if agentCount != 1 || modelCount != 1 {
		t.Fatalf("canonical agent/model counts=%d/%d spans=%d", agentCount, modelCount, len(spans))
	}
	if !agent.SpanID().IsValid() || !model.SpanID().IsValid() || agent.TraceID() != model.TraceID() {
		t.Fatalf("invalid topology agent=%s/%s model=%s/%s", agent.TraceID(), agent.SpanID(), model.TraceID(), model.SpanID())
	}
	parent, ok := model.ParentSpanID()
	if !ok || parent != agent.SpanID() {
		t.Fatalf("model parent=%s/%v want=%s", parent, ok, agent.SpanID())
	}
	for _, span := range []telemetry.V8CanonicalEndedSpan{agent, model} {
		if span.Record().Outcome() != outcome || span.StatusCode().String() != status {
			t.Fatalf("family=%s outcome/status=%s/%s want=%s/%s", span.Record().EventName(), span.Record().Outcome(), span.StatusCode(), outcome, status)
		}
	}
	return agent, model
}

func proxyGeneratedSpansForFamily(
	spans []telemetry.V8CanonicalEndedSpan,
	family string,
) []telemetry.V8CanonicalEndedSpan {
	result := make([]telemetry.V8CanonicalEndedSpan, 0, len(spans))
	for _, span := range spans {
		if span.Record().EventName() == observability.EventName(family) {
			result = append(result, span)
		}
	}
	return result
}

func proxyGeneratedGuardrailSpan(
	t *testing.T,
	spans []telemetry.V8CanonicalEndedSpan,
	direction string,
) telemetry.V8CanonicalEndedSpan {
	t.Helper()
	var result telemetry.V8CanonicalEndedSpan
	count := 0
	for _, span := range proxyGeneratedSpansForFamily(spans, observability.TelemetryFamilyGuardrailApply) {
		if proxyCanonicalAttributes(t, span.Record())["defenseclaw.guardrail.direction"] == direction {
			result = span
			count++
		}
	}
	if count != 1 {
		t.Fatalf("guardrail direction %q count=%d spans=%d", direction, count, len(spans))
	}
	return result
}

func proxyCanonicalAttributes(t *testing.T, record observability.Record) map[string]any {
	t.Helper()
	body, ok := record.Body()
	if !ok {
		t.Fatal("canonical record has no body")
	}
	object, err := body.Object()
	if err != nil {
		t.Fatal(err)
	}
	attributes, ok := object["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("attributes=%T", object["attributes"])
	}
	return attributes
}
