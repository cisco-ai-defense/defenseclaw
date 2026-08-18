// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/scanner"
	"go.opentelemetry.io/otel/trace"
)

type watcherTestRuntime struct {
	mu      sync.Mutex
	logs    []observability.Record
	metrics []observability.Record
}

type watcherAdmissionTraceCapture struct {
	input observability.SpanGuardrailApplyInput
}

func (capture *watcherAdmissionTraceCapture) StartGuardrailApplyTrace(
	ctx context.Context,
	input observability.SpanGuardrailApplyInput,
) (context.Context, *observabilityruntime.GuardrailApplyTrace, error) {
	capture.input = input
	return ctx, nil, nil
}

func (runtime *watcherTestRuntime) EmitRuntimeV8(
	_ context.Context,
	_ router.Metadata,
	build audit.RuntimeV8Builder,
) (audit.RuntimeV8EmitOutcome, error) {
	record, err := build(watcherTestBuildContext(), router.AdmissionOrdinary)
	if err != nil {
		return audit.RuntimeV8EmitOutcome{}, err
	}
	runtime.mu.Lock()
	runtime.logs = append(runtime.logs, record)
	runtime.mu.Unlock()
	return audit.RuntimeV8EmitOutcome{
		Admission: router.AdmissionOrdinary, LocalPersisted: true,
	}, nil
}

func (runtime *watcherTestRuntime) EmitRuntimeV8LogBatch(
	_ context.Context,
	operations []audit.RuntimeV8LogOperation,
) ([]audit.RuntimeV8EmitOutcome, error) {
	outcomes := make([]audit.RuntimeV8EmitOutcome, 0, len(operations))
	for _, operation := range operations {
		record, err := operation.Build(watcherTestBuildContext(), router.AdmissionOrdinary)
		if err != nil {
			return nil, err
		}
		runtime.mu.Lock()
		runtime.logs = append(runtime.logs, record)
		runtime.mu.Unlock()
		outcomes = append(outcomes, audit.RuntimeV8EmitOutcome{
			Admission: router.AdmissionOrdinary, LocalPersisted: true,
		})
	}
	return outcomes, nil
}

func (runtime *watcherTestRuntime) RecordRuntimeV8GeneratedMetric(
	_ context.Context,
	metric audit.RuntimeV8GeneratedMetric,
) error {
	record, err := metric.Build(watcherTestBuildContext())
	if err != nil {
		return err
	}
	runtime.mu.Lock()
	runtime.metrics = append(runtime.metrics, record)
	runtime.mu.Unlock()
	return nil
}

func (runtime *watcherTestRuntime) RecordRuntimeV8GeneratedMetricBatch(
	ctx context.Context,
	metrics []audit.RuntimeV8GeneratedMetric,
) error {
	for _, metric := range metrics {
		if err := runtime.RecordRuntimeV8GeneratedMetric(ctx, metric); err != nil {
			return err
		}
	}
	return nil
}

func (runtime *watcherTestRuntime) snapshot() (logs, metrics []observability.Record) {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return append([]observability.Record(nil), runtime.logs...),
		append([]observability.Record(nil), runtime.metrics...)
}

func watcherTestBuildContext() audit.RuntimeV8BuildContext {
	return audit.RuntimeV8BuildContext{
		ConfigGeneration: 8,
		ConfigDigest:     "0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
	}
}

func TestWatcherAdmissionTraceUsesGeneratedFamilyAndJoinsScanEvaluation(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Guardrail.Connector = "codex"
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil, nil)
	capture := &watcherAdmissionTraceCapture{}
	w.BindObservabilityV8(capture)
	traceID, _ := trace.TraceIDFromHex("0123456789abcdef0123456789abcdef")
	spanID, _ := trace.SpanIDFromHex("0123456789abcdef")
	ctx := audit.ContextWithEnvelope(t.Context(), audit.CorrelationEnvelope{
		RunID: "run-watcher", RequestID: "request-watcher", SessionID: "session-watcher",
		TurnID: "turn-watcher", AgentID: "agent-watcher", AgentInstanceID: "instance-watcher",
		ToolID: "tool-watcher",
	})
	ctx = trace.ContextWithSpanContext(ctx, trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: spanID, TraceFlags: trace.FlagsSampled,
	}))

	started, operation := w.startAdmissionTraceV8(ctx, InstallEvent{
		Type: InstallSkill, Name: "example-skill",
	}, "skill", "policy-watcher")
	if operation == nil || watcherAdmissionEvaluationID(started) == "" {
		t.Fatal("watcher admission did not mint a request-bounded evaluation id")
	}
	if capture.input.DefenseClawGuardrailName != "admission" ||
		capture.input.DefenseClawGuardrailTargetType != "skill" ||
		capture.input.Outcome != observability.OutcomeAttempted ||
		capture.input.Envelope.Correlation.TraceID != traceID.String() ||
		capture.input.Envelope.Correlation.SpanID != spanID.String() ||
		capture.input.Envelope.Correlation.EvaluationID != watcherAdmissionEvaluationID(started) {
		t.Fatalf("watcher admission start input=%+v", capture.input)
	}

	completed := operation.input(observability.OutcomeBlocked, AdmissionResult{
		Verdict: VerdictBlocked, Reason: "unsafe capability", MaxSeverity: "HIGH", FindingCount: 2,
	}, time.Now().UTC())
	decision, decisionPresent := completed.DefenseClawGuardrailDecision.Get()
	findingCount, findingCountPresent := completed.DefenseClawGuardrailFindingCount.Get()
	if decision != "block" || !decisionPresent || findingCount != 2 || !findingCountPresent ||
		completed.Outcome != observability.OutcomeBlocked || !completed.ConditionOperationTerminal ||
		completed.ConditionTechnicalFailure || completed.Envelope.Correlation.EvaluationID != watcherAdmissionEvaluationID(started) {
		t.Fatalf("watcher admission completion input=%+v", completed)
	}
	corr := watcherScanCorrelation(started, "", "codex")
	if corr.EvaluationID != watcherAdmissionEvaluationID(started) || corr.TraceID != traceID.String() ||
		corr.SpanID != spanID.String() {
		t.Fatalf("watcher scan correlation=%+v", corr)
	}
}

func TestWatcherMetricsNeverReachLegacyProvider(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	runtime := &watcherTestRuntime{}
	logger.SetRuntimeV8Emitter(runtime)
	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil, nil)
	ctx := context.Background()
	w.recordWatcherEvent(ctx, "create", "skill", "")
	w.recordWatcherError(ctx)
	w.recordAdmission(ctx, "blocked", "skill")
	w.recordScanError(ctx, "skill-scanner", "skill", "timeout")
	w.emitQuarantineFailure(ctx, "/skills/example", context.DeadlineExceeded)
	w.recordBlockSLO(ctx, "skill", 12)
	if err := logger.RecordProvenanceBumpMetric(ctx, "policy_files"); err != nil {
		t.Fatal(err)
	}

	_, generated := runtime.snapshot()
	if len(generated) != 7 {
		t.Fatalf("generated watcher metrics = %d, want 7", len(generated))
	}
}

func TestEmitRescanResultUsesGeneratedV8AndPreservesForensics(t *testing.T) {
	cfg, store, logger, skillDir := setupTestEnv(t)
	cfg.Guardrail.Connector = "codex"
	runtime := &watcherTestRuntime{}
	logger.SetRuntimeV8Emitter(runtime)

	w := New(cfg, []string{skillDir}, nil, store, logger, nil, nil, nil)
	traceID, err := trace.TraceIDFromHex("0123456789abcdef0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	spanID, err := trace.SpanIDFromHex("0123456789abcdef")
	if err != nil {
		t.Fatal(err)
	}
	ctx := trace.ContextWithSpanContext(context.Background(), trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: spanID, TraceFlags: trace.FlagsSampled,
	}))
	result := &scanner.ScanResult{
		Scanner: "skill-scanner", Target: "/skills/example", TargetType: "skill",
		Timestamp: time.Now().UTC(), Duration: 25 * time.Millisecond, Verdict: "block",
		Findings: []scanner.Finding{{
			RuleID: "SKILL-001", Category: "unsafe_instruction", Severity: scanner.SeverityHigh,
			Title: "Unsafe instruction", Scanner: "skill-scanner",
		}},
	}
	scanID := w.emitRescanResult(ctx, result)
	if scanID == "" || scanID != result.ScanID {
		t.Fatalf("scan id = %q, result scan id = %q", scanID, result.ScanID)
	}
	findings, err := store.ListScanFindings(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(findings) != 1 || findings[0].RuleID.String != "SKILL-001" || findings[0].ID == "" {
		t.Fatalf("forensic findings = %#v", findings)
	}

	logs, metrics := runtime.snapshot()
	if len(logs) != 2 {
		t.Fatalf("generated scan logs = %d, want finding + summary", len(logs))
	}
	wantLogs := map[observability.EventName]bool{
		observability.EventName(observability.TelemetryEventFindingObserved): false,
		observability.EventName(observability.TelemetryEventScanCompleted):   false,
	}
	for _, record := range logs {
		if _, exists := wantLogs[record.EventName()]; exists {
			wantLogs[record.EventName()] = true
		}
		correlation := record.Correlation()
		if correlation.TraceID != traceID.String() || correlation.SpanID != spanID.String() ||
			correlation.ScanID != scanID || correlation.ConnectorID != "codex" {
			t.Fatalf("generated scan correlation = %#v", correlation)
		}
		if correlation.RunID == "" {
			t.Fatal("generated rescan log has no run id")
		}
	}
	for eventName, seen := range wantLogs {
		if !seen {
			t.Fatalf("generated scan log %s was not emitted", eventName)
		}
	}
	if len(metrics) == 0 {
		t.Fatal("generated scan metrics were not emitted")
	}
}
