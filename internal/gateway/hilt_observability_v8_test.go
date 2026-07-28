// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"go.opentelemetry.io/otel/trace"
)

func TestHILTApprovalV8UnavailableEmitsCorrelatedTerminalSignals(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	manager := NewHILTApprovalManager(nil)
	manager.bindObservabilityV8(runtime)

	traceID := trace.TraceID{0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17, 0x18, 0x19, 0x1a, 0x1b, 0x1c, 0x1d, 0x1e, 0x1f}
	parentSpanID := trace.SpanID{0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27}
	traceState, err := trace.ParseTraceState("dc=approval-test")
	if err != nil {
		t.Fatal(err)
	}
	parent := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: parentSpanID, TraceFlags: trace.FlagsSampled,
		TraceState: traceState, Remote: true,
	})
	ctx := trace.ContextWithRemoteSpanContext(context.Background(), parent)
	ctx = audit.ContextWithEnvelope(ctx, audit.CorrelationEnvelope{
		RunID: "run-approval", RequestID: "request-approval", SessionID: "session-approval",
		TurnID: "turn-approval", AgentID: "agent-approval", AgentName: "approval-agent",
		AgentInstanceID: "agent-instance-approval", PolicyID: "policy-approval",
		DestinationApp: "terminal", ToolName: "shell", ToolID: "tool-shell",
	})
	depth, sequence := int64(2), int64(9)

	approved, status, requestErr := manager.Request(
		ctx, "", "shell rm -rf /private/example", "HIGH", "matched sensitive approval policy",
		time.Second,
		HILTApprovalContext{
			EvaluationID: "evaluation-approval", RuleIDs: []string{"rule-approval"},
			OperationID: "operation-approval", AgentType: "subagent",
			RootAgentID: "agent-root", ParentAgentID: "agent-parent",
			RootSessionID: "session-root", ParentSessionID: "session-parent",
			LineageProvenance: "reported", LifecycleID: "lifecycle-approval",
			ExecutionID: "execution-approval", Depth: &depth, Phase: "approval", Sequence: &sequence,
			UserID: "user-approval", UserName: "operator", PolicyVersion: "policy-v1",
			ToolType: "function", ToolCallID: "tool-call-approval",
			ToolProvider: "builtin", ToolSkillKey: "skill-shell",
		},
	)
	if approved || status != hiltStatusUnsupported || requestErr == nil {
		t.Fatalf("approved/status/error=%t/%q/%v", approved, status, requestErr)
	}
	spans := capture.snapshot()
	if len(spans) != 1 {
		t.Fatalf("approval spans=%d, want 1", len(spans))
	}
	span := spans[0]
	record := span.Record()
	if record.EventName() != observability.EventName(observability.TelemetryFamilyApprovalResolve) ||
		record.Bucket() != observability.BucketEnforcementAction ||
		record.Outcome() != observability.OutcomeCancelled ||
		span.Name() != "exec.approval" ||
		span.StatusCode().String() != "Error" || span.StatusDescription() != "approval_unavailable" {
		t.Fatalf("approval span=%s/%s/%s/%q/%s/%q", record.EventName(), record.Bucket(), record.Outcome(), span.Name(), span.StatusCode(), span.StatusDescription())
	}
	if span.TraceID() != traceID || span.TraceState() != traceState.String() || span.OTLPFlags() != 0x301 {
		t.Fatalf("approval W3C context trace=%s state=%q flags=%#x", span.TraceID(), span.TraceState(), span.OTLPFlags())
	}
	if parentID, present := span.ParentSpanID(); !present || parentID != parentSpanID {
		t.Fatalf("approval parent=%s/%t want=%s", parentID, present, parentSpanID)
	}
	correlation := record.Correlation()
	if correlation.TraceID != traceID.String() || correlation.SpanID != span.SpanID().String() ||
		correlation.RunID != "run-approval" || correlation.RequestID != "request-approval" ||
		correlation.SessionID != "session-approval" || correlation.TurnID != "turn-approval" ||
		correlation.AgentID != "agent-approval" || correlation.AgentInstanceID != "agent-instance-approval" ||
		correlation.PolicyID != "policy-approval" || correlation.PolicyVersion != "policy-v1" ||
		correlation.EvaluationID != "evaluation-approval" || correlation.ToolInvocationID != "tool-call-approval" {
		t.Fatalf("approval correlation=%+v", correlation)
	}
	attributes := proxyCanonicalAttributes(t, record)
	for key, want := range map[string]any{
		"defenseclaw.approval.command":    "shell rm -rf /private/example",
		"defenseclaw.approval.result":     "cancelled",
		"defenseclaw.approval.actor_type": "automatic",
		"defenseclaw.guardrail.reason":    "matched sensitive approval policy",
		"defenseclaw.security.severity":   "HIGH",
		"defenseclaw.evaluation.id":       "evaluation-approval",
		"gen_ai.conversation.id":          "session-approval",
		"gen_ai.agent.id":                 "agent-approval",
		"defenseclaw.agent.instance_id":   "agent-instance-approval",
		"defenseclaw.agent.root.id":       "agent-root",
		"defenseclaw.agent.parent.id":     "agent-parent",
		"defenseclaw.session.root.id":     "session-root",
		"defenseclaw.session.parent.id":   "session-parent",
		"defenseclaw.agent.lifecycle.id":  "lifecycle-approval",
		"defenseclaw.agent.execution.id":  "execution-approval",
		"defenseclaw.agent.phase":         "approval",
		"defenseclaw.request.id":          "request-approval",
		"defenseclaw.turn.id":             "turn-approval",
		"defenseclaw.run.id":              "run-approval",
		"defenseclaw.operation.id":        "operation-approval",
		"defenseclaw.policy.id":           "policy-approval",
		"defenseclaw.policy.version":      "policy-v1",
		"defenseclaw.destination.app":     "terminal",
		"defenseclaw.tool.id":             "tool-shell",
		"gen_ai.tool.name":                "shell",
		"gen_ai.tool.type":                "function",
		"gen_ai.tool.call.id":             "tool-call-approval",
		"defenseclaw.tool.provider":       "builtin",
		"defenseclaw.tool.skill_key":      "skill-shell",
		"user.id":                         "user-approval",
		"defenseclaw.user.name":           "operator",
		"error.type":                      "approval_unavailable",
	} {
		if attributes[key] != want {
			t.Errorf("approval attribute %s=%#v want=%#v", key, attributes[key], want)
		}
	}
	ruleIDs, ok := attributes["defenseclaw.guardrail.rule_ids"].([]any)
	if !ok || len(ruleIDs) != 1 || ruleIDs[0] != "rule-approval" {
		t.Fatalf("approval rule IDs=%#v", attributes["defenseclaw.guardrail.rule_ids"])
	}
	events := canonicalTraceEvents(t, record)
	if len(events) != 2 || events[0] != "approval.requested" || events[1] != "approval.resolved" {
		t.Fatalf("approval events=%v", events)
	}

	metrics := capture.metricSnapshot()
	if len(metrics) != 1 || metrics[0].Descriptor().Name != observability.TelemetryInstrumentDefenseClawApprovalLifecycle {
		t.Fatalf("approval metrics=%v", judgeMetricCounts(metrics))
	}
	localLabels := make(map[string]string)
	for _, mapping := range metrics[0].Descriptor().LocalLabelMapping {
		localLabels[mapping.Canonical] = mapping.Local
	}
	for canonical, local := range map[string]string{
		"defenseclaw.approval.lifecycle.result": "result",
		"defenseclaw.approval.surface":          "surface",
		"defenseclaw.connector.source":          "connector",
	} {
		if localLabels[canonical] != local {
			t.Errorf("approval local label %s=%q want=%q", canonical, localLabels[canonical], local)
		}
	}
	metricAttributes := metrics[0].Attributes()
	for key, want := range map[string]any{
		"defenseclaw.approval.lifecycle.result": "unavailable",
		"defenseclaw.approval.surface":          "chat",
		"defenseclaw.connector.source":          "openclaw",
	} {
		if metricAttributes[key] != want {
			t.Errorf("approval metric attribute %s=%#v want=%#v", key, metricAttributes[key], want)
		}
	}
	metricCorrelation := metrics[0].CanonicalRecord().Correlation()
	if metricCorrelation.TraceID != correlation.TraceID || metricCorrelation.SpanID != correlation.SpanID {
		t.Fatalf("metric correlation=%+v span correlation=%+v", metricCorrelation, correlation)
	}

	rows, err := capture.store.ListEvents(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(rows) != 2 {
		t.Fatalf("approval log rows=%d, want request + resolution", len(rows))
	}
	requested, resolved := 0, 0
	var approvalID string
	for _, row := range rows {
		if row.Action != string(audit.ActionGuardrailHILT) || row.TraceID != correlation.TraceID ||
			row.RunID != "run-approval" || row.RequestID != "request-approval" ||
			row.SessionID != "session-approval" || row.TurnID != "turn-approval" ||
			row.AgentID != "agent-approval" || row.AgentInstanceID != "agent-instance-approval" ||
			row.PolicyID != "policy-approval" || row.Connector != hiltV8Connector {
			t.Fatalf("approval log envelope=%+v", row)
		}
		id, _ := row.Structured["defenseclaw.approval.id"].(string)
		if id == "" {
			t.Fatalf("approval log omitted ID: %#v", row.Structured)
		}
		if approvalID == "" {
			approvalID = id
		} else if approvalID != id {
			t.Fatalf("approval IDs differ: %q/%q", approvalID, id)
		}
		if result, present := row.Structured["defenseclaw.approval.result"]; present {
			resolved++
			if result != "cancelled" {
				t.Fatalf("approval resolution=%#v", result)
			}
		} else {
			requested++
		}
	}
	if requested != 1 || resolved != 1 || !strings.HasPrefix(approvalID, "hilt-") {
		t.Fatalf("requested/resolved/id=%d/%d/%q", requested, resolved, approvalID)
	}
	reader, err := sql.Open("sqlite", capture.store.DatabasePath())
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	projectedRows, err := reader.QueryContext(t.Context(), `SELECT projected_record_json FROM audit_events`)
	if err != nil {
		t.Fatal(err)
	}
	defer projectedRows.Close()
	projectedCount := 0
	for projectedRows.Next() {
		var encoded string
		if err := projectedRows.Scan(&encoded); err != nil {
			t.Fatal(err)
		}
		var projected struct {
			Correlation observability.Correlation `json:"correlation"`
		}
		if err := json.Unmarshal([]byte(encoded), &projected); err != nil {
			t.Fatal(err)
		}
		if projected.Correlation.TraceID != correlation.TraceID || projected.Correlation.SpanID != correlation.SpanID {
			t.Fatalf("projected log W3C correlation=%+v", projected.Correlation)
		}
		projectedCount++
	}
	if err := projectedRows.Err(); err != nil || projectedCount != 2 {
		t.Fatalf("projected log rows=%d err=%v", projectedCount, err)
	}
}

func TestHILTApprovalV8SparseContextDoesNotFabricateCorrelation(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	manager := NewHILTApprovalManager(nil)
	manager.bindObservabilityV8(runtime)
	approved, status, requestErr := manager.Request(
		context.Background(), "session-sparse", "shell", "LOW", "approval required", time.Second,
	)
	if approved || status != hiltStatusUnsupported || requestErr == nil {
		t.Fatalf("approved/status/error=%t/%q/%v", approved, status, requestErr)
	}
	spans := capture.snapshot()
	if len(spans) != 1 {
		t.Fatalf("spans=%d", len(spans))
	}
	record := spans[0].Record()
	if record.Correlation().SessionID != "session-sparse" ||
		record.Correlation().ToolInvocationID != "" || record.Correlation().RunID != "" {
		t.Fatalf("sparse correlation=%+v", record.Correlation())
	}
	for _, key := range []string{
		"defenseclaw.request.id", "defenseclaw.turn.id", "defenseclaw.run.id",
		"defenseclaw.operation.id", "defenseclaw.policy.id", "defenseclaw.destination.app",
		"defenseclaw.tool.id", "gen_ai.tool.name", "gen_ai.tool.call.id",
		"gen_ai.agent.id", "defenseclaw.agent.lifecycle.id", "defenseclaw.agent.execution.id",
	} {
		if _, exists := proxyCanonicalAttributes(t, record)[key]; exists {
			t.Fatalf("sparse span fabricated %q", key)
		}
	}
	rows, err := capture.store.ListEvents(10)
	if err != nil || len(rows) != 2 {
		t.Fatalf("rows=%d err=%v", len(rows), err)
	}
	for _, row := range rows {
		approvalID, _ := row.Structured["defenseclaw.approval.id"].(string)
		if approvalID == "" {
			t.Fatal("sparse approval omitted approval id")
		}
		if callID, exists := row.Structured["gen_ai.tool.call.id"]; exists || callID == approvalID {
			t.Fatalf("approval id was treated as tool call id: %#v", row.Structured)
		}
		for _, key := range []string{
			"defenseclaw.request.id", "defenseclaw.turn.id", "defenseclaw.run.id",
			"defenseclaw.operation.id", "defenseclaw.policy.id", "defenseclaw.destination.app",
			"defenseclaw.tool.id", "gen_ai.tool.name", "gen_ai.agent.id",
		} {
			if _, exists := row.Structured[key]; exists {
				t.Fatalf("sparse log fabricated %q: %#v", key, row.Structured)
			}
		}
	}
}

func TestHILTApprovalV8InteractiveOutcomes(t *testing.T) {
	tests := []struct {
		name             string
		decision         string
		wantApproved     bool
		wantStatus       string
		wantResult       string
		wantOutcome      observability.Outcome
		wantMetricResult string
	}{
		{name: "approved", decision: "approve", wantApproved: true, wantStatus: hiltStatusApproved, wantResult: "approved", wantOutcome: observability.OutcomeApproved, wantMetricResult: "approved"},
		{name: "denied", decision: "deny", wantStatus: hiltStatusDenied, wantResult: "denied", wantOutcome: observability.OutcomeDenied, wantMetricResult: "denied"},
		{name: "expired", wantStatus: hiltStatusTimeout, wantResult: "expired", wantOutcome: observability.OutcomeTimedOut, wantMetricResult: "expired"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			runtime, capture := newProxyGeneratedTraceRuntime(t)
			received := make(chan receivedRequest, 5)
			srv := startMockGW(t, rpcRecordingLoop(received))
			client := connectToMockGW(t, srv)
			manager := NewHILTApprovalManager(client)
			manager.bindObservabilityV8(runtime)

			type result struct {
				approved bool
				status   string
				err      error
			}
			resultCh := make(chan result, 1)
			timeout := 500 * time.Millisecond
			if test.decision == "" {
				timeout = 20 * time.Millisecond
			}
			ctx := audit.ContextWithEnvelope(context.Background(), audit.CorrelationEnvelope{
				RunID: "run-" + test.name, RequestID: "request-" + test.name,
				AgentID: "agent-" + test.name,
			})
			go func() {
				approved, status, err := manager.Request(
					ctx, "session-1", "shell", "MEDIUM", "operator confirmation required", timeout,
					HILTApprovalContext{EvaluationID: "evaluation-" + test.name},
				)
				resultCh <- result{approved: approved, status: status, err: err}
			}()

			rpc := drainRPC(t, received)
			assertSessionSendKey(t, rpc, "session-1")
			if test.decision != "" {
				approvalID := pendingHILTApprovalID(t, manager)
				if !manager.ResolveFromMessage("session-1", "user", test.decision+" "+approvalID) {
					t.Fatalf("%s did not resolve %s", test.decision, approvalID)
				}
			}

			select {
			case got := <-resultCh:
				if got.approved != test.wantApproved || got.status != test.wantStatus || got.err != nil {
					t.Fatalf("approved/status/error=%t/%q/%v", got.approved, got.status, got.err)
				}
			case <-time.After(2 * time.Second):
				t.Fatal("approval request did not finish")
			}

			spans := capture.snapshot()
			if len(spans) != 1 {
				t.Fatalf("approval spans=%d", len(spans))
			}
			spanRecord := spans[0].Record()
			if spanRecord.Outcome() != test.wantOutcome || spans[0].StatusCode().String() != "Ok" ||
				spanRecord.Correlation().SessionID != "session-1" {
				t.Fatalf("approval span outcome/status/correlation=%s/%s/%+v", spanRecord.Outcome(), spans[0].StatusCode(), spanRecord.Correlation())
			}
			attributes := proxyCanonicalAttributes(t, spanRecord)
			wantActor := "operator"
			if test.wantResult == "expired" {
				wantActor = "automatic"
			}
			if attributes["defenseclaw.approval.result"] != test.wantResult ||
				attributes["defenseclaw.approval.actor_type"] != wantActor {
				t.Fatalf("approval terminal attributes=%v", attributes)
			}

			metrics := capture.metricSnapshot()
			if len(metrics) != 2 || approvalMetricResults(metrics)["pending"] != 1 ||
				approvalMetricResults(metrics)[test.wantMetricResult] != 1 {
				t.Fatalf("approval metrics=%v", metrics)
			}
			rows, err := capture.store.ListEvents(10)
			if err != nil || len(rows) != 2 {
				t.Fatalf("approval rows=%d err=%v", len(rows), err)
			}
			terminalRows := 0
			for _, row := range rows {
				if row.SessionID != "session-1" || row.TraceID != spanRecord.Correlation().TraceID {
					t.Fatalf("approval row correlation=%+v", row)
				}
				if row.Structured["defenseclaw.approval.result"] == test.wantResult {
					terminalRows++
				}
			}
			if terminalRows != 1 {
				t.Fatalf("terminal rows=%d want 1: %+v", terminalRows, rows)
			}
		})
	}
}

func TestHILTApprovalV8MandatoryResolutionSurvivesLogCollectionDisablement(t *testing.T) {
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
			observability.BucketComplianceActivity: {
				Collect: config.ObservabilityV8CollectSource{Logs: &disabled},
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	reload, reloadErr := runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(plan, false))
	if reloadErr != nil || reload.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("disable compliance logs: status=%s err=%v", reload.Status(), reloadErr)
	}
	manager := NewHILTApprovalManager(nil)
	manager.bindObservabilityV8(runtime)
	ctx := audit.ContextWithEnvelope(context.Background(), audit.CorrelationEnvelope{
		RunID: "run-floor", RequestID: "request-floor", SessionID: "session-floor",
		TurnID: "turn-floor", AgentID: "agent-floor",
	})
	approved, status, requestErr := manager.Request(
		ctx, "session-floor", "private floor command", "CRITICAL", "private floor reason", time.Second,
		HILTApprovalContext{EvaluationID: "evaluation-floor", RuleIDs: []string{"private-floor-rule"}},
	)
	if approved || status != hiltStatusUnsupported || requestErr == nil {
		t.Fatalf("approved/status/error=%t/%q/%v", approved, status, requestErr)
	}

	reader, err := sql.Open("sqlite", storePath)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close()
	rows, err := reader.QueryContext(t.Context(), `
		SELECT COALESCE(event_name,''), COALESCE(bucket,''), COALESCE(mandatory,0),
		       COALESCE(payload_json,''), COALESCE(trace_id,''), COALESCE(turn_id,'')
		FROM audit_events ORDER BY timestamp ASC`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	type stored struct {
		event, bucket, payload, traceID, turnID string
		mandatory                               int
	}
	var storedRows []stored
	for rows.Next() {
		var row stored
		if err := rows.Scan(&row.event, &row.bucket, &row.mandatory, &row.payload, &row.traceID, &row.turnID); err != nil {
			t.Fatal(err)
		}
		storedRows = append(storedRows, row)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	if len(storedRows) != 1 || storedRows[0].event != observability.TelemetryEventApprovalResolved ||
		storedRows[0].bucket != string(observability.BucketComplianceActivity) || storedRows[0].mandatory != 1 ||
		storedRows[0].traceID == "" || storedRows[0].turnID != "turn-floor" {
		t.Fatalf("mandatory approval rows=%+v", storedRows)
	}
	for _, forbidden := range []string{"private floor command", "private floor reason", "private-floor-rule", "evaluation-floor"} {
		if strings.Contains(storedRows[0].payload, forbidden) {
			t.Fatalf("mandatory floor retained %q: %s", forbidden, storedRows[0].payload)
		}
	}
}

func TestHILTApprovalV8LogsAndMetricSurviveTraceSampling(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntimeWithSampler(t, "always_off")
	manager := NewHILTApprovalManager(nil)
	manager.bindObservabilityV8(runtime)
	approved, status, requestErr := manager.Request(
		context.Background(), "session-unsampled", "shell", "LOW", "approval required", time.Second,
	)
	if approved || status != hiltStatusUnsupported || requestErr == nil {
		t.Fatalf("approved/status/error=%t/%q/%v", approved, status, requestErr)
	}
	if spans := capture.snapshot(); len(spans) != 0 {
		t.Fatalf("always-off HILT emitted %d spans", len(spans))
	}
	if metrics := capture.metricSnapshot(); len(metrics) != 1 ||
		metrics[0].Descriptor().Name != observability.TelemetryInstrumentDefenseClawApprovalLifecycle ||
		metrics[0].Attributes()["defenseclaw.approval.lifecycle.result"] != "unavailable" {
		t.Fatalf("always-off HILT metrics=%v", judgeMetricCounts(metrics))
	}
	rows, err := capture.store.ListEvents(10)
	if err != nil || len(rows) != 2 {
		t.Fatalf("always-off HILT logs=%d err=%v", len(rows), err)
	}
	traceID := rows[0].TraceID
	if traceID == "" {
		t.Fatal("unsampled HILT logs omitted the generated W3C trace identity")
	}
	for _, row := range rows {
		if row.TraceID != traceID || row.SessionID != "session-unsampled" {
			t.Fatalf("unsampled HILT correlation=%+v", row)
		}
	}
	metricCorrelation := capture.metricSnapshot()[0].CanonicalRecord().Correlation()
	if metricCorrelation.TraceID != traceID || metricCorrelation.SpanID == "" {
		t.Fatalf("unsampled HILT metric correlation=%+v", metricCorrelation)
	}
}

func TestHILTApprovalV8RejectsInvalidFactsBeforeAnySignal(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	manager := NewHILTApprovalManager(nil)
	manager.bindObservabilityV8(runtime)
	approved, status, requestErr := manager.Request(
		context.Background(), "session-invalid", "shell", "HIGH", "approval required", time.Second,
		HILTApprovalContext{RuleIDs: []string{"invalid rule identity"}},
	)
	if approved || status != hiltStatusUnsupported || requestErr == nil {
		t.Fatalf("approved/status/error=%t/%q/%v", approved, status, requestErr)
	}
	approved, status, requestErr = manager.Request(
		context.Background(), "session-invalid", "shell", "HIGH", "approval required", time.Second,
		HILTApprovalContext{RuleIDs: []string{"rule-1", "rule-2", "rule-3", "rule-4", "rule-5", "rule-6", "rule-7", "rule-8", "rule-9"}},
	)
	if approved || status != hiltStatusUnsupported || requestErr == nil {
		t.Fatalf("oversized approved/status/error=%t/%q/%v", approved, status, requestErr)
	}
	rows, err := capture.store.ListEvents(10)
	if err != nil || len(rows) != 0 || len(capture.snapshot()) != 0 || len(capture.metricSnapshot()) != 0 {
		t.Fatalf("invalid facts emitted logs/spans/metrics=%d/%d/%d err=%v", len(rows), len(capture.snapshot()), len(capture.metricSnapshot()), err)
	}
}

func TestHILTApprovalV8RuntimeBindingFollowsSidecarLifecycle(t *testing.T) {
	runtime, capture := newProxyGeneratedTraceRuntime(t)
	manager := NewHILTApprovalManager(nil)
	sidecar := &Sidecar{hilt: manager}
	if err := sidecar.BindObservabilityRuntime(runtime); err != nil {
		t.Fatal(err)
	}
	bound, authoritative := manager.observabilityV8Snapshot()
	if bound != runtime || !authoritative {
		t.Fatalf("bound HILT runtime=%T authoritative=%t", bound, authoritative)
	}

	sidecar.observabilityV8Mu.Lock()
	sidecar.observabilityV8ConsumersDetached = true
	sidecar.bindObservabilityV8ConsumersLocked()
	sidecar.observabilityV8Mu.Unlock()
	bound, authoritative = manager.observabilityV8Snapshot()
	if bound != nil || !authoritative {
		t.Fatalf("detached HILT runtime=%T authoritative=%t", bound, authoritative)
	}
	approved, status, requestErr := manager.Request(
		context.Background(), "session-detached", "shell", "HIGH", "approval required", time.Second,
	)
	if approved || status != hiltStatusUnsupported || requestErr == nil {
		t.Fatalf("approved/status/error=%t/%q/%v", approved, status, requestErr)
	}
	rows, err := capture.store.ListEvents(10)
	if err != nil || len(rows) != 0 || len(capture.snapshot()) != 0 || len(capture.metricSnapshot()) != 0 {
		t.Fatalf("detached HILT emitted logs/spans/metrics=%d/%d/%d err=%v", len(rows), len(capture.snapshot()), len(capture.metricSnapshot()), err)
	}
}

func pendingHILTApprovalID(t *testing.T, manager *HILTApprovalManager) string {
	t.Helper()
	manager.mu.Lock()
	defer manager.mu.Unlock()
	if len(manager.pending) != 1 {
		t.Fatalf("pending approvals=%d, want 1", len(manager.pending))
	}
	for id := range manager.pending {
		return id
	}
	return ""
}

func approvalMetricResults(metrics []telemetry.V8ProjectedMetric) map[string]int {
	results := make(map[string]int)
	for _, metric := range metrics {
		if metric.Descriptor().Name != observability.TelemetryInstrumentDefenseClawApprovalLifecycle {
			continue
		}
		result, _ := metric.Attributes()["defenseclaw.approval.lifecycle.result"].(string)
		results[result]++
	}
	return results
}

func canonicalTraceEvents(t *testing.T, record observability.Record) []string {
	t.Helper()
	body, present := record.Body()
	if !present {
		t.Fatal("canonical trace body is absent")
	}
	object, err := body.Object()
	if err != nil {
		t.Fatal(err)
	}
	rawEvents, ok := object["events"].([]any)
	if !ok {
		t.Fatalf("canonical trace events=%T", object["events"])
	}
	result := make([]string, 0, len(rawEvents))
	for _, raw := range rawEvents {
		event, ok := raw.(map[string]any)
		if !ok {
			t.Fatalf("canonical trace event=%T", raw)
		}
		name, _ := event["name"].(string)
		result = append(result, name)
	}
	return result
}
