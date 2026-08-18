// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	oteltrace "go.opentelemetry.io/otel/trace"
)

func TestHookDecisionMetricsV8ExportCompleteCompatibilitySetWithoutLegacyProvider(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"logs", "metrics"})
	ctx := audit.ContextWithEnvelope(context.Background(), audit.CorrelationEnvelope{
		RunID: "run-hook-1", RequestID: "request-hook-1", SessionID: "session-hook-1",
		TurnID: "turn-hook-1", AgentID: "agent-hook-1", PolicyID: "policy-hook-1",
		DestinationApp: "mcp.example", ToolName: "shell", ToolID: "tool-call-hook-1",
	})
	spanContext := oteltrace.NewSpanContext(oteltrace.SpanContextConfig{
		TraceID: oteltrace.TraceID{1, 2, 3, 4}, SpanID: oteltrace.SpanID{5, 6, 7, 8},
		TraceFlags: oteltrace.FlagsSampled, Remote: true,
	})
	ctx = oteltrace.ContextWithRemoteSpanContext(ctx, spanContext)
	req := agentHookRequest{
		ConnectorName: "codex", HookEventName: "PreToolUse", SessionID: "session-hook-1",
		TurnID: "turn-hook-1", AgentID: "agent-hook-1", AgentName: "Root Agent",
		AgentType: "root", ToolName: "shell",
		Payload: map[string]interface{}{
			"model": "gpt-5",
			"usage": map[string]interface{}{
				"prompt_tokens": float64(11), "completion_tokens": float64(7),
			},
		},
	}
	resp := agentHookResponse{
		Action: "allow", RawAction: "allow", Severity: "NONE", Mode: "action",
		Reason: "<redacted len=23 sha=response>", SourceReason: "clean decision for alice@example.com",
		RuleIDs: []string{"rule-one"}, EvaluationID: "evaluation-hook-1",
	}
	env := HookAuditEnvelope{ElapsedMs: 23, StepIdx: 4}
	api.emitHookDecisionObservabilityV8(ctx, req, resp, env, false)
	api.recordHookRejectionMetricsV8(ctx, "claudecode", "SessionStart", "invalid_json")
	api.recordUnifiedHookDispatchMetricV8(ctx, "codex")

	wants := map[string]int{
		observability.TelemetryInstrumentDefenseClawConnectorHookInvocations:     2,
		observability.TelemetryInstrumentDefenseClawConnectorHookLatency:         2,
		observability.TelemetryInstrumentDefenseClawInspectEvaluations:           1,
		observability.TelemetryInstrumentDefenseClawInspectLatency:               1,
		observability.TelemetryInstrumentDefenseClawConnectorHookOutcome:         1,
		observability.TelemetryInstrumentDefenseClawConnectorHookTokens:          3,
		observability.TelemetryInstrumentDefenseClawConnectorHookUnifiedDispatch: 1,
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		_, requests := capture.snapshot()
		complete := true
		for name, want := range wants {
			if hookModelV8MetricPointCount(requests, name) < want {
				complete = false
				break
			}
		}
		if complete && len(hookModelV8CapturedLogs(capture.logSnapshot())) >= 1 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	traces, requests := capture.snapshot()
	if len(hookModelV8CapturedSpans(traces)) != 0 {
		t.Fatalf("metrics-only destination received traces: %d", len(hookModelV8CapturedSpans(traces)))
	}
	for name, want := range wants {
		if got := hookModelV8MetricPointCount(requests, name); got != want {
			t.Errorf("metric %q points=%d want=%d", name, got, want)
		}
	}
	logs := hookModelV8CapturedLogs(capture.logSnapshot())
	if len(logs) != 1 {
		t.Fatalf("generated hook decision logs=%d want=1", len(logs))
	}
	traceID, spanID := spanContext.TraceID(), spanContext.SpanID()
	if got := logs[0].GetTraceId(); string(got) != string(traceID[:]) {
		t.Errorf("generated hook decision trace_id=%x want=%s", got, spanContext.TraceID())
	}
	if got := logs[0].GetSpanId(); string(got) != string(spanID[:]) {
		t.Errorf("generated hook decision span_id=%x want=%s", got, spanContext.SpanID())
	}
	logAttributes := hookModelV8MetricAttributes(logs[0].Attributes)
	if logAttributes["defenseclaw.event.name"] != observability.TelemetryEventHookDecision ||
		logAttributes["defenseclaw.bucket"] != string(observability.BucketGuardrailEvaluation) {
		t.Errorf("generated hook decision envelope=%v", logAttributes)
	}
	var logWire struct {
		Body map[string]interface{} `json:"body"`
	}
	if err := json.Unmarshal([]byte(logs[0].Body.GetStringValue()), &logWire); err != nil {
		t.Fatalf("decode generated hook decision body: %v", err)
	}
	for key, want := range map[string]string{
		"defenseclaw.hook.event":                 "PreToolUse",
		"defenseclaw.hook.result":                "ok",
		"defenseclaw.guardrail.effective_action": "allow",
		"defenseclaw.guardrail.raw_action":       "allow",
		"defenseclaw.guardrail.reason":           "clean decision for alice@example.com",
		"defenseclaw.security.severity":          "INFO",
		"defenseclaw.guardrail.mode":             "enforce",
		"defenseclaw.evaluation.id":              "evaluation-hook-1",
	} {
		if got, _ := logWire.Body[key].(string); got != want {
			t.Errorf("generated hook decision %s=%q want=%q body=%v", key, got, want, logWire.Body)
		}
	}
	if got := logWire.Body["defenseclaw.connector.step_idx"]; got != float64(4) {
		t.Errorf("generated hook decision step_idx=%v want=4", got)
	}
	if got, ok := logWire.Body["defenseclaw.guardrail.rule_ids"].([]interface{}); !ok || len(got) != 1 || got[0] != "rule-one" {
		t.Errorf("generated hook decision rule_ids=%v", logWire.Body["defenseclaw.guardrail.rule_ids"])
	}

	invocations := hookModelV8MetricPoints(
		requests, observability.TelemetryInstrumentDefenseClawConnectorHookInvocations,
	)
	assertHookV8MetricPoint(t, invocations, map[string]string{
		"defenseclaw.connector.source": "codex", "defenseclaw.metric.event_type": "tool_call",
		"defenseclaw.metric.result": "ok", "defenseclaw.metric.reason": "allow",
	}, 1)
	assertHookV8MetricPoint(t, invocations, map[string]string{
		"defenseclaw.connector.source": "claudecode", "defenseclaw.metric.event_type": "session_start",
		"defenseclaw.metric.result": "rejected", "defenseclaw.metric.reason": "other",
	}, 1)

	inspect := hookModelV8MetricPoints(
		requests, observability.TelemetryInstrumentDefenseClawInspectEvaluations,
	)
	assertHookV8MetricPoint(t, inspect, map[string]string{
		"defenseclaw.connector.source": "codex", "defenseclaw.metric.action": "allow",
		"defenseclaw.security.severity": "INFO", "defenseclaw.metric.tool": "codex:tool_call",
	}, 1)
	outcome := hookModelV8MetricPoints(
		requests, observability.TelemetryInstrumentDefenseClawConnectorHookOutcome,
	)
	assertHookV8MetricPoint(t, outcome, map[string]string{
		"defenseclaw.connector.source": "codex", "defenseclaw.metric.event_type": "tool_call",
		"defenseclaw.metric.action": "allow", "defenseclaw.security.severity": "INFO",
		"defenseclaw.metric.would_block": "false",
	}, 1)

	tokens := hookModelV8MetricPoints(
		requests, observability.TelemetryInstrumentDefenseClawConnectorHookTokens,
	)
	for kind, want := range map[string]float64{"prompt": 11, "completion": 7, "total": 18} {
		assertHookV8MetricPoint(t, tokens, map[string]string{
			"defenseclaw.connector.source": "codex", "defenseclaw.metric.kind": kind,
			"gen_ai.request.model": "gpt-5",
		}, want)
	}
	dispatch := hookModelV8MetricPoints(
		requests, observability.TelemetryInstrumentDefenseClawConnectorHookUnifiedDispatch,
	)
	assertHookV8MetricPoint(t, dispatch, map[string]string{
		"defenseclaw.connector.source": "codex",
	}, 1)
}

func TestHookDecisionSharesSessionStartExecutionIdentityRealShape(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"logs"})
	payload := map[string]interface{}{
		"hook_event_name": "SessionStart",
		"session_id":      "019f4ef9-3098-7d63-8bfe-1435139f1cce",
		"source":          "startup",
		"model":           "gpt-5-codex",
		"cwd":             "/workspace/defenseclaw",
		"transcript_path": "/workspace/.codex/sessions/019f4ef9.jsonl",
	}
	raw, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	api.emitCodexHookLLMEvent(
		t.Context(), decodeCodexRequestFromBytes(raw, payload), nil, raw,
	)
	request := normalizeAgentHookRequest("codex", payload)
	api.emitHookDecisionObservabilityV8(t.Context(), request, agentHookResponse{
		Action: "allow", RawAction: "allow", Severity: "NONE", Mode: "action",
	}, HookAuditEnvelope{}, false)

	var lifecycle, decision map[string]interface{}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, record := range hookModelV8CapturedLogs(capture.logSnapshot()) {
			var wire struct {
				Body map[string]interface{} `json:"body"`
			}
			if err := json.Unmarshal([]byte(record.Body.GetStringValue()), &wire); err != nil {
				continue
			}
			switch logStringAttribute(record.Attributes, "defenseclaw.event.name") {
			case observability.TelemetryEventSessionStart:
				lifecycle = wire.Body
			case observability.TelemetryEventHookDecision:
				if wire.Body["defenseclaw.hook.event"] == "SessionStart" {
					decision = wire.Body
				}
			}
		}
		if lifecycle != nil && decision != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if lifecycle == nil || decision == nil {
		t.Fatalf("session lifecycle=%v decision=%v", lifecycle, decision)
	}
	if got := lifecycle["defenseclaw.agent.execution.id"]; got == nil || got == "" {
		t.Fatal("session lifecycle execution identity is empty")
	}
	for _, key := range []string{
		"gen_ai.conversation.id",
		"gen_ai.agent.id",
		"defenseclaw.agent.root.id",
		"defenseclaw.agent.lifecycle.id",
		"defenseclaw.agent.execution.id",
		"defenseclaw.agent.lifecycle.event",
		"defenseclaw.agent.lifecycle.state",
		"defenseclaw.agent.phase",
		"defenseclaw.agent.sequence",
		"defenseclaw.operation.id",
	} {
		if got, want := decision[key], lifecycle[key]; got != want {
			t.Errorf("SessionStart hook decision %s=%v want lifecycle value %v", key, got, want)
		}
	}
}

func TestHookDecisionSharesCurrentLifecycleCursorForToolAndTerminalEvents(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"logs"})
	basePayload := map[string]interface{}{
		"session_id":    "session-hook-completion",
		"turn_id":       "turn-hook-completion",
		"agent_id":      "agent-hook-completion",
		"agent_type":    "codex",
		"root_agent_id": "agent-hook-completion",
		"tool_name":     "shell",
		"tool_use_id":   "tool-call-hook-completion",
		"tool_input":    map[string]interface{}{"command": "printf ok"},
	}
	emitCodexPayload := func(payload map[string]interface{}) agentHookRequest {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatalf("marshal %s payload: %v", payload["hook_event_name"], err)
		}
		api.emitCodexHookLLMEvent(
			t.Context(), decodeCodexRequestFromBytes(raw, payload), nil, raw,
		)
		return normalizeAgentHookRequest("codex", payload)
	}
	emitCodex := func(event string, response interface{}) agentHookRequest {
		payload := make(map[string]interface{}, len(basePayload)+2)
		for key, value := range basePayload {
			payload[key] = value
		}
		payload["hook_event_name"] = event
		if response != nil {
			payload["tool_response"] = response
		}
		return emitCodexPayload(payload)
	}

	emitCodex("PreToolUse", nil)
	post := emitCodex("PostToolUse", map[string]interface{}{"output": "ok"})
	api.emitHookDecisionObservabilityV8(t.Context(), post, agentHookResponse{
		Action: "allow", RawAction: "allow", Severity: "NONE", Mode: "action",
	}, HookAuditEnvelope{}, false)

	var completion, decision map[string]interface{}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, record := range hookModelV8CapturedLogs(capture.logSnapshot()) {
			var wire struct {
				Body map[string]interface{} `json:"body"`
			}
			if err := json.Unmarshal([]byte(record.Body.GetStringValue()), &wire); err != nil {
				continue
			}
			switch logStringAttribute(record.Attributes, "defenseclaw.event.name") {
			case "tool_end":
				completion = wire.Body
			case observability.TelemetryEventHookDecision:
				if wire.Body["defenseclaw.hook.event"] == "PostToolUse" {
					decision = wire.Body
				}
			}
		}
		if completion != nil && decision != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if completion == nil || decision == nil {
		t.Fatalf("completion=%v decision=%v", completion, decision)
	}
	if got := completion["defenseclaw.agent.phase"]; got != "planning" {
		t.Fatalf("completion phase=%v want planning", got)
	}
	if got := completion["defenseclaw.agent.sequence"]; got != float64(2) {
		t.Fatalf("completion sequence=%v want 2", got)
	}
	if got := completion["defenseclaw.operation.id"]; got == nil || got == "" {
		t.Fatal("completion operation id is empty")
	}
	for _, key := range []string{
		"defenseclaw.agent.phase",
		"defenseclaw.agent.sequence",
		"defenseclaw.operation.id",
	} {
		if got, want := decision[key], completion[key]; got != want {
			t.Errorf("post hook decision %s=%v want completion value %v", key, got, want)
		}
	}

	terminalRequest := emitCodexPayload(map[string]interface{}{
		"hook_event_name":        "SubagentStop",
		"session_id":             "session-hook-completion",
		"turn_id":                "turn-hook-completion",
		"agent_id":               "agent-hook-completion",
		"agent_type":             "codex",
		"root_agent_id":          "agent-hook-completion",
		"last_assistant_message": "terminal response",
	})
	api.emitHookDecisionObservabilityV8(t.Context(), terminalRequest, agentHookResponse{
		Action: "allow", RawAction: "allow", Severity: "NONE", Mode: "action",
	}, HookAuditEnvelope{}, false)

	var terminal, terminalDecision map[string]interface{}
	deadline = time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, record := range hookModelV8CapturedLogs(capture.logSnapshot()) {
			var wire struct {
				Body map[string]interface{} `json:"body"`
			}
			if err := json.Unmarshal([]byte(record.Body.GetStringValue()), &wire); err != nil {
				continue
			}
			switch logStringAttribute(record.Attributes, "defenseclaw.event.name") {
			case "subagent_stop":
				terminal = wire.Body
			case observability.TelemetryEventHookDecision:
				if wire.Body["defenseclaw.hook.event"] == "SubagentStop" {
					terminalDecision = wire.Body
				}
			}
		}
		if terminal != nil && terminalDecision != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	if terminal == nil || terminalDecision == nil {
		t.Fatalf("terminal=%v decision=%v", terminal, terminalDecision)
	}
	if got := terminal["defenseclaw.agent.phase"]; got != "completed" {
		t.Fatalf("terminal phase=%v want completed", got)
	}
	if got := terminal["defenseclaw.agent.lifecycle.state"]; got != "completed" {
		t.Fatalf("terminal lifecycle state=%v want completed", got)
	}
	if got := terminal["defenseclaw.agent.sequence"]; got != float64(3) {
		t.Fatalf("terminal sequence=%v want 3", got)
	}
	if got := terminal["defenseclaw.operation.id"]; got == nil || got == "" || got == completion["defenseclaw.operation.id"] {
		t.Fatalf("terminal operation id=%v must be nonempty and distinct from tool operation %v", got, completion["defenseclaw.operation.id"])
	}
	for _, key := range []string{
		"defenseclaw.agent.phase",
		"defenseclaw.agent.sequence",
		"defenseclaw.operation.id",
		"defenseclaw.agent.lifecycle.id",
		"defenseclaw.agent.execution.id",
		"defenseclaw.agent.lifecycle.state",
	} {
		if got, want := terminalDecision[key], terminal[key]; got != want {
			t.Errorf("terminal hook decision %s=%v want lifecycle value %v", key, got, want)
		}
	}
}

func assertHookV8MetricPoint(
	t *testing.T,
	points []hookModelV8MetricPoint,
	wantAttributes map[string]string,
	wantValue float64,
) {
	t.Helper()
	for _, point := range points {
		matches := true
		for key, want := range wantAttributes {
			if point.attributes[key] != want {
				matches = false
				break
			}
		}
		if matches && point.value == wantValue {
			return
		}
	}
	t.Errorf("metric point attributes=%v value=%v not found in %+v", wantAttributes, wantValue, points)
}
