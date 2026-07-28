// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
)

type claudeFailureBuildCapture struct {
	records []observability.Record
	errors  []error
}

type claudeFailureRuntimeCapture struct {
	sidecarRuntimeEmitter
	lifecycleV8Runtime
	hookLifecycleMetricV8Runtime

	mu     sync.Mutex
	errors []error
}

func (capture *claudeFailureRuntimeCapture) Emit(
	ctx context.Context,
	metadata router.Metadata,
	build observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	outcome, err := capture.sidecarRuntimeEmitter.Emit(ctx, metadata, build)
	if err != nil {
		capture.mu.Lock()
		capture.errors = append(capture.errors, err)
		capture.mu.Unlock()
	}
	return outcome, err
}

func (capture *claudeFailureRuntimeCapture) snapshotErrors() []error {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]error(nil), capture.errors...)
}

func (capture *claudeFailureBuildCapture) Emit(
	ctx context.Context,
	_ router.Metadata,
	build observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	record, err := build(observabilityruntime.EmitContext{}, router.AdmissionOrdinary)
	if err != nil {
		capture.errors = append(capture.errors, err)
		return pipeline.LocalLogOutcome{}, err
	}
	capture.records = append(capture.records, record)
	return pipeline.LocalLogOutcome{}, nil
}

func TestClaudeFailureHookLogFamiliesBuildCanonically(t *testing.T) {
	capture := &claudeFailureBuildCapture{}
	modelMeta := richHookModelV8Meta()
	modelMeta.Source = "claudecode"
	modelMeta.LifecycleState = "failed"
	modelMeta.LifecycleOutcome = "failed"
	emitHookModelResponseLogV8WithEmitter(
		t.Context(), capture, modelMeta, "partial response", []string{"error"},
	)

	toolMeta := richHookToolV8Meta()
	toolMeta.Source = "claudecode"
	toolMeta.LifecycleState = "active"
	toolMeta.LifecycleOutcome = "failed"
	emitHookToolLogV8WithEmitter(t.Context(), capture, toolMeta, "result", "Bash", `{}`, "command failed", nil)
	toolMeta.ToolID = "tool-call-blocked"
	toolMeta.LifecycleOutcome = "denied"
	emitHookToolLogV8WithEmitter(t.Context(), capture, toolMeta, "result", "Bash", `{}`, "permission denied", nil)

	if len(capture.errors) > 0 {
		t.Fatalf("terminal family build errors: %v", capture.errors)
	}
	if len(capture.records) != 3 {
		t.Fatalf("terminal records=%d want=3", len(capture.records))
	}
	wants := []struct {
		event   observability.EventName
		outcome observability.Outcome
	}{
		{observability.EventName(observability.TelemetryEventModelCallFailed), observability.OutcomeFailed},
		{observability.EventName(observability.TelemetryEventToolInvocationFailed), observability.OutcomeFailed},
		{observability.EventName(observability.TelemetryEventToolInvocationBlocked), observability.OutcomeBlocked},
	}
	for index, want := range wants {
		if capture.records[index].EventName() != want.event || capture.records[index].Outcome() != want.outcome {
			t.Errorf("record %d event/outcome=%s/%s want=%s/%s", index,
				capture.records[index].EventName(), capture.records[index].Outcome(), want.event, want.outcome)
		}
	}
	modelBody, _ := capture.records[0].Body()
	modelObject, err := modelBody.Object()
	if err != nil || modelObject["defenseclaw.agent.lifecycle.state"] != "failed" {
		t.Fatalf("failed model body=%v error=%v", modelObject, err)
	}
	for index, wantStatus := range []string{"failed", "blocked"} {
		body, _ := capture.records[index+1].Body()
		object, objectErr := body.Object()
		if objectErr != nil || object["defenseclaw.tool.status"] != wantStatus {
			t.Fatalf("tool record %d body=%v error=%v want status=%q", index, object, objectErr, wantStatus)
		}
	}
}

func TestClaudeFailureHooksAgreeAcrossLifecycleLogsAndSpans(t *testing.T) {
	api, capture := bindHookModelV8Runtime(t, []string{"logs", "traces", "metrics"})
	emitter := api.observabilityV8RuntimeEmitter()
	runtimeCapture := &claudeFailureRuntimeCapture{
		sidecarRuntimeEmitter:        emitter,
		lifecycleV8Runtime:           emitter.(lifecycleV8Runtime),
		hookLifecycleMetricV8Runtime: emitter.(hookLifecycleMetricV8Runtime),
	}
	api.observabilityV8Mu.Lock()
	api.observabilityV8 = runtimeCapture
	api.observabilityV8Mu.Unlock()

	emitSessionStart := func(sessionID, agentID string) {
		api.emitClaudeCodeHookLLMEvent(t.Context(), claudeCodeHookRequest{
			HookEventName: "SessionStart", SessionID: sessionID, AgentID: agentID,
			AgentType: "claudecode", Payload: map[string]any{
				"root_agent_id": agentID, "source": "startup",
			},
		}, nil, nil)
	}

	const modelSession = "claude-model-failure-session"
	const modelAgent = "claude-model-failure-agent"
	emitSessionStart(modelSession, modelAgent)
	api.emitClaudeCodeHookLLMEvent(t.Context(), claudeCodeHookRequest{
		HookEventName: "UserPromptSubmit", SessionID: modelSession, TurnID: "model-turn",
		AgentID: modelAgent, AgentType: "claudecode", Model: "claude-sonnet-4",
		Prompt: "trigger a provider failure", Payload: map[string]any{"root_agent_id": modelAgent},
	}, nil, []byte(`{"prompt":"trigger a provider failure"}`))
	api.emitClaudeCodeHookLLMEvent(t.Context(), claudeCodeHookRequest{
		HookEventName: "StopFailure", SessionID: modelSession, TurnID: "model-turn",
		AgentID: modelAgent, AgentType: "claudecode", Model: "claude-sonnet-4",
		LastAssistantMessage: "partial response before failure", Error: "provider failed",
		Payload: map[string]any{"root_agent_id": modelAgent, "error": "provider failed"},
	}, nil, []byte(`{"error":"provider failed"}`))

	const failedToolSession = "claude-tool-failure-session"
	const failedToolAgent = "claude-tool-failure-agent"
	const failedToolID = "claude-failed-tool-call"
	emitSessionStart(failedToolSession, failedToolAgent)
	failedToolStart := claudeCodeHookRequest{
		HookEventName: "PreToolUse", SessionID: failedToolSession, TurnID: "failed-tool-turn",
		AgentID: failedToolAgent, AgentType: "claudecode", ToolName: "Bash", ToolUseID: failedToolID,
		ToolInput: map[string]any{"command": "exit 1"}, Payload: map[string]any{"root_agent_id": failedToolAgent},
	}
	api.emitClaudeCodeHookLLMEvent(t.Context(), failedToolStart, nil, nil)
	failedToolEnd := failedToolStart
	failedToolEnd.HookEventName = "PostToolUseFailure"
	failedToolEnd.Error = "command failed"
	failedToolEnd.Payload = map[string]any{"root_agent_id": failedToolAgent, "error": "command failed"}
	api.emitClaudeCodeHookLLMEvent(t.Context(), failedToolEnd, nil, nil)

	const blockedToolSession = "claude-tool-blocked-session"
	const blockedToolAgent = "claude-tool-blocked-agent"
	const blockedToolID = "claude-blocked-tool-call"
	emitSessionStart(blockedToolSession, blockedToolAgent)
	blockedToolStart := claudeCodeHookRequest{
		HookEventName: "PermissionRequest", SessionID: blockedToolSession, TurnID: "blocked-tool-turn",
		AgentID: blockedToolAgent, AgentType: "claudecode", ToolName: "Bash", ToolUseID: blockedToolID,
		ToolInput: map[string]any{"command": "rm -rf scratch"}, Payload: map[string]any{"root_agent_id": blockedToolAgent},
	}
	api.emitClaudeCodeHookLLMEvent(t.Context(), blockedToolStart, nil, nil)
	blockedToolEnd := blockedToolStart
	blockedToolEnd.HookEventName = "PermissionDenied"
	blockedToolEnd.Error = "user denied permission"
	blockedToolEnd.Payload = map[string]any{"root_agent_id": blockedToolAgent, "reason": "permission denied"}
	api.emitClaudeCodeHookLLMEvent(t.Context(), blockedToolEnd, nil, nil)

	var modelFailedLog, toolFailedLog, toolBlockedLog bool
	var modelFailedSpan, toolFailedSpan, toolBlockedSpan *tracepb.Span
	var terminalLogFacts []map[string]string
	var allLogEvents []string
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		terminalLogFacts = terminalLogFacts[:0]
		allLogEvents = allLogEvents[:0]
		for _, record := range hookModelV8CapturedLogs(capture.logSnapshot()) {
			eventName := logStringAttribute(record.Attributes, "defenseclaw.event.name")
			allLogEvents = append(allLogEvents, eventName)
			if eventName == observability.TelemetryEventModelCallFailed ||
				eventName == observability.TelemetryEventToolInvocationFailed ||
				eventName == observability.TelemetryEventToolInvocationBlocked {
				terminalLogFacts = append(terminalLogFacts, map[string]string{
					"event":           eventName,
					"tool_id":         logStringAttribute(record.Attributes, "gen_ai.tool.call.id"),
					"tool_status":     logStringAttribute(record.Attributes, "defenseclaw.tool.status"),
					"lifecycle_state": logStringAttribute(record.Attributes, "defenseclaw.agent.lifecycle.state"),
				})
			}
			switch {
			case eventName == observability.TelemetryEventModelCallFailed:
				modelFailedLog = true
			case eventName == observability.TelemetryEventToolInvocationFailed:
				toolFailedLog = true
			case eventName == observability.TelemetryEventToolInvocationBlocked:
				toolBlockedLog = true
			}
		}
		traceRequests, _ := capture.snapshot()
		for _, span := range hookModelV8CapturedSpans(traceRequests) {
			attributes := hookModelV8ProtoAttributes(span)
			switch {
			case gatewayProtoAttribute(span.Attributes, "defenseclaw.span.family") == observability.TelemetryFamilyModelChat &&
				attributes["gen_ai.conversation.id"] == modelSession:
				modelFailedSpan = span
			case gatewayProtoAttribute(span.Attributes, "defenseclaw.span.family") == observability.TelemetryFamilyToolExecute &&
				attributes["gen_ai.tool.call.id"] == failedToolID:
				toolFailedSpan = span
			case gatewayProtoAttribute(span.Attributes, "defenseclaw.span.family") == observability.TelemetryFamilyToolExecute &&
				attributes["gen_ai.tool.call.id"] == blockedToolID:
				toolBlockedSpan = span
			}
		}
		if modelFailedLog && toolFailedLog && toolBlockedLog &&
			modelFailedSpan != nil && toolFailedSpan != nil && toolBlockedSpan != nil {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}

	if !modelFailedLog || !toolFailedLog || !toolBlockedLog {
		t.Fatalf("terminal logs model_failed=%t tool_failed=%t tool_blocked=%t facts=%v all=%v emit_errors=%v", modelFailedLog, toolFailedLog, toolBlockedLog, terminalLogFacts, allLogEvents, runtimeCapture.snapshotErrors())
	}
	assertFailedSpan := func(name string, span *tracepb.Span) {
		t.Helper()
		if span == nil {
			t.Fatalf("%s span missing", name)
		}
		attributes := hookModelV8ProtoAttributes(span)
		if span.Status.GetCode() != tracepb.Status_STATUS_CODE_ERROR ||
			attributes["defenseclaw.outcome"] != string(observability.OutcomeFailed) ||
			attributes["error.type"] != "hook_failure" {
			t.Fatalf("%s failed span status=%s attributes=%v", name, span.Status.GetCode(), attributes)
		}
	}
	assertFailedSpan("model", modelFailedSpan)
	assertFailedSpan("tool", toolFailedSpan)
	if toolBlockedSpan == nil {
		t.Fatal("blocked tool span missing")
	}
	blockedAttributes := hookModelV8ProtoAttributes(toolBlockedSpan)
	if toolBlockedSpan.Status.GetCode() == tracepb.Status_STATUS_CODE_ERROR ||
		blockedAttributes["defenseclaw.outcome"] != string(observability.OutcomeBlocked) ||
		blockedAttributes["defenseclaw.tool.status"] != "blocked" {
		t.Fatalf("blocked tool span status=%s attributes=%v", toolBlockedSpan.Status.GetCode(), blockedAttributes)
	}
}
