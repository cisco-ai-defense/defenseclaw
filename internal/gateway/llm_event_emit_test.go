// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	osuser "os/user"
	"strconv"
	"strings"
	"testing"
	"time"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

func TestHookLLMEventMetaLifecycleCorrelation(t *testing.T) {
	gatewaylog.SetProcessRunID("gateway-run-a")
	t.Cleanup(func() { gatewaylog.SetProcessRunID("") })

	root := hookLLMEventMeta(
		"codex", "session-stable", "turn-1", "gpt-5", "codex", "", "", "codex",
		map[string]interface{}{
			"hook_event_name": "SessionStart",
			"source":          "resume",
			"user_id":         "user-1",
		},
	)
	if root.AgentID == "" || root.LifecycleID == "" || root.ExecutionID == "" {
		t.Fatalf("root lifecycle identity is incomplete: %+v", root)
	}
	if root.ParentAgentID != "" || root.AgentDepth != 0 || !root.SessionResumed {
		t.Fatalf("root lifecycle hierarchy/resume = %+v", root)
	}
	if root.LifecycleEvent != "session_start" || root.LifecycleState != "active" || root.UserID != "user-1" {
		t.Fatalf("root lifecycle event/state/user = %+v", root)
	}

	child := hookLLMEventMeta(
		"codex", "session-stable", "turn-1", "gpt-5", "codex", "child-7", "worker", "explore",
		map[string]interface{}{"hook_event_name": "SubagentStart", "agent_id": "child-7"},
	)
	if child.ParentAgentID != root.AgentID || child.AgentDepth != 1 || child.LifecycleID == root.LifecycleID {
		t.Fatalf("child hierarchy = %+v, root=%+v", child, root)
	}

	gatewaylog.SetProcessRunID("gateway-run-b")
	resumed := hookLLMEventMeta(
		"codex", "session-stable", "turn-2", "gpt-5", "codex", "", "", "codex",
		map[string]interface{}{"hook_event_name": "SessionStart", "source": "resume"},
	)
	if resumed.LifecycleID != root.LifecycleID {
		t.Fatalf("lifecycle id changed across gateway restart: %q != %q", resumed.LifecycleID, root.LifecycleID)
	}
	if resumed.ExecutionID == root.ExecutionID {
		t.Fatalf("execution id did not change across gateway restart: %q", resumed.ExecutionID)
	}
	api := &APIServer{hookSessionTraces: map[string]hookSessionTrace{
		hookSessionTraceKey(root): {meta: root},
	}}
	turn := hookLLMEventMeta(
		"codex", "session-stable", "turn-3", "gpt-5", "codex", "", "", "codex",
		map[string]interface{}{"hook_event_name": "Stop"},
	)
	turn = api.mergeHookSessionLifecycle(turn)
	if !turn.SessionResumed || turn.SessionSource != "resume" {
		t.Fatalf("turn did not inherit resumed session metadata: %+v", turn)
	}
}

func TestNormalizeAgentHookRequestLabelsLifecycleEvents(t *testing.T) {
	for _, tc := range []struct {
		event string
		want  string
	}{
		{event: "SubagentStart", want: "subagent"},
		{event: "SubagentStop", want: "subagent"},
		{event: "session.created", want: "session"},
		{event: "session.updated", want: "session"},
		{event: "session.status", want: "session"},
		{event: "session.idle", want: "session"},
		{event: "session.compacted", want: "session"},
		{event: "session.error", want: "session"},
		{event: "session.deleted", want: "session"},
	} {
		t.Run(tc.event, func(t *testing.T) {
			req := normalizeAgentHookRequest("opencode", map[string]interface{}{
				"hook_event_name": tc.event,
				"session_id":      "session-1",
			})
			if req.ToolName != tc.want {
				t.Fatalf("ToolName=%q want %q", req.ToolName, tc.want)
			}
		})
	}
}

func TestStampEventCorrelationBackfillsStableLifecycleIDsIndependently(t *testing.T) {
	gatewaylog.SetProcessRunID("run-1")
	t.Cleanup(func() { gatewaylog.SetProcessRunID("") })
	first := gatewaylog.Event{SessionID: "session-1", AgentID: "agent-1", Connector: "codex", AgentType: "codex"}
	stampEventCorrelation(&first, context.Background())
	if first.AgentLifecycleID == "" || first.AgentExecutionID == "" {
		t.Fatalf("missing derived IDs: %+v", first)
	}
	second := gatewaylog.Event{
		SessionID: "session-1", AgentID: "agent-1", Connector: "codex", AgentType: "subagent",
		AgentLifecycleID: first.AgentLifecycleID,
	}
	stampEventCorrelation(&second, context.Background())
	if second.AgentLifecycleID != first.AgentLifecycleID || second.AgentExecutionID != first.AgentExecutionID {
		t.Fatalf("inconsistent derived IDs: first=%+v second=%+v", first, second)
	}
}

func TestHookExecutionRotatesWithinGatewayProcess(t *testing.T) {
	gatewaylog.SetProcessRunID("gateway-run-stable")
	t.Cleanup(func() { gatewaylog.SetProcessRunID("") })
	api := &APIServer{}
	base := hookLLMEventMeta(
		"codex", "session-resumed", "", "gpt-5", "codex", "", "", "codex",
		map[string]interface{}{"hook_event_name": "SessionStart", "source": "resume"},
	)
	first := api.beginHookExecution(base)
	second := api.beginHookExecution(base)
	if first.LifecycleID != second.LifecycleID {
		t.Fatalf("stable lifecycle changed: %q != %q", first.LifecycleID, second.LifecycleID)
	}
	if first.ExecutionID == second.ExecutionID {
		t.Fatalf("resume attempts reused execution id %q", first.ExecutionID)
	}
}

func TestHookPhaseSequenceIsOrderedAndDirected(t *testing.T) {
	t.Parallel()
	api := &APIServer{}
	base := llmEventMeta{
		Source: "codex", SessionID: "phase-session", AgentID: "phase-agent",
		LifecycleID: "phase-lifecycle", ExecutionID: "phase-execution",
	}
	planning := base
	planning.LifecycleEvent = "turn_start"
	planning.LifecycleState = "active"
	planning.Phase = "planning"
	planning = api.enrichHookPhase(planning)
	// First phase has no predecessor: PreviousPhase must be empty so the
	// gateway-event schema serializes agent_previous_phase as null (the enum
	// rejects the "unknown" sentinel, which would drop the event).
	if planning.Sequence != 1 || planning.PreviousPhase != "" {
		t.Fatalf("first phase = %+v", planning)
	}
	tool := base
	tool.LifecycleEvent = "tool_start"
	tool.LifecycleState = "active"
	tool.Phase = "tool"
	tool = api.enrichHookPhase(tool)
	if tool.Sequence != 2 || tool.PreviousPhase != "planning" || tool.OperationID == "" {
		t.Fatalf("second phase = %+v", tool)
	}
	responding := base
	responding.LifecycleEvent = "turn_end"
	responding.LifecycleState = "completed"
	responding.Phase = "responding"
	responding = api.enrichHookPhase(responding)
	if responding.Sequence != 3 || responding.PreviousPhase != "tool" {
		t.Fatalf("third phase = %+v", responding)
	}
}

func TestHookOperationIDPairsToolStartAndEndWithoutCollapsingTurn(t *testing.T) {
	t.Parallel()
	base := llmEventMeta{
		Source: "codex", SessionID: "operation-session", AgentID: "operation-agent",
		TurnID: "shared-turn", ToolName: "Bash",
	}
	firstStart := base
	firstStart.ToolID = "tool-call-1"
	firstStart = applyHookEventMeta(firstStart, "PreToolUse", map[string]interface{}{})
	firstEnd := base
	firstEnd.ToolID = "tool-call-1"
	firstEnd = applyHookEventMeta(firstEnd, "PostToolUse", map[string]interface{}{})
	secondStart := base
	secondStart.ToolID = "tool-call-2"
	secondStart = applyHookEventMeta(secondStart, "PreToolUse", map[string]interface{}{})
	if firstStart.OperationID == "" || firstStart.OperationID != firstEnd.OperationID {
		t.Fatalf("tool pair operation IDs differ: start=%q end=%q", firstStart.OperationID, firstEnd.OperationID)
	}
	if firstStart.OperationID == secondStart.OperationID {
		t.Fatalf("distinct tool calls in one turn collapsed to %q", firstStart.OperationID)
	}
}

func TestOpenCodeChildSessionParentsToParentConversationTrace(t *testing.T) {
	api, exporter := newHookLLMSpanTestAPI(t)
	rootPayload := map[string]interface{}{
		"hook_event_name": "session.created",
		"session_id":      "parent-session",
	}
	api.emitAgentHookLLMEvent(
		context.Background(), normalizeAgentHookRequest("opencode", rootPayload), nil,
	)
	childPayload := map[string]interface{}{
		"hook_event_name":   "session.created",
		"session_id":        "child-session",
		"parent_session_id": "parent-session",
	}
	api.emitAgentHookLLMEvent(
		context.Background(), normalizeAgentHookRequest("opencode", childPayload), nil,
	)

	spans := exporter.GetSpans()
	if len(spans) != 3 {
		t.Fatalf("spans=%d want parent start anchor+fresh parent/child anchors", len(spans))
	}
	var parent, child tracetest.SpanStub
	for _, span := range spans {
		switch spanAttributeStrings(span)["gen_ai.conversation.id"] {
		case "parent-session":
			parent = span
		case "child-session":
			child = span
		}
	}
	if !parent.SpanContext.IsValid() || !child.SpanContext.IsValid() {
		t.Fatalf("missing parent/child spans: %+v", spans)
	}
	if child.Parent.SpanID() != parent.SpanContext.SpanID() ||
		child.SpanContext.TraceID() != parent.SpanContext.TraceID() {
		t.Fatalf("child parent/trace mismatch: parent=%s child.parent=%s", parent.SpanContext.SpanID(), child.Parent.SpanID())
	}
	if got := spanAttributeStrings(child)["defenseclaw.session.parent.id"]; got != "parent-session" {
		t.Fatalf("child parent session=%q", got)
	}
}

func TestExplicitRootAgentIDParentsNativeChildInSameTrace(t *testing.T) {
	api, exporter := newHookLLMSpanTestAPI(t)
	api.emitCodexHookLLMEvent(context.Background(), codexHookRequest{
		HookEventName: "SessionStart",
		SessionID:     "parent-session",
		AgentID:       "native-root",
		AgentType:     "codex",
		Payload: map[string]interface{}{
			"hook_event_name": "SessionStart",
			"session_id":      "parent-session",
			"agent_id":        "native-root",
		},
	}, nil, nil)
	api.emitCodexHookLLMEvent(context.Background(), codexHookRequest{
		HookEventName: "SubagentStart",
		SessionID:     "child-session",
		AgentID:       "native-child",
		AgentType:     "researcher",
		Payload: map[string]interface{}{
			"hook_event_name":   "SubagentStart",
			"session_id":        "child-session",
			"parent_session_id": "parent-session",
			"agent_id":          "native-child",
		},
	}, nil, nil)

	spans := exporter.GetSpans()
	if len(spans) != 3 {
		t.Fatalf("spans=%d want parent start anchor+fresh parent/child anchors", len(spans))
	}
	var parent, child tracetest.SpanStub
	for _, span := range spans {
		attrs := spanAttributeStrings(span)
		switch attrs["gen_ai.agent.id"] {
		case "native-root":
			parent = span
		case "native-child":
			child = span
		}
	}
	if !parent.SpanContext.IsValid() || !child.SpanContext.IsValid() {
		t.Fatalf("missing parent/child spans: %+v", spans)
	}
	if child.Parent.SpanID() != parent.SpanContext.SpanID() ||
		child.SpanContext.TraceID() != parent.SpanContext.TraceID() {
		t.Fatalf("child did not reuse authoritative parent trace: parent=%s child.parent=%s", parent.SpanContext.SpanID(), child.Parent.SpanID())
	}
	if got := spanAttributeStrings(child)["defenseclaw.agent.parent.id"]; got != "native-root" {
		t.Fatalf("child parent agent=%q want native-root", got)
	}
	childAttrs := spanAttributeStrings(child)
	if got := childAttrs["defenseclaw.agent.root.id"]; got != "native-root" {
		t.Fatalf("child root agent=%q want native-root", got)
	}
	if got := childAttrs["defenseclaw.session.root.id"]; got != "parent-session" {
		t.Fatalf("child root session=%q want parent-session", got)
	}
}

func TestLifecycleOnlySessionEndProducesLogAndTrace(t *testing.T) {
	events := captureGatewayEvents(t)
	api, exporter := newHookLLMSpanTestAPI(t)
	for _, event := range []string{"session_start", "session_end"} {
		payload := map[string]interface{}{
			"hook_event_name": event,
			"session_id":      "openhands-lifecycle-only",
		}
		api.emitAgentHookLLMEvent(
			context.Background(), normalizeAgentHookRequest("openhands", payload), nil,
		)
	}
	if got := len(exporter.GetSpans()); got != 3 {
		t.Fatalf("spans=%d want start anchor+terminal anchor+transition", got)
	}
	var terminalLogs int
	for _, event := range *events {
		if event.AgentLifecycleEvent == "session_end" && event.AgentLifecycleState == "completed" {
			terminalLogs++
		}
	}
	if terminalLogs != 1 {
		t.Fatalf("terminal lifecycle logs=%d want 1", terminalLogs)
	}
}

func TestHermesNestedSubagentIdentityNormalizesChildSession(t *testing.T) {
	payload := map[string]interface{}{
		"hook_event_name": "subagent_start",
		"session_id":      "parent-hermes-session",
		"extra": map[string]interface{}{
			"parent_session_id": "parent-hermes-session",
			"child_session_id":  "child-hermes-session",
			"child_subagent_id": "child-hermes-id",
			"child_role":        "leaf",
		},
	}
	req := normalizeAgentHookRequest("hermes", payload)
	if req.SessionID != "child-hermes-session" || req.AgentID != "child-hermes-id" || req.AgentName != "leaf" {
		t.Fatalf("normalized child identity=%+v", req)
	}
	meta := applyHookEventMeta(
		hookLLMEventMeta("hermes", req.SessionID, req.TurnID, "", "hermes", req.AgentID, req.AgentName, req.AgentType, req.Payload),
		req.HookEventName, req.Payload,
	)
	if meta.ParentSessionID != "parent-hermes-session" || meta.ParentAgentID == "" || meta.AgentDepth != 1 {
		t.Fatalf("normalized child hierarchy=%+v", meta)
	}
}

func TestAntigravityDelegationToolInfersEveryChildLifecycle(t *testing.T) {
	events := captureGatewayEvents(t)
	api, exporter := newHookLLMSpanTestAPI(t)
	payload := map[string]interface{}{
		"hook_event_name": "PreToolUse",
		"conversationId":  "antigravity-delegation",
		"tool_name":       "invoke_subagent",
		"tool_call_id":    "delegation-call-1",
		"tool_input": map[string]interface{}{
			"Subagents": []interface{}{
				map[string]interface{}{"Role": "researcher", "Prompt": "research"},
				map[string]interface{}{"Role": "reviewer", "Prompt": "review"},
			},
		},
	}
	api.emitAgentHookLLMEvent(
		context.Background(), normalizeAgentHookRequest("antigravity", payload), nil,
	)
	if got := len(exporter.GetSpans()); got != 3 {
		t.Fatalf("spans=%d want root+two inferred child anchors", got)
	}
	children := map[string]bool{}
	for _, event := range *events {
		if event.AgentLifecycleEvent == "subagent_start" {
			children[event.AgentName] = true
		}
	}
	if !children["researcher"] || !children["reviewer"] || len(children) != 2 {
		t.Fatalf("inferred child lifecycle logs=%v", children)
	}
}

func TestAllHookConnectorsNormalizeStableLifecycle(t *testing.T) {
	tests := []struct {
		connector string
		start     string
		end       string
		startWant string
		endWant   string
	}{
		{"codex", "SessionStart", "Stop", "session_start", "turn_end"},
		{"claudecode", "SessionStart", "SessionEnd", "session_start", "session_end"},
		{"hermes", "on_session_start", "on_session_end", "session_start", "session_end"},
		{"cursor", "sessionStart", "sessionEnd", "session_start", "session_end"},
		{"windsurf", "pre_user_prompt", "post_cascade_response", "turn_start", "turn_end"},
		{"geminicli", "SessionStart", "SessionEnd", "session_start", "session_end"},
		{"copilot", "sessionStart", "sessionEnd", "session_start", "session_end"},
		{"antigravity", "PreInvocation", "Stop", "turn_start", "turn_end"},
		{"openhands", "session_start", "session_end", "session_start", "session_end"},
		{"opencode", "session.created", "session.deleted", "session_start", "session_end"},
	}
	for _, tt := range tests {
		t.Run(tt.connector, func(t *testing.T) {
			base := llmEventMeta{
				Source: tt.connector, SessionID: "stable-session",
				AgentID: stableLLMEventID("agent", tt.connector, "stable-session", "root"),
			}
			base.LifecycleID = stableLLMEventID("lifecycle", tt.connector, base.SessionID, base.AgentID)
			start := applyHookEventMeta(base, tt.start, map[string]interface{}{})
			end := applyHookEventMeta(base, tt.end, map[string]interface{}{})
			if start.LifecycleEvent != tt.startWant || end.LifecycleEvent != tt.endWant {
				t.Fatalf("events start=%q end=%q", start.LifecycleEvent, end.LifecycleEvent)
			}
			if start.LifecycleID != end.LifecycleID {
				t.Fatalf("lifecycle changed: %q != %q", start.LifecycleID, end.LifecycleID)
			}
		})
	}
}

func TestExplicitSubagentConnectorsKeepStableChildIdentity(t *testing.T) {
	for _, connector := range []string{"codex", "claudecode", "cursor", "copilot", "hermes"} {
		t.Run(connector, func(t *testing.T) {
			startPayload := map[string]interface{}{
				"hook_event_name": "SubagentStart",
				"session_id":      "parent-session",
				"agent_name":      "researcher",
			}
			if connector == "hermes" {
				startPayload["hook_event_name"] = "subagent_start"
				startPayload["extra"] = map[string]interface{}{
					"child_subagent_id": "native-child", "child_role": "researcher",
				}
			} else {
				startPayload["agent_id"] = "native-child"
			}
			startReq := normalizeAgentHookRequest(connector, startPayload)
			start := applyHookEventMeta(
				hookLLMEventMeta(connector, startReq.SessionID, "", "", connector, startReq.AgentID, startReq.AgentName, startReq.AgentType, startReq.Payload),
				startReq.HookEventName, startReq.Payload,
			)
			stopPayload := map[string]interface{}{}
			for key, value := range startPayload {
				stopPayload[key] = value
			}
			if connector == "hermes" {
				stopPayload["hook_event_name"] = "subagent_stop"
			} else {
				stopPayload["hook_event_name"] = "SubagentStop"
			}
			stopReq := normalizeAgentHookRequest(connector, stopPayload)
			stop := applyHookEventMeta(
				hookLLMEventMeta(connector, stopReq.SessionID, "", "", connector, stopReq.AgentID, stopReq.AgentName, stopReq.AgentType, stopReq.Payload),
				stopReq.HookEventName, stopReq.Payload,
			)
			if start.AgentID != stop.AgentID || start.LifecycleID != stop.LifecycleID ||
				start.ParentAgentID == "" || stop.ParentAgentID == "" {
				t.Fatalf("child lifecycle start=%+v stop=%+v", start, stop)
			}
		})
	}
}

func captureGatewayEvents(t *testing.T) *[]gatewaylog.Event {
	t.Helper()
	prev := EventWriter()
	w, err := gatewaylog.New(gatewaylog.Config{})
	if err != nil {
		t.Fatalf("gatewaylog.New: %v", err)
	}
	var events []gatewaylog.Event
	w.WithFanout(func(e gatewaylog.Event) {
		events = append(events, e)
	})
	SetEventWriter(w)
	t.Cleanup(func() {
		SetEventWriter(prev)
		_ = w.Close()
	})
	return &events
}

func TestLLMEventEmit_RedactsByDefaultAndSendsRawWhenDisabled(t *testing.T) {
	events := captureGatewayEvents(t)
	t.Cleanup(func() { redaction.SetDisableAll(false) })

	meta := llmEventMeta{
		Source:    "codex",
		Provider:  "openai",
		Model:     "gpt-4o",
		SessionID: "sess-1",
		RequestID: "req-1",
		AgentType: "codex",
		UserID:    "alice",
	}

	redaction.SetDisableAll(false)
	emitLLMPromptEvent(context.Background(), meta, "raw user prompt", []byte(`{"messages":[{"role":"user","content":"raw user prompt"}]}`))
	if len(*events) != 1 {
		t.Fatalf("events=%d want 1", len(*events))
	}
	redacted := (*events)[0]
	if redacted.LLMPrompt == nil {
		t.Fatalf("missing llm_prompt payload: %+v", redacted)
	}
	if redacted.LLMPrompt.Prompt == "raw user prompt" {
		t.Fatalf("prompt leaked with redaction enabled")
	}
	if !strings.HasPrefix(redacted.LLMPrompt.Prompt, "<redacted") {
		t.Fatalf("prompt was not redacted placeholder: %q", redacted.LLMPrompt.Prompt)
	}
	if redacted.UserID != "alice" || redacted.AgentType != "codex" {
		t.Fatalf("envelope lost user/agent type: %+v", redacted)
	}

	redaction.SetDisableAll(true)
	emitLLMPromptEvent(context.Background(), meta, "raw user prompt", []byte(`{"raw":true}`))
	if len(*events) != 2 {
		t.Fatalf("events=%d want 2", len(*events))
	}
	raw := (*events)[1]
	if raw.LLMPrompt.Prompt != "raw user prompt" {
		t.Fatalf("prompt=%q, want raw prompt", raw.LLMPrompt.Prompt)
	}
	if raw.LLMPrompt.RawRequestBody != `{"raw":true}` {
		t.Fatalf("raw_request_body=%q", raw.LLMPrompt.RawRequestBody)
	}
}

func TestClaudeCodeHookResponseLinksToLastPrompt(t *testing.T) {
	events := captureGatewayEvents(t)
	t.Cleanup(func() { redaction.SetDisableAll(false) })
	redaction.SetDisableAll(true)

	api := &APIServer{}
	api.emitClaudeCodeHookLLMEvent(context.Background(), claudeCodeHookRequest{
		HookEventName: "UserPromptSubmit",
		SessionID:     "sess-claude",
		Model:         "claude-3-5-sonnet",
		Prompt:        "write tests",
		AgentType:     "claude-code",
	}, nil, []byte(`{"hook_event_name":"UserPromptSubmit","prompt":"write tests"}`))
	api.emitClaudeCodeHookLLMEvent(context.Background(), claudeCodeHookRequest{
		HookEventName:        "Stop",
		SessionID:            "sess-claude",
		Model:                "claude-3-5-sonnet",
		LastAssistantMessage: "done",
		AgentType:            "claude-code",
	}, nil, []byte(`{"hook_event_name":"Stop","last_assistant_message":"done"}`))

	var prompt *gatewaylog.LLMPromptPayload
	var response *gatewaylog.LLMResponsePayload
	var lifecycleCount int
	for i := range *events {
		if (*events)[i].LLMPrompt != nil {
			prompt = (*events)[i].LLMPrompt
		}
		if (*events)[i].LLMResponse != nil {
			response = (*events)[i].LLMResponse
		}
		if (*events)[i].Lifecycle != nil && (*events)[i].Lifecycle.Subsystem == "agent" {
			lifecycleCount++
		}
	}
	if prompt == nil || response == nil {
		t.Fatalf("unexpected events: %+v", *events)
	}
	if lifecycleCount != 2 {
		t.Fatalf("agent lifecycle events=%d want prompt+stop transitions", lifecycleCount)
	}
	if response.ReplyToPromptID != prompt.PromptID {
		t.Fatalf("reply_to_prompt_id=%q want %q", response.ReplyToPromptID, prompt.PromptID)
	}
	if response.Response != "done" {
		t.Fatalf("response=%q", response.Response)
	}
}

func TestClaudeCodeMessageDisplayEmitsRealtimeCorrelatedResponse(t *testing.T) {
	events := captureGatewayEvents(t)
	t.Cleanup(func() { redaction.SetDisableAll(false) })
	redaction.SetDisableAll(true)
	api := &APIServer{}
	api.emitClaudeCodeHookLLMEvent(context.Background(), claudeCodeHookRequest{
		HookEventName: "MessageDisplay",
		SessionID:     "claude-stream-session",
		TurnID:        "turn-stream",
		MessageID:     "display-message-1",
		Delta:         "streamed assistant output",
		DisplayFinal:  true,
		AgentType:     "claude-code",
	}, nil, nil)
	var response *gatewaylog.LLMResponsePayload
	for i := range *events {
		if (*events)[i].LLMResponse != nil {
			response = (*events)[i].LLMResponse
		}
	}
	if response == nil || response.ResponseID != "display-message-1" ||
		response.TurnID != "turn-stream" || response.Response != "streamed assistant output" {
		t.Fatalf("message display response=%+v events=%+v", response, *events)
	}
}

func TestCodexHookSameTurnPromptsGetDistinctIDsAndCorrelateToLatest(t *testing.T) {
	events := captureGatewayEvents(t)
	t.Cleanup(func() { redaction.SetDisableAll(false) })
	redaction.SetDisableAll(true)

	api := &APIServer{}
	base := codexHookRequest{
		SessionID: "sess-codex",
		TurnID:    "turn-1",
		Model:     "gpt-5.5",
		AgentType: "codex",
		Payload: map[string]interface{}{
			"user_id":   "alice-id",
			"user_name": "alice",
		},
	}
	first := base
	first.HookEventName = "UserPromptSubmit"
	first.Prompt = "first prompt"
	api.emitCodexHookLLMEvent(context.Background(), first, nil, []byte(`{"hook_event_name":"UserPromptSubmit","prompt":"first prompt"}`))

	second := base
	second.HookEventName = "UserPromptSubmit"
	second.Prompt = "second prompt"
	api.emitCodexHookLLMEvent(context.Background(), second, nil, []byte(`{"hook_event_name":"UserPromptSubmit","prompt":"second prompt"}`))

	tool := base
	tool.HookEventName = "PreToolUse"
	tool.ToolName = "shell"
	tool.ToolUseID = "tool-1"
	tool.ToolInput = map[string]interface{}{"cmd": "echo ok"}
	api.emitCodexHookLLMEvent(context.Background(), tool, nil, []byte(`{"hook_event_name":"PreToolUse"}`))

	stop := base
	stop.HookEventName = "Stop"
	stop.LastAssistantMessage = "done"
	api.emitCodexHookLLMEvent(context.Background(), stop, nil, []byte(`{"hook_event_name":"Stop","last_assistant_message":"done"}`))

	var promptEvents []gatewaylog.Event
	var toolEnvelope, responseEnvelope gatewaylog.Event
	for _, event := range *events {
		if event.LLMPrompt != nil {
			promptEvents = append(promptEvents, event)
		}
		if event.Tool != nil {
			toolEnvelope = event
		}
		if event.LLMResponse != nil {
			responseEnvelope = event
		}
	}
	if len(promptEvents) != 2 {
		t.Fatalf("prompt events=%d want 2; all=%+v", len(promptEvents), *events)
	}
	firstPrompt := promptEvents[0].LLMPrompt
	secondPrompt := promptEvents[1].LLMPrompt
	toolEvent := toolEnvelope.Tool
	response := responseEnvelope.LLMResponse
	if firstPrompt == nil || secondPrompt == nil || toolEvent == nil || response == nil {
		t.Fatalf("unexpected events: %+v", *events)
	}
	if firstPrompt.PromptID == secondPrompt.PromptID {
		t.Fatalf("same-turn prompt ids collided: %q", firstPrompt.PromptID)
	}
	if toolEvent.ReplyToPromptID != secondPrompt.PromptID {
		t.Fatalf("tool reply_to_prompt_id=%q want latest prompt %q", toolEvent.ReplyToPromptID, secondPrompt.PromptID)
	}
	if response.ReplyToPromptID != secondPrompt.PromptID {
		t.Fatalf("response reply_to_prompt_id=%q want latest prompt %q", response.ReplyToPromptID, secondPrompt.PromptID)
	}
	if got := promptEvents[1].UserID; got != "alice-id" {
		t.Fatalf("user_id=%q want alice-id", got)
	}
	if got := toolEnvelope.DestinationApp; got != "builtin" {
		t.Fatalf("destination_app=%q want builtin", got)
	}
}

func TestCodexHookMCPToolSetsDestinationApp(t *testing.T) {
	events := captureGatewayEvents(t)
	t.Cleanup(func() { redaction.SetDisableAll(false) })
	redaction.SetDisableAll(true)

	api := &APIServer{}
	req := codexHookRequest{
		HookEventName: "PreToolUse",
		SessionID:     "sess-codex",
		TurnID:        "turn-1",
		Model:         "gpt-5.5",
		ToolName:      "mcp__github__search_issues",
		ToolUseID:     "tool-1",
		Payload: map[string]interface{}{
			"mcp_server_name": "github",
		},
	}
	api.emitCodexHookLLMEvent(context.Background(), req, nil, []byte(`{"hook_event_name":"PreToolUse"}`))

	var toolEvent *gatewaylog.Event
	for i := range *events {
		if (*events)[i].Tool != nil {
			toolEvent = &(*events)[i]
		}
	}
	if toolEvent == nil {
		t.Fatalf("tool event missing: %+v", *events)
	}
	if got := toolEvent.DestinationApp; got != "mcp:github" {
		t.Fatalf("destination_app=%q want mcp:github", got)
	}
}

func TestHookLLMEventMetaFallsBackToLocalUser(t *testing.T) {
	current, err := osuser.Current()
	if err != nil || current == nil {
		t.Skipf("os/user current unavailable: %v", err)
	}

	meta := hookLLMEventMeta("codex", "sess", "turn", "gpt-5.5", "openai", "", "codex", "ide", map[string]interface{}{})
	if meta.UserID == "" && meta.UserName == "" {
		t.Fatalf("expected local user fallback, got user_id=%q user_name=%q", meta.UserID, meta.UserName)
	}
}

func TestHookUserEmailIsPseudonymized(t *testing.T) {
	userID, userName := userFromHookPayload(map[string]interface{}{"user_email": "Alice@Example.COM"})
	if userID == "" || strings.Contains(strings.ToLower(userID), "alice@example.com") {
		t.Fatalf("user email was not pseudonymized: %q", userID)
	}
	if strings.Contains(strings.ToLower(userName), "alice@example.com") {
		t.Fatalf("user name leaked email: %q", userName)
	}
}

func TestHookToolDestinationApp(t *testing.T) {
	cases := []struct {
		name       string
		serverName string
		toolName   string
		want       string
	}{
		{name: "explicit server", serverName: "github", toolName: "Bash", want: "mcp:github"},
		{name: "mcp tool name", toolName: "mcp__filesystem__read_file", want: "mcp:filesystem"},
		{name: "builtin tool", toolName: "apply_patch", want: "builtin"},
		{name: "empty tool", want: ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := hookToolDestinationApp(tc.serverName, tc.toolName); got != tc.want {
				t.Fatalf("hookToolDestinationApp(%q, %q) = %q, want %q", tc.serverName, tc.toolName, got, tc.want)
			}
		})
	}
}

func newHookLLMSpanTestAPI(t *testing.T) (*APIServer, *tracetest.InMemoryExporter) {
	t.Helper()
	reader := sdkmetric.NewManualReader()
	exporter := tracetest.NewInMemoryExporter()
	provider, err := telemetry.NewProviderForTraceTest(reader, exporter)
	if err != nil {
		t.Fatalf("NewProviderForTraceTest: %v", err)
	}
	t.Cleanup(func() { _ = provider.Shutdown(context.Background()) })
	return &APIServer{otel: provider}, exporter
}

func spanAttributeStrings(span tracetest.SpanStub) map[string]string {
	out := make(map[string]string, len(span.Attributes))
	for _, item := range span.Attributes {
		out[string(item.Key)] = item.Value.AsString()
	}
	return out
}

func spanByOperation(t *testing.T, spans tracetest.SpanStubs, operation string) tracetest.SpanStub {
	t.Helper()
	for _, span := range spans {
		if spanAttributeStrings(span)["gen_ai.operation.name"] == operation {
			return span
		}
	}
	t.Fatalf("operation %q not found in %d spans", operation, len(spans))
	return tracetest.SpanStub{}
}

func parentSpan(t *testing.T, spans tracetest.SpanStubs, child tracetest.SpanStub) tracetest.SpanStub {
	t.Helper()
	for _, span := range spans {
		if span.SpanContext.SpanID() == child.Parent.SpanID() {
			return span
		}
	}
	t.Fatalf("parent span %s not found for %q", child.Parent.SpanID(), child.Name)
	return tracetest.SpanStub{}
}

func TestCodexHookCompletedTurnEmitsCanonicalGenAISpan(t *testing.T) {
	t.Cleanup(func() { redaction.SetDisableAll(false) })
	redaction.SetDisableAll(true)
	api, exporter := newHookLLMSpanTestAPI(t)

	prompt := codexHookRequest{
		HookEventName: "UserPromptSubmit",
		SessionID:     "sess-codex-span",
		TurnID:        "turn-1",
		Model:         "gpt-5.5",
		Prompt:        "explain the routing bug",
		AgentID:       "codex-agent",
		AgentType:     "codex",
	}
	api.emitCodexHookLLMEvent(context.Background(), prompt, nil, nil)
	stop := prompt
	stop.HookEventName = "Stop"
	stop.Prompt = ""
	stop.LastAssistantMessage = "the connector bridge was missing"
	api.emitCodexHookLLMEvent(context.Background(), stop, nil, nil)

	spans := exporter.GetSpans()
	if len(spans) != 4 {
		t.Fatalf("spans=%d want prompt anchor+terminal anchor+transition+chat", len(spans))
	}
	span := spanByOperation(t, spans, "chat")
	agent := parentSpan(t, spans, span)
	if agent.Parent.IsValid() {
		t.Fatalf("hook agent retained filtered HTTP parent %s", agent.Parent.SpanID())
	}
	if span.Parent.SpanID() != agent.SpanContext.SpanID() {
		t.Fatalf("chat parent=%s want session agent=%s", span.Parent.SpanID(), agent.SpanContext.SpanID())
	}
	if span.SpanContext.TraceID() != agent.SpanContext.TraceID() {
		t.Fatalf("chat trace=%s want session trace=%s", span.SpanContext.TraceID(), agent.SpanContext.TraceID())
	}
	for _, candidate := range spans {
		if candidate.Name == "agent.lifecycle turn_end" &&
			candidate.SpanContext.TraceID() != span.SpanContext.TraceID() {
			t.Fatalf("terminal transition trace=%s want chat trace=%s", candidate.SpanContext.TraceID(), span.SpanContext.TraceID())
		}
	}
	if span.Name != "chat gpt-5.5" {
		t.Fatalf("span name=%q", span.Name)
	}
	attrs := spanAttributeStrings(span)
	for key, want := range map[string]string{
		"gen_ai.operation.name":            "chat",
		"gen_ai.provider.name":             "openai",
		"gen_ai.request.model":             "gpt-5.5",
		"gen_ai.response.model":            "gpt-5.5",
		"gen_ai.conversation.id":           "sess-codex-span",
		"openinference.span.kind":          "LLM",
		"defenseclaw.llm.guardrail":        "connector_hook",
		"defenseclaw.llm.guardrail.result": "observed",
	} {
		if got := attrs[key]; got != want {
			t.Errorf("%s=%q want %q", key, got, want)
		}
	}
	if !strings.Contains(attrs["gen_ai.input.messages"], "explain the routing bug") {
		t.Fatalf("input messages=%q", attrs["gen_ai.input.messages"])
	}
	if !strings.Contains(attrs["gen_ai.output.messages"], "connector bridge was missing") {
		t.Fatalf("output messages=%q", attrs["gen_ai.output.messages"])
	}

	// Hook delivery may retry after a timeout. The same Stop must not create a
	// duplicate Galileo trace.
	api.emitCodexHookLLMEvent(context.Background(), stop, nil, nil)
	if got := len(exporter.GetSpans()); got != 4 {
		t.Fatalf("spans after duplicate Stop=%d want 4", got)
	}
}

func TestHookLifecycleTransitionDedupeCollapsesEquivalentTurnAndToolEvents(t *testing.T) {
	api := &APIServer{}

	turn := llmEventMeta{
		Source: "codex", SessionID: "session-1", TurnID: "turn-1", AgentID: "Agent/One",
		LifecycleID: "lifecycle-1", LifecycleEvent: "turn_end",
	}
	turn.LifecycleDedupe = hookLifecycleDedupeKey(turn, map[string]interface{}{"response_id": "response-1"})
	if !api.shouldRecordHookLifecycleTransition(turn) {
		t.Fatal("first turn_end transition was dropped")
	}
	afterModel := turn
	afterModel.LifecycleDedupe = hookLifecycleDedupeKey(afterModel, map[string]interface{}{"response_id": "response-1"})
	if api.shouldRecordHookLifecycleTransition(afterModel) {
		t.Fatal("duplicate model/stop transition was counted twice")
	}

	tool := llmEventMeta{
		Source: "codex", SessionID: "session-1", AgentID: "Agent/One",
		LifecycleID: "lifecycle-1", LifecycleEvent: "tool_start",
	}
	tool.LifecycleDedupe = hookLifecycleDedupeKey(tool, map[string]interface{}{"tool_call_id": "call-1"})
	if !api.shouldRecordHookLifecycleTransition(tool) {
		t.Fatal("first tool_start transition was dropped")
	}
	permission := tool
	permission.LifecycleDedupe = hookLifecycleDedupeKey(permission, map[string]interface{}{"tool_call_id": "call-1"})
	if api.shouldRecordHookLifecycleTransition(permission) {
		t.Fatal("duplicate permission/pre-tool transition was counted twice")
	}
}

func TestNormalizeHookReportedCostAccumulatesIncrementalPerCallCost(t *testing.T) {
	api := &APIServer{}
	meta := llmEventMeta{
		Source: "codex", SessionID: "session-1", AgentID: "agent-1", LifecycleID: "lifecycle-1",
		ReportedCost: true, ReportedCostUSD: 0.25,
	}
	first := api.normalizeHookReportedCost(meta)
	if first.ReportedCostUSD != 0.25 || !first.ReportedCostSum {
		t.Fatalf("first incremental cost = %+v, want cumulative 0.25", first)
	}
	meta.ReportedCostUSD = 0.50
	second := api.normalizeHookReportedCost(meta)
	if second.ReportedCostUSD != 0.75 || !second.ReportedCostSum {
		t.Fatalf("second incremental cost = %+v, want cumulative 0.75", second)
	}
	cumulative := meta
	cumulative.ReportedCostUSD = 1.25
	cumulative.ReportedCostSum = true
	if got := api.normalizeHookReportedCost(cumulative); got.ReportedCostUSD != 1.25 {
		t.Fatalf("cumulative reported cost changed: %+v", got)
	}
}

func TestCodexHookCompletedTurnAttachesObservedTokenUsage(t *testing.T) {
	t.Cleanup(func() { redaction.SetDisableAll(false) })
	redaction.SetDisableAll(true)
	api, exporter := newHookLLMSpanTestAPI(t)

	prompt := codexHookRequest{
		HookEventName: "UserPromptSubmit", SessionID: "sess-usage", TurnID: "turn-1",
		Model: "gpt-5.5", Prompt: "count these tokens", AgentType: "codex",
	}
	api.emitCodexHookLLMEvent(context.Background(), prompt, nil, nil)
	stop := prompt
	stop.HookEventName = "Stop"
	stop.Prompt = ""
	stop.LastAssistantMessage = "done"
	stop.Payload = map[string]interface{}{
		"usage": map[string]interface{}{
			"input_tokens": float64(321), "output_tokens": float64(45),
		},
	}
	api.emitCodexHookLLMEvent(context.Background(), stop, nil, nil)

	chat := spanByOperation(t, exporter.GetSpans(), "chat")
	for key, want := range map[string]int64{
		"gen_ai.usage.input_tokens": 321, "gen_ai.usage.output_tokens": 45,
	} {
		got, ok := attrByKey(chat.Attributes, key)
		if !ok || got.AsInt64() != want {
			t.Fatalf("%s=%d ok=%v want %d", key, got.AsInt64(), ok, want)
		}
	}
}

func TestHookChatSpanOmitsUnknownTokenUsage(t *testing.T) {
	t.Cleanup(func() { redaction.SetDisableAll(false) })
	redaction.SetDisableAll(true)
	api, exporter := newHookLLMSpanTestAPI(t)
	api.rememberHookLLMSpanPrompt(llmEventMeta{
		Source: "codex", SessionID: "sess-unknown-usage", TurnID: "turn-1",
	}, "prompt")
	api.emitHookLLMSpan(context.Background(), llmEventMeta{
		Source: "codex", SessionID: "sess-unknown-usage", TurnID: "turn-1",
	}, "response")

	chat := spanByOperation(t, exporter.GetSpans(), "chat")
	for _, key := range []string{"gen_ai.usage.input_tokens", "gen_ai.usage.output_tokens"} {
		if _, ok := attrByKey(chat.Attributes, key); ok {
			t.Fatalf("%s should be absent when the connector did not report usage", key)
		}
	}
}

func TestHookChatSpanUsesPromptTimestampForTurnLatency(t *testing.T) {
	t.Cleanup(func() { redaction.SetDisableAll(false) })
	redaction.SetDisableAll(true)
	api, exporter := newHookLLMSpanTestAPI(t)
	meta := llmEventMeta{Source: "codex", SessionID: "sess-latency", TurnID: "turn-1"}
	api.rememberHookLLMSpanPrompt(meta, "prompt")

	key := hookLLMSpanPromptKeys(meta)[0]
	api.llmPromptMu.Lock()
	snapshot := api.hookLLMSpanPrompts[key]
	snapshot.startedAt = time.Now().Add(-2 * time.Second)
	api.hookLLMSpanPrompts[key] = snapshot
	api.llmPromptMu.Unlock()

	api.emitHookLLMSpan(context.Background(), meta, "response")
	chat := spanByOperation(t, exporter.GetSpans(), "chat")
	if duration := chat.EndTime.Sub(chat.StartTime); duration < 2*time.Second {
		t.Fatalf("chat duration=%s want at least 2s from prompt to completion", duration)
	}
}

func TestClaudeCodeHookSpanUsesFallbackModelAndPersistentSinkRedaction(t *testing.T) {
	t.Cleanup(func() { redaction.SetDisableAll(false) })
	redaction.SetDisableAll(false)
	api, exporter := newHookLLMSpanTestAPI(t)

	api.emitClaudeCodeHookLLMEvent(context.Background(), claudeCodeHookRequest{
		HookEventName: "UserPromptSubmit",
		SessionID:     "sess-claude-span",
		Prompt:        "private prompt marker",
		AgentType:     "claude-code",
	}, nil, nil)
	api.emitClaudeCodeHookLLMEvent(context.Background(), claudeCodeHookRequest{
		HookEventName:        "Stop",
		SessionID:            "sess-claude-span",
		LastAssistantMessage: "private response marker",
		AgentType:            "claude-code",
	}, nil, nil)

	spans := exporter.GetSpans()
	if len(spans) != 4 {
		t.Fatalf("spans=%d want prompt anchor+terminal anchor+transition+chat", len(spans))
	}
	chat := spanByOperation(t, spans, "chat")
	completionAnchor := parentSpan(t, spans, chat)
	if chat.SpanContext.TraceID() != completionAnchor.SpanContext.TraceID() {
		t.Fatalf("chat trace=%s want completion anchor trace=%s", chat.SpanContext.TraceID(), completionAnchor.SpanContext.TraceID())
	}
	if chat.Name != "chat claudecode" {
		t.Fatalf("span name=%q want %q", chat.Name, "chat claudecode")
	}
	attrs := spanAttributeStrings(chat)
	if attrs["gen_ai.provider.name"] != "claudecode" {
		t.Fatalf("provider=%q want claudecode", attrs["gen_ai.provider.name"])
	}
	for _, key := range []string{"gen_ai.input.messages", "gen_ai.output.messages"} {
		if strings.Contains(attrs[key], "private") {
			t.Fatalf("%s leaked raw content: %q", key, attrs[key])
		}
		if attrs[key] == "" {
			t.Fatalf("%s is empty", key)
		}
	}
}

func TestClaudeCodeCompletedToolRotatesTraceAndKeepsSessionCorrelation(t *testing.T) {
	t.Cleanup(func() { redaction.SetDisableAll(false) })
	redaction.SetDisableAll(true)
	api, exporter := newHookLLMSpanTestAPI(t)

	pre := claudeCodeHookRequest{
		HookEventName: "PreToolUse", SessionID: "claude-session", TurnID: "turn-1",
		ToolName: "Bash", ToolUseID: "tool-1", ToolInput: map[string]interface{}{"command": "pwd"},
		AgentID: "claude-agent", AgentType: "claudecode",
	}
	api.emitClaudeCodeHookLLMEvent(context.Background(), pre, nil, nil)
	startSpans := exporter.GetSpans()
	if len(startSpans) != 1 {
		t.Fatalf("spans after PreToolUse=%d want start anchor", len(startSpans))
	}
	startAnchor := spanByOperation(t, startSpans, "invoke_agent")

	post := pre
	post.HookEventName = "PostToolUse"
	post.ToolResponse = map[string]interface{}{"output": "/workspace"}
	api.emitClaudeCodeHookLLMEvent(context.Background(), post, nil, nil)

	spans := exporter.GetSpans()
	if len(spans) != 3 {
		t.Fatalf("spans=%d want start anchor+completion anchor+tool", len(spans))
	}
	toolSpan := spanByOperation(t, spans, "execute_tool")
	completionAnchor := parentSpan(t, spans, toolSpan)
	if completionAnchor.SpanContext.TraceID() == startAnchor.SpanContext.TraceID() {
		t.Fatalf("Claude Code completion reused finalized start trace %s", startAnchor.SpanContext.TraceID())
	}
	if toolSpan.SpanContext.TraceID() != completionAnchor.SpanContext.TraceID() {
		t.Fatalf("tool trace=%s want completion anchor trace=%s", toolSpan.SpanContext.TraceID(), completionAnchor.SpanContext.TraceID())
	}
	for _, span := range []tracetest.SpanStub{completionAnchor, toolSpan} {
		attrs := spanAttributeStrings(span)
		if attrs["gen_ai.conversation.id"] != "claude-session" {
			t.Fatalf("%s conversation=%q want claude-session", span.Name, attrs["gen_ai.conversation.id"])
		}
		if attrs["gen_ai.agent.id"] != "claude-agent" {
			t.Fatalf("%s agent=%q want claude-agent", span.Name, attrs["gen_ai.agent.id"])
		}
	}
}

func TestGenericHookExportsAtModelCompletionWithoutStop(t *testing.T) {
	t.Cleanup(func() { redaction.SetDisableAll(false) })
	redaction.SetDisableAll(true)
	api, exporter := newHookLLMSpanTestAPI(t)

	api.emitAgentHookLLMEvent(context.Background(), agentHookRequest{
		ConnectorName: "geminicli", HookEventName: "BeforeModel", SessionID: "session-1",
		TurnID: "turn-1", Content: "real-time prompt", AgentName: "gemini",
		Payload: map[string]interface{}{"model": "gemini-2.5-pro"},
	}, nil)
	api.emitAgentHookLLMEvent(context.Background(), agentHookRequest{
		ConnectorName: "geminicli", HookEventName: "AfterModel", SessionID: "session-1",
		TurnID: "turn-1", Content: "real-time response", AgentName: "gemini",
		Payload: map[string]interface{}{"model": "gemini-2.5-pro"},
	}, nil)

	spans := exporter.GetSpans()
	if len(spans) != 3 {
		t.Fatalf("spans=%d want prompt anchor+completion anchor+chat before Stop", len(spans))
	}
	chat := spanByOperation(t, spans, "chat")
	agent := parentSpan(t, spans, chat)
	if chat.SpanContext.TraceID() != agent.SpanContext.TraceID() {
		t.Fatalf("chat trace=%s want completion anchor trace=%s", chat.SpanContext.TraceID(), agent.SpanContext.TraceID())
	}
	attrs := spanAttributeStrings(chat)
	if !strings.Contains(attrs["gen_ai.output.messages"], "real-time response") {
		t.Fatalf("output=%q", attrs["gen_ai.output.messages"])
	}
}

func TestCodexHookCompletedToolExportsBeforeSessionStop(t *testing.T) {
	t.Cleanup(func() { redaction.SetDisableAll(false) })
	redaction.SetDisableAll(true)
	api, exporter := newHookLLMSpanTestAPI(t)

	pre := codexHookRequest{
		HookEventName: "PreToolUse", SessionID: "session-tool", TurnID: "turn-1",
		ToolName: "shell", ToolUseID: "tool-1", ToolInput: map[string]interface{}{"cmd": "pwd"},
	}
	api.emitCodexHookLLMEvent(context.Background(), pre, nil, nil)
	spans := exporter.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("spans after PreToolUse=%d want immediate session root", len(spans))
	}
	root := spanByOperation(t, spans, "invoke_agent")
	post := pre
	post.HookEventName = "PostToolUse"
	post.ToolResponse = map[string]interface{}{"output": "/workspace"}
	api.emitCodexHookLLMEvent(context.Background(), post, nil, nil)

	spans = exporter.GetSpans()
	if len(spans) != 3 {
		t.Fatalf("spans=%d want start anchor + completion anchor + completed tool before Stop", len(spans))
	}
	toolSpan := spanByOperation(t, spans, "execute_tool")
	agent := parentSpan(t, spans, toolSpan)
	if agent.SpanContext.TraceID() == root.SpanContext.TraceID() {
		t.Fatalf("tool completion reused the already exported start trace %s", root.SpanContext.TraceID())
	}
	if agent.Parent.IsValid() {
		t.Fatalf("hook agent retained filtered HTTP parent %s", agent.Parent.SpanID())
	}
	if toolSpan.Parent.SpanID() != agent.SpanContext.SpanID() {
		t.Fatalf("tool parent=%s want session agent=%s", toolSpan.Parent.SpanID(), agent.SpanContext.SpanID())
	}
	if toolSpan.SpanContext.TraceID() != agent.SpanContext.TraceID() {
		t.Fatalf("tool trace=%s want session trace=%s", toolSpan.SpanContext.TraceID(), agent.SpanContext.TraceID())
	}
	attrs := spanAttributeStrings(toolSpan)
	for _, key := range []string{"gen_ai.tool.call.arguments", "gen_ai.tool.call.result"} {
		if attrs[key] == "" {
			t.Fatalf("%s is empty", key)
		}
	}

	// A later tool gets another independently indexable completion trace. The
	// stable session and agent attributes, rather than late trace appends,
	// correlate both operations.
	pre2 := pre
	pre2.ToolName = "apply_patch"
	pre2.ToolUseID = "tool-2"
	pre2.ToolInput = map[string]interface{}{"patch": "test"}
	api.emitCodexHookLLMEvent(context.Background(), pre2, nil, nil)
	post2 := pre2
	post2.HookEventName = "PostToolUse"
	post2.ToolResponse = map[string]interface{}{"output": "done"}
	api.emitCodexHookLLMEvent(context.Background(), post2, nil, nil)
	spans = exporter.GetSpans()
	if len(spans) != 6 {
		t.Fatalf("spans after second tool=%d want two start anchors + two completion anchors + two tools", len(spans))
	}
	toolCount := 0
	toolTraceIDs := map[trace.TraceID]struct{}{}
	for _, candidate := range spans {
		if spanAttributeStrings(candidate)["gen_ai.operation.name"] != "execute_tool" {
			continue
		}
		toolCount++
		completionAnchor := parentSpan(t, spans, candidate)
		if candidate.SpanContext.TraceID() != completionAnchor.SpanContext.TraceID() {
			t.Fatalf("tool %q is not attached to its completion anchor", candidate.Name)
		}
		toolTraceIDs[candidate.SpanContext.TraceID()] = struct{}{}
	}
	if toolCount != 2 {
		t.Fatalf("tool spans=%d want 2", toolCount)
	}
	if len(toolTraceIDs) != 2 {
		t.Fatalf("tool completion traces=%d want 2 independently indexable traces", len(toolTraceIDs))
	}
}

func TestHookLLMSpanPromptCacheIsBoundedAndCorrelatesOverlappingTurns(t *testing.T) {
	api := &APIServer{}
	for i := 0; i < hookPromptCacheMaxEntries+10; i++ {
		api.rememberHookLLMSpanPrompt(llmEventMeta{
			Source: "codex", SessionID: "session-" + strconv.Itoa(i), TurnID: "turn",
			PromptID: "prompt-" + strconv.Itoa(i),
		}, "prompt")
	}
	if got := len(api.hookLLMSpanPrompts); got > hookPromptCacheMaxEntries {
		t.Fatalf("prompt cache size=%d exceeds %d", got, hookPromptCacheMaxEntries)
	}
	if got := len(api.hookLLMSpanPromptOrder); got > hookPromptCacheMaxEntries {
		t.Fatalf("prompt cache order size=%d exceeds %d", got, hookPromptCacheMaxEntries)
	}

	overlap := &APIServer{}
	turn1 := llmEventMeta{Source: "codex", SessionID: "shared", TurnID: "1", PromptID: "p1"}
	turn2 := llmEventMeta{Source: "codex", SessionID: "shared", TurnID: "2", PromptID: "p2"}
	overlap.rememberHookLLMSpanPrompt(turn1, "first")
	overlap.rememberHookLLMSpanPrompt(turn2, "second")
	first, ok := overlap.takeHookLLMSpanPrompt(turn1, "response one")
	if !ok || first.content != "first" {
		t.Fatalf("first turn snapshot=%+v emit=%v", first, ok)
	}
	second, ok := overlap.takeHookLLMSpanPrompt(turn2, "response two")
	if !ok || second.content != "second" {
		t.Fatalf("second turn snapshot=%+v emit=%v", second, ok)
	}
}

func TestBoundedHookLLMSpanContent(t *testing.T) {
	content := strings.Repeat("x", hookLLMSpanMaxContentBytes+100)
	if got := len(boundedHookLLMSpanContent(content)); got != hookLLMSpanMaxContentBytes {
		t.Fatalf("bounded content length=%d want %d", got, hookLLMSpanMaxContentBytes)
	}
}

func TestHookToolInvocationQueuePreservesRepeatedSameToolCalls(t *testing.T) {
	api := &APIServer{}
	meta := llmEventMeta{
		Source: "geminicli", SessionID: "session", AgentID: "agent", TurnID: "turn",
	}
	api.rememberHookToolInvocation(meta, "Bash", `{"command":"first"}`)
	api.rememberHookToolInvocation(meta, "Bash", `{"command":"second"}`)

	first, ok := api.takeHookToolInvocation(meta, "Bash", "first-result")
	if !ok || first.arguments != `{"command":"first"}` {
		t.Fatalf("first queued invocation=%+v ok=%v", first, ok)
	}
	second, ok := api.takeHookToolInvocation(meta, "Bash", "second-result")
	if !ok || second.arguments != `{"command":"second"}` {
		t.Fatalf("second queued invocation=%+v ok=%v", second, ok)
	}
	if len(api.hookToolInvocations) != 0 || len(api.hookToolInvocationOrder) != 0 {
		t.Fatalf("tool queue not drained: %#v %#v", api.hookToolInvocations, api.hookToolInvocationOrder)
	}
}

func TestBeforeToolSelectionHasBoundedToolLifecycle(t *testing.T) {
	if got := canonicalHookLifecycleEvent("BeforeToolSelection"); got != "tool_start" {
		t.Fatalf("lifecycle=%q want tool_start", got)
	}
	if got := hookLifecyclePhase("BeforeToolSelection", "tool_start", "active"); got != "tool" {
		t.Fatalf("phase=%q want tool", got)
	}
}
