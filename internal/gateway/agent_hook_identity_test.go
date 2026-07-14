// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

func TestNormalizeAgentHookRequest_DoesNotGuessTurnFromOtherIDKinds(t *testing.T) {
	for name, payload := range map[string]map[string]interface{}{
		"execution":  {"execution_id": "exec-1"},
		"generation": {"generation_id": "gen-1"},
		"tool call":  {"tool_call_id": "call-1"},
		"message":    {"message_id": "message-1"},
		"step":       {"step_id": "step-1"},
	} {
		t.Run(name, func(t *testing.T) {
			payload["hook_event_name"] = "PreToolUse"
			if got := normalizeAgentHookRequest("unknown", payload).TurnID; got != "" {
				t.Fatalf("TurnID=%q want empty", got)
			}
		})
	}
}

func TestNormalizeAgentHookRequest_PreservesExplicitTurnID(t *testing.T) {
	req := normalizeAgentHookRequest("unknown", map[string]interface{}{
		"hook_event_name": "UserPromptSubmit",
		"turn_id":         "turn-7",
	})
	if req.TurnID != "turn-7" {
		t.Fatalf("TurnID=%q want turn-7", req.TurnID)
	}
}

func TestNormalizeAgentHookRequest_UnknownDoesNotGuessSessionOrAgent(t *testing.T) {
	req := normalizeAgentHookRequestWithProfile("plugin-example", map[string]interface{}{
		"hook_event_name": "PreToolUse",
		"conversation_id": "conversation-1",
		"task_id":         "task-1",
		"assistant_id":    "assistant-1",
		"tool_use_id":     "tool-1",
	}, connector.HookProfile{Name: "plugin-example"})
	if req.SessionID != "" || req.AgentID != "" || req.ToolInvocationID != "" {
		t.Fatalf("unknown profile guessed identities: %+v", req)
	}
	if req.CorrelationProfileVersion != connector.CorrelationProfileExplicitV1 {
		t.Fatalf("profile=%q", req.CorrelationProfileVersion)
	}
}

func TestNormalizeAgentHookRequest_ProfileDecodeCannotOverrideIdentity(t *testing.T) {
	profile := connector.HookProfile{
		Name:        "plugin-example",
		Correlation: connector.ExplicitCanonicalCorrelationSpec("plugin-example"),
		Decode: func(payload map[string]interface{}) connector.HookProfileRequest {
			return connector.HookProfileRequest{
				ConnectorName:    "spoofed-connector",
				HookEventName:    "PreToolUse",
				SessionID:        "spoofed-session",
				TurnID:           "execution-as-turn",
				MessageID:        "message-as-turn",
				AgentID:          "spoofed-agent",
				ToolInvocationID: "spoofed-tool",
				SemanticEventID:  "spoofed-semantic",
				Content:          "decoded content remains allowed",
				Payload:          payload,
			}
		},
	}
	req := normalizeAgentHookRequestWithProfile("plugin-example", map[string]interface{}{
		"hook_event_name": "PreToolUse",
		"execution_id":    "execution-1",
		"step_id":         "step-1",
		"message_id":      "message-1",
	}, profile)
	if req.ConnectorName != "plugin-example" || req.SessionID != "" || req.TurnID != "" || req.AgentID != "" || req.ToolInvocationID != "" || req.SemanticEventID != "" {
		t.Fatalf("Decode overrode identity: %+v", req)
	}
	if req.MessageID != "message-1" {
		t.Fatalf("exact canonical message binding lost: %q", req.MessageID)
	}
	if req.Content != "decoded content remains allowed" {
		t.Fatalf("content decoder did not run: %q", req.Content)
	}
}

func TestNormalizeAgentHookRequest_AntigravityStepIsEvidenceNotTurn(t *testing.T) {
	profile := connector.NewAntigravityConnector().HookProfile(connector.SetupOpts{})
	req := normalizeAgentHookRequestWithProfile("antigravity", map[string]interface{}{
		"hookEventName":  "PreInvocation",
		"conversationId": "conversation-1",
		"stepIdx":        42,
		"invocationNum":  3,
	}, profile)
	if req.SessionID != "conversation-1" || req.StepID != "42" || req.ExecutionID != "3" {
		t.Fatalf("antigravity mapping=%+v", req)
	}
	if req.TurnID != "" {
		t.Fatalf("stepIdx became TurnID=%q", req.TurnID)
	}
}

func TestNormalizeAgentHookRequest_HermesNestedIdentityUsesProfile(t *testing.T) {
	profile := connector.NewHermesConnector().HookProfile(connector.SetupOpts{})
	req := normalizeAgentHookRequestWithProfile("hermes", map[string]interface{}{
		"hook_event_name": "subagent_start",
		"session_id":      "parent-1",
		"extra": map[string]interface{}{
			"parent_session_id": "parent-1",
			"child_session_id":  "child-1",
			"child_subagent_id": "agent-child",
			"child_role":        "researcher",
			"tool_call_id":      "tool-1",
		},
	}, profile)
	if req.SessionID != "child-1" || req.ParentSessionID != "parent-1" || req.ChildSessionID != "child-1" || req.AgentID != "agent-child" || req.ToolInvocationID != "tool-1" {
		t.Fatalf("nested Hermes mapping=%+v", req)
	}
	if req.CorrelationOrigins[connector.CorrelationTargetAgent] != connector.CorrelationOriginReported {
		t.Fatalf("agent origin=%q", req.CorrelationOrigins[connector.CorrelationTargetAgent])
	}
}
