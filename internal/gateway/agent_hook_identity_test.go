// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

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
