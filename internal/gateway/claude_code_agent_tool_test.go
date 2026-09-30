// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"testing"
)

// The measured session's hooks through the Claude Code emitter: every
// subagent, the two parallel ones included, has the main agent as its
// parent at depth 1, and no spawn intent is left once each subagent
// started. Parallel Agent calls used to tie, leaving the second subagent
// without a parent, and each Agent result left a completed intent behind
// that later subagents tied on.
func TestClaudeCodeMeasuredSubagentsHaveTheMainAgentAsParent(t *testing.T) {
	api := &APIServer{}
	events := readClaudeCodeAgentToolFixture(t)
	sessionID := fmt.Sprint(events[0]["session_id"])
	mainAgent := stableLLMEventID("agent", "claudecode", sessionID, "root")
	subagents := 0
	for i, payload := range events {
		raw, err := json.Marshal(payload)
		if err != nil {
			t.Fatal(err)
		}
		api.emitClaudeCodeHookLLMEvent(t.Context(), decodeClaudeCodeRequestFromBytes(raw, payload), nil, raw)
		id, ok := payload["agent_id"].(string)
		if !ok {
			continue
		}
		// The lineage each of the subagent's hooks is recorded with, not
		// one a later SubagentStop repairs.
		snapshot, ok := api.hookLifecycleSnapshot("claudecode", sessionID, id)
		if !ok || snapshot.ParentAgentID != mainAgent || snapshot.RootAgentID != mainAgent || snapshot.AgentDepth != 1 {
			t.Errorf("fixture line %d (%v): subagent %s lineage=%+v retained=%v", i+1, payload["hook_event_name"], id, snapshot, ok)
		}
		if payload["hook_event_name"] == "SubagentStart" {
			subagents++
		}
	}
	if subagents != 7 {
		t.Fatalf("subagents = %d, want 7 (fixture changed?)", subagents)
	}
	if got := hookSpawnIntentCount(api); got != 0 {
		t.Fatalf("spawn intents left after every subagent started = %d", got)
	}
}

// Only Claude Code's own Agent tool names the subagent it ran; another
// tool's response is that tool's output.
func TestClaudeCodeSpawnedAgentID(t *testing.T) {
	response := map[string]interface{}{"agentId": "a68b3f56907fa1ebc", "status": "completed"}
	for _, tc := range []struct {
		name string
		req  claudeCodeHookRequest
		want string
	}{
		{"agent result", claudeCodeHookRequest{HookEventName: "PostToolUse", ToolName: "Agent", ToolResponse: response}, "a68b3f56907fa1ebc"},
		{"failure", claudeCodeHookRequest{HookEventName: "PostToolUseFailure", ToolName: "Agent", ToolResponse: response}, ""},
		{"other tool", claudeCodeHookRequest{HookEventName: "PostToolUse", ToolName: "Bash", ToolResponse: response}, ""},
		{"mcp tool", claudeCodeHookRequest{HookEventName: "PostToolUse", ToolName: "Agent", MCPServerName: "evil", ToolResponse: response}, ""},
		{"string response", claudeCodeHookRequest{HookEventName: "PostToolUse", ToolName: "Agent", ToolResponse: "agentId: x"}, ""},
	} {
		if got := claudeCodeSpawnedAgentID(tc.req); got != tc.want {
			t.Errorf("%s: %q, want %q", tc.name, got, tc.want)
		}
	}
	if !isAgentSpawnerTool(claudeCodeAgentTool) {
		t.Fatal("isAgentSpawnerTool does not know Claude Code's Agent tool")
	}
}
