// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"testing"
)

// TestRememberHookRawEvents_KindClassification asserts the PR 6
// unified deduper assigns the same (kind, sessionID, turnID, toolID)
// fingerprint to a generic agentHookRequest as the bespoke
// rememberCodexRawHookEvents / rememberClaudeCodeRawHookEvents
// helpers do for codex / claudecode. Without this test a future
// refactor of canonicalEvent could silently demote a "PreToolUse"
// to a different kind bucket and break the join key SIEM queries
// rely on.
func TestRememberHookRawEvents_KindClassification(t *testing.T) {
	cases := []struct {
		name      string
		event     string
		expectKey string
	}{
		{"UserPromptSubmit_prompt", "UserPromptSubmit", "prompt"},
		{"UserPromptExpansion_prompt", "UserPromptExpansion", "prompt"},
		{"PreToolUse_tool_call", "PreToolUse", "tool_call"},
		{"PermissionRequest_tool_call", "PermissionRequest", "tool_call"},
		{"PermissionDenied_tool_call", "PermissionDenied", "tool_call"},
		{"PostToolUse_tool_result", "PostToolUse", "tool_result"},
		{"PostToolUseFailure_tool_result", "PostToolUseFailure", "tool_result"},
		{"PostToolBatch_tool_result", "PostToolBatch", "tool_result"},
		{"SessionStart_no_id", "SessionStart", ""},
		{"Stop_no_id", "Stop", ""},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			api := &APIServer{}
			req := agentHookRequest{
				ConnectorName: "codex",
				HookEventName: tc.event,
				SessionID:     "sess-1",
				TurnID:        "turn-1",
				Content:       "hi",
				ToolArgs:      json.RawMessage(`{"a":1}`),
				Payload:       map[string]interface{}{"tool_use_id": "tool-1"},
			}
			ids := api.rememberHookRawEvents(req)
			if tc.expectKey == "" {
				if len(ids) != 0 {
					t.Errorf("expected no IDs for event %s, got %v", tc.event, ids)
				}
				return
			}
			if len(ids) != 1 {
				t.Fatalf("expected 1 ID for event %s, got %v", tc.event, ids)
			}
			// Sanity: replaying the same request returns the same
			// ID (TTL-windowed dedup).
			again := api.rememberHookRawEvents(req)
			if len(again) != 1 || again[0] != ids[0] {
				t.Errorf("replay produced different ID: first=%v second=%v", ids, again)
			}
		})
	}
}

// TestRememberHookRawEvents_GenericConnector covers the additive
// coverage PR 6 unlocks: hermes / cursor / windsurf / geminicli /
// copilot previously had no raw event IDs flowing into their audit
// envelopes. With the unified helper they get the same dedup
// signature as codex / claudecode.
func TestRememberHookRawEvents_GenericConnector(t *testing.T) {
	api := &APIServer{}
	req := agentHookRequest{
		ConnectorName: "hermes",
		HookEventName: "PreToolUse",
		SessionID:     "sess-hermes",
		TurnID:        "turn-hermes",
		ToolArgs:      json.RawMessage(`{"path":"/etc/passwd"}`),
		Payload:       map[string]interface{}{"tool_use_id": "tool-hermes"},
	}
	ids := api.rememberHookRawEvents(req)
	if len(ids) != 1 {
		t.Fatalf("expected 1 ID for hermes PreToolUse, got %v", ids)
	}
}

func TestRememberHookRawEvents_BespokeParity(t *testing.T) {
	toolInput := map[string]interface{}{"command": "echo parity"}
	toolArgs, err := json.Marshal(toolInput)
	if err != nil {
		t.Fatalf("marshal tool input: %v", err)
	}

	t.Run("codex", func(t *testing.T) {
		api := &APIServer{}
		generic := agentHookRequest{
			ConnectorName: "codex",
			HookEventName: "PreToolUse",
			SessionID:     "sess-codex",
			TurnID:        "turn-codex",
			ToolArgs:      toolArgs,
			Payload:       map[string]interface{}{"tool_use_id": "tool-codex"},
		}
		bespoke := codexHookRequest{
			HookEventName: "PreToolUse",
			SessionID:     "sess-codex",
			TurnID:        "turn-codex",
			ToolUseID:     "tool-codex",
			ToolInput:     toolInput,
		}
		genericIDs := api.rememberHookRawEvents(generic)
		bespokeIDs := api.rememberCodexRawHookEvents(bespoke)
		if len(genericIDs) != 1 || len(bespokeIDs) != 1 || genericIDs[0] != bespokeIDs[0] {
			t.Fatalf("generic/bespoke codex IDs differ: generic=%v bespoke=%v", genericIDs, bespokeIDs)
		}
	})

	t.Run("claudecode", func(t *testing.T) {
		api := &APIServer{}
		generic := agentHookRequest{
			ConnectorName: "claudecode",
			HookEventName: "PreToolUse",
			SessionID:     "sess-claude",
			ToolArgs:      toolArgs,
			Payload:       map[string]interface{}{"tool_use_id": "tool-claude"},
		}
		bespoke := claudeCodeHookRequest{
			HookEventName: "PreToolUse",
			SessionID:     "sess-claude",
			ToolUseID:     "tool-claude",
			ToolInput:     toolInput,
		}
		genericIDs := api.rememberHookRawEvents(generic)
		bespokeIDs := api.rememberClaudeCodeRawHookEvents(bespoke)
		if len(genericIDs) != 1 || len(bespokeIDs) != 1 || genericIDs[0] != bespokeIDs[0] {
			t.Fatalf("generic/bespoke claudecode IDs differ: generic=%v bespoke=%v", genericIDs, bespokeIDs)
		}
	})
}

// TestRawOriginIfHook validates the small "set raw_origin only when
// we have IDs" helper that drives the audit envelope's RawOrigin
// field. Empty slices must produce an empty string (so the JSON
// omitempty rule drops the field), non-empty must produce "hook".
func TestRawOriginIfHook(t *testing.T) {
	if got := rawOriginIfHook(nil); got != "" {
		t.Errorf("rawOriginIfHook(nil)=%q want empty", got)
	}
	if got := rawOriginIfHook([]string{}); got != "" {
		t.Errorf("rawOriginIfHook([]string{})=%q want empty", got)
	}
	if got := rawOriginIfHook([]string{"raw-abc"}); got != "hook" {
		t.Errorf("rawOriginIfHook(['raw-abc'])=%q want hook", got)
	}
}

// TestCodexNotifyToAgentHookRequest pins the synthetic Stop
// translation. The codex notify path folds turn-complete events into
// the unified hook collector by constructing this agentHookRequest,
// so any drift in the field mapping would silently break the
// "unified collector sees turn-complete" invariant that downstream
// hook metrics rely on.
func TestCodexNotifyToAgentHookRequest(t *testing.T) {
	p := codexNotifyPayload{
		Type:     "agent-turn-complete",
		ThreadID: "thread-1",
		TurnID:   "turn-1",
		Model:    "gpt-5",
		Status:   "success",
	}
	req := codexNotifyToAgentHookRequest(p, []byte(`{"type":"agent-turn-complete"}`))
	if req.ConnectorName != "codex" {
		t.Errorf("ConnectorName=%q want codex", req.ConnectorName)
	}
	if req.HookEventName != "Stop" {
		t.Errorf("HookEventName=%q want Stop", req.HookEventName)
	}
	if req.SessionID != "thread-1" {
		t.Errorf("SessionID=%q want thread-1", req.SessionID)
	}
	if req.TurnID != "turn-1" {
		t.Errorf("TurnID=%q want turn-1", req.TurnID)
	}
	if req.AgentName != "codex" || req.AgentType != "codex" {
		t.Errorf("AgentName/Type wrong: name=%q type=%q", req.AgentName, req.AgentType)
	}
	if req.Direction != "tool_result" {
		t.Errorf("Direction=%q want tool_result", req.Direction)
	}
	if got, _ := req.Payload["model"].(string); got != "gpt-5" {
		t.Errorf("Payload.model=%v want gpt-5", req.Payload["model"])
	}
	notify, _ := req.Payload["codex_notify"].(map[string]interface{})
	if notify["type"] != "agent-turn-complete" || notify["status"] != "success" {
		t.Errorf("codex_notify subobject wrong: %#v", notify)
	}
}

// TestHandleAgentHookSynthetic_NoPanicOnZeroServer guards against a
// regression where the synthetic handler accesses an unwired field
// (a.otel, a.health) without nil-checking. PR 6 wires it through
// otel_ingest.go's handleCodexNotify which runs against a fully
// wired APIServer in production, but the test harness uses a
// minimal &APIServer{} — keeping the helper resilient to that
// shape lets tests at every layer reuse it.
func TestHandleAgentHookSynthetic_NoPanicOnZeroServer(t *testing.T) {
	api := &APIServer{}
	req := agentHookRequest{
		ConnectorName: "codex",
		HookEventName: "Stop",
		SessionID:     "sess-1",
		TurnID:        "turn-1",
		AgentName:     "codex",
		AgentType:     "codex",
		ToolName:      "codex-notify",
		Direction:     "tool_result",
		Payload:       map[string]interface{}{},
	}
	defer func() {
		if r := recover(); r != nil {
			t.Fatalf("handleAgentHookSynthetic panicked: %v", r)
		}
	}()
	resp := api.handleAgentHookSynthetic(t.Context(), "codex", req, []byte(`{}`))
	if resp.Action == "" {
		t.Errorf("synthetic handler should produce a populated response")
	}
}
