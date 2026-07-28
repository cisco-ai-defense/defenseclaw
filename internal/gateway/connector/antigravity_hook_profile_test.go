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

package connector

import (
	"encoding/json"
	"testing"
)

// TestAntigravityProfileDecode_RealAgyPayload pins the decoder
// against an exact payload captured from agy v1.0.1 during the
// end-to-end smoke test in
// docs/connectors/antigravity.mdx. Regressions here mean the
// gateway will start returning HTTP 400 ("hook event name is
// required") for every PreToolUse — the silent failure mode that
// motivated this decoder in the first place.
//
// PreToolUse is the only event empirically captured against agy
// v1.0.1; coverage for the other four Antigravity 2.0 lifecycle
// events (PreInvocation, PostToolUse, PostInvocation, Stop) lives
// in TestAntigravityProfileDecode_LifecycleEvents below using
// payload shapes derived from agy's Claude-Code lineage.
func TestAntigravityProfileDecode_RealAgyPayload(t *testing.T) {
	const raw = `{
  "artifactDirectoryPath": "/Users/kevinob/.gemini/antigravity-cli/brain/f74b1ea2-4369-45c5-9716-8f6b57b3e999",
  "conversationId": "f74b1ea2-4369-45c5-9716-8f6b57b3e999",
  "stepIdx": 21,
  "toolCall": {
    "args": {
      "CommandLine": "echo phaseE-claude-shape",
      "Cwd": "/tmp/agy-smoketest",
      "WaitMsBeforeAsync": 1000
    },
    "name": "run_command"
  },
  "transcriptPath": "/Users/kevinob/.gemini/antigravity-cli/brain/f74b1ea2-4369-45c5-9716-8f6b57b3e999/.system_generated/logs/transcript.jsonl",
  "workspacePaths": ["/tmp/agy-smoketest"]
}`

	var payload map[string]interface{}
	if err := json.Unmarshal([]byte(raw), &payload); err != nil {
		t.Fatalf("unmarshal captured agy payload: %v", err)
	}

	req := antigravityProfileDecode(payload)

	if req.ConnectorName != "antigravity" {
		t.Errorf("ConnectorName=%q want antigravity", req.ConnectorName)
	}
	if req.HookEventName != "PreToolUse" {
		t.Errorf("HookEventName=%q want PreToolUse — agy v1 only fires PreToolUse", req.HookEventName)
	}
	if req.SessionID != "f74b1ea2-4369-45c5-9716-8f6b57b3e999" {
		t.Errorf("SessionID=%q want f74b1ea2-4369-45c5-9716-8f6b57b3e999", req.SessionID)
	}
	if req.TurnID != "" {
		t.Errorf("TurnID=%q want empty; stepIdx is a trajectory step, not a turn", req.TurnID)
	}
	if req.ToolName != "run_command" {
		t.Errorf("ToolName=%q want run_command — must come from toolCall.name not top-level", req.ToolName)
	}
	if req.CWD != "/tmp/agy-smoketest" {
		t.Errorf("CWD=%q want /tmp/agy-smoketest", req.CWD)
	}
	if req.Content != "echo phaseE-claude-shape" {
		t.Errorf("Content=%q want \"echo phaseE-claude-shape\" — must be lifted from toolCall.args.CommandLine", req.Content)
	}
	if req.Direction != "tool_call" {
		t.Errorf("Direction=%q want tool_call", req.Direction)
	}
	if req.AgentName != "antigravity" {
		t.Errorf("AgentName=%q want antigravity", req.AgentName)
	}
	if req.Payload == nil {
		t.Errorf("Payload nil — must round-trip the original payload for downstream evaluators")
	}
}

func TestAntigravityProfileDecode_DoesNotConflateOperationIDsWithTurns(t *testing.T) {
	for name, payload := range map[string]map[string]interface{}{
		"step index":   {"stepIdx": float64(21), "toolCall": map[string]interface{}{"name": "run_command"}},
		"tool call id": {"toolCallId": "call-21", "toolCall": map[string]interface{}{"name": "run_command"}},
	} {
		t.Run(name, func(t *testing.T) {
			if got := antigravityProfileDecode(payload).TurnID; got != "" {
				t.Fatalf("TurnID=%q want empty", got)
			}
		})
	}
}

func TestAntigravityProfileDecode_PreservesExplicitTurnID(t *testing.T) {
	if got := antigravityProfileDecode(map[string]interface{}{
		"turn_id":  "turn-21",
		"stepIdx":  float64(21),
		"toolCall": map[string]interface{}{"name": "run_command"},
	}).TurnID; got != "turn-21" {
		t.Fatalf("TurnID=%q want turn-21", got)
	}
}

// TestAntigravityProfileDecode_ExplicitEventOverride covers the
// forward-compat branch where a future agy version supplies an
// explicit `hookEventName` field. We must respect it over the
// hardcoded PreToolUse default so the connector survives an upstream
// contract widening (PostToolUse, UserPromptSubmit) without a
// re-deploy of the gateway.
func TestAntigravityProfileDecode_ExplicitEventOverride(t *testing.T) {
	cases := []struct {
		name    string
		payload map[string]interface{}
		want    string
	}{
		{
			name: "camelCase hookEventName wins over default",
			payload: map[string]interface{}{
				"hookEventName": "PostToolUse",
				"toolCall":      map[string]interface{}{"name": "run_command"},
			},
			want: "PostToolUse",
		},
		{
			name: "snake_case hook_event_name also honored",
			payload: map[string]interface{}{
				"hook_event_name": "UserPromptSubmit",
			},
			want: "UserPromptSubmit",
		},
		{
			name: "no override falls back to PreToolUse",
			payload: map[string]interface{}{
				"toolCall": map[string]interface{}{"name": "run_command"},
			},
			want: "PreToolUse",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := antigravityProfileDecode(tc.payload)
			if req.HookEventName != tc.want {
				t.Errorf("HookEventName=%q want %q", req.HookEventName, tc.want)
			}
		})
	}
}

// TestAntigravityProfileDecode_WorkspacePathFallback exercises the
// CWD fallback for tools that don't ship args.Cwd (e.g. hypothetical
// future agy tools that operate over workspace-relative paths).
func TestAntigravityProfileDecode_WorkspacePathFallback(t *testing.T) {
	payload := map[string]interface{}{
		"workspacePaths": []interface{}{"/tmp/proj-a", "/tmp/proj-b"},
		"toolCall": map[string]interface{}{
			"name": "read_file",
			"args": map[string]interface{}{"path": "src/main.go"},
		},
	}
	req := antigravityProfileDecode(payload)
	if req.CWD != "/tmp/proj-a" {
		t.Errorf("CWD=%q want /tmp/proj-a — should fall back to workspacePaths[0] when toolCall.args.Cwd is absent", req.CWD)
	}
	if req.ToolName != "read_file" {
		t.Errorf("ToolName=%q want read_file", req.ToolName)
	}
}

// TestAntigravityProfileDecode_EmptyPayload ensures the decoder
// degrades gracefully for malformed/empty payloads instead of
// panicking. The unified handler still rejects an empty
// HookEventName with HTTP 400, but that's a far better failure mode
// than a goroutine crash.
func TestAntigravityProfileDecode_EmptyPayload(t *testing.T) {
	req := antigravityProfileDecode(map[string]interface{}{})
	if req.ConnectorName != "antigravity" {
		t.Errorf("ConnectorName=%q want antigravity", req.ConnectorName)
	}
	if req.HookEventName != "PreToolUse" {
		t.Errorf("HookEventName=%q want PreToolUse default", req.HookEventName)
	}
	if req.ToolName != "tool" {
		t.Errorf("ToolName=%q want tool sentinel", req.ToolName)
	}
	if req.CWD != "" {
		t.Errorf("CWD=%q want empty for minimal payload", req.CWD)
	}
}

// TestAntigravityProfileDecode_LifecycleEvents pins the decoder
// against each of the five Antigravity 2.0 lifecycle events. Each
// case ships a representative payload shape derived from the
// published spec + agy's Claude-Code lineage, and asserts the
// decoder routes the event onto the canonical HookProfileRequest
// fields the unified evaluator expects (Direction is the critical
// field — it determines which classifier branch in
// evaluateAgentHook the event hits).
//
// Empirical confidence:
//   - PreToolUse: verified against real agy v1.0.1 payloads
//     (TestAntigravityProfileDecode_RealAgyPayload above).
//   - The other four: payload shapes here are spec-conformant
//     guesses; if empirical agy testing reveals different field
//     names, this is the central edit point. The decoder uses
//     defensive keypath fallbacks so multiple shape variants
//     decode correctly.
func TestAntigravityProfileDecode_LifecycleEvents(t *testing.T) {
	cases := []struct {
		name          string
		payload       map[string]interface{}
		wantEvent     string
		wantDirection string
		wantToolName  string
		wantContent   string
	}{
		{
			name: "PreInvocation lifts user prompt onto Content",
			payload: map[string]interface{}{
				"hookEventName":  "PreInvocation",
				"conversationId": "conv-pre-inv",
				"stepIdx":        float64(3),
				"prompt":         "Please refactor the authentication module.",
				"workspacePaths": []interface{}{"/tmp/proj"},
			},
			wantEvent:     "PreInvocation",
			wantDirection: "prompt",
			wantToolName:  "message",
			wantContent:   "Please refactor the authentication module.",
		},
		{
			name: "PostToolUse extracts toolResponse output over toolCall command",
			payload: map[string]interface{}{
				"hookEventName":  "PostToolUse",
				"conversationId": "conv-post-tool",
				"stepIdx":        float64(7),
				"toolCall": map[string]interface{}{
					"name": "run_command",
					"args": map[string]interface{}{"CommandLine": "cat secrets.txt", "Cwd": "/tmp/proj"},
				},
				"toolResponse": map[string]interface{}{
					"output": "API_KEY=sk-test-...",
				},
			},
			wantEvent:     "PostToolUse",
			wantDirection: "tool_result",
			wantToolName:  "run_command",
			// Content is the RESPONSE, not the call — confirms the
			// PostToolUse branch overrides Content set by the shared
			// toolCall extractor.
			wantContent: "API_KEY=sk-test-...",
		},
		{
			name: "PostInvocation lifts model response onto Content",
			payload: map[string]interface{}{
				"hookEventName":  "PostInvocation",
				"conversationId": "conv-post-inv",
				"stepIdx":        float64(11),
				"modelResponse":  "Refactor complete. 4 files modified.",
			},
			wantEvent:     "PostInvocation",
			wantDirection: "tool_result",
			wantToolName:  "message",
			wantContent:   "Refactor complete. 4 files modified.",
		},
		{
			name: "Stop captures session metadata + reason without inspection direction",
			payload: map[string]interface{}{
				"hookEventName":  "Stop",
				"conversationId": "conv-stop",
				"stepIdx":        float64(20),
				"stopReason":     "user_quit",
			},
			wantEvent: "Stop",
			// Stop intentionally has no Direction so the evaluator's
			// classifier dispatch falls to the default audit-only
			// branch — Stop has no inspection target.
			wantDirection: "",
			wantToolName:  "session",
			wantContent:   "user_quit",
		},
		{
			name: "PreToolUse continues to round-trip via the lifecycle table",
			payload: map[string]interface{}{
				"hookEventName":  "PreToolUse",
				"conversationId": "conv-pre-tool",
				"stepIdx":        float64(1),
				"toolCall": map[string]interface{}{
					"name": "run_command",
					"args": map[string]interface{}{"CommandLine": "ls", "Cwd": "/tmp/proj"},
				},
			},
			wantEvent:     "PreToolUse",
			wantDirection: "tool_call",
			wantToolName:  "run_command",
			wantContent:   "ls",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := antigravityProfileDecode(tc.payload)
			if req.HookEventName != tc.wantEvent {
				t.Errorf("HookEventName=%q want %q", req.HookEventName, tc.wantEvent)
			}
			if req.Direction != tc.wantDirection {
				t.Errorf("Direction=%q want %q", req.Direction, tc.wantDirection)
			}
			if req.ToolName != tc.wantToolName {
				t.Errorf("ToolName=%q want %q", req.ToolName, tc.wantToolName)
			}
			if req.Content != tc.wantContent {
				t.Errorf("Content=%q want %q", req.Content, tc.wantContent)
			}
		})
	}
}

// TestAntigravityProfileDecode_StructuralInferenceFallback pins the
// antigravityInferEvent fallback for legacy agy payloads that omit
// the explicit hookEventName field. Critical for backward-compat:
// agy v1.0.0 / v1.0.1 PreToolUse payloads predate the spec'd
// hookEventName field, and this fallback is what keeps the
// existing PreToolUse integration working alongside the new
// per-event branches.
func TestAntigravityProfileDecode_StructuralInferenceFallback(t *testing.T) {
	cases := []struct {
		name      string
		payload   map[string]interface{}
		wantEvent string
	}{
		{
			name: "toolCall + toolResponse infers PostToolUse",
			payload: map[string]interface{}{
				"toolCall":     map[string]interface{}{"name": "run_command"},
				"toolResponse": map[string]interface{}{"output": "ok"},
			},
			wantEvent: "PostToolUse",
		},
		{
			name: "modelResponse infers PostInvocation",
			payload: map[string]interface{}{
				"modelResponse": "the answer is 42",
			},
			wantEvent: "PostInvocation",
		},
		{
			name: "prompt without toolCall infers PreInvocation",
			payload: map[string]interface{}{
				"prompt": "what is 2+2?",
			},
			wantEvent: "PreInvocation",
		},
		{
			name:      "empty payload conservatively defaults to PreToolUse",
			payload:   map[string]interface{}{},
			wantEvent: "PreToolUse",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := antigravityProfileDecode(tc.payload)
			if req.HookEventName != tc.wantEvent {
				t.Errorf("HookEventName=%q want %q (structural inference fallback)", req.HookEventName, tc.wantEvent)
			}
		})
	}
}
