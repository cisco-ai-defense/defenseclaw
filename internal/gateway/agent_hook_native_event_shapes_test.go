// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Native event shapes the malformed-event check refused with HTTP 400 on
// rc.6 (rel-1-0-4 GAP-0924, 0925, 0931, 0944, 0945). Each body has the
// fields and types the agent itself sends: Claude Code 2.1.286 FileChanged
// (its bundled hook input builder), the DefenseClaw OpenCode plugin's
// lifecycle payload (defenseclawLifecyclePayload), and Hermes shell-hook
// stdin for non-tool events (agent/shell_hooks.py _payload_fields).
var nativeHookEventShapes = []struct {
	name, connector, event, body string
}{
	{"claude code FileChanged", "claudecode", "FileChanged",
		`{"session_id":"0b7e5a52-3c1e-4c39-9d43-0d2a1f5c9e11","transcript_path":"/home/u/.claude/projects/-home-u-proj/0b7e5a52-3c1e-4c39-9d43-0d2a1f5c9e11.jsonl","cwd":"/home/u/proj","hook_event_name":"FileChanged","file_path":"/home/u/proj/README.md","event":"change"}`},
	{"opencode lifecycle", "opencode", "session.idle",
		`{"hook_event_name":"session.idle","event_type":"session.idle","source_event_id":"evt_01","session_id":"ses_01","parent_session_id":"","agent_id":"","agent_name":"build","status":"","cwd":"/sandbox/proj","load_heartbeat":true,"event":{"sessionID":"ses_01"}}`},
	{"opencode session error", "opencode", "session.error",
		`{"hook_event_name":"session.error","event_type":"session.error","source_event_id":"evt_02","session_id":"ses_01","parent_session_id":"","agent_id":"","agent_name":"","status":"error","cwd":"/sandbox/proj","load_heartbeat":true,"event":{"sessionID":"ses_01","error":{"name":"ProviderAuthError","data":{"message":"x"}}}}`},
	{"hermes session start", "hermes", "on_session_start",
		`{"hook_event_name":"on_session_start","tool_name":null,"tool_input":null,"session_id":"20261023_165609_ab12cd","cwd":"/home/u","profile":"default","extra":{"model":"us.openai.gpt-5.6-luna","platform":"cli"}}`},
	{"hermes post llm call", "hermes", "post_llm_call",
		`{"hook_event_name":"post_llm_call","tool_name":null,"tool_input":null,"session_id":"20261023_165609_ab12cd","cwd":"/home/u","profile":"default","extra":{"user_message":"run echo ok","assistant_response":"ok"}}`},
	{"hermes pre tool call", "hermes", "pre_tool_call",
		`{"hook_event_name":"pre_tool_call","tool_name":"terminal","tool_input":{"command":"echo ok"},"session_id":"20261023_165609_ab12cd","cwd":"/home/u","profile":"default","extra":{"tool_call_id":"call_1"}}`},
}

func TestNativeHookEventShapesAreNotMalformed(t *testing.T) {
	for _, tc := range nativeHookEventShapes {
		t.Run(tc.name, func(t *testing.T) {
			var payload map[string]interface{}
			if err := json.Unmarshal([]byte(tc.body), &payload); err != nil {
				t.Fatal(err)
			}
			if reason := malformedHookPayloadReason(tc.connector, []byte(tc.body), payload, ""); reason != "" {
				t.Fatalf("native %s refused as malformed: %s", tc.event, reason)
			}
			if got := normalizeAgentHookRequest(tc.connector, payload).HookEventName; got != tc.event {
				t.Fatalf("normalized event = %q, want %q", got, tc.event)
			}
		})
	}
}

// The Claude Code FileChanged payload reaches the policy path: no 400.
func TestClaudeFileChangedIsAnsweredNot400(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	store, logger := testStoreAndLogger(t)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(nativeHookEventShapes[0].body))
	req.Header.Set("Content-Type", "application/json")
	recorder := httptest.NewRecorder()
	api.handleAgentHook("claudecode").ServeHTTP(recorder, req)
	if recorder.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200: %s", recorder.Code, recorder.Body.String())
	}
}

// Still malformed: the generic event key on a tool call disagrees with the
// named event or is not a name, a tool call names no tool, and a body whose
// only event key is not a name.
func TestMalformedEventShapesStayRefused(t *testing.T) {
	for _, tc := range []struct {
		connector, body, reason string
	}{
		{"claudecode", `{"hook_event_name":"PreToolUse","event":"Stop","session_id":"s","tool_name":"Bash","tool_input":{"command":"echo ok"}}`, "conflicting_event"},
		{"claudecode", `{"hook_event_name":"PreToolUse","event":{"kind":"change"},"session_id":"s","tool_name":"Bash","tool_input":{"command":"echo ok"}}`, "invalid_event_type"},
		{"opencode", `{"hook_event_name":"tool.execute.before","event":{"sessionID":"s"},"tool_name":"bash","tool_input":{"command":"echo ok"}}`, "invalid_event_type"},
		{"hermes", `{"hook_event_name":"pre_tool_call","tool_name":null,"tool_input":{"command":"echo ok"},"session_id":"s","cwd":"/home/u"}`, "invalid_field_type"},
		{"claudecode", `{"hook_event_name":"PreToolUse","toolName":null,"tool_input":{"command":"echo ok"}}`, "invalid_field_type"},
		{"hermes", `{"hook_event_name":"on_session_start","tool_name":7,"session_id":"s"}`, "invalid_field_type"},
		{"opencode", `{"event":{"type":"session.idle"},"session_id":"s"}`, "invalid_event_type"},
		{"claudecode", `{"hook_event_name":"FileChanged","eventType":"Stop","event":"change"}`, "conflicting_event"},
	} {
		var payload map[string]interface{}
		if err := json.Unmarshal([]byte(tc.body), &payload); err != nil {
			t.Fatal(err)
		}
		if reason := malformedHookPayloadReason(tc.connector, []byte(tc.body), payload, ""); reason != tc.reason {
			t.Errorf("%s %s: reason = %q, want %q", tc.connector, tc.body, reason, tc.reason)
		}
	}
}
