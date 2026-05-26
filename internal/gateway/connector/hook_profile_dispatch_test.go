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
	"reflect"
	"testing"
)

// TestHookProfile_HasDispatchCallbacks asserts the profile runtime
// surface is populated for every hook-capable connector. Connector
// differences must live behind HookProfile callbacks instead of the
// gateway growing per-connector response/mode branches.
func TestHookProfile_HasDispatchCallbacks(t *testing.T) {
	cases := []struct {
		name           string
		newConn        func() Connector
		wantDecode     bool
		wantMapVerdict bool
		wantRespond    bool
	}{
		{"codex", func() Connector { return NewCodexConnector() }, true, true, true},
		{"claudecode", func() Connector { return NewClaudeCodeConnector() }, true, true, true},
		{"hermes", func() Connector { return NewHermesConnector() }, false, true, true},
		{"cursor", func() Connector { return NewCursorConnector() }, false, true, true},
		{"windsurf", func() Connector { return NewWindsurfConnector() }, false, true, true},
		{"geminicli", func() Connector { return NewGeminiCLIConnector() }, false, true, true},
		{"copilot", func() Connector { return NewCopilotConnector() }, false, true, true},
		{"openhands", func() Connector { return NewOpenHandsConnector() }, false, true, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			conn := tc.newConn()
			provider, ok := conn.(HookProfileProvider)
			if !ok {
				t.Fatalf("%s does not implement HookProfileProvider", tc.name)
			}
			profile := provider.HookProfile(SetupOpts{APIAddr: "127.0.0.1:18970"})
			if got := profile.Decode != nil; got != tc.wantDecode {
				t.Errorf("%s Decode set=%v want=%v", tc.name, got, tc.wantDecode)
			}
			if got := profile.MapVerdict != nil; got != tc.wantMapVerdict {
				t.Errorf("%s MapVerdict set=%v want=%v", tc.name, got, tc.wantMapVerdict)
			}
			if got := profile.Respond != nil; got != tc.wantRespond {
				t.Errorf("%s Respond set=%v want=%v", tc.name, got, tc.wantRespond)
			}
		})
	}
}

// TestCodexProfileDecode_Shape exercises codexProfileDecode against a
// representative codex hook payload and asserts the resulting
// HookProfileRequest reads back the structured fields a unified
// evaluator (PR 6) will need: ConnectorName, HookEventName, ToolName,
// Model, SessionID, TurnID, AgentID, AgentName, CWD, Direction.
// Direction is the field most likely to drift if normalization
// inside the decoder regresses (PreToolUse → tool_call,
// UserPromptSubmit → prompt, PostToolUse → tool_result), so we
// exercise all three.
func TestCodexProfileDecode_Shape(t *testing.T) {
	cases := []struct {
		name      string
		event     string
		direction string
	}{
		{"PreToolUse", "PreToolUse", "tool_call"},
		{"UserPromptSubmit", "UserPromptSubmit", "prompt"},
		{"PostToolUse", "PostToolUse", "tool_result"},
		{"Stop", "Stop", "tool_call"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			payload := map[string]interface{}{
				"hook_event_name": tc.event,
				"session_id":      "sess-codex-42",
				"turn_id":         "turn-7",
				"agent_id":        "ag-c0",
				"agent_type":      "codex-agent",
				"cwd":             "/work",
				"model":           "gpt-5",
				"tool_name":       "shell",
				"prompt":          "ls /",
			}
			req := codexProfileDecode(payload)
			if req.ConnectorName != "codex" {
				t.Errorf("ConnectorName=%q want codex", req.ConnectorName)
			}
			if req.HookEventName != tc.event {
				t.Errorf("HookEventName=%q want %q", req.HookEventName, tc.event)
			}
			if req.Direction != tc.direction {
				t.Errorf("Direction=%q want %q", req.Direction, tc.direction)
			}
			if req.AgentName == "" {
				t.Errorf("AgentName empty; expected fallback")
			}
			if !reflect.DeepEqual(req.Payload, payload) {
				t.Errorf("Payload not preserved verbatim: got %#v want %#v", req.Payload, payload)
			}
		})
	}
}

// TestCodexProfileMapVerdict covers the mapping rules that govern
// observe-vs-action mode plus the BlockEvents membership gate.
// claudecode and codex have subtly different rules, so each has its
// own matrix.
func TestCodexProfileMapVerdict(t *testing.T) {
	caps := HookCapability{
		CanBlock:    true,
		BlockEvents: []string{"UserPromptSubmit", "PreToolUse", "PermissionRequest", "PostToolUse", "Stop"},
	}
	cases := []struct {
		name          string
		raw           string
		event         string
		mode          string
		wantAction    string
		wantWouldBlk  bool
		permissiveCap bool
	}{
		{"observe_block", "block", "PreToolUse", "observe", "allow", true, false},
		{"observe_allow", "allow", "PreToolUse", "observe", "allow", false, false},
		{"action_block_supported", "block", "PreToolUse", "action", "block", false, false},
		{"action_block_unsupported_event", "block", "SessionStart", "action", "allow", true, false},
		{"action_confirm_demote", "confirm", "PreToolUse", "action", "alert", false, false},
		{"action_alert_passthrough", "alert", "PreToolUse", "action", "alert", false, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := codexProfileMapVerdict(HookVerdictInput{
				RawAction: tc.raw,
				Event:     tc.event,
				Mode:      tc.mode,
				Caps:      caps,
			})
			if out.Action != tc.wantAction {
				t.Errorf("Action=%q want %q", out.Action, tc.wantAction)
			}
			if out.WouldBlock != tc.wantWouldBlk {
				t.Errorf("WouldBlock=%v want %v", out.WouldBlock, tc.wantWouldBlk)
			}
		})
	}
}

// TestClaudeCodeProfileMapVerdict covers Claude Code's "can enforce"
// gate plus the chat-side-ask demote rule.
func TestClaudeCodeProfileMapVerdict(t *testing.T) {
	caps := HookCapability{
		CanBlock:     true,
		CanAskNative: true,
		AskEvents:    []string{"PreToolUse"},
		BlockEvents:  []string{"UserPromptSubmit", "PreToolUse", "PermissionRequest", "PostToolUse", "Stop"},
	}
	cases := []struct {
		name         string
		raw          string
		event        string
		mode         string
		wantAction   string
		wantWouldBlk bool
	}{
		{"observe_block", "block", "PreToolUse", "observe", "allow", true},
		{"action_block_enforceable", "block", "PreToolUse", "action", "block", false},
		{"action_block_unenforceable", "block", "SessionStart", "action", "allow", true},
		{"action_confirm_ask_event", "confirm", "PreToolUse", "action", "confirm", false},
		{"action_confirm_non_ask_event", "confirm", "PostToolUse", "action", "alert", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := claudeCodeProfileMapVerdict(HookVerdictInput{
				RawAction: tc.raw,
				Event:     tc.event,
				Mode:      tc.mode,
				Caps:      caps,
			})
			if out.Action != tc.wantAction {
				t.Errorf("Action=%q want %q", out.Action, tc.wantAction)
			}
			if out.WouldBlock != tc.wantWouldBlk {
				t.Errorf("WouldBlock=%v want %v", out.WouldBlock, tc.wantWouldBlk)
			}
		})
	}
}

// TestCodexProfileRespond_Parity asserts the codex profile's Respond
// produces a payload whose top-level field name is "codex_output"
// and whose shape matches the typed codexOutput() helper for the
// canonical block / confirm / allow paths.
//
// Byte-for-byte parity with codexOutput() is enforced by the
// gateway-side TestUnifiedDispatchParity_Codex test in PR 5 — this
// connector-package test pins the shape locally so a regression in
// codex_hook_profile.go fails fast in the small unit suite.
func TestCodexProfileRespond_Parity(t *testing.T) {
	cases := []struct {
		name     string
		event    string
		action   string
		raw      string
		reason   string
		expected map[string]interface{}
	}{
		{
			name:   "PreToolUse_block",
			event:  "PreToolUse",
			action: "block",
			raw:    "block",
			reason: "policy denied",
			expected: map[string]interface{}{
				"hookSpecificOutput": map[string]interface{}{
					"hookEventName":            "PreToolUse",
					"permissionDecision":       "deny",
					"permissionDecisionReason": "policy denied",
				},
			},
		},
		{
			name:   "Stop_allow",
			event:  "Stop",
			action: "allow",
			raw:    "allow",
			expected: map[string]interface{}{
				"continue": true,
			},
		},
		{
			name:   "PreToolUse_allow_no_additional",
			event:  "PreToolUse",
			action: "allow",
			raw:    "allow",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := codexProfileRespond(HookRespondInput{
				Req:       HookProfileRequest{ConnectorName: "codex", HookEventName: tc.event},
				Action:    tc.action,
				RawAction: tc.raw,
				Reason:    tc.reason,
			})
			if out.FieldName != "codex_output" {
				t.Errorf("FieldName=%q want codex_output", out.FieldName)
			}
			if tc.expected == nil {
				if out.Output != nil {
					t.Errorf("Output=%#v want nil", out.Output)
				}
				return
			}
			if !reflect.DeepEqual(out.Output, tc.expected) {
				t.Errorf("Output mismatch\n got: %#v\nwant: %#v", out.Output, tc.expected)
			}
		})
	}
}

// TestClaudeCodeProfileRespond_Parity is the claudecode-side mirror
// of TestCodexProfileRespond_Parity. Covers the "confirm on PreToolUse
// becomes permissionDecision=ask" and "deny on PermissionRequest"
// branches that diverge from the codex wire shape.
func TestClaudeCodeProfileRespond_Parity(t *testing.T) {
	cases := []struct {
		name     string
		event    string
		action   string
		raw      string
		reason   string
		expected map[string]interface{}
	}{
		{
			name:   "PreToolUse_confirm_ask",
			event:  "PreToolUse",
			action: "confirm",
			raw:    "confirm",
			reason: "needs approval",
			expected: map[string]interface{}{
				"hookSpecificOutput": map[string]interface{}{
					"hookEventName":            "PreToolUse",
					"permissionDecision":       "ask",
					"permissionDecisionReason": "needs approval",
				},
			},
		},
		{
			name:   "PermissionRequest_block_decision_deny",
			event:  "PermissionRequest",
			action: "block",
			raw:    "block",
			reason: "deny payload",
			expected: map[string]interface{}{
				"hookSpecificOutput": map[string]interface{}{
					"hookEventName": "PermissionRequest",
					"decision": map[string]interface{}{
						"behavior": "deny",
						"message":  "deny payload",
					},
				},
			},
		},
		{
			name:   "TaskCreated_block_stops_continuation",
			event:  "TaskCreated",
			action: "block",
			raw:    "block",
			expected: map[string]interface{}{
				"continue":   false,
				"stopReason": "Blocked by DefenseClaw Claude Code policy.",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := claudeCodeProfileRespond(HookRespondInput{
				Req:       HookProfileRequest{ConnectorName: "claudecode", HookEventName: tc.event},
				Action:    tc.action,
				RawAction: tc.raw,
				Reason:    tc.reason,
			})
			if out.FieldName != "claude_code_output" {
				t.Errorf("FieldName=%q want claude_code_output", out.FieldName)
			}
			if !reflect.DeepEqual(out.Output, tc.expected) {
				t.Errorf("Output mismatch\n got: %#v\nwant: %#v", out.Output, tc.expected)
			}
		})
	}
}

// TestCodexAdditionalContextForProfile pins the additional-context
// wording. Operators have alerts on the exact phrasing
// ("DefenseClaw would block this in action mode...") so a typo
// regression should fail loudly. The corresponding gateway helper
// (codexAdditionalContext) is exercised by gateway tests; this test
// pins the connector-package copy so the two cannot silently
// diverge during PR 6's pull-up.
func TestCodexAdditionalContextForProfile(t *testing.T) {
	cases := []struct {
		name       string
		raw        string
		severity   string
		reason     string
		wouldBlock bool
		want       string
	}{
		{"allow_empty", "allow", "NONE", "", false, ""},
		{"observe_block_with_reason", "block", "HIGH", "matched policy", false,
			"DefenseClaw observed a HIGH Codex hook finding: matched policy"},
		{"action_would_block", "block", "HIGH", "matched policy", true,
			"DefenseClaw would block this in action mode a HIGH Codex hook finding: matched policy"},
		{"alert_no_reason", "alert", "MEDIUM", "", false,
			"DefenseClaw observed a MEDIUM Codex hook finding."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got := codexAdditionalContextForProfile(tc.raw, tc.severity, tc.reason, tc.wouldBlock)
			if got != tc.want {
				t.Errorf("got %q want %q", got, tc.want)
			}
		})
	}
}
