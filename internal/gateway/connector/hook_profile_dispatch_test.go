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
	"os"
	"path/filepath"
	"reflect"
	"slices"
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
		// Hermes needs no Decode: its nested `extra` content is
		// recovered by the generic decoder's ContentEnvelopeKey
		// fallback (declared on the hermes hook contract), and its
		// wire replies come from the shared hookOnlyProfileRespond
		// hermes case.
		{"hermes", func() Connector { return NewHermesConnector() }, false, true, true},
		{"cursor", func() Connector { return NewCursorConnector() }, true, true, true},
		{"windsurf", func() Connector { return NewWindsurfConnector() }, true, true, true},
		{"geminicli", func() Connector { return NewGeminiCLIConnector() }, false, true, true},
		{"copilot", func() Connector { return NewCopilotConnector() }, false, true, true},
		{"openhands", func() Connector { return NewOpenHandsConnector() }, false, true, true},
		// Antigravity uses Decode because agy v1 ships a nested
		// `toolCall` wire shape that the generic normalizer cannot read.
		// Cursor and Windsurf use Decode only for their connector-native
		// generation/execution-to-turn semantics.
		{"antigravity", func() Connector { return NewAntigravityConnector() }, true, true, true},
		// opencode controls its own flat wire shape (the bridge plugin we
		// ship), so it needs no Decode; Respond comes from the shared
		// hookOnlyProfileRespond opencode case.
		{"opencode", func() Connector { return NewOpenCodeConnector() }, false, true, true},
		{"omnigent", func() Connector { return NewOmnigentConnector() }, false, true, true},
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

func TestHookOnlyProfiles_MapDocumentedNativeTurnIDs(t *testing.T) {
	cases := []struct {
		name    string
		profile func(map[string]interface{}) HookProfileRequest
		payload map[string]interface{}
		want    string
	}{
		{"cursor generation", cursorProfileDecode, map[string]interface{}{"generation_id": "gen-7"}, "gen-7"},
		{"cursor explicit turn fallback", cursorProfileDecode, map[string]interface{}{"turn_id": "turn-7"}, "turn-7"},
		{"windsurf execution", windsurfProfileDecode, map[string]interface{}{"execution_id": "exec-9"}, "exec-9"},
		{"windsurf explicit turn fallback", windsurfProfileDecode, map[string]interface{}{"turn_id": "turn-9"}, "turn-9"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.profile(tc.payload).TurnID; got != tc.want {
				t.Fatalf("TurnID=%q want %q", got, tc.want)
			}
		})
	}
}

func TestHookOnlyProfiles_DoNotCrossMapUnrelatedIDsToTurns(t *testing.T) {
	cases := []struct {
		name    string
		profile func(map[string]interface{}) HookProfileRequest
		payload map[string]interface{}
	}{
		{"cursor execution", cursorProfileDecode, map[string]interface{}{"execution_id": "exec-7"}},
		{"cursor tool call", cursorProfileDecode, map[string]interface{}{"tool_call_id": "tool-7"}},
		{"windsurf generation", windsurfProfileDecode, map[string]interface{}{"generation_id": "gen-9"}},
		{"windsurf step", windsurfProfileDecode, map[string]interface{}{"step_id": "step-9"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := tc.profile(tc.payload).TurnID; got != "" {
				t.Fatalf("TurnID=%q want empty", got)
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
		CanBlock: true,
		BlockEvents: []string{
			"SessionStart", "UserPromptSubmit", "PreToolUse", "PermissionRequest",
			"PostToolUse", "SubagentStop", "PreCompact", "PostCompact", "Stop",
		},
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
		{"action_block_session_start", "block", "SessionStart", "action", "block", false, false},
		{"action_block_subagent_stop", "block", "SubagentStop", "action", "block", false, false},
		{"action_block_pre_compact", "block", "PreCompact", "action", "block", false, false},
		{"action_block_post_compact", "block", "PostCompact", "action", "block", false, false},
		{"action_block_unsupported_event", "block", "SessionEnd", "action", "allow", true, false},
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
		BlockEvents:  []string{"UserPromptSubmit", "PreToolUse", "PermissionRequest", "PostToolBatch", "ConfigChange", "Stop"},
	}
	cases := []struct {
		name         string
		raw          string
		event        string
		mode         string
		payload      map[string]interface{}
		wantAction   string
		wantWouldBlk bool
	}{
		{"observe_block", "block", "PreToolUse", "observe", nil, "allow", true},
		{"action_block_enforceable", "block", "PreToolUse", "action", nil, "block", false},
		{"action_block_unenforceable", "block", "SessionStart", "action", nil, "allow", true},
		{"post_tool_use_is_advisory", "block", "PostToolUse", "action", nil, "allow", true},
		{"post_tool_batch_stops_next_model_call", "block", "PostToolBatch", "action", nil, "block", false},
		{"policy_config_change_is_advisory", "block", "ConfigChange", "action", map[string]interface{}{"source": "policy_settings"}, "allow", true},
		{"user_config_change_is_enforceable", "block", "ConfigChange", "action", map[string]interface{}{"source": "user_settings"}, "block", false},
		{"action_confirm_ask_event", "confirm", "PreToolUse", "action", nil, "confirm", false},
		{"action_confirm_non_ask_event", "confirm", "PostToolUse", "action", nil, "alert", false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := claudeCodeProfileMapVerdict(HookVerdictInput{
				RawAction: tc.raw,
				Event:     tc.event,
				Mode:      tc.mode,
				Caps:      caps,
				Payload:   tc.payload,
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
			name:   "SessionStart_block_stops_turn",
			event:  "SessionStart",
			action: "block",
			raw:    "block",
			reason: "stop current turn",
			expected: map[string]interface{}{
				"continue":   false,
				"stopReason": "stop current turn",
			},
		},
		{
			name:   "PreCompact_block_stops_before_compaction",
			event:  "PreCompact",
			action: "block",
			raw:    "block",
			reason: "keep full context",
			expected: map[string]interface{}{
				"continue":   false,
				"stopReason": "keep full context",
			},
		},
		{
			name:   "PostCompact_block_stops_after_compaction",
			event:  "PostCompact",
			action: "block",
			raw:    "block",
			reason: "review compacted context",
			expected: map[string]interface{}{
				"continue":   false,
				"stopReason": "review compacted context",
			},
		},
		{
			name:   "SubagentStop_block_continues_subagent",
			event:  "SubagentStop",
			action: "block",
			raw:    "block",
			reason: "one more focused pass",
			expected: map[string]interface{}{
				"decision": "block",
				"reason":   "one more focused pass",
			},
		},
		{
			name:   "SessionEnd_block_is_advisory",
			event:  "SessionEnd",
			action: "block",
			raw:    "block",
			reason: "must not steer",
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
			name:     "TaskCreated_block_uses_exit_two_feedback",
			event:    "TaskCreated",
			action:   "block",
			raw:      "block",
			expected: nil,
		},
		{
			name:   "Notification_advisory_uses_system_message",
			event:  "Notification",
			action: "allow",
			raw:    "block",
			expected: map[string]interface{}{
				"systemMessage": "advisory context",
			},
		},
		{
			name:   "SubagentStop_advisory_uses_additional_context",
			event:  "SubagentStop",
			action: "allow",
			raw:    "block",
			expected: map[string]interface{}{
				"hookSpecificOutput": map[string]interface{}{
					"hookEventName":     "SubagentStop",
					"additionalContext": "advisory context",
				},
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
				AdditionalContext: func() string {
					if tc.event == "Notification" || tc.event == "SubagentStop" {
						return "advisory context"
					}
					return ""
				}(),
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

func TestClaudeCodeProfileRespond_WatchPathsForEveryDynamicSource(t *testing.T) {
	configDir := filepath.Join(t.TempDir(), "claude-config")
	workspace := filepath.Join(t.TempDir(), "workspace")
	t.Setenv("CLAUDE_CONFIG_DIR", configDir)
	previous := ClaudeCodeSettingsPathOverride
	ClaudeCodeSettingsPathOverride = ""
	t.Cleanup(func() { ClaudeCodeSettingsPathOverride = previous })

	rule := filepath.Join(workspace, ".claude", "rules", "security.md")
	if err := os.MkdirAll(filepath.Dir(rule), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rule, []byte("fixture\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	for _, event := range []string{"SessionStart", "CwdChanged", "FileChanged"} {
		t.Run(event, func(t *testing.T) {
			req := HookProfileRequest{
				ConnectorName: "claudecode",
				HookEventName: event,
				CWD:           workspace,
				Payload:       map[string]interface{}{"new_cwd": workspace},
			}
			output := claudeCodeProfileRespond(HookRespondInput{Req: req, Action: "allow"}).Output
			if event == "SessionStart" {
				output = output["hookSpecificOutput"].(map[string]interface{})
			}
			watchPaths, ok := output["watchPaths"].([]string)
			if !ok {
				t.Fatalf("watchPaths = %#v, want []string", output["watchPaths"])
			}
			for _, want := range []string{
				filepath.Join(configDir, "settings.json"),
				filepath.Join(configDir, ".claude.json"),
				filepath.Join(workspace, ".claude", "settings.json"),
				filepath.Join(workspace, ".mcp.json"),
				filepath.Join(workspace, "CLAUDE.md"),
				rule,
			} {
				if !slices.Contains(watchPaths, want) {
					t.Errorf("watchPaths = %v, missing %q", watchPaths, want)
				}
			}
		})
	}
}

// TestAntigravityProfileRespond_Parity mirrors
// TestCodexProfileRespond_Parity / TestClaudeCodeProfileRespond_Parity:
// representative cases pinning the antigravity branch of
// hookOnlyProfileRespond across the five Antigravity 2.0 lifecycle
// events. Antigravity is wired through the shared
// hookOnlyProfileRespond (its connector-package profile file only
// adds Decode), so this table exercises hookOnlyProfileRespond with
// ConnectorName="antigravity" parameterised on event name.
//
// Wire-shape contract per event follows Google's hooks documentation exactly.
func TestAntigravityProfileRespond_Parity(t *testing.T) {
	const alertMsg = "DefenseClaw observed a MEDIUM antigravity hook finding: matched: SOFT-WARN-RULE"
	cases := []struct {
		name       string
		event      string
		action     string
		raw        string
		reason     string
		additional string
		expected   map[string]interface{}
	}{
		{
			name:       "PreToolUse_observe_mode_block_finding_allows",
			event:      "PreToolUse",
			action:     "allow",
			raw:        "block",
			additional: "DefenseClaw would block this in action mode a HIGH antigravity hook finding: matched policy",
			expected:   map[string]interface{}{"decision": "allow"},
		},
		{
			name:   "PreToolUse_action_mode_block_renders_decision_deny",
			event:  "PreToolUse",
			action: "block",
			raw:    "block",
			reason: "matched policy: deny-rm-rf",
			expected: map[string]interface{}{
				"decision": "deny",
				"reason":   "matched policy: deny-rm-rf",
			},
		},
		{
			name:       "PreToolUse_action_mode_alert_allows",
			event:      "PreToolUse",
			action:     "alert",
			raw:        "alert",
			additional: alertMsg,
			expected:   map[string]interface{}{"decision": "allow"},
		},
		{
			name:       "PreInvocation_finding_injects_ephemeral_message",
			event:      "PreInvocation",
			action:     "alert",
			raw:        "alert",
			additional: alertMsg,
			expected: map[string]interface{}{
				"injectSteps": []interface{}{
					map[string]interface{}{"ephemeralMessage": alertMsg},
				},
			},
		},
		{
			name:     "Stop_does_not_claim_hard_blocking",
			event:    "Stop",
			action:   "block",
			raw:      "block",
			reason:   "validation checks failed",
			expected: map[string]interface{}{"decision": "allow"},
		},
		{
			name:       "PostToolUse_returns_empty_object",
			event:      "PostToolUse",
			action:     "alert",
			raw:        "alert",
			additional: "Tool lifecycle metadata matched policy",
			expected:   map[string]interface{}{},
		},
		{
			name:       "PostInvocation_injects_ephemeral_message",
			event:      "PostInvocation",
			action:     "alert",
			raw:        "alert",
			additional: "Invocation context matched policy",
			expected: map[string]interface{}{
				"injectSteps": []interface{}{
					map[string]interface{}{"ephemeralMessage": "Invocation context matched policy"},
				},
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := hookOnlyProfileRespond(HookRespondInput{
				Req:               HookProfileRequest{ConnectorName: "antigravity", HookEventName: tc.event},
				Action:            tc.action,
				RawAction:         tc.raw,
				Reason:            tc.reason,
				AdditionalContext: tc.additional,
				Caps:              HookCapability{CanAskNative: true, AskEvents: []string{"PreToolUse"}},
			})
			if out.FieldName != "hook_output" {
				t.Errorf("FieldName=%q want hook_output", out.FieldName)
			}
			if !reflect.DeepEqual(out.Output, tc.expected) {
				t.Errorf("Output mismatch\n got: %#v\nwant: %#v", out.Output, tc.expected)
			}
		})
	}
}

func TestAntigravityProfileMapVerdict_AskOnlyAtPreToolUse(t *testing.T) {
	caps := HookCapability{
		CanBlock:     true,
		CanAskNative: true,
		AskEvents:    []string{"PreToolUse"},
		BlockEvents:  []string{"PreToolUse"},
	}
	cases := []struct {
		name       string
		event      string
		wantAction string
	}{
		{name: "pre_tool_use_retains_native_confirm", event: "PreToolUse", wantAction: "confirm"},
		{name: "pre_invocation_downgrades_confirm", event: "PreInvocation", wantAction: "alert"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := hookOnlyProfileMapVerdict(HookVerdictInput{
				RawAction: "confirm",
				Event:     tc.event,
				Mode:      "action",
				Caps:      caps,
			})
			if out.Action != tc.wantAction {
				t.Fatalf("Action=%q want %q", out.Action, tc.wantAction)
			}
			if out.WouldBlock {
				t.Fatal("confirm verdict must not be reported as would-block")
			}
		})
	}
}

// TestHermesProfileRespond_Parity pins the hermes branch of
// hookOnlyProfileRespond (hermes is wired through the shared responder;
// it has no profile file of its own). pre_tool_call blocks
// ({"decision":"block"}); pre_llm_call injects context; pre_verify can
// continue Hermes's bounded verification loop. Every other shell-hook-valid
// event is audit-only from DefenseClaw's JSON shell lane. Wire parity with the legacy
// hookOutputFor("hermes") shaper and the hermes/verdict-blocked golden
// is intentional — a divergence here ships a silent behavior change.
// Confirm verdicts (Hermes has no native ask/approve or message response)
// remain audit/alert-only and produce no hook output.
func TestHermesProfileRespond_Parity(t *testing.T) {
	cases := []struct {
		name       string
		event      string
		action     string
		rawAction  string
		reason     string
		additional string
		expected   map[string]interface{}
	}{
		{
			name:      "pre_tool_call_block_renders_decision_block",
			event:     "pre_tool_call",
			action:    "block",
			rawAction: "block",
			reason:    "matched policy: deny-rm-rf",
			expected:  map[string]interface{}{"decision": "block", "reason": "matched policy: deny-rm-rf"},
		},
		{
			name:       "pre_llm_call_injects_context",
			event:      "pre_llm_call",
			action:     "alert",
			rawAction:  "alert",
			additional: "DefenseClaw observed a HIGH hermes hook finding: prompt looks risky",
			expected:   map[string]interface{}{"context": "DefenseClaw observed a HIGH hermes hook finding: prompt looks risky"},
		},
		{
			name:      "pre_llm_call_allow_no_context_is_nil",
			event:     "pre_llm_call",
			action:    "allow",
			rawAction: "allow",
			expected:  nil,
		},
		{
			name:      "pre_verify_block_keeps_bounded_verification_loop_going",
			event:     "pre_verify",
			action:    "continue",
			rawAction: "block",
			reason:    "run the required focused verification",
			expected: map[string]interface{}{
				"action":  "continue",
				"message": "run the required focused verification",
			},
		},
		{
			name:       "post_tool_call_alert_is_observe_only",
			event:      "post_tool_call",
			action:     "alert",
			rawAction:  "alert",
			additional: "tool output leaked a secret",
			expected:   nil,
		},
		{
			name:      "on_session_end_is_observe_only",
			event:     "on_session_end",
			action:    "allow",
			rawAction: "allow",
			expected:  nil,
		},
		{
			name:       "transform_tool_result_is_audit_only_in_shell_lane",
			event:      "transform_tool_result",
			action:     "block",
			rawAction:  "block",
			reason:     "Python transform requires a string return",
			additional: "do not synthesize a transform",
			expected:   nil,
		},
		{
			name:       "pre_gateway_dispatch_is_audit_only_in_shell_lane",
			event:      "pre_gateway_dispatch",
			action:     "block",
			rawAction:  "block",
			reason:     "shell parser cannot express skip or rewrite",
			additional: "do not synthesize a gateway action",
			expected:   nil,
		},
		{
			// Confirm downgrade: Hermes CanAskNative=false, so the
			// gateway records/alerts it without fabricating an
			// undocumented hook response.
			name:       "pre_tool_call_confirm_is_audit_only",
			event:      "pre_tool_call",
			action:     "alert",
			rawAction:  "confirm",
			additional: "DefenseClaw needs your approval before terminal can run.",
			expected:   nil,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := hookOnlyProfileRespond(HookRespondInput{
				Req:               HookProfileRequest{ConnectorName: "hermes", HookEventName: tc.event},
				Action:            tc.action,
				RawAction:         tc.rawAction,
				Reason:            tc.reason,
				AdditionalContext: tc.additional,
				Caps:              HookCapability{CanBlock: true, CanAskNative: false, BlockEvents: []string{"pre_tool_call"}},
			})
			if out.FieldName != "hook_output" {
				t.Errorf("FieldName=%q want hook_output", out.FieldName)
			}
			if !reflect.DeepEqual(out.Output, tc.expected) {
				t.Errorf("Output mismatch\n got: %#v\nwant: %#v", out.Output, tc.expected)
			}
		})
	}
}

func TestHermesProfileMapAndRespondPreVerifyContinue(t *testing.T) {
	caps := HookCapability{
		CanBlock:    true,
		BlockEvents: []string{"pre_tool_call"},
	}
	mapped := hermesProfileMapVerdict(HookVerdictInput{
		Mode:      "action",
		Event:     "pre_verify",
		RawAction: "block",
		Caps:      caps,
	})
	if mapped.Action != "continue" || mapped.WouldBlock {
		t.Fatalf("mapped verdict = %#v, want bounded continue without block attribution", mapped)
	}
	out := hookOnlyProfileRespond(HookRespondInput{
		Req:       HookProfileRequest{ConnectorName: "hermes", HookEventName: "pre_verify"},
		Action:    mapped.Action,
		RawAction: "block",
		Reason:    "run the required focused verification",
		Caps:      caps,
	})
	want := map[string]interface{}{
		"action":  "continue",
		"message": "run the required focused verification",
	}
	if !reflect.DeepEqual(out.Output, want) {
		t.Fatalf("pre_verify output = %#v, want %#v", out.Output, want)
	}

	observe := hermesProfileMapVerdict(HookVerdictInput{
		Mode:      "observe",
		Event:     "pre_verify",
		RawAction: "block",
		Caps:      caps,
	})
	if observe.Action != "allow" || !observe.WouldBlock {
		t.Fatalf("observe verdict = %#v, want audit-only allow/would-block", observe)
	}
}

func TestCursorProfileRespond_CurrentEventOutputMatrix(t *testing.T) {
	cases := []struct {
		event    string
		expected map[string]interface{}
	}{
		{"sessionStart", map[string]interface{}{}},
		{"sessionEnd", map[string]interface{}{}},
		{"preToolUse", map[string]interface{}{"permission": "allow"}},
		{"postToolUse", map[string]interface{}{}},
		{"postToolUseFailure", map[string]interface{}{}},
		{"subagentStart", map[string]interface{}{"permission": "allow"}},
		{"subagentStop", map[string]interface{}{}},
		{"beforeShellExecution", map[string]interface{}{"permission": "allow"}},
		{"afterShellExecution", map[string]interface{}{}},
		{"beforeMCPExecution", map[string]interface{}{"permission": "allow"}},
		{"afterMCPExecution", map[string]interface{}{}},
		{"beforeReadFile", map[string]interface{}{"permission": "allow"}},
		{"afterFileEdit", map[string]interface{}{}},
		{"beforeTabFileRead", map[string]interface{}{"permission": "allow"}},
		{"afterTabFileEdit", map[string]interface{}{}},
		{"beforeSubmitPrompt", map[string]interface{}{"continue": true}},
		{"preCompact", map[string]interface{}{}},
		{"stop", map[string]interface{}{}},
		{"afterAgentResponse", map[string]interface{}{}},
		{"afterAgentThought", map[string]interface{}{}},
		{"workspaceOpen", map[string]interface{}{}},
	}
	for _, tc := range cases {
		t.Run(tc.event, func(t *testing.T) {
			out := hookOnlyProfileRespond(HookRespondInput{
				Req: HookProfileRequest{
					ConnectorName: "cursor",
					HookEventName: tc.event,
				},
				Action:    "allow",
				RawAction: "allow",
				Caps: HookCapability{
					CanBlock:     true,
					CanAskNative: true,
				},
			})
			if out.FieldName != "hook_output" {
				t.Errorf("FieldName=%q want hook_output", out.FieldName)
			}
			if out.Output == nil {
				t.Fatal("Cursor command hooks must return a JSON object, including {} for no-output events")
			}
			if !reflect.DeepEqual(out.Output, tc.expected) {
				t.Errorf("Output mismatch\n got: %#v\nwant: %#v", out.Output, tc.expected)
			}
		})
	}
}

func TestCursorProfileRespond_EventSpecificFields(t *testing.T) {
	cases := []struct {
		name       string
		event      string
		action     string
		rawAction  string
		reason     string
		additional string
		expected   map[string]interface{}
	}{
		{
			name:      "pre_tool_deny_supports_both_messages",
			event:     "preToolUse",
			action:    "block",
			rawAction: "block",
			reason:    "matched SEC-AWS-KEY",
			expected: map[string]interface{}{
				"permission":    "deny",
				"user_message":  "matched SEC-AWS-KEY",
				"agent_message": "matched SEC-AWS-KEY",
			},
		},
		{
			name:      "subagent_start_deny_has_no_agent_message",
			event:     "subagentStart",
			action:    "block",
			rawAction: "block",
			reason:    "subagent creation denied",
			expected: map[string]interface{}{
				"permission":   "deny",
				"user_message": "subagent creation denied",
			},
		},
		{
			name:      "shell_confirm_is_native_ask",
			event:     "beforeShellExecution",
			action:    "confirm",
			rawAction: "confirm",
			reason:    "shell command needs approval",
			expected: map[string]interface{}{
				"permission":    "ask",
				"user_message":  "shell command needs approval",
				"agent_message": "shell command needs approval",
			},
		},
		{
			name:      "tab_read_deny_has_permission_only",
			event:     "beforeTabFileRead",
			action:    "block",
			rawAction: "block",
			reason:    "sensitive file",
			expected:  map[string]interface{}{"permission": "deny"},
		},
		{
			name:       "session_start_context",
			event:      "sessionStart",
			action:     "alert",
			rawAction:  "alert",
			additional: "session policy context",
			expected:   map[string]interface{}{"additional_context": "session policy context"},
		},
		{
			name:       "post_tool_context",
			event:      "postToolUse",
			action:     "alert",
			rawAction:  "alert",
			additional: "tool result context",
			expected:   map[string]interface{}{"additional_context": "tool result context"},
		},
		{
			name:       "pre_compact_user_message",
			event:      "preCompact",
			action:     "alert",
			rawAction:  "alert",
			additional: "context compaction observed",
			expected:   map[string]interface{}{"user_message": "context compaction observed"},
		},
		{
			name:       "subagent_stop_followup",
			event:      "subagentStop",
			action:     "allow",
			rawAction:  "allow",
			additional: "review the subagent result",
			expected:   map[string]interface{}{"followup_message": "review the subagent result"},
		},
		{
			name:       "workspace_open_does_not_invent_plugin_paths",
			event:      "workspaceOpen",
			action:     "alert",
			rawAction:  "alert",
			additional: "inventory finding",
			expected:   map[string]interface{}{},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := hookOnlyProfileRespond(HookRespondInput{
				Req: HookProfileRequest{
					ConnectorName: "cursor",
					HookEventName: tc.event,
				},
				Action:            tc.action,
				RawAction:         tc.rawAction,
				Reason:            tc.reason,
				AdditionalContext: tc.additional,
				Caps:              NewCursorConnector().HookCapabilities(SetupOpts{}),
			})
			if !reflect.DeepEqual(out.Output, tc.expected) {
				t.Errorf("Output mismatch\n got: %#v\nwant: %#v", out.Output, tc.expected)
			}
		})
	}
}

func TestCursorProfileMapVerdict_SubagentStartDenyWithoutAsk(t *testing.T) {
	caps := KnownHookContracts("cursor")[0].Capabilities
	tests := []struct {
		name           string
		event          string
		mode           string
		rawAction      string
		wantAction     string
		wantWouldBlock bool
	}{
		{"action_block_subagent", "subagentStart", "action", "block", "block", false},
		{"observe_block_subagent", "subagentStart", "observe", "block", "allow", true},
		{"confirm_subagent_downgrades", "subagentStart", "action", "confirm", "alert", false},
		{"confirm_shell_uses_native_ask", "beforeShellExecution", "action", "confirm", "confirm", false},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			out := hookOnlyProfileMapVerdict(HookVerdictInput{
				Event:     tc.event,
				Mode:      tc.mode,
				RawAction: tc.rawAction,
				Caps:      caps,
			})
			if out.Action != tc.wantAction || out.WouldBlock != tc.wantWouldBlock {
				t.Fatalf("verdict=%+v want action=%q would_block=%v", out, tc.wantAction, tc.wantWouldBlock)
			}
		})
	}
}

// TestCursorProfileRespond_BeforeSubmitPromptBlockUsesContinue pins the
// continue-gated contract for Cursor's beforeSubmitPrompt: per
// https://cursor.com/docs/hooks it blocks ONLY via {"continue":false}
// and ignores the `permission` field. Emitting the permission-gated
// {"continue":true,"permission":"deny"} shape here silently submits the
// prompt (regression guard for the block-message-never-shown bug).
func TestCursorProfileRespond_BeforeSubmitPromptBlockUsesContinue(t *testing.T) {
	out := hookOnlyProfileRespond(HookRespondInput{
		Req: HookProfileRequest{
			ConnectorName: "cursor",
			HookEventName: "beforeSubmitPrompt",
		},
		Action:    "block",
		RawAction: "block",
		Reason:    "matched SEC-AWS-KEY",
		Caps:      HookCapability{CanBlock: true},
	})
	if out.FieldName != "hook_output" {
		t.Errorf("FieldName=%q want hook_output", out.FieldName)
	}
	want := map[string]interface{}{
		"continue":     false,
		"user_message": "matched SEC-AWS-KEY",
	}
	if !reflect.DeepEqual(out.Output, want) {
		t.Errorf("beforeSubmitPrompt block Output mismatch\n got: %#v\nwant: %#v", out.Output, want)
	}
	if cont, _ := out.Output["continue"].(bool); cont {
		t.Errorf("beforeSubmitPrompt block must set continue:false to actually block the prompt")
	}
	if _, hasPerm := out.Output["permission"]; hasPerm {
		t.Errorf("beforeSubmitPrompt block must not rely on `permission` (Cursor ignores it): %#v", out.Output)
	}
}

func TestCursorProfileRespond_StopUsesFollowupInsteadOfPermissionDeny(t *testing.T) {
	out := hookOnlyProfileRespond(HookRespondInput{
		Req: HookProfileRequest{
			ConnectorName: "cursor",
			HookEventName: "stop",
		},
		Action:    "block",
		RawAction: "block",
		Reason:    "review the final response",
		Caps:      NewCursorConnector().HookCapabilities(SetupOpts{}),
	})
	want := map[string]interface{}{"followup_message": "review the final response"}
	if !reflect.DeepEqual(out.Output, want) {
		t.Errorf("Cursor Stop output mismatch\n got: %#v\nwant: %#v", out.Output, want)
	}
	if _, found := out.Output["permission"]; found {
		t.Fatal("Cursor Stop output must not claim permission-gate enforcement")
	}
}

// TestHermesProfileRespond_BlockDefaultReason asserts a hermes block
// with an empty upstream reason still produces an actionable default
// reason (rather than an empty string) on the wire.
func TestHermesProfileRespond_BlockDefaultReason(t *testing.T) {
	out := hookOnlyProfileRespond(HookRespondInput{
		Req:    HookProfileRequest{ConnectorName: "hermes", HookEventName: "pre_tool_call", ToolName: "terminal"},
		Action: "block",
	})
	body, ok := out.Output["reason"].(string)
	if !ok || body == "" {
		t.Fatalf("block reason should be non-empty default, got %#v", out.Output)
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
