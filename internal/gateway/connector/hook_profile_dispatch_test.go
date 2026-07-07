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
		// Hermes needs no Decode: its nested `extra` content is
		// recovered by the generic decoder's ContentEnvelopeKey
		// fallback (declared on the hermes hook contract), and its
		// wire replies come from the shared hookOnlyProfileRespond
		// hermes case.
		{"hermes", func() Connector { return NewHermesConnector() }, false, true, true},
		{"cursor", func() Connector { return NewCursorConnector() }, false, true, true},
		{"windsurf", func() Connector { return NewWindsurfConnector() }, false, true, true},
		{"geminicli", func() Connector { return NewGeminiCLIConnector() }, false, true, true},
		{"copilot", func() Connector { return NewCopilotConnector() }, false, true, true},
		{"openhands", func() Connector { return NewOpenHandsConnector() }, false, true, true},
		// Antigravity is the only generic hook-only connector that
		// SETS Decode, because agy v1 ships a nested `toolCall`
		// wire shape that the generic normalizer can't read. See
		// antigravity_hook_profile.go.
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

// TestAntigravityProfileRespond_Parity mirrors
// TestCodexProfileRespond_Parity / TestClaudeCodeProfileRespond_Parity:
// representative cases pinning the antigravity branch of
// hookOnlyProfileRespond across the five Antigravity 2.0 lifecycle
// events. Antigravity is wired through the shared
// hookOnlyProfileRespond (its connector-package profile file only
// adds Decode), so this table exercises hookOnlyProfileRespond with
// ConnectorName="antigravity" parameterised on event name.
//
// Wire-shape contract per event:
//
//	PreInvocation  + PreToolUse → block→{decision:deny}, confirm→{decision:ask}, alert→{systemMessage}
//	Stop                        → block→{decision:block} (spec-distinct verb)
//	PostToolUse + PostInvocation → alert→{additionalContext} only (no block)
//
// observe_mode_block intentionally expects nil — agy v1.0.1 does
// not render any PreToolUse field inline for observe-mode
// demoted-allow findings; visibility ships via gateway.log + OTel
// until agy adds a render channel (see the antigravity case in
// hook_only_profile.go for the empirical history).
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
		// PreToolUse: full action-matrix (block/alert/observe).
		{
			name:       "PreToolUse_observe_mode_block_finding_returns_nil",
			event:      "PreToolUse",
			action:     "allow",
			raw:        "block",
			additional: "DefenseClaw would block this in action mode a HIGH antigravity hook finding: matched policy",
			expected:   nil,
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
			name:       "PreToolUse_action_mode_alert_renders_systemMessage",
			event:      "PreToolUse",
			action:     "alert",
			raw:        "alert",
			additional: alertMsg,
			expected:   map[string]interface{}{"systemMessage": alertMsg},
		},
		// PreInvocation: same wire shape as PreToolUse — block emits
		// decision:deny, prompt-content rules can deny harmful prompts
		// before they reach the LLM.
		{
			name:   "PreInvocation_action_mode_block_renders_decision_deny",
			event:  "PreInvocation",
			action: "block",
			raw:    "block",
			reason: "prompt contains exfiltration intent",
			expected: map[string]interface{}{
				"decision": "deny",
				"reason":   "prompt contains exfiltration intent",
			},
		},
		// Stop: spec-distinct verb. block emits decision:"block" (not
		// "deny"), matching the spec's "block-terminating the agent
		// if validation checks fail" phrasing.
		{
			name:   "Stop_action_mode_block_renders_decision_block",
			event:  "Stop",
			action: "block",
			raw:    "block",
			reason: "validation checks failed; agent must keep running",
			expected: map[string]interface{}{
				"decision": "block",
				"reason":   "validation checks failed; agent must keep running",
			},
		},
		// PostToolUse: cannot block (tool already ran). Alert findings
		// surface as additionalContext for next-turn ingestion.
		{
			name:       "PostToolUse_alert_renders_additionalContext_only",
			event:      "PostToolUse",
			action:     "alert",
			raw:        "alert",
			additional: "Tool output contained API_KEY=sk-...",
			expected:   map[string]interface{}{"additionalContext": "Tool output contained API_KEY=sk-..."},
		},
		// PostInvocation: same as PostToolUse — cannot block, alert
		// surfaces as additionalContext.
		{
			name:       "PostInvocation_alert_renders_additionalContext_only",
			event:      "PostInvocation",
			action:     "alert",
			raw:        "alert",
			additional: "Model response leaked PII",
			expected:   map[string]interface{}{"additionalContext": "Model response leaked PII"},
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
				Caps:              HookCapability{CanAskNative: true, AskEvents: []string{"PreInvocation", "PreToolUse"}},
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

// TestHermesProfileRespond_Parity pins the hermes branch of
// hookOnlyProfileRespond (hermes is wired through the shared responder;
// it has no profile file of its own). Only pre_tool_call blocks
// ({"decision":"block"}); pre_llm_call injects context; every other
// event is observe-only (nil body). Wire parity with the legacy
// hookOutputFor("hermes") shaper and the hermes/verdict-blocked golden
// is intentional — a divergence here ships a silent behavior change.
// Confirm verdicts (hermes has no native ask surface) downgrade via the
// shared epilogue to {"systemMessage":...}.
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
			// Confirm downgrade: hermes CanAskNative=false, so a confirm
			// verdict reaches Respond as action=alert / rawAction=confirm
			// and the shared epilogue surfaces the warning as a
			// systemMessage (the pre-bespoke-profile shipped behavior).
			name:       "pre_tool_call_confirm_downgrades_to_systemMessage",
			event:      "pre_tool_call",
			action:     "alert",
			rawAction:  "confirm",
			additional: "DefenseClaw needs your approval before terminal can run.",
			expected:   map[string]interface{}{"systemMessage": "DefenseClaw needs your approval before terminal can run."},
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

// TestCursorProfileRespond_AlwaysEmitsEnvelope pins the cursor branch
// of hookOnlyProfileRespond. Cursor's hook script is fail-closed on
// empty stdout — a hook that returns nothing gets treated as a hook
// failure and blocks the tool call. That means every code path in the
// cursor case must produce a non-nil Output map, including the plain
// allow case where earlier versions left it nil and every benign
// prompt in Cursor would fail-close.
func TestCursorProfileRespond_AlwaysEmitsEnvelope(t *testing.T) {
	cases := []struct {
		name       string
		action     string
		rawAction  string
		reason     string
		additional string
		expected   map[string]interface{}
	}{
		{
			name:      "block_renders_deny_permission",
			action:    "block",
			rawAction: "block",
			reason:    "matched SEC-AWS-KEY",
			expected: map[string]interface{}{
				"continue":      true,
				"permission":    "deny",
				"user_message":  "matched SEC-AWS-KEY",
				"agent_message": "matched SEC-AWS-KEY",
			},
		},
		{
			name:      "confirm_renders_ask_permission",
			action:    "confirm",
			rawAction: "confirm",
			reason:    "shell command needs approval",
			expected: map[string]interface{}{
				"continue":      true,
				"permission":    "ask",
				"user_message":  "shell command needs approval",
				"agent_message": "shell command needs approval",
			},
		},
		{
			name:       "alert_with_context_renders_allow_with_agent_message",
			action:     "alert",
			rawAction:  "alert",
			additional: "DefenseClaw observed a HIGH cursor finding",
			expected: map[string]interface{}{
				"continue":      true,
				"permission":    "allow",
				"agent_message": "DefenseClaw observed a HIGH cursor finding",
			},
		},
		{
			// Regression guard: an alert with NO AdditionalContext used
			// to fall through to a nil Output map, which produced an
			// empty response body and tripped Cursor's failClosed=true.
			// Must return the default allow envelope so the tool call
			// proceeds and the finding still surfaces via the audit
			// pipeline / other channels.
			name:      "alert_without_context_falls_through_to_allow",
			action:    "alert",
			rawAction: "alert",
			expected: map[string]interface{}{
				"continue":   true,
				"permission": "allow",
			},
		},
		{
			// Regression: plain allow used to leave Output nil, which
			// produced an empty stdout in the hook script and tripped
			// Cursor's failClosed=true guard. Must be a concrete allow.
			name:      "allow_renders_explicit_allow_envelope",
			action:    "allow",
			rawAction: "allow",
			expected: map[string]interface{}{
				"continue":   true,
				"permission": "allow",
			},
		},
		{
			name:      "empty_action_treated_as_allow",
			action:    "",
			rawAction: "",
			expected: map[string]interface{}{
				"continue":   true,
				"permission": "allow",
			},
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := hookOnlyProfileRespond(HookRespondInput{
				Req: HookProfileRequest{
					ConnectorName: "cursor",
					HookEventName: "beforeSubmitPrompt",
				},
				Action:            tc.action,
				RawAction:         tc.rawAction,
				Reason:            tc.reason,
				AdditionalContext: tc.additional,
				Caps: HookCapability{
					CanBlock:     true,
					CanAskNative: true,
				},
			})
			if out.FieldName != "hook_output" {
				t.Errorf("FieldName=%q want hook_output", out.FieldName)
			}
			if out.Output == nil {
				t.Fatalf("cursor Respond must never return nil Output — Cursor fail-closes on empty stdout")
			}
			if !reflect.DeepEqual(out.Output, tc.expected) {
				t.Errorf("Output mismatch\n got: %#v\nwant: %#v", out.Output, tc.expected)
			}
		})
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
