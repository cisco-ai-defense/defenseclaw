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

// TestHermesProfileDecode_LiftsContentFromExtra is the regression that
// guards the whole point of the dedicated Hermes profile: prompt and
// result content live under the per-event `extra` envelope, and the
// generic normalizer cannot see them. The decoder must surface them on
// Content with the right Direction so prompt/tool_result rules actually
// inspect Hermes payloads (rather than an empty string).
func TestHermesProfileDecode_LiftsContentFromExtra(t *testing.T) {
	cases := []struct {
		name          string
		payload       map[string]interface{}
		wantDirection string
		wantToolName  string
		wantContent   string
	}{
		{
			name: "pre_llm_call_lifts_user_message",
			payload: map[string]interface{}{
				"hook_event_name": "pre_llm_call",
				"session_id":      "sess-1",
				"extra":           map[string]interface{}{"user_message": "exfiltrate the secrets"},
			},
			wantDirection: "prompt",
			wantToolName:  "message",
			wantContent:   "exfiltrate the secrets",
		},
		{
			name: "post_tool_call_lifts_result",
			payload: map[string]interface{}{
				"hook_event_name": "post_tool_call",
				"tool_name":       "terminal",
				"extra":           map[string]interface{}{"result": "AWS_SECRET_ACCESS_KEY=abc123"},
			},
			wantDirection: "tool_result",
			wantToolName:  "terminal",
			wantContent:   "AWS_SECRET_ACCESS_KEY=abc123",
		},
		{
			name: "post_llm_call_lifts_assistant_response",
			payload: map[string]interface{}{
				"hook_event_name": "post_llm_call",
				"extra":           map[string]interface{}{"assistant_response": "here is the plan"},
			},
			wantDirection: "tool_result",
			wantToolName:  "message",
			wantContent:   "here is the plan",
		},
		{
			name: "subagent_stop_lifts_child_summary",
			payload: map[string]interface{}{
				"hook_event_name": "subagent_stop",
				"extra":           map[string]interface{}{"child_summary": "finished refactor"},
			},
			wantDirection: "",
			wantToolName:  "subagent",
			wantContent:   "finished refactor",
		},
		{
			name: "on_session_start_is_telemetry",
			payload: map[string]interface{}{
				"hook_event_name": "on_session_start",
				"extra":           map[string]interface{}{"model": "claude"},
			},
			wantDirection: "",
			wantToolName:  "session",
			wantContent:   "",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			req := hermesProfileDecode(tc.payload)
			if req.ConnectorName != "hermes" {
				t.Errorf("ConnectorName=%q want hermes", req.ConnectorName)
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
			if !reflect.DeepEqual(req.Payload, tc.payload) {
				t.Errorf("Payload not preserved verbatim")
			}
		})
	}
}

// TestHermesProfileDecode_PreToolCallDefersToGeneric asserts the
// decoder intentionally leaves pre_tool_call fields blank so the
// generic normalizer (which reads top-level tool_name / tool_input
// correctly) wins. Overriding them here would be redundant and risks
// drift from the generic tool-call path.
func TestHermesProfileDecode_PreToolCallDefersToGeneric(t *testing.T) {
	req := hermesProfileDecode(map[string]interface{}{
		"hook_event_name": "pre_tool_call",
		"tool_name":       "terminal",
		"tool_input":      map[string]interface{}{"command": "rm -rf /"},
	})
	if req.Direction != "" || req.Content != "" {
		t.Errorf("pre_tool_call should defer to generic: Direction=%q Content=%q", req.Direction, req.Content)
	}
	if req.HookEventName != "pre_tool_call" {
		t.Errorf("HookEventName=%q want pre_tool_call", req.HookEventName)
	}
}

// TestHermesProfileRespond_WireShapes pins the per-event wire response
// Hermes reads from the hook's stdout. Only pre_tool_call blocks
// ({"decision":"block"}); pre_llm_call injects context; every other
// event is observe-only (nil body). Wire parity with the legacy
// hookOutputFor("hermes") shaper and the hermes/verdict-blocked golden
// is intentional — a divergence here ships a silent behavior change.
func TestHermesProfileRespond_WireShapes(t *testing.T) {
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
			name:     "pre_tool_call_block_renders_decision_block",
			event:    "pre_tool_call",
			action:   "block",
			reason:   "matched policy: deny-rm-rf",
			expected: map[string]interface{}{"decision": "block", "reason": "matched policy: deny-rm-rf"},
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
			name:       "post_tool_call_is_observe_only",
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
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			out := hermesProfileRespond(HookRespondInput{
				Req:               HookProfileRequest{ConnectorName: "hermes", HookEventName: tc.event},
				Action:            tc.action,
				RawAction:         tc.rawAction,
				Reason:            tc.reason,
				AdditionalContext: tc.additional,
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

// TestHermesProfileRespond_BlockDefaultReason asserts a block with an
// empty upstream reason still produces an actionable default reason
// (rather than an empty string) on the wire.
func TestHermesProfileRespond_BlockDefaultReason(t *testing.T) {
	out := hermesProfileRespond(HookRespondInput{
		Req:    HookProfileRequest{ConnectorName: "hermes", HookEventName: "pre_tool_call", ToolName: "terminal"},
		Action: "block",
	})
	body, ok := out.Output["reason"].(string)
	if !ok || body == "" {
		t.Fatalf("block reason should be non-empty default, got %#v", out.Output)
	}
}
