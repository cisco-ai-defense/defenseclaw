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
	"strings"
	"testing"
)

// Claude Code shows the native ask only in default (Manual) mode; every other
// mode, and a missing one, turns a PreToolUse confirmation into a deny that
// says how to approve (GAP-0371).
func TestClaudeCodeConfirmPerPermissionMode(t *testing.T) {
	caps := HookCapability{CanBlock: true, CanAskNative: true, AskEvents: []string{"PreToolUse"}}
	for _, tc := range []struct{ mode, wantAction, wantDecision string }{
		{"default", "confirm", "ask"},
		{"acceptEdits", "block", "deny"},
		{"bypassPermissions", "block", "deny"},
		{"dontAsk", "block", "deny"},
		{"auto", "block", "deny"},
		{"plan", "block", "deny"},
		{"manual", "block", "deny"},
		{"", "block", "deny"},
	} {
		t.Run("mode="+tc.mode, func(t *testing.T) {
			payload := map[string]interface{}{"hook_event_name": "PreToolUse"}
			if tc.mode != "" {
				payload["permission_mode"] = tc.mode
			}
			out := claudeCodeProfileMapVerdict(HookVerdictInput{
				RawAction: "confirm", Event: "PreToolUse", Mode: "action", Caps: caps, Payload: payload,
			})
			if out.Action != tc.wantAction || out.WouldBlock {
				t.Fatalf("MapVerdict = %+v, want %s", out, tc.wantAction)
			}
			resp := claudeCodeProfileRespond(HookRespondInput{
				Req:       HookProfileRequest{ConnectorName: "claudecode", HookEventName: "PreToolUse", Payload: payload},
				Action:    out.Action,
				RawAction: "confirm",
				Reason:    "DefenseClaw policy needs your confirmation for this action.",
			})
			hso, _ := resp.Output["hookSpecificOutput"].(map[string]interface{})
			if hso["hookEventName"] != "PreToolUse" || hso["permissionDecision"] != tc.wantDecision {
				t.Fatalf("output = %#v, want PreToolUse %s", resp.Output, tc.wantDecision)
			}
			reason, _ := hso["permissionDecisionReason"].(string)
			if !strings.HasPrefix(reason, "DefenseClaw policy needs your confirmation") {
				t.Fatalf("reason %q lost the confirmation wording", reason)
			}
			if hasHint := strings.Contains(reason, "switch Claude Code to Manual mode"); hasHint != (tc.wantDecision == "deny") {
				t.Fatalf("reason %q: next step present=%v, want %v", reason, hasHint, tc.wantDecision == "deny")
			}
		})
	}
}

func TestClaudeCodeNoAskReasonIsIdempotent(t *testing.T) {
	once := ClaudeCodeNoAskReason("needs approval", "acceptEdits")
	if twice := ClaudeCodeNoAskReason(once, "acceptEdits"); twice != once {
		t.Fatalf("second pass changed the reason:\n%q\n%q", once, twice)
	}
	if !strings.Contains(once, "acceptEdits mode") || !strings.HasPrefix(once, "needs approval ") {
		t.Fatalf("reason = %q", once)
	}
	if got := ClaudeCodeNoAskReason("", ""); !strings.Contains(got, "this permission mode") {
		t.Fatalf("empty mode reason = %q", got)
	}
}
