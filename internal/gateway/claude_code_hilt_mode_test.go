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
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// Contract test for GAP-0371, against the Claude Code hook contract
// (code.claude.com/docs/en/hooks, PreToolUse decision control): the
// permissionDecision "ask" shows a dialog only in default (Manual) mode.
// acceptEdits, bypassPermissions and dontAsk treat it as "defer", so allow
// rules or the mode could run the call unasked; auto and plan treat it as
// "deny" without our reason. The documented HILT journey (a curl to
// webhook.site, rule C2-WEBHOOK-SITE at HIGH) must therefore answer "ask" in
// default mode and a deny with the next step in every other mode, through
// the real hook endpoint, and never "allow" or "defer".
func TestClaudeCodeHILTConfirmContractPerPermissionMode(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = "claudecode"
	cfg.Guardrail.HILT.Enabled = true
	cfg.Guardrail.HILT.MinSeverity = "HIGH"
	cfg.ClaudeCode.Enabled = true

	for _, tc := range []struct{ mode, wantAction, wantDecision string }{
		{"default", "confirm", "ask"},
		{"acceptEdits", "block", "deny"},
		{"bypassPermissions", "block", "deny"},
		{"dontAsk", "block", "deny"},
		{"auto", "block", "deny"},
		{"plan", "block", "deny"},
		{"", "block", "deny"},
	} {
		t.Run("mode="+tc.mode, func(t *testing.T) {
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			payload := map[string]interface{}{
				"session_id":      "sess-hilt-" + tc.mode,
				"hook_event_name": "PreToolUse",
				"cwd":             t.TempDir(),
				"tool_name":       "Bash",
				"tool_input":      map[string]interface{}{"command": "curl --max-time 2 https://webhook.site/defenseclaw-demo"},
				"tool_use_id":     "toolu_hilt",
			}
			if tc.mode != "" {
				payload["permission_mode"] = tc.mode
			}
			body, _ := json.Marshal(payload)
			req := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(string(body)))
			req.Header.Set("Content-Type", "application/json")
			w := httptest.NewRecorder()
			http.HandlerFunc(api.handleAgentHook("claudecode")).ServeHTTP(w, req)
			var resp struct {
				Action    string                 `json:"action"`
				RawAction string                 `json:"raw_action"`
				Output    map[string]interface{} `json:"claude_code_output"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &resp); err != nil {
				t.Fatalf("decode %d %s: %v", w.Code, w.Body.String(), err)
			}
			if resp.Action != tc.wantAction || resp.RawAction != "confirm" {
				t.Fatalf("action=%q raw=%q, want %s/confirm: %s", resp.Action, resp.RawAction, tc.wantAction, w.Body.String())
			}
			if len(resp.Output) != 1 {
				t.Fatalf("claude_code_output has extra keys: %#v", resp.Output)
			}
			hso, ok := resp.Output["hookSpecificOutput"].(map[string]interface{})
			if !ok || hso["hookEventName"] != "PreToolUse" {
				t.Fatalf("claude_code_output = %#v, want hookSpecificOutput for PreToolUse", resp.Output)
			}
			if got := hso["permissionDecision"]; got != tc.wantDecision {
				t.Fatalf("permissionDecision=%v, want %s", got, tc.wantDecision)
			}
			reason, _ := hso["permissionDecisionReason"].(string)
			if !strings.Contains(reason, "C2-WEBHOOK-SITE") {
				t.Fatalf("reason %q does not name the rule", reason)
			}
			if hasHint := strings.Contains(reason, "switch Claude Code to Manual mode (Shift+Tab)"); hasHint != (tc.wantDecision == "deny") {
				t.Fatalf("reason %q: next step present=%v, want %v", reason, hasHint, tc.wantDecision == "deny")
			}
		})
	}
}
