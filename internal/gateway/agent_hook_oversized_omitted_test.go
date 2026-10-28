// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

// Loop round 2 review of 06bb83dd (GAP-1022): a bounded review keeps only a
// head of a Write's file text, so a configured rule matching past the head
// (a migrated literal) was never checked, and action mode allowed the call
// that rel/1.0.4 blocked. The review is marked like every bounded review and
// blocked in action mode; a review that carries bounded_prefix_review but
// not the marker is treated the same. Observe mode (the balanced default)
// keeps the benign write allowed with the warning.
func TestOversizedWriteReviewIsNeverAllowedAsInspected(t *testing.T) {
	full := `{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Write","tool_input":{"file_path":"/w/notes.txt","content":"` +
		strings.Repeat("a", 20<<10) + "DC-MIGRATED-LITERAL-7f3a" + strings.Repeat("p", 2<<20) + `"}}`
	review := string(hookexec.OversizedReviewPayload([]byte(full[:hookexec.DefaultMaxBody]), "PreToolUse"))
	marker := `"` + hookexec.OversizeUninspectedField + `":true,`
	unmarked := strings.Replace(review, marker, "", 1)
	if unmarked == review || !json.Valid([]byte(unmarked)) || strings.Contains(review, "DC-MIGRATED-LITERAL-7f3a") {
		t.Fatalf("review shape: marked=%v valid=%v: %.300s", unmarked != review, json.Valid([]byte(unmarked)), review)
	}
	for _, tc := range []struct {
		name, mode, body, want string
	}{
		{"observe allows the write with the warning", "observe", review, "allow"},
		{"action blocks the write", "action", review, "block"},
		{"observe allows an unmarked review with the warning", "observe", unmarked, "allow"},
		{"action blocks an unmarked review", "action", unmarked, "block"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = tc.mode
			cfg.Guardrail.Connector = "claudecode"
			store, logger := testStoreAndLogger(t)
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
			request := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(tc.body))
			request.Header.Set("Content-Type", "application/json")
			reply := httptest.NewRecorder()
			api.handleAgentHook("claudecode").ServeHTTP(reply, request)
			var answer agentHookResponse
			if err := json.Unmarshal(reply.Body.Bytes(), &answer); err != nil {
				t.Fatalf("status=%d body=%.300s", reply.Code, reply.Body.String())
			}
			if answer.Action != tc.want {
				t.Fatalf("action=%q, want %q: %.400s", answer.Action, tc.want, reply.Body.String())
			}
			if answer.Severity != "HIGH" || !strings.Contains(answer.Reason, "oversize, command not inspected") ||
				!strings.Contains(strings.Join(answer.Findings, ","), hookOversizeUninspectedRuleID) {
				t.Fatalf("answer lacks the uninspected finding: %+v", answer)
			}
		})
	}
}

// The per-user shell inspect hooks (inspect-tool.sh, inspect-tool-response.sh,
// inspect-request.sh, inspect-response.sh) send the bounded review of a call
// over their cap with bounded_prefix_review. The generic inspect endpoints
// ignored it, so action mode allowed what they read only in part. Each now
// warns and audits it in observe mode and blocks it in action mode; a call
// without the field is unchanged.
func TestGenericInspectBoundedReviewIsNeverAllowedAsInspected(t *testing.T) {
	type route struct {
		name, path, body string
		handle           func(*APIServer, http.ResponseWriter, *http.Request)
	}
	routes := []route{
		{"tool", "/api/v1/inspect/tool", `{"tool":"write_file","args":{"path":"/w/notes.txt","content":"aaaa"}`,
			func(a *APIServer, w http.ResponseWriter, r *http.Request) { a.handleInspectTool(w, r) }},
		{"tool response", "/api/v1/inspect/tool-response", `{"tool":"read_file","output":"aaaa"`,
			func(a *APIServer, w http.ResponseWriter, r *http.Request) { a.handleInspectToolResponse(w, r) }},
		{"request", "/api/v1/inspect/request", `{"content":"aaaa"`,
			func(a *APIServer, w http.ResponseWriter, r *http.Request) { a.handleInspectRequest(w, r) }},
		{"response", "/api/v1/inspect/response", `{"content":"aaaa"`,
			func(a *APIServer, w http.ResponseWriter, r *http.Request) { a.handleInspectResponse(w, r) }},
	}
	for _, rt := range routes {
		for _, tc := range []struct {
			mode      string
			bounded   bool
			want      string
			wouldWarn bool
		}{
			{"observe", false, "allow", false},
			{"action", false, "allow", false},
			{"observe", true, "allow", true},
			{"action", true, "block", true},
		} {
			name := rt.name + "/" + tc.mode
			if tc.bounded {
				name += "/bounded"
			}
			t.Run(name, func(t *testing.T) {
				api := testAPIServerWithConfig(t, tc.mode)
				body := rt.body + `}`
				if tc.bounded {
					body = rt.body + `,"content_truncated":true,"bounded_prefix_review":true}`
				}
				request := httptest.NewRequest(http.MethodPost, rt.path, bytes.NewBufferString(body))
				request.Header.Set("Content-Type", "application/json")
				reply := httptest.NewRecorder()
				rt.handle(api, reply, request)
				var verdict ToolInspectVerdict
				if err := json.Unmarshal(reply.Body.Bytes(), &verdict); err != nil {
					t.Fatalf("status=%d body=%.300s", reply.Code, reply.Body.String())
				}
				if verdict.Action != tc.want {
					t.Fatalf("action=%q, want %q: %.400s", verdict.Action, tc.want, reply.Body.String())
				}
				uninspected := strings.Contains(strings.Join(verdict.Findings, ","), hookOversizeUninspectedRuleID)
				if uninspected != tc.wouldWarn {
					t.Fatalf("uninspected finding=%v, want %v: %.400s", uninspected, tc.wouldWarn, reply.Body.String())
				}
				if tc.mode == "observe" && tc.bounded && (!verdict.WouldBlock || verdict.Reason != oversizeUninspectedReason) {
					t.Fatalf("observe answer must warn: %+v", verdict)
				}
			})
		}
	}
}
