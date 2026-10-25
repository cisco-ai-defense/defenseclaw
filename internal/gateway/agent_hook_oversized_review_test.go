// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector/hookexec"
)

func TestBoundedPrefixAllowHasHighAuditSeverity(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Connector = "claudecode"
	store, logger := testStoreAndLogger(t)
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/claude-code/hook", strings.NewReader(`{
		"hook_event_name":"PreToolUse", "session_id":"s", "tool_name":"Bash",
		"tool_input":{"command":"echo safe"}, "bounded_prefix_review":true,
		"content_truncated":true}`))
	request.Header.Set("Content-Type", "application/json")
	reply := httptest.NewRecorder()
	api.handleAgentHook("claudecode").ServeHTTP(reply, request)
	if reply.Code != http.StatusOK {
		t.Fatalf("status=%d body=%q", reply.Code, reply.Body.String())
	}
	var answer agentHookResponse
	if err := json.Unmarshal(reply.Body.Bytes(), &answer); err != nil {
		t.Fatal(err)
	}
	if answer.Action != "allow" || answer.Severity != "HIGH" {
		t.Fatalf("bounded allow = %+v", answer)
	}
	events, err := store.ListEvents(20)
	if err != nil {
		t.Fatal(err)
	}
	for _, event := range events {
		if event.Action == string(audit.ActionConnectorHook) && event.Severity == "HIGH" {
			return
		}
	}
	t.Fatalf("no HIGH connector-hook audit row: %+v", events)
}

// An oversized call keeps every command and target field in its bounded
// review, wherever the connector puts it (Amp and Codex exec_command "cmd",
// Cursor's top-level command, Copilot's toolArgs string,
// apply_patch input, a Write whose content comes first) and whatever long
// value sits before it or is cut after it. The gateway then gives the review
// the same verdict as the call at normal size: a protected target blocks in
// action mode, and observe mode audits the call with its command.
func TestOversizedReviewKeepsEveryConnectorsCommandForTheGatewayVerdict(t *testing.T) {
	const protected = "echo marker >> ~/.ssh/authorized_keys"
	quoted := strconv.Quote(protected)
	long := strings.Repeat("d", 20<<10)
	for _, tc := range []struct {
		name, connector, path, header, event, body string
	}{
		{"claude bash after a long description", "claudecode", "claude-code", "", "",
			`{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Bash","tool_input":{"description":"` + long + `","command":CMD},"padding":"PAD"}`},
		{"codex exec_command cmd", "codex", "codex", "X-DefenseClaw-Hook-Event", "PreToolUse",
			`{"hook_event_name":"PreToolUse","session_id":"s","turn_id":"t","tool_name":"exec_command","tool_input":{"justification":"` + long + `","cmd":CMD,"workdir":"/tmp"},"padding":"PAD"}`},
		{"amp bash cmd", "amp", "amp", "", "",
			`{"hook_event_name":"tool.call","session_id":"s","thread_id":"s","tool_call_id":"c","tool_name":"Bash","tool_input":{"cmd":CMD},"padding":"PAD"}`},
		{"cursor shell command", "cursor", "cursor", "", "",
			`{"hook_event_name":"beforeShellExecution","conversation_id":"c","generation_id":"g","command":CMD,"cwd":"/tmp","padding":"PAD"}`},
		{"opencode bash command", "opencode", "opencode", "", "",
			`{"hook_event_name":"tool.execute.before","session_id":"s","tool_name":"bash","tool_input":{"command":CMD},"padding":"PAD"}`},
		{"claude write with content first", "claudecode", "claude-code", "", "",
			`{"hook_event_name":"PreToolUse","session_id":"s","tool_name":"Write","tool_input":{"content":"` + long + `","file_path":"/home/alice/.ssh/authorized_keys"},"padding":"PAD"}`},
		{"copilot toolArgs cut by the cap", "copilot", "copilot", "X-DefenseClaw-Copilot-Event", "preToolUse",
			`{"sessionId":"s","toolName":"bash","toolArgs":"{\"command\":` + strings.ReplaceAll(quoted, `"`, `\"`) + `,\"description\":\"PAD\"}"}`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			full := strings.Replace(strings.Replace(tc.body, "CMD", quoted, 1), "PAD", strings.Repeat("p", 2<<20), 1)
			normal := strings.Replace(strings.Replace(tc.body, "CMD", quoted, 1), "PAD", "p", 1)
			// Copilot carries its event in a header, never in the body.
			bound := tc.event
			if tc.connector == "copilot" {
				bound = ""
			}
			review := hookexec.OversizedReviewPayload([]byte(full[:hookexec.DefaultMaxBody]), bound)
			if review == nil || !strings.Contains(string(review), "authorized_keys") {
				t.Fatalf("bounded review lost the command or target: %.400s", review)
			}
			for _, mode := range []string{"action", "observe"} {
				for _, body := range []string{normal, string(review)} {
					cfg := &config.Config{}
					cfg.Guardrail.Mode = mode
					cfg.Guardrail.Connector = tc.connector
					store, logger := testStoreAndLogger(t)
					api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth(), store: store, logger: logger}
					request := httptest.NewRequest(http.MethodPost, "/api/v1/"+tc.path+"/hook", strings.NewReader(body))
					request.Header.Set("Content-Type", "application/json")
					if tc.header != "" {
						request.Header.Set(tc.header, tc.event)
					}
					if tc.connector == "codex" {
						setTestCodexHookBinding(request, tc.event, defaultTestCodexHookContract)
					}
					reply := httptest.NewRecorder()
					api.handleAgentHook(tc.connector).ServeHTTP(reply, request)
					var answer struct {
						Action    string `json:"action"`
						RawAction string `json:"raw_action"`
					}
					if err := json.Unmarshal(reply.Body.Bytes(), &answer); err != nil {
						t.Fatalf("%s: status=%d body=%.300s", mode, reply.Code, reply.Body.String())
					}
					kind := "normal"
					if body != normal {
						kind = "bounded review"
					}
					if mode == "action" && answer.Action != "block" {
						t.Fatalf("action mode %s = %.400s, want block", kind, reply.Body.String())
					}
					if mode == "observe" {
						events, err := store.ListEvents(50)
						if err != nil {
							t.Fatal(err)
						}
						found := false
						for _, event := range events {
							found = found || strings.Contains(event.Details, "authorized_keys")
						}
						if !found {
							t.Fatalf("observe mode %s audit has no command or target: %.300s", kind, reply.Body.String())
						}
					}
				}
			}
		})
	}
}
