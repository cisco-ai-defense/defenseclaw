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

// Copilot CLI's native PermissionRequest carries a shell call's command in
// toolInput, as captured from Copilot CLI 1.0.103:
//
//	{"hookName":"permissionRequest","sessionId":"...","timestamp":...,
//	 "cwd":"...","permissionSuggestions":[],"toolName":"powershell",
//	 "toolInput":{"command":"echo dc-ok"}}
//
// T7 projected toolInput only for an edit's diff, so every shell call had no
// command to verify and the interactive approval blocked echo ok and pwd with
// TOOL-ARGS-UNVERIFIED on Linux, macOS and Windows (rel-1-0-4 GAP-0636,
// GAP-0638, GAP-0646, GAP-0648). The command is judged as PreToolUse judges
// it: benign calls allow, a protected write blocks, and a call whose command
// cannot be read stays blocked as unverified.
func TestCopilotPermissionRequestShellJudgesToolInputCommand(t *testing.T) {
	for _, row := range []struct {
		name       string
		tool       string
		input      any
		extra      map[string]any
		want       string
		wantReason string
	}{
		{name: "bash echo ok", tool: "bash", input: map[string]any{"command": "echo ok"}, want: "allow"},
		{name: "bash pwd", tool: "bash", input: map[string]any{"command": "pwd"}, want: "allow"},
		{name: "powershell echo ok", tool: "powershell", input: map[string]any{"command": "echo ok"}, want: "allow"},
		{name: "bash append to authorized_keys", tool: "bash",
			input: map[string]any{"command": "printf 'ssh-ed25519 AAAA marker\\n' >> ~/.ssh/authorized_keys"}, want: "block"},
		{name: "bash with no command", tool: "bash", input: map[string]any{"description": "Run echo"},
			want: "block", wantReason: unverifiedShellCommandRuleID},
		{name: "bash command not a string", tool: "bash", input: map[string]any{"command": 42},
			want: "block", wantReason: unverifiedShellCommandRuleID},
		{name: "bash toolInput null", tool: "bash", input: nil,
			want: "block", wantReason: unverifiedShellCommandRuleID},
		{name: "bash toolInput and a different toolArgs", tool: "bash", input: map[string]any{"command": "echo ok"},
			extra: map[string]any{"toolArgs": map[string]any{"command": "echo ok"}}, want: "block"},
	} {
		t.Run(row.name, func(t *testing.T) {
			body := map[string]any{
				"hookName":              "permissionRequest",
				"sessionId":             "s-" + strings.ReplaceAll(row.name, " ", "-"),
				"timestamp":             1792671292481,
				"cwd":                   t.TempDir(),
				"permissionSuggestions": []any{},
				"toolName":              row.tool,
				"toolInput":             row.input,
			}
			for key, value := range row.extra {
				body[key] = value
			}
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "copilot"
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(string(mustJSON(t, body))))
			req.Header.Set("Content-Type", "application/json")
			req.Header.Set("X-DefenseClaw-Copilot-Event", "permissionRequest")
			recorder := httptest.NewRecorder()
			api.handleAgentHook("copilot").ServeHTTP(recorder, req)
			var verdict map[string]any
			if err := json.Unmarshal(recorder.Body.Bytes(), &verdict); err != nil {
				t.Fatalf("verdict %q: %v", recorder.Body.String(), err)
			}
			if verdict["action"] != row.want {
				t.Fatalf("action = %v, want %s: %.800s", verdict["action"], row.want, recorder.Body.String())
			}
			if row.wantReason != "" && !strings.Contains(recorder.Body.String(), row.wantReason) {
				t.Fatalf("verdict does not name %s: %.800s", row.wantReason, recorder.Body.String())
			}
		})
	}
}
