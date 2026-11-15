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
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A Copilot apply_patch that adds TypeScript calling RegExp.exec is not an
// unsafe command execution; the same patch calling child_process.exec still
// alerts (CI #1456 gw17, TestCopilotNativeBenignCorpus on Windows, where the
// corpus case runs).
func TestCopilotPatchRegExpExecIsNotCommandExecution(t *testing.T) {
	patch := func(body string) string {
		return "*** Begin Patch\n*** Add File: /tmp/proj/src/parser.ts\n+" +
			strings.ReplaceAll(body, "\n", "\n+") + "\n*** End Patch\n"
	}
	for _, tc := range []struct {
		name, body, want string
	}{
		{"regexp exec", "const logLinePattern = /^(INFO|WARN)\\s+(.+)$/;\nexport const parse = (line: string) => logLinePattern.exec(line.trim());", "allow"},
		{"child_process exec", "import * as child_process from \"child_process\";\nexport const run = (cmd: string) => child_process.exec(cmd);", "alert"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			input := map[string]any{
				"sessionId": "wred3",
				"cwd":       "/tmp/proj",
				"toolCalls": []any{map[string]any{"id": "call_1", "name": "apply_patch", "args": patch(tc.body)}},
			}
			body, err := json.Marshal(input)
			if err != nil {
				t.Fatal(err)
			}
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = "copilot"
			api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
			req := httptest.NewRequest(http.MethodPost, "/api/v1/copilot/hook", strings.NewReader(string(body)))
			req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
			req.Header.Set(hookpaths.Header, hookpaths.ResolveConnector("copilot", "", "preToolUse", body))
			w := httptest.NewRecorder()
			api.handleAgentHook("copilot").ServeHTTP(w, req)
			var verdict struct {
				Action string `json:"action"`
			}
			if err := json.Unmarshal(w.Body.Bytes(), &verdict); err != nil {
				t.Fatal(err)
			}
			if verdict.Action != tc.want {
				t.Fatalf("action=%s, want %s: %s", verdict.Action, tc.want, w.Body.String())
			}
		})
	}
}
