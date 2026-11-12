// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// TestRecoveredParseHookCallIsGradedWithoutClientEvidence drives the hook
// handler as a per-user hook does: the body alone, with no client write
// evidence header. A call whose reading ends at the recovered-parse proof
// bound (a statement the reader cannot parse glued to a removal of the
// DefenseClaw state folder) gets the evaluation-limit finding the profile
// decides, as it does when a managed hook client reports the same bound: it
// alerts in default and blocks in strict (rel-1-0-6:GAP-0534). An ordinary
// call allows in both profiles.
func TestRecoveredParseHookCallIsGradedWithoutClientEvidence(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home reading; the Windows reader parses the whole call")
	}
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	stateDir := filepath.Join(home, ".defenseclaw")
	for _, dir := range []string{cwd, stateDir} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(stateDir, "config.yaml"), []byte("enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	const recovered = `Write-Output $(.\a[1]<#x#>); Remove-Item -Recurse -Force ~/.defenseclaw`
	rows := []struct {
		name, command, posture, want string
	}{
		{"state folder/default", recovered, "default", guardrailActionAlert},
		{"state folder/strict", recovered, "strict", guardrailActionBlock},
		{"ordinary/default", "Get-ChildItem -Name", "default", guardrailActionAllow},
		{"ordinary/strict", "Get-ChildItem -Name", "strict", guardrailActionAllow},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, row := range rows {
			t.Run(connector+"/"+row.name, func(t *testing.T) {
				api := instructionProtectionTestAPIWithPack(t, connector, "action", "HIGH", row.posture)
				api.health = NewSidecarHealth()
				body := map[string]any{"session_id": "recovered", "hook_event_name": "PreToolUse", "cwd": cwd,
					"tool_name": "PowerShell", "tool_input": map[string]any{"command": row.command},
					"tool_use_id": "toolu_recovered", "permission_mode": "default"}
				if connector == "codex" {
					body["tool_name"], body["tool_input"] = "exec_command", map[string]any{"cmd": row.command}
					body["turn_id"], body["model"] = "t-recovered", "test"
				}
				req := httptest.NewRequest(http.MethodPost, "/api/v1/hook", strings.NewReader(string(mustJSON(t, body))))
				if connector == "codex" {
					setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
				}
				recorder := httptest.NewRecorder()
				api.handleAgentHook(connector).ServeHTTP(recorder, req)
				var answer agentHookResponse
				if err := json.Unmarshal(recorder.Body.Bytes(), &answer); err != nil {
					t.Fatalf("status %d answer %.300s: %v", recorder.Code, recorder.Body.String(), err)
				}
				if answer.Action != row.want {
					t.Fatalf("action = %q (raw %q), want %q; findings %v", answer.Action, answer.RawAction, row.want, answer.Findings)
				}
			})
		}
	}
}
