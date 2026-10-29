// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// shellExtraKeyHook sends one host shell tool call through handleAgentHook
// in action mode and returns the response body.
func shellExtraKeyHook(t *testing.T, connectorName, tool string, args json.RawMessage) string {
	t.Helper()
	root := t.TempDir()
	home, project := filepath.Join(root, "home"), filepath.Join(root, "home", "proj")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Chdir(project)
	args = json.RawMessage(strings.ReplaceAll(string(args), "{PROJ}", project))
	var payload map[string]any
	switch connectorName {
	case "opencode":
		payload = map[string]any{"hook_event_name": "tool.execute.before", "tool_name": tool, "tool_input": args,
			"session_id": "s1", "turn_id": "m1", "tool_call_id": "c1", "agent_name": "build", "cwd": project,
			"arguments_authoritative": true, "mcp_identity_status": "not_mcp"}
	case "claudecode", "codex":
		payload = map[string]any{"hook_event_name": "PreToolUse", "session_id": "s1", "turn_id": "t1", "cwd": project,
			"tool_name": tool, "tool_input": args, "tool_use_id": "u1"}
	case "devin":
		payload = map[string]any{"hook_event_name": "PreToolUse", "session_id": "s1", "prompt_id": "p1", "cwd": project,
			"tool_name": tool, "tool_input": args}
	case "kiro":
		payload = map[string]any{"hook_event_name": "preToolUse", "session_id": "s1", "cwd": project,
			"tool_name": tool, "tool_input": args}
	case "hermes":
		payload = map[string]any{"hook_event_name": "pre_tool_call", "session_id": "20260929_1", "cwd": project,
			"tool_name": tool, "tool_input": args, "extra": map[string]any{"tool_call_id": "call_1", "task_id": "t1"}}
	default:
		t.Fatalf("no payload for %s", connectorName)
	}
	body := mustJSON(t, payload)
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connectorName
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+connectorName+"/hook", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookpaths.Header, hookpaths.Resolve(body))
	if connectorName == "codex" {
		setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
	}
	req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connectorName).ServeHTTP(recorder, req)
	return recorder.Body.String()
}

// TestShellToolCallWithExtraArgumentKeys: an argument key next to command
// that the connector's projection does not know left the parse partial, so
// the command reached no rule and was allowed while the same call without
// that key blocked (GAP-0686). The command is now judged on its own.
func TestShellToolCallWithExtraArgumentKeys(t *testing.T) {
	const rm = `"rm -rf ~/"`
	for _, shell := range []struct{ connector, tool, workdir string }{
		{"opencode", "shell", "workdir"},
		{"claudecode", "Bash", "workdir"},
		{"devin", "exec", "workdir"},
		{"kiro", "execute_bash", "working_dir"},
		{"kiro", "shell", "working_dir"},
		{"hermes", "terminal", "workdir"},
		{"codex", "Bash", "workdir"},
	} {
		upper := strings.ToUpper(shell.workdir[:1]) + shell.workdir[1:]
		for _, row := range []struct {
			name, args, rule string
		}{
			{"alone", `{"command":` + rm + `}`, "CMD-RM-RF"},
			{"extra", `{"command":` + rm + `,"extra":"x"}`, "CMD-RM-RF"},
			{"timeout-case", `{"command":` + rm + `,"Timeout":5000}`, "CMD-RM-RF"},
			{"workdir-case", `{"command":` + rm + `,"` + upper + `":"{PROJ}"}`, "CMD-RM-RF"},
			{"command-case-extra", `{"command":` + rm + `,"Command":"true","extra":"x"}`, "CMD-RM-RF"},
			// Two keys for the command stay a conflict (GAP-0678).
			{"command-case-value-extra", `{"command":"true","Command":` + rm + `,"extra":"x"}`, conflictingToolArgumentsRuleID},
			// No single command argument to judge: conservative block.
			{"no-command-key", `{"Command":` + rm + `,"extra":"x"}`, unverifiedShellCommandRuleID},
			{"extra-only", `{"extra":"x"}`, unverifiedShellCommandRuleID},
			{"number-command", `{"command":7,"extra":"x"}`, unverifiedShellCommandRuleID},
			{"null-command", `{"command":null,"extra":"x"}`, unverifiedShellCommandRuleID},
			{"blank-command", `{"command":"  ","extra":"x"}`, unverifiedShellCommandRuleID},
			{"object-command", `{"command":{"cmd":` + rm + `},"extra":"x"}`, unverifiedShellCommandRuleID},
			{"empty-args", `{}`, unverifiedShellCommandRuleID},
			{"benign", `{"command":"ls","description":"x","timeout":5}`, "allow"},
			{"benign-extra", `{"command":"ls","extra":"x"}`, "allow"},
		} {
			t.Run(shell.connector+"/"+shell.tool+"/"+row.name, func(t *testing.T) {
				got := shellExtraKeyHook(t, shell.connector, shell.tool, json.RawMessage(row.args))
				if row.rule == "allow" {
					if !strings.HasPrefix(got, `{"action":"allow"`) {
						t.Fatalf("benign call = %.600s", got)
					}
					return
				}
				if !strings.HasPrefix(got, `{"action":"block"`) || !strings.Contains(got, row.rule) {
					t.Fatalf("verdict = %.600s; want block with %q", got, row.rule)
				}
			})
		}
	}
}
