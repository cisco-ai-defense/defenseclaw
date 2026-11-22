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

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// shellExtraKeyHookTier is shellExtraKeyHook through the hook route of api
// (one tier of the bound rule, gap0589TierAPI). It returns the response body.
func shellExtraKeyHookTier(t *testing.T, api *APIServer, connectorName, tool string, args json.RawMessage) string {
	t.Helper()
	root := t.TempDir()
	home, project := filepath.Join(root, "home"), filepath.Join(root, "home", "proj")
	if err := os.MkdirAll(project, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Chdir(project)
	var payload map[string]any
	switch connectorName {
	case "opencode":
		payload = map[string]any{"hook_event_name": "tool.execute.before", "tool_name": tool, "tool_input": args,
			"session_id": "s1", "turn_id": "m1", "tool_call_id": "c1", "agent_name": "build", "cwd": project,
			"arguments_authoritative": true, "mcp_identity_status": "not_mcp"}
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
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+connectorName+"/hook", strings.NewReader(string(body)))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookpaths.Header, hookpaths.Resolve(body))
	req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connectorName).ServeHTTP(recorder, req)
	return recorder.Body.String()
}

// TestShellToolCallWithTwoCommandKeysInEveryTier: a shell call that spells
// the command key twice with two values, or only in a spelling the
// projection does not take, cannot be verified. Both readings are judged:
// the conservative finding (TOOL-ARGS-CONFLICT for two spellings,
// TOOL-ARGS-UNVERIFIED for no single command key) is always in the answer,
// and the strictest finding a reading proves stays beside it, so the
// recursive delete of the home blocks with both CMD-RM-RF and the
// conservative finding, in every tier. A benign call with two spellings or
// with no command key is never a clean allow (rel-1-0-10:GAP-0833,
// GAP-0863, GAP-0678, GAP-0686).
func TestShellToolCallWithTwoCommandKeysInEveryTier(t *testing.T) {
	const rm = `"rm -rf ~/"`
	shells := []struct{ connector, tool string }{
		{"opencode", "shell"}, {"devin", "exec"}, {"kiro", "execute_bash"},
		{"kiro", "execute_pwsh"}, {"kiro", "shell"}, {"hermes", "terminal"},
	}
	rows := []struct {
		name, args, conservative, proven string
	}{
		{"command-case-value-extra", `{"command":"true","Command":` + rm + `,"extra":"x"}`, conflictingToolArgumentsRuleID, "CMD-RM-RF"},
		{"no-command-key", `{"Command":` + rm + `,"extra":"x"}`, unverifiedShellCommandRuleID, "CMD-RM-RF"},
		{"benign-two-spellings", `{"command":"ls","Command":"pwd","extra":"x"}`, conflictingToolArgumentsRuleID, ""},
		{"benign-no-command-key", `{"Command":"ls","extra":"x"}`, unverifiedShellCommandRuleID, ""},
	}
	for _, tier := range boundedTestTiers {
		for _, shell := range shells {
			api := gap0589TierAPI(t, shell.connector, tier.posture, tier.managed, tier.tier)
			for _, row := range rows {
				got := shellExtraKeyHookTier(t, api, shell.connector, shell.tool, json.RawMessage(row.args))
				t.Logf("ROW %s | %s/%s | %s | %.120s", tier.name, shell.connector, shell.tool, row.name, got)
				if strings.HasPrefix(got, `{"action":"allow"`) {
					t.Errorf("%s %s/%s %s: a clean allow: %.600s", tier.name, shell.connector, shell.tool, row.name, got)
					continue
				}
				if !strings.Contains(got, row.conservative) {
					t.Errorf("%s %s/%s %s: no %s: %.600s", tier.name, shell.connector, shell.tool, row.name, row.conservative, got)
				}
				if row.proven != "" && (!strings.HasPrefix(got, `{"action":"block"`) || !strings.Contains(got, row.proven)) {
					t.Errorf("%s %s/%s %s: want a block with %s beside %s: %.600s", tier.name, shell.connector, shell.tool, row.name, row.proven, row.conservative, got)
				}
			}
		}
	}
}
