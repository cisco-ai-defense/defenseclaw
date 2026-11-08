// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// The Windows twin of file_tool_unknown_keys_test.go (gas-ux-r1 GAP-0076,
// CI red GAP-0725): a file-tool Write with a key outside the tool schema
// that names the DefenseClaw state file by its drive path
// (C:\Users\<u>\.defenseclaw\config.yaml), reviewed or hidden under the
// extra key, is blocked in balanced just like the call without the extra
// key, and an ordinary project file stays allowed.

func postWindowsFileTool(t *testing.T, f windowsPatchFixture, connectorName, tool string, args map[string]any) (string, string) {
	t.Helper()
	installToolCallCorpusProfileConnector(t, connectorName, "default")
	var body map[string]any
	if connectorName == "opencode" {
		body = map[string]any{"hook_event_name": "tool.execute.before", "tool_name": tool, "tool_input": args,
			"session_id": "gap0076w", "turn_id": "m1", "tool_call_id": "c1", "agent_name": "build", "cwd": f.project,
			"arguments_authoritative": true, "mcp_identity_status": "not_mcp"}
	} else {
		body = map[string]any{"hook_event_name": "PreToolUse", "session_id": "gap0076w", "turn_id": "t1",
			"cwd": f.project, "tool_name": tool, "tool_input": args, "tool_use_id": "u1"}
	}
	raw := string(mustJSON(t, body))
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Connector = connectorName
	cfg.Guardrail.RulePackDir = filepath.Join(guardrailPoliciesRoot(t), "default")
	api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/"+connectorName+"/hook", strings.NewReader(raw))
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set(hookpaths.Header, hookpaths.ResolveConnector(connectorName, "", "PreToolUse", []byte(raw)))
	recorder := httptest.NewRecorder()
	api.handleAgentHook(connectorName).ServeHTTP(recorder, req)
	out := recorder.Body.String()
	if recorder.Code != http.StatusOK {
		t.Fatalf("status %d: %.400s", recorder.Code, out)
	}
	switch {
	case strings.Contains(out, `"action":"block"`) || strings.Contains(out, `"permissionDecision":"deny"`):
		return "block", out
	case strings.Contains(out, `"action":"alert"`):
		return "alert", out
	default:
		return "allow", out
	}
}

func TestWindowsFileToolExtraKeyStateWriteIsBlocked(t *testing.T) {
	calls := []struct {
		connector, tool, key string
	}{
		{"claudecode", "Write", "file_path"},
		{"opencode", "write", "filePath"},
	}
	for _, call := range calls {
		t.Run(call.connector, func(t *testing.T) {
			f := newWindowsPatchFixture(t)
			state := filepath.Join(f.home, ".defenseclaw", "config.yaml")
			ordinary := filepath.Join(f.project, "src", "main.go")
			for name, row := range map[string]struct {
				path  string
				extra map[string]any
				want  string
			}{
				"control: state, no extra key":        {state, nil, "block"},
				"state + extra key":                   {state, map[string]any{"description": "add a line"}, "block"},
				"state + several extra keys":          {state, map[string]any{"description": "x", "timeout": 5, "meta": map[string]any{"a": "b"}}, "block"},
				"drive path hidden under extra key":   {ordinary, map[string]any{"target_file": state}, "block"},
				"home form hidden under extra key":    {ordinary, map[string]any{"target_file": "~/.defenseclaw/config.yaml"}, "block"},
				"control: ordinary file, no extra":    {ordinary, nil, "allow"},
				"control: ordinary file + extra key":  {ordinary, map[string]any{"description": "add a line"}, "allow"},
				"control: ordinary file + text value": {ordinary, map[string]any{"note": "update the notes"}, "allow"},
			} {
				args := map[string]any{call.key: row.path, "content": "# k\n"}
				for k, v := range row.extra {
					args[k] = v
				}
				got, out := postWindowsFileTool(t, f, call.connector, call.tool, args)
				if got != row.want {
					t.Errorf("%s: %s of %s is %q, want %q: %.500s", name, call.tool, row.path, got, row.want, out)
				}
			}
		})
	}
}
