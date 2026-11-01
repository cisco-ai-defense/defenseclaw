// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

const nativeWriteAuthorizedKeysRule = "persistence.ssh_authorized_keys_command"

// nativeWriteCall is one native file-write tool of a connector, in the
// argument shape its harness sends, for the file at path.
type nativeWriteCall struct {
	connector, tool string
	args            func(path string) map[string]any
}

func nativeWriteCalls() []nativeWriteCall {
	patch := func(path string) string {
		return "*** Begin Patch\n*** Update File: " + path + "\n@@\n # base\n+# k\n*** End Patch\n"
	}
	return []nativeWriteCall{
		{"opencode", "edit", func(p string) map[string]any {
			return map[string]any{"path": p, "oldString": "# base", "newString": "# base\n# k"}
		}},
		{"opencode", "edit", func(p string) map[string]any {
			return map[string]any{"path": p, "oldString": "# base", "newString": "# k", "replaceAll": true}
		}},

		{"opencode", "write", func(p string) map[string]any { return map[string]any{"path": p, "content": "# k\n"} }},
		{"opencode", "patch", func(p string) map[string]any { return map[string]any{"patchText": patch(p)} }},
		{"claudecode", "Write", func(p string) map[string]any { return map[string]any{"file_path": p, "content": "# k\n"} }},
		{"claudecode", "Edit", func(p string) map[string]any {
			return map[string]any{"file_path": p, "old_string": "# base", "new_string": "# base\n# k"}
		}},
		{"claudecode", "MultiEdit", func(p string) map[string]any {
			return map[string]any{"file_path": p, "edits": []any{map[string]any{"old_string": "# base", "new_string": "# k"}}}
		}},
		{"codex", "apply_patch", func(p string) map[string]any { return map[string]any{"command": patch(p)} }},
		{"copilot", "apply_patch", func(p string) map[string]any { return map[string]any{"": patch(p)} }},
		{"copilot", "edit", func(p string) map[string]any {
			return map[string]any{"path": p, "old_str": "# base", "new_str": "# base\n# k"}
		}},
		{"copilot", "create", func(p string) map[string]any { return map[string]any{"path": p, "file_text": "# k\n"} }},
	}
}

func (c nativeWriteCall) name(i int) string { return fmt.Sprintf("%s-%s-%d", c.connector, c.tool, i) }

// body is the hook body the connector's harness posts. Copilot CLI sends
// its own camelCase object, with the tool arguments as a JSON string; its
// apply_patch arguments are the patch text itself.
func (c nativeWriteCall) body(t *testing.T, cwd, path string) string {
	t.Helper()
	args := c.args(path)
	// One session per call: Copilot folds a repeated call of a session into
	// the verdict it already has.
	session := "s-" + c.connector + "-" + c.tool + strings.NewReplacer("/", "-", "\\", "-", ":", "").Replace(path)
	switch c.connector {
	case "copilot":
		var toolArgs any = args
		if text, ok := args[""]; ok {
			toolArgs = text
		}
		toolArgs = string(mustJSON(t, toolArgs))
		return string(mustJSON(t, map[string]any{"sessionId": session, "timestamp": 1790483549431, "cwd": cwd,
			"toolName": c.tool, "toolArgs": toolArgs}))
	case "opencode":
		return string(mustJSON(t, map[string]any{"hook_event_name": "tool.execute.before", "tool_name": c.tool, "tool_input": args,
			"session_id": session, "turn_id": "m1", "tool_call_id": "c1", "agent_name": "build", "cwd": cwd,
			"arguments_authoritative": true, "mcp_identity_status": "not_mcp"}))
	default:
		return string(mustJSON(t, map[string]any{"hook_event_name": "PreToolUse", "session_id": session, "turn_id": "t1",
			"cwd": cwd, "tool_name": c.tool, "tool_input": args, "tool_use_id": "u1"}))
	}
}

func nativeWriteBlocked(t *testing.T, got string) bool {
	t.Helper()
	var resp map[string]any
	if err := json.Unmarshal([]byte(got), &resp); err != nil {
		t.Fatalf("verdict %q: %v", got, err)
	}
	if resp["action"] == "block" {
		if !strings.Contains(got, nativeWriteAuthorizedKeysRule) {
			t.Fatalf("blocked by another rule: %.600s", got)
		}
		return true
	}
	if resp["action"] != "allow" {
		t.Fatalf("verdict = %.600s", got)
	}
	return false
}

// TestNativeWriteToolsOfAuthorizedKeysAreBlockedOnTheHost pins that every
// native file-write tool of every connector that names the active user's
// ~/.ssh/authorized_keys is blocked by the SSH persistence rule, and that
// the same tool writing a project file stays allowed. The native edit and
// create tools of OpenCode and Copilot parse as complete write calls and are
// judged like Claude Code's, and a call with one argument outside its
// tool's reviewed schema is judged by its target too (GAP-0655).
func TestNativeWriteToolsOfAuthorizedKeysAreBlockedOnTheHost(t *testing.T) {
	root := t.TempDir()
	home, project := filepath.Join(root, "home"), filepath.Join(root, "home", "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, file := range []string{keys, filepath.Join(project, "notes.txt")} {
		if err := os.WriteFile(file, []byte("# base\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	t.Chdir(project)
	for i, call := range nativeWriteTableCalls() {
		for target, want := range map[string]bool{keys: true, filepath.Join(project, "notes.txt"): false} {
			t.Run(fmt.Sprintf("%s/block=%t", call.name(i), want), func(t *testing.T) {
				body := call.body(t, project, target)
				cfg := &config.Config{}
				cfg.Guardrail.Mode = "action"
				cfg.Guardrail.Connector = call.connector
				api := &APIServer{scannerCfg: cfg, health: NewSidecarHealth()}
				req := httptest.NewRequest(http.MethodPost, "/api/v1/"+call.connector+"/hook", strings.NewReader(body))
				req.Header.Set("Content-Type", "application/json")
				req.Header.Set(hookpaths.Header, hookpaths.ResolveConnector(call.connector, "", "preToolUse", []byte(body)))
				switch call.connector {
				case "codex":
					setTestCodexHookBinding(req, "PreToolUse", defaultTestCodexHookContract)
				case "copilot":
					req.Header.Set("X-DefenseClaw-Copilot-Event", "preToolUse")
				}
				req = req.WithContext(withManagedHookPeer(req.Context(), managedHookPeer{Home: home}))
				recorder := httptest.NewRecorder()
				api.handleAgentHook(call.connector).ServeHTTP(recorder, req)
				if got := nativeWriteBlocked(t, recorder.Body.String()); got != want {
					t.Fatalf("blocked = %t, want %t: %.600s", got, want, recorder.Body.String())
				}
			})
		}
	}
}
