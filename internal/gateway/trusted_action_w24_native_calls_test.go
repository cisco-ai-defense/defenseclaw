// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0992 and GAP-0997 through the hook entry point, on the host's own
// file system and home (natively on Windows the Windows grammar decides):
// Codex's exact exec_command arguments for a PowerShell echo-and-sleep, and
// a native Write or Edit of an ordinary hard-linked package file, are not
// SSH persistence in action mode. A literal authorized_keys write still is.
func TestW24NativeHookCallsAreNotPersistence(t *testing.T) {
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project := filepath.Join(home, "project")
	store := filepath.Join(home, "store")
	for _, dir := range []string{filepath.Join(home, ".ssh"), filepath.Join(project, "node_modules", ".pnpm", "pkg"), store} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	stored := filepath.Join(store, "00ab")
	if err := os.WriteFile(stored, []byte("test\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	installed := filepath.Join(project, "node_modules", ".pnpm", "pkg", "index.js")
	if err := os.Link(stored, installed); err != nil {
		t.Skipf("hard links unavailable: %v", err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	marshal := func(fields map[string]any) json.RawMessage {
		raw, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	for _, tc := range []struct {
		name, connector, tool string
		args                  json.RawMessage
		block                 bool
	}{
		{"GAP-0992 Codex exec_command echo and sleep", "codex", "exec_command", marshal(map[string]any{
			"cmd": "Write-Output ok; Start-Sleep -Seconds 70", "workdir": project, "shell": "powershell",
			"login": false, "tty": true, "yield_time_ms": 30000, "max_output_tokens": 2000}), false},
		{"GAP-0997 Write of a hard-linked package file", "claudecode", "Write",
			marshal(map[string]any{"file_path": installed, "content": "changed"}), false},
		{"GAP-0997 Edit of a hard-linked package file", "claudecode", "Edit",
			marshal(map[string]any{"file_path": installed, "old_string": "test", "new_string": "changed"}), false},
		{"literal authorized_keys write", "claudecode", "Write",
			marshal(map[string]any{"file_path": filepath.Join(home, ".ssh", "authorized_keys"), "content": "dummy-key"}), true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &config.Config{}
			cfg.Guardrail.Mode = "action"
			cfg.Guardrail.Connector = tc.connector
			api := &APIServer{scannerCfg: cfg}
			resp := api.evaluateAgentHook(t.Context(), agentHookRequest{
				ConnectorName: tc.connector, HookEventName: "PreToolUse", ToolName: tc.tool, ToolArgs: tc.args, CWD: project,
			})
			blocked := resp.Action == "block" || resp.RawAction == "block"
			if blocked != tc.block {
				t.Fatalf("blocked=%v, want %v: action=%q raw=%q reason=%q rules=%v", blocked, tc.block, resp.Action, resp.RawAction, resp.Reason, resp.RuleIDs)
			}
		})
	}
}
