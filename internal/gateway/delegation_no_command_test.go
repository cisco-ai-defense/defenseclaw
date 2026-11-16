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

// gap0958Prompt is the native Copilot task prompt from the T9 report: it
// names a harmless command in backticks and carries no command field.
const gap0958Prompt = "Run exactly this harmless command once: `echo DC_T9_LINEAGE_03`. " +
	"Do not run any other command and do not edit files. Report the command output, then report completion."

// GAP-0958: in action mode a subagent delegation has no command text, so the
// shared action decision has nothing to judge. On Windows it was read as a
// dynamic command and the persistence rule blocked every delegation. Each
// connector's delegation form must be allowed on every OS, while a protected
// write through the same connector event still blocks.
func TestGAP0958DelegationCallsAreNotProtectedWrites(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("marker\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	delegation := func(fields map[string]any) json.RawMessage {
		raw, err := json.Marshal(fields)
		if err != nil {
			t.Fatal(err)
		}
		return raw
	}
	evaluate := func(t *testing.T, connectorName, event, tool string, args json.RawMessage) agentHookResponse {
		t.Helper()
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Connector = connectorName
		api := &APIServer{scannerCfg: cfg}
		return api.evaluateAgentHook(t.Context(), agentHookRequest{
			ConnectorName: connectorName, HookEventName: event, ToolName: tool, ToolArgs: args, CWD: cwd,
		})
	}
	for _, tc := range []struct {
		name, connector, event, tool string
		args                         json.RawMessage
	}{
		{"Copilot CLI task (T9 native arguments)", "copilot", "preToolUse", "task",
			delegation(map[string]any{"description": "Run harmless echo command", "prompt": gap0958Prompt, "agent_type": "task", "mode": "sync"})},
		{"Copilot CLI task with a protected path in the prompt", "copilot", "preToolUse", "task",
			delegation(map[string]any{"description": "Explain a file", "prompt": "Explain what `cat ~/.ssh/authorized_keys` would show; do not run it.", "agent_type": "explore", "mode": "sync"})},
		{"Copilot VS Code runSubagent", "copilot", "preToolUse", "runSubagent",
			delegation(map[string]any{"description": "Summarize README", "prompt": gap0958Prompt})},
		{"Claude Code Task", "claudecode", "PreToolUse", "Task",
			delegation(map[string]any{"description": "Run harmless echo", "prompt": gap0958Prompt, "subagent_type": "general-purpose"})},
		{"Claude Code Agent", "claudecode", "PreToolUse", "Agent",
			delegation(map[string]any{"description": "Run harmless echo", "prompt": gap0958Prompt, "subagent_type": "general-purpose"})},
		{"Codex spawn_agent", "codex", "PreToolUse", "spawn_agent",
			delegation(map[string]any{"message": gap0958Prompt, "agent_type": "worker"})},
		{"Cursor Task", "cursor", "preToolUse", "Task",
			delegation(map[string]any{"description": "Run harmless echo", "prompt": gap0958Prompt, "subagent_type": "generalPurpose"})},
		{"OpenCode task", "opencode", "tool.execute.before", "task",
			delegation(map[string]any{"description": "Run harmless echo", "prompt": gap0958Prompt, "subagent_type": "general"})},
		{"Amp Task", "amp", "tool.call", "Task",
			delegation(map[string]any{"description": "Run harmless echo", "prompt": gap0958Prompt})},
		{"Hermes delegate_task", "hermes", "pre_tool_call", "delegate_task",
			delegation(map[string]any{"goal": gap0958Prompt, "context": "T9 lineage check", "toolsets": []string{"terminal"}})},
		{"Kiro use_subagent", "kiro", "PreToolUse", "use_subagent",
			delegation(map[string]any{"task": gap0958Prompt, "agent_name": "default"})},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if resp := evaluate(t, tc.connector, tc.event, tc.tool, tc.args); resp.Action != "allow" || resp.RawAction == "block" {
				t.Fatalf("delegation action=%q raw=%q reason=%q rules=%v", resp.Action, resp.RawAction, resp.Reason, resp.RuleIDs)
			}
		})
	}
	// The same connector events still enforce a protected write.
	write := `echo key >> ~/.ssh/authorized_keys`
	for _, tc := range []struct{ connector, event, tool, key string }{
		{"copilot", "preToolUse", "bash", "command"},
		{"claudecode", "PreToolUse", "Bash", "command"},
		{"hermes", "pre_tool_call", "terminal", "command"},
	} {
		t.Run(tc.connector+" protected write control", func(t *testing.T) {
			resp := evaluate(t, tc.connector, tc.event, tc.tool, delegation(map[string]any{tc.key: write}))
			if resp.Action != "block" || resp.RawAction != "block" {
				t.Fatalf("protected write action=%q raw=%q reason=%q", resp.Action, resp.RawAction, resp.Reason)
			}
		})
	}
}
