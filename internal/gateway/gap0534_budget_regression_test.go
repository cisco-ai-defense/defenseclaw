// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

func TestGAP0534RecoveredToolVerdicts(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{cwd, filepath.Join(home, ".defenseclaw")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".defenseclaw", "config.yaml"), []byte("enabled: true\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	for _, tc := range []struct {
		name, command, action string
	}{
		{"protected", `Write-Output $(.\a[1]<#x#>); Remove-Item -Recurse -Force ~/.defenseclaw`, "block"},
		{"ordinary", `Write-Output $(.\a[1]<#x#>); Remove-Item -Recurse -Force ~/project/output`, "allow"},
	} {
		for _, connector := range []string{"claudecode", "codex"} {
			for _, mode := range []string{"action", "observe"} {
				t.Run(tc.name+"/"+connector+"/"+mode, func(t *testing.T) {
					tool := "PowerShell"
					if connector == "codex" {
						tool = "exec_command"
					}
					body, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "cwd": cwd,
						"tool_name": tool, "tool_input": map[string]string{"command": tc.command}})
					if err != nil {
						t.Fatal(err)
					}
					targets, ok := hookpaths.Decode(hookpaths.Resolve(body))
					if !ok {
						t.Fatal("hook write evidence is unavailable")
					}
					ctx := context.WithValue(t.Context(), resolvedWritesContextKey{}, targets)
					api := instructionProtectionTestAPI(t, connector, mode, "HIGH")
					start := time.Now()
					var action, raw string
					var wouldBlock bool
					if connector == "claudecode" {
						response := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{HookEventName: "PreToolUse", CWD: cwd,
							ToolName: tool, ToolInput: map[string]any{"command": tc.command}})
						action, raw, wouldBlock = response.Action, response.RawAction, response.WouldBlock
					} else {
						response := api.evaluateCodexHook(ctx, codexHookRequest{HookEventName: "PreToolUse", CWD: cwd,
							ToolName: tool, ToolInput: map[string]any{"cmd": tc.command}})
						action, raw, wouldBlock = response.Action, response.RawAction, response.WouldBlock
					}
					wantAction := tc.action
					if mode == "observe" {
						wantAction = "allow"
					}
					if action != wantAction || (mode == "observe" && tc.action == "block" && (raw != "block" || !wouldBlock)) ||
						(tc.action == "allow" && (raw != "allow" || wouldBlock)) {
						t.Fatalf("action=%q raw=%q wouldBlock=%t, want action=%q", action, raw, wouldBlock, wantAction)
					}
					if elapsed := time.Since(start); elapsed > time.Second {
						t.Fatalf("hook answer took %s", elapsed)
					}
				})
			}
		}
	}
}
