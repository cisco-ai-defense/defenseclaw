// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// A move from a working directory outside the user's home keeps the
// protected-state source verdict in per-user and managed hook calls.
func TestGAP0474WindowsMoveVerdictsOutsideHomeFourCell(t *testing.T) {
	home := filepath.Join(t.TempDir(), "home")
	state := filepath.Join(home, ".defenseclaw")
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("USERPROFILE", home)
	work, err := os.MkdirTemp(filepath.Join(os.Getenv("SystemRoot"), "Temp"), "dc-hp474-decision-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(work) })
	if err := os.Mkdir(filepath.Join(work, "new"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name, command string
		block         bool
	}{
		{"ordinary move", "mv new renamed", false},
		{"out of protected state", "mv " + filepath.ToSlash(state) + " moved", true},
	} {
		for _, connector := range []string{"claudecode", "codex"} {
			for _, managed := range []bool{false, true} {
				name := connector + "/per-user/" + row.name
				if managed {
					name = connector + "/managed/" + row.name
				}
				t.Run(name, func(t *testing.T) {
					api := instructionProtectionTestAPI(t, connector, "action", "HIGH")
					ctx := t.Context()
					if managed {
						ctx = withManagedHookPeer(withServiceAccountGateway(ctx), managedHookPeer{Home: home})
					}
					var action string
					if connector == "claudecode" {
						response := api.evaluateClaudeCodeHook(ctx, claudeCodeHookRequest{
							HookEventName: "PreToolUse", SessionID: "hp474", CWD: work,
							ToolName: "Bash", ToolInput: map[string]interface{}{"command": row.command},
						})
						action = response.Action
					} else {
						response := api.evaluateCodexHook(ctx, codexHookRequest{
							HookEventName: "PreToolUse", SessionID: "hp474", CWD: work,
							ToolName: "exec_command", ToolInput: map[string]interface{}{"cmd": row.command, "workdir": work},
						})
						action = response.Action
					}
					if blocked := action == guardrailActionBlock; blocked != row.block {
						t.Fatalf("action %q for %q, want block=%t", action, row.command, row.block)
					}
				})
			}
		}
	}
}
