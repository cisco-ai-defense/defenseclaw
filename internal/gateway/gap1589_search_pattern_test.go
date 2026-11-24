// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

// Search patterns stay data through pipes and lists, while commands passed to
// launchers keep their baseline block. This test was red at 1.0.10.
func TestGAP1589SearchPatternDataVerdicts(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	if err := os.WriteFile(filepath.Join(home, "notes.txt"), []byte("ordinary notes\n"), 0600); err != nil {
		t.Fatal(err)
	}
	useEffectsRulesMode(t, "on")
	rows := []struct{ command, want string }{
		{"gapctl list | rg 'apply_patch|authorized_keys'", "allow"},
		{"gapctl list; rg 'apply_patch|authorized_keys' notes.txt", "allow"},
		{"find . -exec apply_patch < patch.txt \\; | rg authorized_keys", "block"},
		{"flock lockfile apply_patch < patch.txt | rg authorized_keys", "block"},
	}
	for _, tier := range boundedTestTiers {
		for _, connector := range []string{"claudecode", "codex"} {
			api := gap0589TierAPI(t, connector, tier.posture, tier.managed, tier.tier)
			for _, row := range rows {
				t.Run(tier.name+"/"+connector+"/"+row.command, func(t *testing.T) {
					var action string
					if connector == "codex" {
						resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
							HookEventName: "PreToolUse", ToolName: "shell", CWD: home,
							ToolInput: map[string]interface{}{"command": row.command},
						})
						action = resp.Action
					} else {
						resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
							HookEventName: "PreToolUse", SessionID: "gap1589-test",
							ToolName: "Bash", CWD: home,
							ToolInput: map[string]interface{}{"command": row.command},
						})
						action = resp.Action
					}
					if action != row.want {
						t.Errorf("search/launcher verdict = %s, want %s", action, row.want)
					}
				})
			}
		}
	}
}
