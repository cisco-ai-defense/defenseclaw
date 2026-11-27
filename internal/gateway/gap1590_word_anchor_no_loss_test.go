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

// The GNU word-anchor expression is not proven harmless by the find reader.
// Preserve the 1.0.10 block on a protected-name twin while GAP-1590 remains
// open for the benign pattern.
func TestGAP1590WordAnchorProtectedNameKeepsBaselineBlock(t *testing.T) {
	home := t.TempDir()
	target := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(target), 0700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(target, []byte("fixture\n"), 0600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	useEffectsRulesMode(t, "on")
	command := `find . -regex '.*\<authorized_keys\>.*' -delete`
	for _, tier := range boundedTestTiers {
		for _, connector := range []string{"claudecode", "codex"} {
			t.Run(tier.name+"/"+connector, func(t *testing.T) {
				api := gap0589TierAPI(t, connector, tier.posture, tier.managed, tier.tier)
				var action string
				if connector == "codex" {
					resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
						HookEventName: "PreToolUse", ToolName: "shell", CWD: home,
						ToolInput: map[string]interface{}{"command": command},
					})
					action = resp.Action
				} else {
					resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
						HookEventName: "PreToolUse", SessionID: "gap1590-test",
						ToolName: "Bash", CWD: home,
						ToolInput: map[string]interface{}{"command": command},
					})
					action = resp.Action
				}
				if action != "block" {
					t.Errorf("protected-name word-anchor verdict = %s, want block", action)
				}
			})
		}
	}
}
