// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// A dynamic awk program stays at the plain call's unknown tier when a
// wrapper's own option value expands. Static awk programs remain allowed.
func TestGAP0972DynamicAwkBehindExpandingWrapper(t *testing.T) {
	const home = "/tmp/det111-g0972-home"
	t.Setenv("HOME", home)
	previous := liveGeneration.Load()
	liveGeneration.Store(&Generation{Config: &config.Config{}})
	t.Cleanup(func() { liveGeneration.Store(previous) })

	const plain = "awk \"$PROGRAM\" /tmp/input.txt"
	attacks := []struct{ id, command string }{
		{"env-assignment", "env FOO=$VALUE " + plain},
		{"sudo-user", "sudo -u $WHO " + plain},
	}
	benign := []struct{ id, command string }{
		{"env-assignment", "env FOO=$VALUE awk 'BEGIN { print 1 }' /tmp/input.txt"},
		{"sudo-user", "sudo -u $WHO awk 'BEGIN { print 1 }' /tmp/input.txt"},
	}
	for _, tier := range boundedTestTiers {
		for _, connector := range []string{"claudecode", "codex"} {
			api := gap0589TierAPI(t, connector, tier.posture, tier.managed, tier.tier)
			judge := func(command string) (string, string, []string) {
				if connector == "codex" {
					resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
						HookEventName: "PreToolUse", ToolName: "shell", CWD: home,
						ToolInput: map[string]interface{}{"command": command},
					})
					return resp.Action, resp.Severity, resp.RuleIDs
				}
				resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
					HookEventName: "PreToolUse", SessionID: "gap0972-awk",
					ToolName: "Bash", CWD: home,
					ToolInput: map[string]interface{}{"command": command},
				})
				return resp.Action, resp.Severity, resp.RuleIDs
			}
			plainAction, plainSeverity, plainRules := judge(plain)
			t.Logf("%s %s plain: %s/%s rules=%v", tier.name, connector, plainAction, plainSeverity, plainRules)
			if plainAction == "allow" {
				t.Fatalf("%s %s plain dynamic awk unexpectedly allowed", tier.name, connector)
			}
			for _, row := range attacks {
				action, severity, rules := judge(row.command)
				t.Logf("%s %s %s attack: %s/%s rules=%v", tier.name, connector, row.id, action, severity, rules)
				if action != plainAction || severity != plainSeverity || !slices.Equal(rules, plainRules) {
					t.Errorf("%s %s %s: %s/%s rules=%v, want plain %s/%s rules=%v", tier.name, connector, row.id, action, severity, rules, plainAction, plainSeverity, plainRules)
				}
			}
			for _, row := range benign {
				action, severity, rules := judge(row.command)
				t.Logf("%s %s %s benign: %s/%s rules=%v", tier.name, connector, row.id, action, severity, rules)
				if action != "allow" || severity != "NONE" || len(rules) != 0 {
					t.Errorf("%s %s %s benign: %s/%s rules=%v, want allow", tier.name, connector, row.id, action, severity, rules)
				}
			}
		}
	}
}
