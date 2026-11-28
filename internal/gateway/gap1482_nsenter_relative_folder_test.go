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

// A relative nsenter working directory is based at the caller's directory.
// The state-write twin must keep its finding; a project-local file is benign.
func TestGAP1482NSEnterRelativeChildFolderVerdicts(t *testing.T) {
	const home = "/tmp/det111-g1482-home/alice"
	t.Setenv("HOME", home)
	previous := liveGeneration.Load()
	liveGeneration.Store(&Generation{Config: &config.Config{}})
	t.Cleanup(func() { liveGeneration.Store(previous) })
	t.Cleanup(setEffectResolverIdle(t, func(path string) (string, bool) { return path, true }))

	rows := []struct {
		id, command string
		protected   bool
	}{
		{"relative-state", "nsenter --target=1 --wd=.. sh -c ': >> alice/.defenseclaw/config.yaml'", true},
		{"relative-project", "nsenter --target=1 --wd=.. sh -c ': >> project/.defenseclaw/config.yaml'", false},
		{"same-folder-state", "nsenter --target=1 --wd=. sh -c ': >> .defenseclaw/config.yaml'", true},
	}
	for _, tier := range boundedTestTiers {
		for _, connector := range []string{"claudecode", "codex"} {
			api := gap0589TierAPI(t, connector, tier.posture, tier.managed, tier.tier)
			for _, row := range rows {
				var action, severity string
				var rules []string
				if connector == "codex" {
					resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
						HookEventName: "PreToolUse", ToolName: "shell", CWD: home,
						ToolInput: map[string]interface{}{"command": row.command},
					})
					action, severity, rules = resp.Action, resp.Severity, resp.RuleIDs
				} else {
					resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
						HookEventName: "PreToolUse", SessionID: "gap1482-nsenter",
						ToolName: "Bash", CWD: home,
						ToolInput: map[string]interface{}{"command": row.command},
					})
					action, severity, rules = resp.Action, resp.Severity, resp.RuleIDs
				}
				t.Logf("%s %s %s: %s/%s rules=%v", tier.name, connector, row.id, action, severity, rules)
				want := "allow"
				if row.protected {
					want = "alert"
					if tier.name == "strict" || tier.name == "managed strict" {
						want = "block"
					}
				}
				if action != want || (row.protected && (severity == "NONE" || !slices.Contains(rules, "tamper.detector_state_write"))) {
					t.Errorf("%s %s %s: %s/%s rules=%v, want %s with state-write rule", tier.name, connector, row.id, action, severity, rules, want)
				}
			}
		}
	}
}
