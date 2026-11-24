// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1483: a shell fed by a here-document runs in its launcher's child
// folder. The root child is benign; protected and unresolved child roots
// retain their guardrail verdicts.
func TestGAP1483HereDocChildFolderVerdicts(t *testing.T) {
	const home = "/tmp/det111-g1483-home"
	t.Setenv("HOME", home)
	previous := liveGeneration.Load()
	liveGeneration.Store(&Generation{Config: &config.Config{}})
	t.Cleanup(func() { liveGeneration.Store(previous) })
	t.Cleanup(setEffectResolverIdle(t, func(path string) (string, bool) { return path, true }))

	rows := []struct {
		id, command string
	}{
		{"benign-root", "chroot / sh <<'E'\n: >> .defenseclaw/config.yaml\nE"},
		{"benign-inline", "chroot / sh -c ': >> .defenseclaw/config.yaml'"},
		{"protected-root", "chroot /tmp/det111-g1483-home sh <<'E'\n: >> .defenseclaw/config.yaml\nE"},
		{"unknown-root", "chroot \"$ROOT\" sh <<'E'\n: >> .defenseclaw/config.yaml\nE"},
		{"escape-state", "chroot / sh <<'E'\n: >> tmp/det111-g1483-home/.defenseclaw/config.yaml\nE"},
		{"opaque-body", "chroot / sh <<'E'\n: >> .defenseclaw/config.yaml; true\nE"},
		{"outer-write", "chroot / sh -c ': >> .defenseclaw/config.yaml' >> /tmp/det111-g1483-home/.defenseclaw/config.yaml"},
		{"skip-chdir", "chroot --skip-chdir / sh <<'E'\n: >> .defenseclaw/config.yaml\nE"},
		{"compound-sequence", "chroot / sh <<'E'; echo x >> ~/.defenseclaw/config.yaml\n: >> .defenseclaw/config.yaml\nE"},
		{"compound-and", "chroot / sh <<'E' && echo x >> ~/.defenseclaw/config.yaml\n: >> .defenseclaw/config.yaml\nE"},
		{"compound-pipe", "chroot / sh <<'E' | echo x >> ~/.defenseclaw/config.yaml\n: >> .defenseclaw/config.yaml\nE"},
		{"two-chroot", "chroot / sh <<'E'; chroot \"$ROOT\" sh -c ': >> ~/.defenseclaw/config.yaml'\n: >> .defenseclaw/config.yaml\nE"},
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
						HookEventName: "PreToolUse", SessionID: "gap1483-heredoc",
						ToolName: "Bash", CWD: home,
						ToolInput: map[string]interface{}{"command": row.command},
					})
					action, severity, rules = resp.Action, resp.Severity, resp.RuleIDs
				}
				t.Logf("%s %s %s: %s/%s rules=%v", tier.name, connector, row.id, action, severity, rules)
				wantAction, wantSeverity := "allow", "NONE"
				switch row.id {
				case "protected-root", "opaque-body", "outer-write", "skip-chdir":
					wantAction, wantSeverity = "alert", "HIGH"
					if tier.name == "strict" || tier.name == "managed strict" {
						wantAction, wantSeverity = "block", "CRITICAL"
					}
				case "escape-state":
					wantAction, wantSeverity = "alert", "CRITICAL"
					if tier.name == "strict" || tier.name == "managed strict" {
						wantAction = "block"
					}
				case "compound-sequence", "compound-and", "compound-pipe", "two-chroot":
					wantAction, wantSeverity = "alert", ""
					if tier.name == "strict" || tier.name == "managed strict" {
						wantAction = "block"
					}
				}
				if action != wantAction || (wantSeverity != "" && severity != wantSeverity) ||
					(wantSeverity == "" && severity == "NONE") {
					t.Errorf("%s %s %s: %s/%s, want %s/%s", tier.name, connector, row.id,
						action, severity, wantAction, wantSeverity)
				}
			}
		}
	}
}
