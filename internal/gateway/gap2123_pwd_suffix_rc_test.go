// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-2123: a resolved PWD suffix expansion names the same startup file as
// its direct spelling. A project-local lookalike stays outside that member.
func TestGAP2123PWDSuffixShellRCVerdicts(t *testing.T) {
	t.Setenv("HOME", "/home/det111")
	// A blank config takes this build's shipped cascade default. The
	// lexical resolver only replaces filesystem reads of the fake home.
	previous := liveGeneration.Load()
	liveGeneration.Store(&Generation{Config: &config.Config{}})
	t.Cleanup(func() { liveGeneration.Store(previous) })
	t.Cleanup(setEffectResolverIdle(t, func(path string) (string, bool) { return path, true }))
	const cwd = "/home/det111/proj"
	rows := []struct {
		id, command string
		protected   bool
	}{
		{"plain", "echo y >> ~/.bashrc", true},
		{"pwd-suffix", "echo y >> ${PWD%/proj}/.bashrc", true},
		{"two-targets", "echo y >> ${PWD%/proj}/.bashrc >> ${PWD%/proj}/.zshrc", true},
		{"project-lookalike", "echo y >> ${PWD%/proj}/proj/.bashrc.fixture", false},
		{"plain-safe-content", `echo 'export PATH=$HOME/bin:$PATH' >> ~/.bashrc`, false},
		{"suffix-safe-content", `echo 'export PATH=$HOME/bin:$PATH' >> ${PWD%/proj}/.bashrc`, false},
	}
	for _, tier := range boundedTestTiers {
		for _, connector := range []string{"claudecode", "codex"} {
			api := gap0589TierAPI(t, connector, tier.posture, tier.managed, tier.tier)
			for _, row := range rows {
				var action, severity string
				if connector == "codex" {
					resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
						HookEventName: "PreToolUse", ToolName: "shell", CWD: cwd,
						ToolInput: map[string]interface{}{"command": row.command},
					})
					action, severity = resp.Action, resp.Severity
				} else {
					resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
						HookEventName: "PreToolUse", SessionID: "gap2123-pwd-suffix",
						ToolName: "Bash", CWD: cwd,
						ToolInput: map[string]interface{}{"command": row.command},
					})
					action, severity = resp.Action, resp.Severity
				}
				want := "allow"
				if row.protected {
					want = "alert"
					if tier.posture == "strict" {
						want = "block"
					}
				}
				wantSeverity := "NONE"
				if row.protected {
					wantSeverity = "MEDIUM"
				}
				if action != want || severity != wantSeverity {
					t.Errorf("%s %s %s: %s/%s, want %s/%s", tier.name, connector, row.id, action, severity, want, wantSeverity)
				}
			}
		}
	}
}
