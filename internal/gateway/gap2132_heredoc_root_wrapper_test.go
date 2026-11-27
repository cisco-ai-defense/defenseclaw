// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-2132: a here-document fed to a shell behind a root or namespace
// wrapper (chroot, nsenter) is judged as its -c spelling, in every tier and
// on both connectors: no stronger, no weaker. The run-time shell twin
// stopped at the wrapper, so behind an unresolved root the body was judged
// nowhere (allow in all ten cells) while the -c spelling alerted
// (rel-1-0-10:GAP-2132).
func TestGAP2132HereDocBehindRootWrapperMatchesInlineForm(t *testing.T) {
	const home = "/tmp/det111-g2132-home"
	t.Setenv("HOME", home)
	previous := liveGeneration.Load()
	liveGeneration.Store(&Generation{Config: &config.Config{}})
	t.Cleanup(func() { liveGeneration.Store(previous) })
	t.Cleanup(setEffectResolverIdle(t, func(path string) (string, bool) { return path, true }))

	const state = ": >> .defenseclaw/config.yaml"
	const benign = ": >> notes.txt"
	rows := []struct {
		id, wrapper, body string
		// unknown marks a row whose -c spelling is not allowed: the
		// here-document must not be allowed either.
		unknown bool
	}{
		{"chroot-unknown-root-state", `chroot "$ROOT" sh`, state, true},
		{"chroot-unknown-root-benign", `chroot "$ROOT" sh`, benign, false},
		{"chroot-unknown-userspec-state", `chroot --userspec="$U" "$ROOT" sh`, state, true},
		{"chroot-protected-root-state", "chroot " + home + " sh", state, false},
		{"chroot-root-state", "chroot / sh", state, false},
		{"chroot-root-benign", "chroot / sh", benign, false},
		{"nsenter-root-state", "nsenter -r -m -t 1 sh", state, false},
		{"nsenter-unknown-wd-state", `nsenter --wd="$D" -m -t 1 sh`, state, false},
		{"nsenter-wd-benign", "nsenter --wd=/srv -m -t 1 sh", benign, false},
		{"nice-chroot-unknown-root-state", `nice chroot "$ROOT" sh`, state, true},
	}
	judge := func(api *APIServer, connector, command string) (string, string) {
		if connector == "codex" {
			resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
				HookEventName: "PreToolUse", ToolName: "shell", CWD: home,
				ToolInput: map[string]interface{}{"command": command},
			})
			return resp.Action, resp.Severity
		}
		resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: "gap2132-heredoc",
			ToolName: "Bash", CWD: home,
			ToolInput: map[string]interface{}{"command": command},
		})
		return resp.Action, resp.Severity
	}
	for _, tier := range boundedTestTiers {
		for _, connector := range []string{"claudecode", "codex"} {
			api := gap0589TierAPI(t, connector, tier.posture, tier.managed, tier.tier)
			for _, row := range rows {
				inline := row.wrapper + " -c '" + row.body + "'"
				wantAction, wantSeverity := judge(api, connector, inline)
				// The <<- spelling must be no weaker than the -c spelling;
				// at the literal root it is judged above it by the child
				// folder reading of the parent (GAP-1483), which this twin
				// does not lower.
				for _, form := range []struct {
					name, command string
					atLeast       bool
				}{
					{"heredoc", row.wrapper + " <<'E'\n" + row.body + "\nE", false},
					{"heredoc-dash", row.wrapper + " <<-E\n\t" + row.body + "\nE", true},
				} {
					action, severity := judge(api, connector, form.command)
					t.Logf("%s %s %s %s: %s/%s inline %s/%s", tier.name, connector, row.id, form.name,
						action, severity, wantAction, wantSeverity)
					if form.atLeast {
						if gap2132ActionRank[action] < gap2132ActionRank[wantAction] {
							t.Errorf("%s %s %s %s: %s/%s, weaker than the -c verdict %s/%s", tier.name, connector,
								row.id, form.name, action, severity, wantAction, wantSeverity)
						}
					} else if action != wantAction || severity != wantSeverity {
						t.Errorf("%s %s %s %s: %s/%s, want the -c verdict %s/%s", tier.name, connector,
							row.id, form.name, action, severity, wantAction, wantSeverity)
					}
					if row.unknown && action == "allow" {
						t.Errorf("%s %s %s %s: allow behind an unresolved root", tier.name, connector, row.id, form.name)
					}
				}
			}
		}
	}
}

var gap2132ActionRank = map[string]int{"allow": 0, "alert": 1, "block": 2}
