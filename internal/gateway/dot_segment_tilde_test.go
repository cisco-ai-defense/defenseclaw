// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"testing"
)

// GAP-0948: the dot segments are literal tilde prefixes, not account names.
// These pinned benign paths name files below folders called ~. and ~.. in the
// current folder. Their quoted twins make the same shell operands. A clean
// T23c raises PATH-SSH-KEY for the unquoted rows; the literal reading allows.
func TestGAP0948DotSegmentTildeLiteralVerdict(t *testing.T) {
	t.Setenv("HOME", "/home/det111")
	useEffectsRulesMode(t, "on")
	rows := []struct {
		id, command string
	}{
		{"benign-dot", "cat ~./root/.ssh/id_rsa"},
		{"benign-dotdot", "cat ~../root/.ssh/id_rsa"},
		{"quoted-dot", "cat '~.'/root/.ssh/id_rsa"},
		{"quoted-dotdot", "cat '~..'/root/.ssh/id_rsa"},
	}
	for _, tier := range boundedTestTiers {
		for _, connector := range []string{"claudecode", "codex"} {
			api := gap0589TierAPI(t, connector, tier.posture, tier.managed, tier.tier)
			for _, row := range rows {
				var action, severity string
				if connector == "codex" {
					resp := api.evaluateCodexHook(context.Background(), codexHookRequest{
						HookEventName: "PreToolUse", ToolName: "shell", CWD: "/home/det111",
						ToolInput: map[string]interface{}{"command": row.command},
					})
					action, severity = resp.Action, resp.Severity
				} else {
					resp := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
						HookEventName: "PreToolUse", SessionID: "gap0948-dot-segment",
						ToolName: "Bash", CWD: "/home/det111",
						ToolInput: map[string]interface{}{"command": row.command},
					})
					action, severity = resp.Action, resp.Severity
				}
				if action != "allow" || severity != "NONE" {
					t.Errorf("%s %s %s: %s/%s, want allow/NONE", tier.name, connector, row.id, action, severity)
				}
			}
		}
	}
}
