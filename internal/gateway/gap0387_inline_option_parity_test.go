// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"slices"
	"testing"
)

// GAP-0387: alternative interpreter option forms carry the same inline code
// capabilities as a separate code operand. A code body without both
// capabilities remains allowed.
func TestGAP0387InlineOptionParityFiveTiers(t *testing.T) {
	useDefaultEffectsLane(t)
	rows := []struct {
		name, control, variant, benign string
	}{
		{"python-attached",
			`python3 -c 'import socket; import os; os.system("id")'`,
			`python3 -c'import socket; import os; os.system("id")'`,
			`python3 -c'print(1)'`},
		{"python-cluster",
			`python3 -c 'import socket; import os; os.system("id")'`,
			`python3 -Ic 'import socket; import os; os.system("id")'`,
			`python3 -Ic 'print(1)'`},
		{"node-long-equals",
			`node --eval 'require("net"); require("child_process").execSync("id")'`,
			`node --eval='require("net"); require("child_process").execSync("id")'`,
			`node --eval='console.log(1)'`},
		{"perl-module",
			`perl -e 'use IO::Socket; system("id")'`,
			`perl -MIO::Socket -e 'system("id")'`,
			`perl -MIO::Socket -e 'print 1'`},
		{"ruby-module",
			`ruby -e 'require "socket"; system("id")'`,
			`ruby -rsocket -e 'system("id")'`,
			`ruby -rsocket -e 'puts 1'`},
	}
	const rule = "exec.inline_code_network_and_exec"
	for _, tier := range boundedTestTiers {
		for _, connector := range []string{"claudecode", "codex"} {
			api := gap0589TierAPI(t, connector, tier.posture, tier.managed, tier.tier)
			decide := func(command string) (string, string, []string) {
				if connector == "codex" {
					r := api.evaluateCodexHook(context.Background(), codexHookRequest{
						HookEventName: "PreToolUse", ToolName: "shell", CWD: "/repo",
						ToolInput: map[string]interface{}{"command": command},
					})
					return r.Action, r.Severity, r.RuleIDs
				}
				r := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
					HookEventName: "PreToolUse", SessionID: "gap0387-inline",
					ToolName: "Bash", CWD: "/repo",
					ToolInput: map[string]interface{}{"command": command},
				})
				return r.Action, r.Severity, r.RuleIDs
			}
			for _, row := range rows {
				controlAction, controlSeverity, controlIDs := decide(row.control)
				action, severity, ids := decide(row.variant)
				if tier.name == "default" && (controlAction == "allow" || !slices.Contains(controlIDs, rule)) {
					t.Fatalf("%s %s %s: control did not prove rule: %s/%s %v",
						tier.name, connector, row.name, controlAction, controlSeverity, controlIDs)
				}
				if action != controlAction || severity != controlSeverity ||
					slices.Contains(ids, rule) != slices.Contains(controlIDs, rule) {
					t.Errorf("%s %s %s: %s/%s %v, control %s/%s %v",
						tier.name, connector, row.name, action, severity, ids,
						controlAction, controlSeverity, controlIDs)
				}
				benignAction, _, benignIDs := decide(row.benign)
				if benignAction != "allow" || slices.Contains(benignIDs, rule) {
					t.Errorf("%s %s %s benign: %s %v, want allow without rule",
						tier.name, connector, row.name, benignAction, benignIDs)
				}
			}
		}
	}
}
