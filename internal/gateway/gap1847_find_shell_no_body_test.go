// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"context"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

// TestGAP1847FindShellChildWithoutInlineBodyKeepsStateWriteFiveTiers is
// rel-1-0-10:GAP-1847 (agenthazard-srcmal f353d3d0/window-011, call 6): a
// find -exec shell child with no -c body (it runs code from its standard
// input or from the handed file) keeps the 1.0.10 tamper.detector_state_write
// finding and its cells (alert HIGH in default, permissive and managed, block
// CRITICAL in strict and managed strict), Claude Code and Codex hooks, the
// effects lane on. The GAP-1327 body read only reads a -c body; the train
// read the empty argv of a bare shell as "every effect a read" and dropped
// the finding. Fail-before: red at det111/engine-train-2 b9afab1ef9 (allow
// NONE in every tier), green at the fix.
func TestGAP1847FindShellChildWithoutInlineBodyKeepsStateWriteFiveTiers(t *testing.T) {
	home := det111R1Home(t)
	cwd := filepath.Join(home, "proj")
	want := map[string][2]string{
		"default": {"alert", "HIGH"}, "permissive": {"alert", "HIGH"}, "strict": {"block", "CRITICAL"},
		"managed": {"alert", "HIGH"}, "managed strict": {"block", "CRITICAL"},
	}
	for _, command := range []string{
		`find / -name "*.txt" -exec /bin/sh \; 2>/dev/null || echo "done"`,
		`find / -name "*.txt" -exec sh {} \;`,
		`find ~/.defenseclaw -type f -exec bash {} +`,
	} {
		for _, tier := range boundedTestTiers {
			for _, connector := range []string{"claudecode", "codex"} {
				api := gap0589TierAPI(t, connector, tier.posture, tier.managed, tier.tier)
				api.scannerCfg.DataDir = filepath.Join(home, ".defenseclaw")
				useDefaultEffectsLane(t)
				var action, severity string
				var rules []string
				if connector == "claudecode" {
					r := api.evaluateClaudeCodeHook(context.Background(), claudeCodeHookRequest{
						HookEventName: "PreToolUse", SessionID: "gap1847", CWD: cwd, ToolName: "Bash",
						ToolInput: map[string]interface{}{"command": command},
					})
					action, severity, rules = r.Action, r.Severity, r.RuleIDs
				} else {
					r := api.evaluateCodexHook(context.Background(), codexHookRequest{
						HookEventName: "PreToolUse", ToolName: "shell", CWD: cwd,
						ToolInput: map[string]interface{}{"command": command},
					})
					action, severity, rules = r.Action, r.Severity, r.RuleIDs
				}
				w := want[tier.name]
				if action != w[0] || !strings.EqualFold(severity, w[1]) || !slices.Contains(rules, "tamper.detector_state_write") {
					t.Errorf("%s %s %q: %s %s %v, want the 1.0.10 cell %s %s tamper.detector_state_write", tier.name, connector, command, action, severity, rules, w[0], w[1])
				}
			}
		}
	}
}
