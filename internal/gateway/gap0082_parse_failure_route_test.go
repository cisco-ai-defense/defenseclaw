// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"runtime"
	"slices"
	"testing"
)

// gas-ux-r2:GAP-0082 on the hook route: a reader failure during the
// per-command split answers ACTION-PARSE-FAILURE, an alert in the default
// and permissive tiers and a block in strict, for Claude Code and Codex;
// never a silent allow. A protected write beside it keeps its own block.
func TestGAP0082ReaderFailureOnTheHookRoute(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell rows")
	}
	home, cwd := shellProtectedFileHome(t)
	trustedSimpleCommandsFaultHook = func() { panic("injected reader fault") }
	t.Cleanup(func() { trustedSimpleCommandsFaultHook = nil })
	want := map[string]string{"default": "alert", "permissive": "alert", "strict": "block"}
	for _, connectorName := range []string{"claudecode", "codex"} {
		for _, posture := range []string{"default", "permissive", "strict"} {
			for _, command := range []string{"echo hi", "command -v unzip && command -v uncompress && command -v tar"} {
				action, rules := shellProtectedFileRoute(t, home, cwd, connectorName, posture, false, command)
				if action != want[posture] || !slices.Contains(rules, parseFailureRuleID) {
					t.Errorf("%s %s %q: action = %q rules = %v, want %s by %s", connectorName, posture, command, action, rules, want[posture], parseFailureRuleID)
				}
			}
			action, rules := shellProtectedFileRoute(t, home, cwd, connectorName, posture, false, "echo marker >> ~/.ssh/authorized_keys")
			if action != "block" || !slices.Contains(rules, "persistence.ssh_authorized_keys_command") {
				t.Errorf("%s %s keys append: action = %q rules = %v, want block", connectorName, posture, action, rules)
			}
		}
	}
}
