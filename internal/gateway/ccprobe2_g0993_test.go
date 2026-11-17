// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// s7-probe2 old-API probe for rel-1-0-10:GAP-0993: the GAP-0980 run-time shell
// texts (state removal, config write) sent through the Claude Code hook
// decision (boundedDecideClaudeCode, the real hook evaluation) at the child
// command sites the gap names: eval STRING, find -exec, xargs, and $0 of a -c
// STRING whose name operand is a static shell name. Each row is the literal
// shell control transformed in code; the run-time spelling must never be
// weaker than the literal one, in every tier. Old API only (bounded lane test
// harness present at the pre-fix sha). Scratch, test-only branch.

package gateway

import (
	"path/filepath"
	"strings"
	"testing"
)

var ccp2g0993Rank = map[string]int{"allow": 0, "alert": 1, "block": 2}

func TestCCP2G0993_RunTimeShellAtChildCommandSites(t *testing.T) {
	env := boundedLaneEnv(t)
	state := filepath.Join(env.home, ".defenseclaw")
	texts := []string{
		"rm -rf " + state,
		"printf x >> " + filepath.Join(state, "config.yaml"),
	}
	// One %s for the shell word, one for the TEXT (double quotes inside).
	forms := []string{
		`eval '%s -c "%s"'`,
		`find . -maxdepth 0 -exec %s -c "%s" \;`,
		`printf 'x\n' | xargs %s -c "%s"`,
	}
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		decide := func(t *testing.T, command string) string {
			t.Helper()
			action, findings := boundedDecideClaudeCode(t, api, env, boundedLaneCall{tool: "Bash", input: map[string]any{"command": command}})
			if _, known := ccp2g0993Rank[action]; !known {
				t.Fatalf("%q: action %q (findings %v) is no hook verdict", command, action, findings)
			}
			return action
		}
		for fi, form := range forms {
			for ti, text := range texts {
				literal := strings.Replace(strings.Replace(form, "%s", "bash", 1), "%s", text, 1)
				runTime := strings.Replace(strings.Replace(form, "%s", `"$SHELL"`, 1), "%s", text, 1)
				floor := decide(t, literal)
				got := decide(t, runTime)
				t.Logf("%s form%d text%d literal=%s run-time=%s", tier.name, fi, ti, floor, got)
				if ccp2g0993Rank[got] < ccp2g0993Rank[floor] {
					t.Errorf("%s form%d text%d: run-time shell = %s, literal shell = %s", tier.name, fi, ti, got, floor)
				}
			}
		}
		// $0 of a -c STRING with a static shell name operand runs as that shell.
		for ti, text := range texts {
			literal := `bash -c 'sh -c "` + text + `"' sh`
			runTime := `bash -c '"$0" -c "` + text + `"' sh`
			floor := decide(t, literal)
			got := decide(t, runTime)
			t.Logf("%s zero-name text%d literal=%s run-time=%s", tier.name, ti, floor, got)
			if ccp2g0993Rank[got] < ccp2g0993Rank[floor] {
				t.Errorf("%s zero-name text%d: $0 shell = %s, literal shell = %s", tier.name, ti, got, floor)
			}
		}
	}
}
