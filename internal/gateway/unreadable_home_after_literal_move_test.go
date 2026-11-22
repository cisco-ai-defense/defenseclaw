// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// TestUnreadableHomeAfterALiteralMoveIsTheActiveHome is rel-1-0-10:GAP-1087.
// HOME moved to a literal home and then set to a value the analysis cannot
// read (a substitution, an unknown variable) kept the literal home, so a
// later ~ delete or write of DefenseClaw state was a clean allow in all five
// tiers, where the same statements without the literal move are judged
// against the active home (GAP-2476). Through the Claude Code hook, in the
// five tiers, every such form gets at least the verdict of the form without
// the move and at least the unknown tier. Controls: an ordinary ~ write keeps
// the verdict it has without the moves, and a move into DefenseClaw state
// keeps its verdict when HOME is then made unreadable (the moved home stays
// one of the readings).
func TestUnreadableHomeAfterALiteralMoveIsTheActiveHome(t *testing.T) {
	env := boundedLaneEnv(t)
	const unread = "export HOME=$(getent passwd $USER | cut -d: -f6); "
	moves := map[string]string{
		"function-move": "f(){ export HOME=/tmp/x; }; f; " + unread,
		"export-move":   "export HOME=/tmp/x; " + unread,
		"assign-move":   "HOME=/tmp/x; HOME=$O; ",
		"newline-move":  "export HOME=/tmp/x\nexport HOME=$O\n",
	}
	operations := map[string]string{
		"delete": "rm -f ~/.defenseclaw/config.yaml",
		"write":  "cp a.txt ~/.defenseclaw/config.yaml",
	}
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		verdict := func(command string) bounded.Action {
			action, _ := boundedDecideClaudeCode(t, api, env, boundedShellCommand(command))
			return boundedParse(action)
		}
		floor := bounded.Unknown(tier.tier)
		for opName, op := range operations {
			for _, n := range []int{0, 2} {
				chain := strings.Repeat("true && ", n)
				oracle := verdict(unread + chain + op)
				for moveName, move := range moves {
					command := move + chain + op
					got := verdict(command)
					if got < oracle || got < floor {
						t.Errorf("%s %s %s chain=%d: %q is %s, without the move %s (unknown tier %s)",
							tier.name, moveName, opName, n, command, got, oracle, floor)
					}
				}
			}
		}
		for _, control := range []struct{ command, alone string }{
			{"export HOME=/tmp/x; " + unread + "cp a.txt ~/project/out.txt", "cp a.txt ~/project/out.txt"},
			{"HOME=/tmp/x; HOME=$O; cp a.txt ~/project/out.txt", "cp a.txt ~/project/out.txt"},
			{"export HOME=$HOME/.defenseclaw; export HOME=$O; cp a.txt ~/config.yaml",
				"export HOME=$HOME/.defenseclaw; cp a.txt ~/config.yaml"},
		} {
			got, want := verdict(control.command), verdict(control.alone)
			if strings.Contains(control.alone, ".defenseclaw") {
				if got < want {
					t.Errorf("%s control %q is %s, below %s of %q", tier.name, control.command, got, want, control.alone)
				}
				continue
			}
			if got != want {
				t.Errorf("%s control %q is %s, %q is %s", tier.name, control.command, got, control.alone, want)
			}
		}
	}
}
