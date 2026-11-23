// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"
)

// TestGAP1229MoverDefinedInAListLeavesTheShellWhereItMayFiveTiers pins
// rel-1-0-10:GAP-1229 (review round 1 of s7/cdcand, row m-return-semi): a
// function whose body has a cd that may fail and then returns leaves the
// shell where it was or where the cd took it, wherever the text defines it.
// Defined in an && tail, a branch or the body of a function called first
// (not at the top level of the text), its call left an unresolved folder,
// and a write of the DefenseClaw state or the authorized keys by the bare
// name after it was allowed in every tier. Each row is judged as its write
// right after the first cd (the oracle, which blocks), through the Claude
// Code hook in the five tiers; the same shapes on project files stay
// unblocked.
func TestGAP1229MoverDefinedInAListLeavesTheShellWhereItMayFiveTiers(t *testing.T) {
	// Every row runs on a Windows gateway too: the and-tail-variable row (the
	// write through $x) was allowed there in every tier while its oracle
	// kept its verdict (rel-1-0-10:GAP-1880).
	env := boundedLaneEnvAnyOS(t)
	const mover = "f() { cd /nonexistent-g1229 || return; }"
	state, key := "cd ~/.defenseclaw && echo m > config.yaml", "cd ~/.ssh && echo k >> authorized_keys"
	rows := []struct{ id, command, oracle string }{
		{"and-tail", "cd ~/.defenseclaw && " + mover + "; f; echo m > config.yaml", state},
		{"and-tail-and", "cd ~/.defenseclaw && f() { cd /nonexistent-g1229 || return 0; }; f && echo m > config.yaml", state},
		{"and-tail-variable", "cd ~/.defenseclaw && " + mover + "; f; x=config.yaml; echo m > $x", state},
		// The same write after a top-level cd that may fail: the folder of
		// cd ~/.defenseclaw was dropped under a Windows home (GAP-1880).
		{"may-fail-cd-variable", "cd ~/.defenseclaw; cd /nonexistent-g1229 || true; x=config.yaml; echo m > $x", state},
		{"may-fail-cd-relative-variable", "cd ~ && cd .defenseclaw; cd /nonexistent-g1229 || true; x=config.yaml; echo m > $x", state},
		{"and-tail-key", "cd ~/.ssh && " + mover + "; f; echo k >> authorized_keys", key},
		{"branch", "cd ~/.defenseclaw; if true; then " + mover + "; fi; f; echo m > config.yaml", state},
		{"body-called-first", "h() { " + mover + "; }; cd ~/.defenseclaw && h; f; echo m > config.yaml", state},
	}
	benign := []string{
		"cd {cwd} && " + mover + "; f; echo m > notes.txt",
		"cd {cwd} && f() { cd {cwd}/sub || return; }; f; echo m > config.yaml",
	}
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		decide := func(command string) (string, []string) {
			return boundedDecideClaudeCode(t, api, env, boundedShellCommand(strings.ReplaceAll(command, "{cwd}", env.cwd)))
		}
		for _, r := range rows {
			// A proven state write is a HIGH alert outside strict (GAP-0747
			// owner tiering 2026-11-15T15:20Z).
			wantAction := gap0747TierWantAction(tier.tier)
			if r.oracle == key {
				wantAction = "block" // the SSH authorized-keys rule, not the state write
			}
			if want, findings := decide(r.oracle); want != wantAction {
				t.Errorf("%s %s: the oracle %q is %s (%q), want %s", tier.name, r.id, r.oracle, want, findings, wantAction)
			}
			if got, findings := decide(r.command); got != wantAction {
				t.Errorf("%s %s: %q is %s (%q), its write right after the cd blocks", tier.name, r.id, r.command, got, findings)
			}
		}
		for _, command := range benign {
			if got, findings := decide(command); got == "block" {
				t.Errorf("%s: %q is %s (%q), want no block", tier.name, command, got, findings)
			}
		}
	}
}
