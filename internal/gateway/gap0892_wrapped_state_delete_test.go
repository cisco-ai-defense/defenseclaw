// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// gap0892Wrappers are the mixed prefix wrappers of the tamper-min probe rows
// (tbfx-*-mix-N): a chain of the first n is the mix-n spelling.
var gap0892Wrappers = []string{"nohup", "env", "timeout 5", "nice -n 1", "stdbuf -o0", "command", "sudo -n", "nohup"}

func gap0892Chain(n int) string {
	if n == 0 {
		return ""
	}
	return strings.Join(gap0892Wrappers[:n], " ") + " "
}

// A delete of the DefenseClaw config with a tilde operand behind any chain of
// mixed prefix wrappers is never a clean allow: the analysis reads the
// wrapped call as partial, so the proven state-mutation finding alone does not
// enforce, and the call gets the unknown tier of the pack or the block the
// finding proves, in every tier (rel-1-0-10:GAP-0892; a chain of exactly
// MaxWrapperDepth wrappers was allowed in all 5, and so was a chain of 2).
// The bare delete blocks; 3 and 5 wrappers are the controls on either side of
// the bound. A wrapped ordinary delete in the project stays allowed within the
// wrapper depth.
func TestGAP0892WrappedStateDeleteIsNeverAClearAllow(t *testing.T) {
	env := boundedLaneEnv(t)
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		floor := bounded.Unknown(tier.tier)
		for n := 0; n <= len(gap0892Wrappers); n++ {
			id := fmt.Sprintf("%s/mix-%d", tier.name, n)
			action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(gap0892Chain(n)+gap0892StateDelete))
			got := boundedParse(action)
			if n == 0 && got != gap0747StateWriteAction(tier.tier) {
				t.Errorf("%s: action %q, want %s (alert outside strict); findings=%v", id, action, gap0747StateWriteAction(tier.tier), findings)
			}
			if got < floor || got == bounded.Allow {
				t.Errorf("%s: action %q, want at least %s, never allow; findings=%v", id, action, floor, findings)
			}
			// Past MaxWrapperDepth the chain floor makes any call the unknown
			// tier (rel-1-0-10:GAP-0689); within it an ordinary delete is allowed.
			benign, bfindings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(gap0892Chain(n)+gap0892ProjectDelete))
			if b := boundedParse(benign); n <= actionfacts.MaxWrapperDepth && b != bounded.Allow || b > floor {
				t.Errorf("%s benign: action %q, want allow (at most %s past the wrapper depth); findings=%v", id, benign, floor, bfindings)
			}
		}
	}
}

// gap0892StateDelete and gap0892ProjectDelete are the wrapped deletes of
// TestGAP0892WrappedStateDeleteIsNeverAClearAllow: the DefenseClaw config
// with a tilde operand and an ordinary file in the project.
const (
	gap0892StateDelete   = "rm -f ~/.defenseclaw/config.yaml"
	gap0892ProjectDelete = "rm -f build/out.txt"
)

// The GAP-0892 floor holds when the wrapped delete sits in a construct the
// analysis does not model (a function body, a group, a loop, a list, a
// pipeline, a background job, a dynamic word): such a call is read with
// unsupported_construct or dynamic_word as well as unknown_operand_grammar,
// and the readings of its parts floor it. A HOME that a function call moves
// to another literal home before the delete makes it a delete below that
// home, no state write, so the call stays allowed: the floor fired on it
// from a nested reading of the delete without the HOME it runs under, which
// blocked 12 benign rows of TestHomeDeclarationInAFunctionBody on
// d4a0441127. A HOME the function does not move (not called, local to the
// body, set to itself, moved in a subshell, a prefix assignment the shell
// expands the tilde before) keeps the floor. Chains of 2 and 4 wrappers are
// the GAP-0892 spellings, 3 the control between them.
func TestGAP0892WrappedStateDeleteInAConstructIsNeverAClearAllow(t *testing.T) {
	env := boundedLaneEnv(t)
	floored := []string{
		"f(){ %s; }; f", "f(){ %s; }; true; f", "f(){ local A=1; %s; }; f",
		"%s; g(){ :; }", "g(){ :; }; g; %s", "{ %s; }", "(%s)",
		"for i in 1; do %s; done", "if true; then %s; fi", "true && %s",
		"case a in a) %s;; esac", "echo y | %s", "%s &", "%s $(true)", "%s 2>/dev/null",
		"f(){ export HOME=$HOME; }; f; %s", "f(){ export HOME=/tmp/x; }; %s",
		"f(){ declare HOME=/tmp/x; }; f; %s", "(export HOME=/tmp/x); %s", "HOME=/tmp/x %s",
	}
	moved := []string{
		"f(){ export HOME=/tmp/x; }; f; %s", "f(){ export HOME=/tmp/x; }; f; cd; %s",
		"f(){ export HOME=/tmp/x; }; f; %s; g(){ :; }", "export HOME=/tmp/x; %s",
	}
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		floor := bounded.Unknown(tier.tier)
		for _, n := range []int{2, 3, 4} {
			chain := gap0892Chain(n)
			for _, shape := range floored {
				command := fmt.Sprintf(shape, chain+gap0892StateDelete)
				action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(command))
				if got := boundedParse(action); got < floor || got == bounded.Allow {
					t.Errorf("%s mix-%d %q: action %q, want at least %s, never allow; findings=%v", tier.name, n, command, action, floor, findings)
				}
				benign := fmt.Sprintf(shape, chain+gap0892ProjectDelete)
				if action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(benign)); boundedParse(action) != bounded.Allow {
					t.Errorf("%s mix-%d %q: action %q, want allow; findings=%v", tier.name, n, benign, action, findings)
				}
			}
			for _, shape := range moved {
				command := fmt.Sprintf(shape, chain+gap0892StateDelete)
				if action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(command)); boundedParse(action) != bounded.Allow {
					t.Errorf("%s mix-%d %q: action %q, want allow (HOME moved); findings=%v", tier.name, n, command, action, findings)
				}
			}
		}
	}
}
