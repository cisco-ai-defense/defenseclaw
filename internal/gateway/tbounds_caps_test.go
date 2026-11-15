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

// The property test of the bound rule (TestBoundRuleEveryLaneCap) covers two
// caps of this train: the chain of prefix wrappers the action analysis
// unwraps (cap depth, a run-time operand after the chain so that nothing
// proves a block at the cap), and the depth of eval the in-place backup
// reader enters (cap paths, rel-1-0-10:GAP-0738).
func init() {
	chain := func(size int) string {
		return strings.Repeat("sudo -n ", size) + `printf done > "$HOME/$OUT"`
	}
	evals := func(size int) string {
		return strings.Repeat("eval ", size) + `sed -i.bak s/x/y/ "$F"`
	}
	only := func(fill func(int) string) func(int, boundedShape) (boundedLaneCall, bool) {
		return func(size int, shape boundedShape) (boundedLaneCall, bool) {
			if shape.nested || shape.multi {
				return boundedLaneCall{}, false
			}
			return boundedShellLane(fill, fill)(size, shape)
		}
	}
	registerBoundedLane(
		boundedLaneCap{lane: "prefix wrapper chain", cap: bounded.Depth, limit: 4,
			gen: only(chain), seen: boundedShellSeenCall},
		boundedLaneCap{lane: "sed backup reader eval depth", cap: bounded.Paths, limit: 8,
			gen: only(evals), seen: boundedShellSeenCall},
	)
}

// TestBoundRulePrefixWrapperChain: a chain of plain prefix wrappers ahead of
// a command is unwrapped up to actionfacts.MaxPrefixWrapperChain, so the
// delete of the home blocks behind any chain the readers unwrap in full; a
// chain past the bound is truncated at cap depth (at least the unknown tier
// of the pack), never a clean allow, and whatever the text before the chain
// proves still decides (rel-1-0-10:GAP-0689, the wrapper chains of s7-cf2chk
// round 2: sudo -n, command, exec, env, nohup, timeout).
func TestBoundRulePrefixWrapperChain(t *testing.T) {
	env := boundedLaneEnv(t)
	max := actionfacts.MaxPrefixWrapperChain
	// The action analysis unwraps a chain of plain prefix wrappers to its
	// wrapper depth; past it the call is truncated at cap depth, whatever else
	// it holds (a dynamic word such as ~ used to hide the limit and left only
	// the first wrapper read). The readers that unwrap further still prove a
	// block of their own.
	read := actionfacts.MaxWrapperDepth
	groups := []struct {
		wrappers []string
		readTo   int
	}{
		{[]string{"sudo -n", "command", "env A=1", "nohup", "timeout 5"}, read},
	}
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		floor := bounded.Unknown(tier.tier)
		for _, group := range groups {
			for _, wrapper := range group.wrappers {
				for _, n := range []int{1, group.readTo} {
					id := fmt.Sprintf("CW-%s-%d", strings.ReplaceAll(wrapper, " ", "_"), n)
					command := strings.Repeat(wrapper+" ", n) + "rm -rf ~"
					if action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(command)); action != "block" {
						t.Errorf("%s in tier %s: action %q, want block; findings=%v", id, tier.name, action, findings)
					}
					command = strings.Repeat(wrapper+" ", n) + "echo hi"
					if action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(command)); action != "allow" {
						t.Errorf("%s-benign in tier %s: action %q, want allow; findings=%v", id, tier.name, action, findings)
					}
				}
				for _, n := range []int{group.readTo + 1, 8, max + 1, max + 8} {
					id := fmt.Sprintf("CW-%s-%d", strings.ReplaceAll(wrapper, " ", "_"), n)
					for _, tail := range []string{"rm -rf ~", "echo hi", `echo "$HOME"`} {
						command := strings.Repeat(wrapper+" ", n) + tail
						action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(command))
						if got := boundedParse(action); got < floor {
							t.Errorf("%s %q in tier %s: action %q, want at least %s (the unknown tier); findings=%v", id, tail, tier.name, action, floor, findings)
						}
						if !boundedHasLimit(findings, bounded.Depth, true) && boundedParse(action) < bounded.Block {
							t.Errorf("%s %q in tier %s: no evaluation-limit finding naming cap depth: %v", id, tail, tier.name, findings)
						}
					}
					// A delete of the home written before the chain still blocks.
					command := "rm -rf ~; " + strings.Repeat(wrapper+" ", n) + "echo hi"
					if action, _ := boundedDecideClaudeCode(t, api, env, boundedShellCommand(command)); action != "block" {
						t.Errorf("%s-seen-before in tier %s: action %q, want block", id, tier.name, action)
					}
				}
			}
		}
	}
}

// TestBoundRuleArgvArrayWordPastTheBound: a call whose command is an array of
// words (the Codex shell tool) with a word past the 4 KiB string bound is
// judged as the same call written as text: a word the shell runs as code
// (bash -lc SCRIPT) is truncated at the unknown tier of the pack, a plain
// operand of a program that passes it on stays data and allowed
// (rel-1-0-10:GAP-0689, rows k13 and k14 of the s7-pcapchk bound probe).
func TestBoundRuleArgvArrayWordPastTheBound(t *testing.T) {
	env := boundedLaneEnv(t)
	big := strings.Repeat("a", 4100)
	cases := []struct {
		id   string
		argv []any
		code bool
	}{
		{"k13-codex-argv-word-4100", []any{"bash", "-lc", big}, true},
		{"k13-sh-c", []any{"sh", "-c", big}, true},
		{"k13-env-sh-c", []any{"env", "X=1", "sh", "-c", big}, true},
		// The script of a shell is read as shell text: a word past the bound
		// that is the plain operand of a program inside it is data.
		{"k13-echo-in-script", []any{"bash", "-lc", "echo " + big}, false},
		{"k13-ssh-in-script", []any{"bash", "-lc", "ssh host '" + big + "'"}, false},
		{"k14-codex-argv-arg-4100", []any{"echo", big}, false},
		{"k14-dcx", []any{"dcx", "-", big}, false},
	}
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		floor := bounded.Unknown(tier.tier)
		for _, tc := range cases {
			call := boundedLaneCall{tool: "shell", input: map[string]any{"command": tc.argv}}
			action, findings := boundedDecideClaudeCode(t, api, env, call)
			if tc.code {
				if got := boundedParse(action); got < floor {
					t.Errorf("%s in tier %s: action %q, want at least %s (the unknown tier); findings=%v", tc.id, tier.name, action, floor, findings)
				}
				if !boundedHasLimit(findings, bounded.Bytes, true) && boundedParse(action) < bounded.Block {
					t.Errorf("%s in tier %s: no evaluation-limit finding naming cap bytes: %v", tc.id, tier.name, findings)
				}
				continue
			}
			if action != "allow" {
				t.Errorf("%s in tier %s: action %q, want allow (data word); findings=%v", tc.id, tier.name, action, findings)
			}
		}
	}
}
