// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"strings"
	"testing"
)

// gap1144Rank orders the hook answers.
var gap1144Rank = map[string]int{"allow": 0, "alert": 1, "block": 2}

// TestChainBodyWritesAreJudgedInEveryFolderTheChainMayLeave: a cd chain with
// || or && leaves the shell in one of several folders (each cd may fail),
// and a write made inside an eval, sh -c or bash -c body or a function body
// after it runs in each of them. A write of the DefenseClaw state by its bare
// name there is the protected write it is in the state folder, in every tier,
// through the Claude Code hook with the hook client's resolved writes
// (rel-1-0-10:GAP-1144, cert lane L69 on IB1: the eval form after
// `cd A || cd B &&` overwrote config.yaml with only a CMD-EVAL alert; the
// GAP-0183 replay). The oracle of each body is its form after a plain
// `cd ~/.defenseclaw &&`, which blocks in every tier. A chain that never
// leaves the shell in the state folder (a subshell, folders of the project)
// stays as it was: no block.
func TestChainBodyWritesAreJudgedInEveryFolderTheChainMayLeave(t *testing.T) {
	env := boundedLaneEnv(t)
	writes := []string{
		"echo m > config.yaml",
		"rm -f config.yaml",
		"x=config.yaml; echo m > $x",
	}
	// Each chain may leave the shell in the state folder before BODY.
	chains := []string{
		"cd ~/.defenseclaw || cd /tmp && BODY",
		"cd /tmp || cd ~/.defenseclaw && BODY",
		"cd ~/.defenseclaw || cd /tmp; BODY",
		"cd ~/.defenseclaw 2>/dev/null || cd /tmp && BODY",
		"cd /nonexistent-g1144 || cd ~/.defenseclaw && BODY",
		"{ cd ~/.defenseclaw || cd /tmp; } && BODY",
		"cd ~/.defenseclaw || true && BODY",
		"pushd ~/.defenseclaw || pushd /tmp && BODY",
		"cd ~/.defenseclaw || cd /tmp\nBODY",
		// A function whose body moves leaves the shell where its body may.
		"f() { cd ~/.defenseclaw || cd /tmp; }; f && BODY",
		"f() { cd ~/.defenseclaw || cd /tmp; }; f; BODY",
	}
	wrappers := []string{
		"eval 'W'",
		"command eval 'W'",
		"sh -c 'W'",
		"bash -c 'W'",
		"f() { W; }; f",
		"( eval 'W' )",
	}
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		decide := func(command string) (string, []string) {
			command = strings.ReplaceAll(command, "{cwd}", env.cwd)
			return boundedDecideClaudeCode(t, api, env, boundedShellCommand(command))
		}
		check := func(command, oracle string) {
			want, wantFindings := decide(oracle)
			if want != "block" {
				t.Errorf("%s: the oracle %q is %s (%q), want block", tier.name, oracle, want, wantFindings)
			}
			if got, findings := decide(command); gap1144Rank[got] < gap1144Rank[want] {
				t.Errorf("%s: %q is %s (%q), its form in the state folder is %s", tier.name, command, got, findings, want)
			}
		}
		for _, write := range writes {
			for _, wrapper := range wrappers {
				body := strings.ReplaceAll(wrapper, "W", write)
				oracle := "cd ~/.defenseclaw && " + body
				// Every wrapper after the first two chains; the eval form after
				// every chain.
				for index, chain := range chains {
					if index < 2 || wrapper == wrappers[0] {
						check(strings.ReplaceAll(chain, "BODY", body), oracle)
					}
				}
			}
			// A function defined before the chain runs where it is called.
			check("f() { "+write+"; }; cd ~/.defenseclaw || cd /tmp && f", "cd ~/.defenseclaw && f() { "+write+"; }; f")
		}
		for _, command := range []string{
			"cd /tmp || cd {cwd} && eval 'echo m > notes.txt'",
			"cd /tmp || cd {cwd} && eval 'x=notes.txt; echo m > $x'",
			"cd /tmp || cd {cwd} && sh -c 'echo m > config.yaml'",
			"cd {cwd}/build 2>/dev/null || cd {cwd} && sh -c 'x=out.txt; echo m > $x'",
			"cd /tmp || cd {cwd} && f() { echo m > notes.txt; }; f",
			"(cd ~/.defenseclaw || cd /tmp) && eval 'echo m > config.yaml'",
			"(cd ~/.defenseclaw || cd /tmp) && eval 'x=config.yaml; echo m > $x'",
			"f() { echo m > config.yaml; }; (cd ~/.defenseclaw || cd /tmp); f",
			"cd ~/.defenseclaw || cd /tmp && eval 'cat config.yaml'",
			"cd ~/.defenseclaw && cd {cwd} || cd /tmp && eval 'x=config.yaml; echo m > $x'",
			"f() { cd /tmp || cd {cwd}; }; f; eval 'x=notes.txt; echo m > $x'",
			"f() { (cd ~/.defenseclaw || cd /tmp); }; f && eval 'x=config.yaml; echo m > $x'",
		} {
			if got, findings := decide(command); got == "block" {
				t.Errorf("%s: %q is %s (%q), want no block", tier.name, command, got, findings)
			}
		}
	}
}
