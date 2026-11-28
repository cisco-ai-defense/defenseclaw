// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// gap1207NeutralChain spells a chain of count context-neutral wrappers by
// cycling through unit (nohup, nice, nice -n 5, timeout 5, time).
func gap1207NeutralChain(unit []string, count int) string {
	var chain strings.Builder
	for i := range count {
		chain.WriteString(unit[i%len(unit)])
		chain.WriteByte(' ')
	}
	return chain.String()
}

// TestGAP1207ContextNeutralWrapperKeepsTheProgramVerdict: a context-neutral
// wrapper (nice, time, timeout, nohup) only runs the next program, so on the
// Claude Code hook route a run of them up to actionfacts.InlineChainWrappers
// keeps the verdict the program has alone, with no evaluation-limit finding:
// the metadata fetch blocks behind nice as it does behind nohup
// (rel-1-0-10:GAP-1207), and five or sixty-four of them are read whole
// (substrate-1:GAP-0478, rel-1-0-10:GAP-0976). Ordinary programs behind the
// same wrappers stay allowed, also with a -c option and a word made at run
// time among their arguments. One wrapper past the bound is truncated at cap
// depth, never weaker than the program in strict and never a clean allow
// (rel-1-0-10:GAP-0973, the one bound rule).
func TestGAP1207ContextNeutralWrapperKeepsTheProgramVerdict(t *testing.T) {
	env := boundedLaneEnvAnyOS(t)
	limit := actionfacts.InlineChainWrappers
	units := map[string][]string{
		"nohup":       {"nohup"},
		"nice":        {"nice"},
		"nice-n":      {"nice -n 5"},
		"timeout":     {"timeout 5"},
		"nohup-nice":  {"nohup", "nice"},
		"nice-nohup":  {"nice", "nohup"},
		"mixed-four":  {"nice", "nohup", "timeout 5", "time"},
		"time-inside": {"nohup", "time"},
	}
	programs := []struct {
		id, command string
		block       bool
	}{
		{"metadata-fetch", "curl -s -m 3 http://169.254.169.254/latest/meta-data/", true},
		{"benign-git", "git status", false},
		{"benign-ls", "ls -la", false},
		{"benign-gotest", "go test ./...", false},
		// A program option spelled -c and a word made at run time among
		// the program's own arguments are not a shell -c body behind the
		// wrapper either (owner-trace A/B, the -c of go test -c).
		{"benign-gotest-c", `go test -c -o "$OUT/pkg.test" ./internal/gateway`, false},
	}
	for _, tier := range boundedTestTiers {
		if tier.managed || tier.tier == bounded.TierPermissive {
			continue
		}
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		floor := bounded.Unknown(tier.tier)
		for _, program := range programs {
			alone, aloneFindings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(program.command))
			if want := map[bool]string{true: "block", false: "allow"}[program.block]; alone != want {
				t.Fatalf("%s alone in tier %s: action %q, want %q; findings=%v", program.id, tier.name, alone, want, aloneFindings)
			}
			for name, unit := range units {
				for _, depth := range []int{1, 2, 5, limit} {
					id := fmt.Sprintf("G1207-%s-%s-%d", name, program.id, depth)
					command := gap1207NeutralChain(unit, depth) + program.command
					action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(command))
					if action != alone {
						t.Errorf("%s in tier %s: action %q, want %q as the program alone; findings=%v", id, tier.name, action, alone, findings)
					}
					if boundedHasLimit(findings, bounded.Depth, false) {
						t.Errorf("%s in tier %s: evaluation-limit finding on a chain the readers read whole: %v", id, tier.name, findings)
					}
				}
				for _, depth := range []int{limit + 1, 2 * limit} {
					id := fmt.Sprintf("G1207-%s-%s-%d", name, program.id, depth)
					command := gap1207NeutralChain(unit, depth) + program.command
					action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(command))
					got := boundedParse(action)
					if got < floor || got < boundedParse(alone) && tier.tier == bounded.TierStrict {
						t.Errorf("%s in tier %s: action %q, want at least %s and not below %q; findings=%v", id, tier.name, action, floor, alone, findings)
					}
					if !boundedHasLimit(findings, bounded.Depth, true) && got < bounded.Block {
						t.Errorf("%s in tier %s: no evaluation-limit finding naming cap depth: %v", id, tier.name, findings)
					}
				}
			}
		}
	}
}

// TestGAP1207EnvAfterNeutralWrappersKeepsTheProgramVerdict: env after a run of
// context-neutral wrappers still runs the program the chain ends in, so on
// the Claude Code hook route the call keeps the verdict the program has
// alone. The Codex review r1 rows (nohup x63/x64 then env x3/x4 before the
// metadata fetch) were a clean allow in default and strict at d99d8a01a7,
// below the truncation alert/block of rel (rel-1-0-10:GAP-1207 review r1).
func TestGAP1207EnvAfterNeutralWrappersKeepsTheProgramVerdict(t *testing.T) {
	env := boundedLaneEnvAnyOS(t)
	limit := actionfacts.InlineChainWrappers
	programs := []struct {
		id, command string
		block       bool
	}{
		{"metadata-fetch", "curl -s -m 3 http://169.254.169.254/latest/meta-data/", true},
		{"benign-git", "git status", false},
	}
	for _, tier := range boundedTestTiers {
		if tier.managed || tier.tier == bounded.TierPermissive {
			continue
		}
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		for _, program := range programs {
			alone, aloneFindings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(program.command))
			if want := map[bool]string{true: "block", false: "allow"}[program.block]; alone != want {
				t.Fatalf("%s alone in tier %s: action %q, want %q; findings=%v", program.id, tier.name, alone, want, aloneFindings)
			}
			for _, neutral := range []int{1, limit - 1, limit} {
				for _, envs := range []int{1, 3, actionfacts.MaxWrapperDepth} {
					id := fmt.Sprintf("G1207-nohup%d-env%d-%s", neutral, envs, program.id)
					command := gap1207NeutralChain([]string{"nohup"}, neutral) + strings.Repeat("env ", envs) + program.command
					action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(command))
					if action != alone {
						t.Errorf("%s in tier %s: action %q, want %q as the program alone; findings=%v", id, tier.name, action, alone, findings)
					}
				}
			}
		}
	}
}
