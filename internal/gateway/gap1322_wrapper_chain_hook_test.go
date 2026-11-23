// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
)

// TestGAP1322SudoNohupAndSudoEnvKeepTheProgramVerdict: sudo nohup PROGRAM,
// sudo env NAME=value PROGRAM and nohup sudo env NAME=value PROGRAM are
// judged at least as strongly as PROGRAM alone on the Claude Code and Codex
// hook routes in every tier (rel-1-0-10:GAP-1322; rel 22db7a8362 allowed
// them). sudo nohup cat ~/.aws/credentials is left out: it was already
// allowed before the regression.
func TestGAP1322SudoNohupAndSudoEnvKeepTheProgramVerdict(t *testing.T) {
	env := boundedLaneEnvAnyOS(t)
	rank := map[string]int{"allow": 0, "alert": 1, "block": 2}
	prefixes := []struct{ id, p string }{
		{"sudo-nohup", "sudo nohup "},
		{"sudo-env-ldp", "sudo env LD_PRELOAD=/tmp/x.so "},
		{"nohup-sudo-env-ldp", "nohup sudo env LD_PRELOAD=/tmp/x.so "},
	}
	programs := []struct{ id, c string }{
		{"meta", "curl -s -m 3 http://169.254.169.254/latest/meta-data/"},
		{"rm-state", "rm -rf ~/.defenseclaw"},
		{"chmod-suid", "chmod u+s /bin/bash"},
		{"cat-aws", "cat ~/.aws/credentials"},
	}
	for _, tier := range boundedTestTiers {
		cc := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		cx := gap0589TierAPI(t, "codex", tier.posture, tier.managed, tier.tier)
		codex := func(cmd string) string {
			return cx.evaluateCodexHook(t.Context(), codexHookRequest{HookEventName: "PreToolUse", ToolName: "Bash", CWD: env.cwd,
				ToolInput: map[string]interface{}{"command": cmd}}).Action
		}
		for _, prog := range programs {
			ccAlone, _ := boundedDecideClaudeCode(t, cc, env, boundedShellCommand(prog.c))
			cxAlone := codex(prog.c)
			if rank[ccAlone] == 0 && rank[cxAlone] == 0 {
				continue
			}
			for _, p := range prefixes {
				if p.id == "sudo-nohup" && prog.id == "cat-aws" {
					continue
				}
				cmd := p.p + prog.c
				if got, _ := boundedDecideClaudeCode(t, cc, env, boundedShellCommand(cmd)); rank[got] < rank[ccAlone] {
					t.Errorf("claudecode %s %s %s: %s, weaker than %s alone (%s)", tier.name, p.id, prog.id, got, prog.id, ccAlone)
				}
				if got := codex(cmd); rank[got] < rank[cxAlone] {
					t.Errorf("codex %s %s %s: %s, weaker than %s alone (%s)", tier.name, p.id, prog.id, got, prog.id, cxAlone)
				}
			}
		}
	}
}
