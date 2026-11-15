// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// TestGAP0748POSIXShellOverTheInputBoundIsTruncatedFiveTiers: a POSIX shell
// command line past actionfacts.MaxCommandBytes with no proven finding is
// TRUNCATED at cap=bytes: exactly the unknown tier of its pack in all five
// tiers (an alert in the default, permissive and managed default packs, a
// block in strict and managed strict), never below it and never a CRITICAL
// block outside strict. It was a clean allow in every pack once the byte floor
// was reverted from batch 11 (rel-1-0-10:GAP-0611, GAP-0748). A command at the
// bound is read in full, and a finding proven on the text keeps its own
// verdict beside the padding (the bounded twin).
func TestGAP0748POSIXShellOverTheInputBoundIsTruncatedFiveTiers(t *testing.T) {
	env := boundedLaneEnv(t)
	pad := func(command string, extra int) string {
		prefix := command + "\n# "
		return prefix + strings.Repeat("x", actionfacts.MaxCommandBytes+extra-len(prefix))
	}
	const ordinary = "ls -la project"
	for _, tier := range boundedTestTiers {
		floor := bounded.Unknown(tier.tier)
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(pad(ordinary, 0)))
		t.Logf("ROW %s | claudecode Bash | at the bound | %s", tier.name, action)
		if got := boundedParse(action); got != bounded.Allow || boundedHasLimit(findings, bounded.Bytes, false) {
			t.Errorf("%s at the bound: action %s, want allow and no limit finding; findings %v", tier.name, action, findings)
		}
		action, findings = boundedDecideClaudeCode(t, api, env, boundedShellCommand(pad(ordinary, 1)))
		t.Logf("ROW %s | claudecode Bash | one byte over | %s", tier.name, action)
		if got := boundedParse(action); got != floor || !boundedHasLimit(findings, bounded.Bytes, true) {
			t.Errorf("%s one byte over: action %s, want %s with %s naming cap=bytes; findings %v", tier.name, action, floor, evaluationLimitRuleID, findings)
		}
		action, findings = boundedDecideClaudeCode(t, api, env, boundedShellCommand(pad(boundedShellSeen, 1)))
		t.Logf("ROW %s | claudecode Bash | state write + padding | %s", tier.name, action)
		if got := boundedParse(action); got != bounded.Block {
			t.Errorf("%s state write beside padding: action %s, want block; findings %v", tier.name, action, findings)
		}
	}
}
