// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// s7-probe2 old-API probe for rel-1-0-10:GAP-1041: the rel hook-route tests of the fix,
// copied with only the rel test helpers the pre-fix sha c312dd117b lacks (renamed),
// so the file compiles on the pre-fix tree and on rel. Scratch, test-only branch.

package gateway

import (
	"fmt"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
	"strings"
	"testing"
	"time"
)

// TestGAP1041NestedSubstitutionsDecideInTime: a Bash call whose program
// word nests command substitutions is decided in time at every depth and in
// every tier, as TRUNCATED: the evaluation-limit finding and at least the
// unknown tier of the pack. A shell named at the innermost level still runs
// the -c text as the literal shell, so the seen write blocks in every tier
// up to the reader bound (rel-1-0-10:GAP-1041, GAP-0980).
func TestCCP2G1041_GAP1041NestedSubstitutionsDecideInTime(t *testing.T) {
	env := boundedLaneEnv(t)
	bodies := []struct {
		id, text string
		seen     bool
	}{{"benign", "echo hi", false}, {"seen", boundedShellSeen, true}}
	for _, body := range bodies {
		if strings.Contains(body.text, "'") {
			t.Fatalf("body %s must not hold a single quote", body.id)
		}
	}
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		for _, levels := range []int{15, 20, 22, 30, 65} {
			for _, seed := range []string{"$T", "bash"} {
				for _, body := range bodies {
					name := fmt.Sprintf("%s/%d/%s/%s", tier.name, levels, seed, body.id)
					command := gap1041ProgramWord(seed, levels) + " -c '" + body.text + "'"
					start := time.Now()
					action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(command))
					elapsed := time.Since(start)
					t.Logf("ROW|%s|%s|ms=%d", name, action, elapsed.Milliseconds())
					if elapsed > gap1041DecisionBudget {
						t.Errorf("%s: decision took %v, budget %v", name, elapsed, gap1041DecisionBudget)
					}
					if !boundedHasLimit(findings, 0, false) {
						t.Errorf("%s: no evaluation-limit finding: %v", name, findings)
					}
					if got, floor := boundedParse(action), bounded.Unknown(tier.tier); bounded.Stricter(got, floor) != got {
						t.Errorf("%s: action %s below the unknown tier %s", name, action, floor)
					}
					if body.seen && seed == "bash" && levels <= 64 && action != "block" {
						t.Errorf("%s: action %s; the seen write must block", name, action)
					}
				}
			}
		}
	}
}
