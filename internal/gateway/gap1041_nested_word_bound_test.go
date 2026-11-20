// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// gap1041DecisionBudget is the time one hook decision on a nested program
// word may take: a fifth of the hook request deadline. rel/1.0.10 decides
// these calls in tens of milliseconds; before rel-1-0-10:GAP-1041 the
// run-time shell reading doubled per level (12.5 s at 20 levels, 50 s at
// 22), past the deadline.
const gap1041DecisionBudget = 2 * time.Second

func gap1041ProgramWord(seed string, levels int) string {
	inner := seed
	for i := 0; i < levels; i++ {
		inner = "$(which " + inner + ")"
	}
	return `"` + inner + `"`
}

// TestGAP1041NestedSubstitutionsDecideInTime: a Bash call whose program
// word nests command substitutions is decided in time at every depth and in
// every tier, as TRUNCATED: the evaluation-limit finding and at least the
// unknown tier of the pack. A shell named at the innermost level still runs
// the -c text as the literal shell, so the seen write is a state write (alert, block in strict)
// up to the reader bound (rel-1-0-10:GAP-1041, GAP-0980).
func TestGAP1041NestedSubstitutionsDecideInTime(t *testing.T) {
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
					if body.seen && seed == "bash" && levels <= 64 && boundedParse(action) != gap0747StateWriteAction(tier.tier) {
						t.Errorf("%s: action %s; the seen write must be %s", name, action, gap0747StateWriteAction(tier.tier))
					}
				}
			}
		}
	}
}
