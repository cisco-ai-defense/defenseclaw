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

// TestCriticalScopeWrapperChainIsReadToTheBound: the delete of the contents
// of the home (rel-1-0-10:GAP-0594) behind a chain of plain prefix wrappers
// is read through the whole chain the readers unwrap
// (actionfacts.MaxPrefixWrapperChain, not the 4 that silently ended the
// unwrap before) and blocks in every tier; a chain past it is truncated, at
// least the unknown tier of the pack (rel-1-0-10:GAP-0689).
func TestCriticalScopeWrapperChainIsReadToTheBound(t *testing.T) {
	env := boundedLaneEnv(t)
	max := actionfacts.MaxPrefixWrapperChain
	for _, tier := range boundedTestTiers {
		api := boundedTierAPI(t, tier.posture, tier.managed, tier.tier)
		floor := bounded.Unknown(tier.tier)
		for _, wrapper := range []string{"sudo -n", "env A=1", "nohup", "timeout 5"} {
			for _, n := range []int{1, 4, 5, 9, max} {
				id := fmt.Sprintf("CS-%s-%d", strings.ReplaceAll(wrapper, " ", "_"), n)
				command := strings.Repeat(wrapper+" ", n) + "rm -rf ~/*"
				if action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(command)); action != "block" {
					t.Errorf("%s in tier %s: action %q, want block; findings=%v", id, tier.name, action, findings)
				}
			}
			command := strings.Repeat(wrapper+" ", max+1) + "rm -rf ~/*"
			action, findings := boundedDecideClaudeCode(t, api, env, boundedShellCommand(command))
			if got := boundedParse(action); got < floor {
				t.Errorf("CS-%s-%d in tier %s: action %q, want at least %s; findings=%v", wrapper, max+1, tier.name, action, floor, findings)
			}
		}
	}
}
