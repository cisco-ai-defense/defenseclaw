// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// gap0747StateRule is the rule of a proven write to DefenseClaw state.
const gap0747StateRule = "tamper.detector_state_write"

// gap0747DefaultTierCheck judges the verdict of findings in a pack that is
// not strict (default, permissive, managed default). want is the old
// every-tier expectation "this call is a proven DefenseClaw state write that
// blocks". GAP-0747 owner tiering 2026-11-15T15:20Z: such a write is a HIGH
// alert outside strict and managed-strict (rows that still block for another
// rule keep blocking, and strict rows live in gap_fu12_rules_tiers_test.go).
// It returns "" when the verdict is the expected one, else what was wrong.
func gap0747DefaultTierCheck(findings []RuleFinding, want bool) string {
	blocked := buildVerdict(findings, "tool_call").Action == "block"
	if !want {
		if blocked {
			return "blocked, want no block"
		}
		return ""
	}
	var rest []RuleFinding
	var state *RuleFinding
	for i := range findings {
		if findings[i].RuleID == gap0747StateRule {
			state = &findings[i]
			continue
		}
		rest = append(rest, findings[i])
	}
	if state == nil {
		if !blocked {
			return "not blocked, want block"
		}
		return ""
	}
	if buildVerdict(rest, "tool_call").Action == "block" {
		if !blocked {
			return "not blocked, want block for another rule"
		}
		return ""
	}
	if blocked {
		return "blocked, want an alert (HIGH state write outside strict)"
	}
	if !strings.EqualFold(state.Severity, "HIGH") {
		return "state write severity " + state.Severity + ", want HIGH"
	}
	return ""
}

// gap0747StateWriteAction is the verdict of a proven DefenseClaw state write
// in tier (GAP-0747 owner tiering 2026-11-15T15:20Z): a HIGH alert in the
// default and permissive tiers (and a managed install on the default pack),
// a block in strict and managed-strict.
func gap0747StateWriteAction(tier bounded.Tier) bounded.Action {
	if tier == bounded.TierStrict {
		return bounded.Block
	}
	return bounded.Alert
}

// gap0747Blocked is the blocked verdict of findings for a row whose old
// expectation is want (true: a proven DefenseClaw state write, which blocked
// in every tier). In a pack that is not strict the write is a HIGH alert
// (GAP-0747 owner tiering 2026-11-15T15:20Z), so a row that wants a block and
// gets exactly that alert counts as the expected verdict; any other
// difference keeps the old comparison and fails.
func gap0747Blocked(findings []RuleFinding, want bool) bool {
	if gap0747DefaultTierCheck(findings, want) == "" {
		return want
	}
	return !want
}
