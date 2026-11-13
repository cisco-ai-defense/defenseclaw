// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// gas-ux-r2:GAP-0082: a call the reader failed on carries the
// ACTION-PARSE-FAILURE rule id. Like the evaluation limit it alerts outside
// the strict tier and blocks in it; it is never a silent allow.
func TestGAP0082ParseFailureFindingAlertsOrBlocksWithRuleID(t *testing.T) {
	findings := trustedActionParseFailureFindings(true)
	if len(findings) != 1 || findings[0].RuleID != parseFailureRuleID || !findings[0].contributesToEnforcement() {
		t.Fatalf("findings = %+v, want one enforcing %s", findings, parseFailureRuleID)
	}
	blockAt := func(severity string) string {
		if severity == "CRITICAL" || severity == "HIGH" {
			return guardrailActionBlock
		}
		return guardrailActionAllow
	}
	for _, tc := range []struct {
		strict bool
		want   string
	}{{false, guardrailActionAlert}, {true, guardrailActionBlock}} {
		if got := guardrailActionForProfile(findings, false, func() bool { return tc.strict }, blockAt); got != tc.want {
			t.Errorf("strict=%t action = %q, want %q", tc.strict, got, tc.want)
		}
	}
}
