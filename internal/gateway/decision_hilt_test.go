// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// GAP-0056: with human approval on at HIGH, a MEDIUM finding (CodeGuard's
// CG-EXEC-002, for one) is an alert, not an approval prompt; HIGH asks and
// CRITICAL blocks on the default profile.
func TestGuardrailActionForRankHILTAtHighLeavesMediumAnAlert(t *testing.T) {
	block, alert := guardrailProfileThresholds("default")
	for rank, want := range map[int]string{
		severityLow:      guardrailActionAllow,
		severityMedium:   guardrailActionAlert,
		severityHigh:     guardrailActionConfirm,
		severityCritical: guardrailActionBlock,
	} {
		if got := guardrailActionForRank(rank, block, alert, true, severityHigh); got != want {
			t.Errorf("rank %d with HILT at HIGH = %q, want %q", rank, got, want)
		}
	}
}
