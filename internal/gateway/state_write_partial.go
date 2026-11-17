// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

// partialStateWriteTitle names the unknown-tier finding of a DefenseClaw state
// write that only a reading the analysis could not finish proves.
const (
	partialStateWriteTitle  = "DefenseClaw state write in a call the analysis did not read in full"
	partialStateWriteReason = "state_write_partial_reading"
)

// withPartialStateWriteFloor gives a call at least the unknown tier of its
// pack when the exact-fallback contract of tamper.detector_state_write proved
// a mutation of the active state on the facts the analysis read, the analysis
// read the call only in part (a wrapped delete whose operand grammar it does
// not know), so no enforcing reader ran, and no reading proves the write.
// Such a finding is detection-only, so the call was a clean allow with a
// CRITICAL finding in every tier (rel-1-0-10:GAP-0892). A write that is proven keeps its own verdict; an
// audit-only or observe-mode finding stays as the pack has it.
func withPartialStateWriteFloor(request trustedActionRequest, findings []RuleFinding) []RuleFinding {
	partial := false
	for _, finding := range findings {
		if canonicalTrustedRuleID(finding.RuleID) != canonicalTrustedRuleID(stateWriteRuleID) {
			continue
		}
		if finding.contributesToEnforcement() {
			return findings // the write is proven: its own verdict decides
		}
		if finding.enforcement == findingEnforcementDetectionOnly && finding.partialReading {
			partial = true
		}
	}
	if !partial || !request.EnforcementCapable {
		return findings
	}
	return withUnknownFinding(findings, unknownReasonFinding(partialStateWriteTitle, partialStateWriteReason, true))
}
