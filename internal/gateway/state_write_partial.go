// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "github.com/defenseclaw/defenseclaw/internal/actionfacts"

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
		if finding.contributesToEnforcement() && !isEffectFinding(finding) {
			return findings // the legacy write is proven: its own verdict decides
		}
		if finding.Proof.Recorded() && finding.partialReading {
			partial = true
		}
	}
	if !partial || !request.EnforcementCapable {
		return findings
	}
	return withUnknownFinding(findings, unknownReasonFinding(partialStateWriteTitle, partialStateWriteReason, true))
}

// operandGrammarOnlyReading reports whether the only reason the analysis read
// the call in part is a command word whose operand grammar it does not model
// (a wrapped delete). A call that also has a construct the analysis does not
// model (a function body, a group, a loop, a dynamic word) is floored by the
// readings of its parts, which each read the wrapped delete on its own. Its
// own contract match can come from a nested reading of a write without the
// HOME that write runs under, so a function that moves HOME to another home
// made a write below that home a state write (TestHomeDeclarationInAFunctionBody,
// TestGAP0892WrappedStateDeleteInAConstructIsNeverAClearAllow).
func operandGrammarOnlyReading(facts actionfacts.Facts) bool {
	if len(facts.Parse.Issues) == 0 {
		return false
	}
	for _, issue := range facts.Parse.Issues {
		if issue != actionfacts.IssueUnknownOperandGrammar {
			return false
		}
	}
	return true
}
