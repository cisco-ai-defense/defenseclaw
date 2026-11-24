// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

// TestGAP1191PartialStateBoundSurvivesEffectFold pins the
// r3/fwd/corpus/det111/GAP-1191/tilde-new-item-value/var row. The partial
// legacy reading needs its evaluation-limit finding even when the effect
// lane independently proves the state write. A genuine legacy proof still
// satisfies the partial reading without a bound.
func TestGAP1191PartialStateBoundSurvivesEffectFold(t *testing.T) {
	request := trustedActionRequest{EnforcementCapable: true}
	partial := RuleFinding{RuleID: stateWriteRuleID, Severity: "HIGH", Proof: recordProof, partialReading: true}
	effect := RuleFinding{RuleID: stateWriteRuleID, Severity: "HIGH",
		Proof: decide.Proof{Kind: decide.KindWrite, Target: decide.TargetState,
			Certainty: decide.CertKnown, Source: decide.SourceEffects}}
	effect.proof = newFindingProof(findingProofEffect, stateWriteRuleID, true)
	if got := withPartialStateWriteFloor(request, []RuleFinding{partial, effect}); findingWithID(got, evaluationLimitRuleID) == nil {
		t.Fatal("effect finding suppressed the legacy partial-reading bound")
	}
	legacy := effect
	legacy.Proof.Source = "legacy"
	legacy.proof = newFindingProof(findingProofActionFactsSemantic, stateWriteRuleID, true)
	if got := withPartialStateWriteFloor(request, []RuleFinding{partial, legacy}); findingWithID(got, evaluationLimitRuleID) != nil {
		t.Fatal("genuine legacy proof added a redundant bound")
	}
	if got := withPartialStateWriteFloor(request, []RuleFinding{effect}); findingWithID(got, evaluationLimitRuleID) != nil {
		t.Fatal("effect-only state write added a partial-reading bound")
	}
}
