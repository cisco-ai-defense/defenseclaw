// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

// TestGAP2025ClassWriteSeverityKeepsTheTierFinding: only the class rule
// finding of a credential write takes the pack's rule severity; the call's
// effect.protected_target_restricted findings, of that class or another,
// with or without the class rule in the pack, are kept as they are (dropping
// them lowered every restricted credential write of the gen to allow, and
// folding the same-class one lowered a call that also writes the member by
// an effects-only spelling, GAP-2121).
func TestGAP2025ClassWriteSeverityKeepsTheTierFinding(t *testing.T) {
	proof := decide.Proof{Kind: decide.KindAppend, Target: decide.TargetCredential,
		Certainty: decide.CertKnown, Set: decide.SetNpmrc, Source: decide.SourceEffects}
	tierFinding := RuleFinding{RuleID: decide.RuleEffectRestricted, Severity: "CRITICAL", Proof: proof}
	classFinding := RuleFinding{RuleID: decide.RuleFor(proof), Severity: "HIGH", Proof: proof}
	gen := func() *compiledRulePackCategories {
		return &compiledRulePackCategories{categories: []ruleCategory{{Name: "paths",
			Rules: []PatternRule{{ID: "PATH-NPMRC", Severity: "MEDIUM"}}}}}
	}
	other := RuleFinding{RuleID: decide.RuleEffectRestricted, Severity: "CRITICAL",
		Proof: decide.Proof{Kind: decide.KindWrite, Target: decide.TargetCredential, Certainty: decide.CertKnown,
			Set: decide.SetKubeConfig, Source: decide.SourceEffects}}
	got := withEffectClassWriteSeverity([]RuleFinding{tierFinding, classFinding, other}, gen)
	if len(got) != 3 || got[0].RuleID != decide.RuleEffectRestricted || got[0].Severity != "CRITICAL" || got[0].Proof != proof {
		t.Fatalf("got %+v, want the npmrc tier finding kept as it is", got)
	}
	if got[1].RuleID != "PATH-NPMRC" || got[1].Severity != "MEDIUM" || !got[1].Proof.IsZero() || !got[1].floorRaiseOnly {
		t.Fatalf("class finding = %+v, want PATH-NPMRC MEDIUM with the reader's (zero) proof, floorRaiseOnly", got[1])
	}
	if got[2].RuleID != decide.RuleEffectRestricted || got[2].Proof.Set != decide.SetKubeConfig {
		t.Fatalf("tier finding of another class = %+v, want it kept", got[2])
	}
	// No tier finding folds into the class finding, in either order.
	if joined := joinEffectFindings(nil, got); len(joined) != 3 {
		t.Fatalf("joined %d findings, want all 3", len(joined))
	}
	if kept := withEffectsFoldedIntoCall([]RuleFinding{got[1], got[0]}); len(kept) != 2 {
		t.Fatalf("call fold kept %d findings, want both", len(kept))
	}
	none := func() *compiledRulePackCategories { return &compiledRulePackCategories{} }
	if got := withEffectClassWriteSeverity([]RuleFinding{tierFinding, classFinding}, none); len(got) != 1 || got[0].RuleID != decide.RuleEffectRestricted {
		t.Fatalf("pack without the class rule: %+v, want only the tier finding", got)
	}
}
