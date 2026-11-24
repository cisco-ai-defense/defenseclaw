// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

// TestGAP2025ClassWriteSeverityKeepsTheTierFinding: only the class rule
// finding of a credential write takes the pack's rule severity, and the
// call's effect.protected_target_restricted finding of the same class folds
// into it, as the plain write's folds into the reader's (GAP-2114). A tier
// finding of another class, and every tier finding in a pack without the
// class rule, is kept as it is (dropping them lowered every restricted
// credential write of the gen to allow).
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
	if len(got) != 2 || got[0].RuleID != "PATH-NPMRC" || got[0].Severity != "MEDIUM" || !got[0].Proof.IsZero() {
		t.Fatalf("got %+v, want PATH-NPMRC MEDIUM with the reader's (zero) proof, the npmrc tier finding folded into it", got)
	}
	if got[1].RuleID != decide.RuleEffectRestricted || got[1].Proof.Set != decide.SetKubeConfig {
		t.Fatalf("tier finding of another class = %+v, want it kept", got[1])
	}
	none := func() *compiledRulePackCategories { return &compiledRulePackCategories{} }
	if got := withEffectClassWriteSeverity([]RuleFinding{tierFinding, classFinding}, none); len(got) != 1 || got[0].RuleID != decide.RuleEffectRestricted {
		t.Fatalf("pack without the class rule: %+v, want only the tier finding", got)
	}
}
