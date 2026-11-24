// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

// TestGAP2025ClassWriteSeverityKeepsTheTierFinding: only the class rule
// finding of a credential write takes the pack's rule severity; the call's
// own effect.protected_target_restricted finding, whose proof also names a
// credential, is kept as it is (a pack has no rule of that id, and dropping
// it lowered every restricted credential write of the gen to allow).
func TestGAP2025ClassWriteSeverityKeepsTheTierFinding(t *testing.T) {
	proof := decide.Proof{Kind: decide.KindAppend, Target: decide.TargetCredential,
		Certainty: decide.CertKnown, Set: decide.SetNpmrc, Source: decide.SourceEffects}
	tierFinding := RuleFinding{RuleID: decide.RuleEffectRestricted, Severity: "CRITICAL", Proof: proof}
	classFinding := RuleFinding{RuleID: decide.RuleFor(proof), Severity: "HIGH", Proof: proof}
	gen := func() *compiledRulePackCategories {
		return &compiledRulePackCategories{categories: []ruleCategory{{Name: "paths",
			Rules: []PatternRule{{ID: "PATH-NPMRC", Severity: "MEDIUM"}}}}}
	}
	got := withEffectClassWriteSeverity([]RuleFinding{tierFinding, classFinding}, gen)
	if len(got) != 2 || got[0].RuleID != decide.RuleEffectRestricted || got[0].Severity != "CRITICAL" || got[0].Proof != proof {
		t.Fatalf("tier finding changed: %+v", got)
	}
	if got[1].RuleID != "PATH-NPMRC" || got[1].Severity != "MEDIUM" || !got[1].Proof.IsZero() {
		t.Fatalf("class finding = %+v, want PATH-NPMRC MEDIUM with the reader's (zero) proof", got[1])
	}
	none := func() *compiledRulePackCategories { return &compiledRulePackCategories{} }
	if got := withEffectClassWriteSeverity([]RuleFinding{tierFinding, classFinding}, none); len(got) != 1 || got[0].RuleID != decide.RuleEffectRestricted {
		t.Fatalf("pack without the class rule: %+v, want only the tier finding", got)
	}
}
