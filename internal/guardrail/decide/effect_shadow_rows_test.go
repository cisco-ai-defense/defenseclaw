// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package decide

import "testing"

// TestEffectShadowOnlyRows (GAP-1796, GAP-1795, GAP-1797): the effect lane's
// unknown tier is recorded only, whatever its Known flag, except on a
// target-decided set (GAP-0662, GAP-1173, GAP-1671); a Known effect
// write to a shell startup file (a set whose 1.0.10 rule is decided by the
// content written) is recorded only; a Known effect write to a
// target-decided set keeps its row and raises. The CLAUDE.md content rule
// names the hook config set, so an effect write there folds into it.
func TestEffectShadowOnlyRows(t *testing.T) {
	tiers := []struct {
		d    Deployment
		tier Tier
	}{{PerUser, TierDefault}, {PerUser, TierPermissive}, {PerUser, TierStrict}, {Managed, TierDefault}, {Managed, TierStrict}}
	effect := func(rule string, kind ProofKind, target TargetClass, cert Certainty) Finding {
		p := Proof{Kind: kind, Target: target, Certainty: cert, Source: SourceEffects}
		if cert == CertMaybe {
			p = p.Advise()
		}
		return Finding{RuleID: rule, Severity: SevCritical, Proof: p}
	}
	for _, tc := range []struct {
		name   string
		f      Finding
		shadow bool
	}{
		{"unknown known write autostart", effect(RuleEffectUnknown, KindAppend, TargetAutostart, CertKnown), true},
		{"unknown known write other", effect(RuleEffectUnknown, KindWrite, TargetOther, CertKnown), true},
		{"unknown maybe reach system", effect(RuleEffectUnknown, KindWrite, TargetSystem, CertMaybe), true},
		{"unknown known write no target", effect(RuleEffectUnknown, KindExec, TargetNone, CertKnown), true},
		{"unknown known write keys (GAP-1671)", effect(RuleEffectUnknown, KindWrite, TargetAuthorizedKeys, CertKnown), false},
		{"unknown advisory write state (GAP-0662)", effect(RuleEffectUnknown, KindAppend, TargetState, CertMaybe), false},
		{"unknown known write hook config", effect(RuleEffectUnknown, KindWrite, TargetHookConfig, CertKnown), false},
		{"restricted append shell rc", effect(RuleEffectRestricted, KindAppend, TargetAutostart, CertKnown), true},
		{"restricted write shell rc", effect(RuleEffectRestricted, KindWrite, TargetAutostart, CertKnown), true},
		{"restricted append authorized_keys", effect(RuleEffectRestricted, KindAppend, TargetAuthorizedKeys, CertKnown), false},
		{"restricted write state", effect(RuleEffectRestricted, KindWrite, TargetState, CertKnown), false},
		{"restricted write hook config", effect(RuleEffectRestricted, KindWrite, TargetHookConfig, CertKnown), false},
		{"restricted delete credential", effect(RuleEffectRestricted, KindDelete, TargetCredential, CertKnown), false},
		{"legacy unknown-named rule", Finding{RuleID: RuleEffectUnknown, Severity: SevHigh, Proof: Proof{Kind: KindWrite, Target: TargetAutostart}}, false},
	} {
		if got := ShadowOnly(tc.f); got != tc.shadow {
			t.Errorf("%s: ShadowOnly %v, want %v", tc.name, got, tc.shadow)
		}
		if !tc.shadow || tc.f.Proof.Source != SourceEffects {
			continue
		}
		for _, tier := range tiers {
			out := Decide(Input{Findings: []Finding{tc.f}, Deployment: tier.d, Levels: TierLevels(tier.tier),
				Tier: func() Tier { return tier.tier }})
			if out.Action != Allow {
				t.Errorf("%s %s/%s: %s, want allow (recorded)", tc.name, tier.d, tier.tier, out.Action)
			}
		}
	}
	claude := effect(RuleEffectRestricted, KindWrite, TargetHookConfig, CertKnown)
	if !FoldsIntoLegacy(claude, []Finding{{RuleID: "COG-CLAUDE-MD", Severity: SevHigh}}) {
		t.Errorf("an effect write on the hook config set does not fold into COG-CLAUDE-MD of the call")
	}
	keys := effect(RuleEffectRestricted, KindAppend, TargetAuthorizedKeys, CertKnown)
	if FoldsIntoLegacy(keys, []Finding{{RuleID: "COG-CLAUDE-MD", Severity: SevHigh}}) {
		t.Errorf("an authorized_keys effect write folds into COG-CLAUDE-MD")
	}
}
