// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package decide

import "testing"

// TestEffectShadowOnlyRows (GAP-1796, GAP-1795, GAP-1797): the effect lane's
// unknown tier is recorded only, whatever its Known flag or target (DET111
// ruling 2026-11-22T17:00Z, the target-decided exception is gone); a Known effect
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
	linkTo := func(f Finding) Finding { f.Proof.LinkTo = true; return f }
	inSet := func(f Finding, set string) Finding { f.Proof.Set = set; return f }
	for _, tc := range []struct {
		name   string
		f      Finding
		shadow bool
	}{
		{"unknown known write autostart", effect(RuleEffectUnknown, KindAppend, TargetAutostart, CertKnown), true},
		{"unknown known write other", effect(RuleEffectUnknown, KindWrite, TargetOther, CertKnown), true},
		{"unknown maybe reach system", effect(RuleEffectUnknown, KindWrite, TargetSystem, CertMaybe), true},
		{"unknown known write no target", effect(RuleEffectUnknown, KindExec, TargetNone, CertKnown), true},
		{"unknown known write keys", effect(RuleEffectUnknown, KindWrite, TargetAuthorizedKeys, CertKnown), true},
		{"unknown advisory write state", effect(RuleEffectUnknown, KindAppend, TargetState, CertMaybe), true},
		{"unknown known write hook config", effect(RuleEffectUnknown, KindWrite, TargetHookConfig, CertKnown), true},
		{"unknown known write credential", effect(RuleEffectUnknown, KindWrite, TargetCredential, CertKnown), true},
		{"restricted append shell rc", effect(RuleEffectRestricted, KindAppend, TargetAutostart, CertKnown), true},
		{"restricted write shell rc", effect(RuleEffectRestricted, KindWrite, TargetAutostart, CertKnown), true},
		{"restricted append authorized_keys", effect(RuleEffectRestricted, KindAppend, TargetAuthorizedKeys, CertKnown), false},
		{"restricted write state", effect(RuleEffectRestricted, KindWrite, TargetState, CertKnown), false},
		{"restricted write hook config", effect(RuleEffectRestricted, KindWrite, TargetHookConfig, CertKnown), false},
		{"restricted delete credential", effect(RuleEffectRestricted, KindDelete, TargetCredential, CertKnown), false},
		{"restricted link authorized_keys", effect(RuleEffectRestricted, KindLink, TargetAuthorizedKeys, CertKnown), true},
		{"restricted link hook config", effect(RuleEffectRestricted, KindLink, TargetHookConfig, CertKnown), true},
		{"restricted link state", effect(RuleEffectRestricted, KindLink, TargetState, CertKnown), false},
		// A link TO a member (ln -s ~/.ssh/authorized_keys s) is an alias the
		// call can write through: it keeps its row (GAP-1530, GAP-1538).
		{"restricted link to authorized_keys", linkTo(effect(RuleEffectRestricted, KindLink, TargetAuthorizedKeys, CertKnown)), false},
		{"restricted link to credential", linkTo(effect(RuleEffectRestricted, KindLink, TargetCredential, CertKnown)), false},
		// GAP-1878: an own SSH private key write or mode change no 1.0.10
		// rule names is recorded; an append (GAP-1666/114), a delete, another
		// credential class, a write with no single class and another
		// account's key keep rows.
		{"restricted write own ssh key", inSet(effect(RuleEffectRestricted, KindWrite, TargetCredential, CertKnown), SetSSHPrivateKey), true},
		{"restricted append own ssh key", inSet(effect(RuleEffectRestricted, KindAppend, TargetCredential, CertKnown), SetSSHPrivateKey), false},
		{"restricted perm own ssh key", inSet(effect(RuleEffectRestricted, KindPerm, TargetCredential, CertKnown), SetSSHPrivateKey), true},
		{"restricted delete own ssh key", inSet(effect(RuleEffectRestricted, KindDelete, TargetCredential, CertKnown), SetSSHPrivateKey), false},
		{"restricted link own ssh key", inSet(effect(RuleEffectRestricted, KindLink, TargetCredential, CertKnown), SetSSHPrivateKey), true},
		{"restricted write own aws credentials", inSet(effect(RuleEffectRestricted, KindWrite, TargetCredential, CertKnown), SetAWSCredentials), false},
		{"restricted write credential no single class", effect(RuleEffectRestricted, KindWrite, TargetCredential, CertKnown), false},
		{"restricted write other home ssh key", inSet(effect(RuleEffectRestricted, KindWrite, TargetOtherHomeCredential, CertKnown), SetSSHPrivateKey), false},
		{"legacy write own ssh key", Finding{RuleID: RuleEffectRestricted, Severity: SevCritical, Proof: Proof{Kind: KindWrite, Target: TargetCredential, Certainty: CertKnown, Set: SetSSHPrivateKey, Source: "PATH-SSH-KEY"}}, false},
		{"effects read ssh key", Finding{RuleID: "PATH-SSH-KEY", Severity: SevCritical, Proof: Proof{Kind: KindRead, Target: TargetCredential, Certainty: CertKnown, Set: SetSSHPrivateKey, Source: SourceEffects}}, true},
		{"effects read aws", Finding{RuleID: "PATH-AWS-CREDS", Severity: SevCritical, Proof: Proof{Kind: KindRead, Target: TargetCredential, Certainty: CertKnown, Set: SetAWSCredentials, Source: SourceEffects}}, true},
		{"effects read other home ssh key", Finding{RuleID: "PATH-SSH-KEY", Severity: SevCritical, Proof: Proof{Kind: KindRead, Target: TargetOtherHomeCredential, Certainty: CertKnown, Set: SetSSHPrivateKey, Source: SourceEffects}}, false},
		{"legacy read ssh key", Finding{RuleID: "PATH-SSH-KEY", Severity: SevCritical, Proof: Proof{Kind: KindRead, Target: TargetCredential, Certainty: CertKnown, Set: SetSSHPrivateKey, Source: "PATH-SSH-KEY"}}, false},
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
