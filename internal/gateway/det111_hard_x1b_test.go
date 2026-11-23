// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

func TestDET111KnownAuthorizedKeysWriteAcrossTiers(t *testing.T) {
	useEffectsRulesMode(t, "on")
	for _, command := range []string{
		"sed -i s/old/new/ /home/v/.ssh/authorized_keys",
		"sudo sed -i s/old/new/ /home/v/.ssh/authorized_keys",
		"sudo -u root sed -i s/old/new/ /home/v/.ssh/authorized_keys",
	} {
		res := effectShadowRun(shadowLiveRequest(command), effectRulesOn, tierRestricted)[0]
		if res.Tier != string(effectTierRestricted) || !res.KnownMutation {
			t.Errorf("%q: tier %q known mutation %v, want restricted known", command, res.Tier, res.KnownMutation)
			continue
		}
		for _, deployment := range []decide.Deployment{decide.PerUser, decide.Managed} {
			for _, tier := range []decide.Tier{decide.TierDefault, decide.TierPermissive, decide.TierStrict} {
				fs := effectShadowFindings(res, effectRulesOn)
				if len(fs) == 0 {
					t.Errorf("%q: no effects finding", command)
					continue
				}
				got := decide.Decide(decide.Input{
					Findings:   []decide.Finding{{RuleID: fs[len(fs)-1].RuleID, Severity: decide.ParseSeverity(fs[len(fs)-1].Severity), Proof: fs[len(fs)-1].Proof}},
					Deployment: deployment, Levels: decide.TierLevels(tier), Tier: func() decide.Tier { return tier },
				})
				if got.Action != decide.Block {
					t.Errorf("%q deployment %v tier %v: action %v, want block", command, deployment, tier, got.Action)
				}
			}
		}
	}
}

func TestDET111SessionAliasCredentialRead(t *testing.T) {
	useEffectsRulesMode(t, "on")
	first := shadowLiveRequest("ln -sf ~/.ssh/id_rsa ./scratch/see")
	first.sessionID = "det111-alias-session"
	effectShadowRun(first, effectRulesOn, tierRestricted)
	second := shadowLiveRequest("cat ./scratch/see")
	second.sessionID = first.sessionID
	got := effectShadowRun(second, effectRulesOn, tierRestricted)[0]
	if len(got.ReadProofs) == 0 || got.ReadProofs[0].Set != decide.SetSSHPrivateKey {
		t.Fatalf("same-session alias read proofs = %+v, want SSH private key", got.ReadProofs)
	}
	for _, deployment := range []decide.Deployment{decide.PerUser, decide.Managed} {
		for _, tier := range []decide.Tier{decide.TierDefault, decide.TierPermissive, decide.TierStrict} {
			var findings []decide.Finding
			for _, f := range effectShadowFindings(got, effectRulesOn) {
				findings = append(findings, decide.Finding{RuleID: f.RuleID,
					Severity: decide.ParseSeverity(f.Severity), Proof: f.Proof})
			}
			decision := decide.Decide(decide.Input{Findings: findings, Deployment: deployment,
				Levels: decide.TierLevels(tier), Tier: func() decide.Tier { return tier }})
			if decision.Action != decide.Block {
				t.Errorf("alias read deployment %v tier %v: %v, want block", deployment, tier, decision.Action)
			}
		}
	}
	second.sessionID = "det111-other-session"
	other := effectShadowRun(second, effectRulesOn, tierRestricted)[0]
	if len(other.ReadProofs) != 0 {
		t.Fatalf("cross-session alias read proofs = %+v, want none", other.ReadProofs)
	}
	second.sessionID = first.sessionID
	second.Input.CWD = "/home/u/elsewhere"
	if changedCWD := effectShadowRun(second, effectRulesOn, tierRestricted)[0]; len(changedCWD.ReadProofs) != 0 {
		t.Fatalf("changed working folder carried alias proof: %+v", changedCWD.ReadProofs)
	}
	second.Input.CWD = first.Input.CWD
	second.Input.ActiveHome = "/home/another"
	if changedHome := effectShadowRun(second, effectRulesOn, tierRestricted)[0]; len(changedHome.ReadProofs) != 0 {
		t.Fatalf("changed home carried alias proof: %+v", changedHome.ReadProofs)
	}
}

func TestDET111OwnKeyMaintenanceNoNewMutationProof(t *testing.T) {
	useEffectsRulesMode(t, "on")
	for _, command := range []string{
		"ssh-keygen -R old.example",
		"sed -i '/old.example/d' ~/.ssh/known_hosts",
		"ssh-copy-id -n host.example",
	} {
		res := effectShadowRun(shadowLiveRequest(command), effectRulesOn, tierRestricted)[0]
		if len(res.MutationProofs) != 0 {
			t.Errorf("%q: new keys write proof = %+v", command, res.MutationProofs)
		}
	}
}
