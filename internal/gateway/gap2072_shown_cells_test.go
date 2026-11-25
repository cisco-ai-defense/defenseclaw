// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

func TestGAP2072ShownCredentialReadKeepsPlainCell(t *testing.T) {
	useEffectsRulesMode(t, "on")
	const key = "/home/u/.ssh/id_rsa"
	plain := effectShadowRun(shadowLiveRequest("cat "+key), effectRulesOn, tierRestricted)[0]
	decision := func(res EffectShadowResult, deployment decide.Deployment, tier decide.Tier) decide.Output {
		t.Helper()
		var findings []decide.Finding
		for _, f := range effectShadowFindings(res, effectRulesOn) {
			findings = append(findings, decide.Finding{RuleID: f.RuleID,
				Severity: decide.ParseSeverity(f.Severity), Proof: f.Proof})
		}
		return decide.Decide(decide.Input{Findings: findings, Deployment: deployment,
			Levels: decide.TierLevels(tier), Tier: func() decide.Tier { return tier }})
	}
	tiers := []struct {
		name       string
		deployment decide.Deployment
		tier       decide.Tier
	}{
		{"default", decide.PerUser, decide.TierDefault},
		{"permissive", decide.PerUser, decide.TierPermissive},
		{"strict", decide.PerUser, decide.TierStrict},
		{"managed", decide.Managed, decide.TierDefault},
		{"managed strict", decide.Managed, decide.TierStrict},
	}
	for _, command := range []string{
		"echo \"$(cat " + key + ")\"",
		"k=$(cat " + key + "); echo \"$k\"",
		"cat " + key + " | tr a a",
		"cat " + key + " | xxd",
		"cat " + key + " >&2",
	} {
		res := effectShadowRun(shadowLiveRequest(command), effectRulesOn, tierRestricted)[0]
		for _, tc := range tiers {
			got, want := decision(res, tc.deployment, tc.tier), decision(plain, tc.deployment, tc.tier)
			if got.Action != want.Action || got.Severity != want.Severity {
				t.Errorf("%q %s: action/severity %v/%v, plain %v/%v",
					command, tc.name, got.Action, got.Severity, want.Action, want.Severity)
			}
		}
	}
}
