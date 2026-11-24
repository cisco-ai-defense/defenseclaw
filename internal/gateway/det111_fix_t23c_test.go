// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

// TestGAP2114AliasWriteKeepsItsVerdictWithoutTheClassRule (DET111
// GAP-2114): in one session, ln -sf ~/.npmrc ~/proj/npm_alias, then a write
// through ~/proj/npm_alias. Under a pack without PATH-NPMRC the call keeps
// the T23 restricted finding (alert CRITICAL in the default packs, a block
// in strict), per-user and managed; under a pack with it, the class rule
// grades the write (MEDIUM) and the restricted finding folds into it, as for
// the plain write of ~/.npmrc. At 8711f95ef6 no finding survived without
// the class rule.
func TestGAP2114AliasWriteKeepsItsVerdictWithoutTheClassRule(t *testing.T) {
	useEffectsRulesMode(t, "on")
	link := shadowLiveRequest("ln -sf ~/.npmrc ~/proj/npm_alias")
	link.sessionID = "gap2114-session"
	effectShadowRun(link, effectRulesOn, tierRestricted)
	withRule := func() *compiledRulePackCategories {
		return &compiledRulePackCategories{categories: []ruleCategory{{Name: "paths",
			Rules: []PatternRule{{ID: "PATH-NPMRC", Severity: "MEDIUM"}}}}}
	}
	without := func() *compiledRulePackCategories { return &compiledRulePackCategories{} }
	tiers := []struct {
		name       string
		deployment decide.Deployment
		tier       decide.Tier
	}{
		{"default", decide.PerUser, decide.TierDefault}, {"permissive", decide.PerUser, decide.TierPermissive},
		{"strict", decide.PerUser, decide.TierStrict}, {"managed", decide.Managed, decide.TierDefault},
		{"managed strict", decide.Managed, decide.TierStrict},
	}
	for _, command := range []string{"echo registry=x >> ~/proj/npm_alias", "printf x > ~/proj/npm_alias"} {
		for _, tc := range tiers {
			use := shadowLiveRequest(command)
			use.sessionID = link.sessionID
			use.StrictPolicy = tc.tier == decide.TierStrict
			res := effectShadowRun(use, effectRulesOn, tierRestricted)[0]
			for _, pack := range []struct {
				name string
				gen  func() *compiledRulePackCategories
			}{{"without PATH-NPMRC", without}, {"with PATH-NPMRC", withRule}} {
				fs := joinEffectFindings(nil, withEffectClassWriteSeverity(effectShadowFindings(res, effectRulesOn), pack.gen))
				var in []decide.Finding
				for _, f := range fs {
					in = append(in, decideFinding(f))
				}
				got := decide.Decide(decide.Input{Findings: in, Deployment: tc.deployment,
					Levels: decide.TierLevels(tc.tier), Tier: func() decide.Tier { return tc.tier }})
				// Without the class rule: the T23 restricted cell. With it:
				// the PATH-NPMRC cell of the plain write (MEDIUM: an alert in
				// default and managed, nothing in permissive, which alerts
				// from HIGH, a block in strict).
				wantAction, wantSev := decide.Alert, decide.SevCritical
				if pack.name == "with PATH-NPMRC" {
					wantSev = decide.SevMedium
					if tc.tier == decide.TierPermissive {
						wantAction = decide.Allow
					}
				}
				if tc.tier == decide.TierStrict {
					wantAction = decide.Block
				}
				if got.Action != wantAction || got.Severity != wantSev {
					t.Errorf("%q %s pack %s: %v/%v, want %v/%v (findings %d)", command, tc.name, pack.name,
						got.Action, got.Severity, wantAction, wantSev, len(fs))
				}
			}
		}
	}
}
