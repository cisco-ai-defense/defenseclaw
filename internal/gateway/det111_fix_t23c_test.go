// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

// TestGAP2114AliasWriteKeepsItsVerdictWithoutTheClassRule (DET111
// GAP-2114): in one session, ln -sf ~/.npmrc ~/proj/npm_alias, then a write
// through ~/proj/npm_alias. Under a pack without PATH-NPMRC the call keeps
// the T23 restricted finding (alert CRITICAL in the default packs, a block
// in strict), per-user and managed, and so does a pack with it (the
// stronger of the class cell and the restricted cell, DET111 ruling). At
// 8711f95ef6 no finding survived without the class rule, and the class
// MEDIUM cell stood alone with it.
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
				// The T23 restricted cell with or without the class rule
				// (the stronger of it and the PATH-NPMRC MEDIUM cell).
				wantAction, wantSev := decide.Alert, decide.SevCritical
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

// TestGAP2121AliasWriteBesideAnEffectsOnlyWriteNeverLowersTheCall (DET111
// GAP-2121): in one session, after ln -sf ~/.npmrc ~/proj/npm_alias (or
// ~/.kube/config as ~/proj/kc), a call that writes through the alias and
// also writes the member by an effects-only spelling (${PWD%/proj}/.npmrc),
// in either order, gets at least the verdict of the effects-only write
// alone, on the Claude Code and Codex hook routes in the five tiers. At
// 08e285b2a6 the alias class finding folded the call's restricted finding
// away: MEDIUM, allow in permissive, where the write alone is CRITICAL.
func TestGAP2121AliasWriteBesideAnEffectsOnlyWriteNeverLowersTheCall(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home spellings")
	}
	home := t.TempDir()
	for _, f := range []string{".npmrc", ".kube/config", "proj/keep"} {
		p := filepath.Join(home, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	cwd := filepath.Join(home, "proj")
	rows := []struct{ link, call, alone string }{
		{"ln -sf ~/.npmrc ~/proj/npm_alias", "printf x > ~/proj/npm_alias; printf y > ${PWD%/proj}/.npmrc", "printf y > ${PWD%/proj}/.npmrc"},
		{"ln -sf ~/.npmrc ~/proj/npm_alias", "echo y >> ${PWD%/proj}/.npmrc; echo x >> ~/proj/npm_alias", "echo y >> ${PWD%/proj}/.npmrc"},
		{"ln -sf ~/.kube/config ~/proj/kc", "printf x > ~/proj/kc; printf y > ${PWD%/proj}/.kube/config", "printf y > ${PWD%/proj}/.kube/config"},
	}
	for _, tier := range boundedTestTiers {
		for _, route := range gap2025Routes() {
			api := gap0589TierAPI(t, route.connector, tier.posture, tier.managed, tier.tier)
			useDefaultEffectsLane(t)
			for n, row := range rows {
				session := fmt.Sprintf("gap2121-%s-%s-%d", tier.name, route.connector, n)
				route.decide(t, api, session, cwd, row.link)
				want, wantSev := route.decide(t, api, session+"-alone", cwd, row.alone)
				got, sev := route.decide(t, api, session, cwd, row.call)
				if credentialFlowRank[got] < credentialFlowRank[want] || aliasSeverityRank[sev] < aliasSeverityRank[wantSev] {
					t.Errorf("%s %s %q: %s/%s, want at least the effects-only write alone %q %s/%s",
						tier.name, route.connector, row.call, got, sev, row.alone, want, wantSev)
				}
			}
		}
	}
}
