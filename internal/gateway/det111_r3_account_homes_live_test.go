// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

func TestDET111EffectShadowProjectsCountedAccountHomes(t *testing.T) {
	if effectHostGOOS == "windows" {
		t.Skip("POSIX account home paths")
	}
	useEffectsRulesMode(t, "on")
	const peerHome = "/srv/homes/bob"
	oldLookup := effectLookupAccountHome
	effectLookupAccountHome = func(name string) (string, bool) {
		if name == "peer" {
			return peerHome, true
		}
		return "", false
	}
	t.Cleanup(func() { effectLookupAccountHome = oldLookup })

	home := t.TempDir()
	request := shadowLiveRequest(`cat ~peer/.aws/credentials /srv/homes/bob/.ssh/id_rsa`)
	request.Input.ActiveHome = home
	request.Input.CWD = filepath.Join(home, "proj")
	before := effectAccountLookups.Load()
	res := effectShadowRun(request, effectRulesOn, tierRestricted)[0]
	if got := effectAccountLookups.Load() - before; got != 1 {
		t.Fatalf("account lookups = %d, want exactly one counted passwd lookup", got)
	}
	findings := effectShadowFindings(res, effectRulesOn)
	got := map[string]bool{}
	for _, finding := range findings {
		p := finding.Proof
		if p.Kind == decide.KindRead && p.Certainty == decide.CertKnown && p.Source == "effects" {
			got[p.Set] = p.Target == decide.TargetOtherHomeCredential && finding.RuleID == decide.RuleFor(p)
		}
	}
	for _, set := range []string{decide.CredentialSet(".aws/credentials"), decide.CredentialSet(".ssh/id_rsa")} {
		if ok, found := got[set]; !found || !ok {
			t.Errorf("missing Known other-home read proof for %q (findings=%+v result=%+v)", set, findings, res)
		}
	}
}
