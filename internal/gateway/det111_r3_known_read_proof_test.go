// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

func TestDET111KnownCredentialReadsProducePerMemberDecisionProofs(t *testing.T) {
	useEffectsRulesMode(t, "on")
	home := t.TempDir()
	cwd := filepath.Join(home, "proj")
	if runtime.GOOS == "windows" {
		// A POSIX host's call (no file is read): a drive-path home would make
		// it a Windows call (effectWindowsCall), where ${PWD%/proj} and
		// /home/bob are no paths of that host.
		home, cwd = "/home/alice", "/home/alice/proj"
	}
	request := shadowLiveRequest(`cat ${PWD%/proj}/.aws/credentials /home/bob/.ssh/id_rsa`)
	request.Input.ActiveHome = home
	request.Input.CWD = cwd

	res := effectShadowRun(request, effectRulesOn, tierRestricted)[0]
	findings := effectShadowFindings(res, effectRulesOn)
	got := map[string]bool{}
	for _, finding := range findings {
		p := finding.Proof
		if p.Kind == decide.KindRead && p.Certainty == decide.CertKnown && p.Source == "effects" {
			got[string(p.Target)+":"+p.Set] = finding.RuleID == decide.RuleFor(p)
		}
	}
	want := []string{
		string(decide.TargetCredential) + ":" + decide.CredentialSet(".aws/credentials"),
		string(decide.TargetOtherHomeCredential) + ":" + decide.CredentialSet(".ssh/id_rsa"),
	}
	for _, key := range want {
		if ok, found := got[key]; !found || !ok {
			t.Errorf("missing Known credential read decision proof %q (findings=%+v result=%+v)", key, findings, res)
		}
	}
	if len(got) != len(want) {
		t.Errorf("got Known read proofs %v, want exactly %v", got, want)
	}
}
