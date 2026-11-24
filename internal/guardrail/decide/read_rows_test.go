// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package decide

import "testing"

// TestKnownCredentialReadRows (GAP-1244, GAP-0888, GAP-0898/0899): a known
// read on a credential file class gets the cell the 1.0.10 rule naming that
// class gives its plain spelling, characterized at a64bfdb931 on the Claude
// Code and Codex hook routes (cat <file>, five tiers), whatever severity the
// proving reader put on its finding.
func TestKnownCredentialReadRows(t *testing.T) {
	type tierCase struct {
		name string
		d    Deployment
		tier Tier
	}
	tiers := []tierCase{
		{"default", PerUser, TierDefault}, {"permissive", PerUser, TierPermissive}, {"strict", PerUser, TierStrict},
		{"managed", Managed, TierDefault}, {"managed strict", Managed, TierStrict},
	}
	// verdicts in tier order: default, permissive, strict, managed, managed strict.
	type want struct {
		action Action
		sev    Severity
	}
	block, alertMed, allowMed := want{Block, SevCritical}, want{Alert, SevMedium}, want{Allow, SevMedium}
	alertHigh := want{Alert, SevHigh}
	alertCrit := want{Alert, SevCritical}
	own := [5]want{alertMed, allowMed, alertMed, alertMed, alertMed}
	for _, tc := range []struct {
		name   string
		target TargetClass
		set    string
		rule   string
		want   [5]want
	}{
		{"own ssh key", TargetCredential, SetSSHPrivateKey, "PATH-SSH-KEY", [5]want{block, block, block, block, block}},
		{"own aws", TargetCredential, SetAWSCredentials, "PATH-AWS-CREDS", own},
		{"own git", TargetCredential, SetGitCredentials, "PATH-GIT-CREDS", own},
		{"own npmrc", TargetCredential, SetNpmrc, "PATH-NPMRC", own},
		{"own pypirc", TargetCredential, SetPypirc, "PATH-PYPIRC", own},
		{"own kube", TargetCredential, SetKubeConfig, "PATH-KUBE", own},
		{"own docker", TargetCredential, SetDockerConfig, "PATH-DOCKER", own},
		{"other ssh key", TargetOtherHomeCredential, SetSSHPrivateKey, "PATH-SSH-KEY", [5]want{alertHigh, alertHigh, block, alertHigh, block}},
		{"other git", TargetOtherHomeCredential, SetGitCredentials, "PATH-GIT-CREDS", [5]want{alertCrit, alertCrit, block, block, block}},
		{"other aws", TargetOtherHomeCredential, SetAWSCredentials, "PATH-AWS-CREDS", own},
		{"other npmrc", TargetOtherHomeCredential, SetNpmrc, "PATH-NPMRC", own},
		{"other pypirc", TargetOtherHomeCredential, SetPypirc, "PATH-PYPIRC", own},
		{"other kube", TargetOtherHomeCredential, SetKubeConfig, "PATH-KUBE", own},
		{"other docker", TargetOtherHomeCredential, SetDockerConfig, "PATH-DOCKER", own},
	} {
		// An effects read of one's own file is a shadow record
		// (RowEffectRead, TestEffectShadowOnlyRows); the own-home rows grade
		// a read proof from any other reader.
		src := SourceEffects
		if tc.target == TargetCredential {
			src = "reader"
		}
		p := Proof{Kind: KindRead, Target: tc.target, Certainty: CertKnown, Set: tc.set, Source: src}
		if got := RuleFor(p); got != tc.rule {
			t.Errorf("%s: RuleFor %q, want %q", tc.name, got, tc.rule)
		}
		for i, tier := range tiers {
			for _, sev := range []Severity{SevMedium, SevHigh, SevCritical} {
				out := Decide(Input{
					Findings:   []Finding{{RuleID: RuleFor(p), Severity: sev, Proof: p}},
					Deployment: tier.d,
					Levels:     TierLevels(tier.tier),
					Tier:       func() Tier { return tier.tier },
				})
				if w := tc.want[i]; out.Action != w.action || out.Severity != w.sev {
					t.Errorf("%s %s (finding %s): %s/%s, want %s/%s", tc.name, tier.name, sev, out.Action, out.Severity, w.action, w.sev)
				}
			}
		}
	}
}

// TestKnownCredentialReadRowsNeedASet: a proof that names no file class (the
// 1.0.10 readers, which grade their own findings) and a read of a class-less
// target keep their own severity: the read rows only replace what a set names.
func TestKnownCredentialReadRowsNeedASet(t *testing.T) {
	for _, p := range []Proof{
		{Kind: KindRead, Target: TargetCredential, Certainty: CertKnown},
		{Kind: KindRead, Target: TargetOtherHomeCredential, Certainty: CertKnown},
		{Kind: KindRead, Target: TargetProject, Certainty: CertKnown, Set: SetSSHPrivateKey},
		{Kind: KindWrite, Target: TargetOther, Certainty: CertKnown, Set: SetAWSCredentials},
	} {
		out := Decide(Input{
			Findings: []Finding{{RuleID: "r", Severity: SevHigh, Proof: p}},
			Levels:   TierLevels(TierDefault),
			Tier:     func() Tier { return TierDefault },
		})
		if out.Action != Alert || out.Severity != SevHigh {
			t.Errorf("%s: %s/%s, want alert/HIGH (its own severity)", p, out.Action, out.Severity)
		}
	}
	// A maybe read never takes a read row (the precision rule: it is recorded).
	maybe := Proof{Kind: KindRead, Target: TargetCredential, Certainty: CertMaybe, Set: SetSSHPrivateKey}
	if out := Decide(Input{Findings: []Finding{{RuleID: "r", Severity: SevCritical, Proof: maybe}}, Levels: TierLevels(TierDefault)}); out.Action != Allow {
		t.Errorf("maybe read: %s, want allow (recorded)", out.Action)
	}
}

func TestCredentialSet(t *testing.T) {
	for tail, want := range map[string]string{
		".ssh/id_rsa": SetSSHPrivateKey, "/.ssh/id_ed25519": SetSSHPrivateKey, `.ssh\id_ecdsa`: SetSSHPrivateKey,
		`\.SSH\ID_DSA`: SetSSHPrivateKey, ".aws/credentials": SetAWSCredentials, ".git-credentials": SetGitCredentials,
		".netrc": SetGitCredentials, ".npmrc": SetNpmrc, ".pypirc": SetPypirc, ".kube/config": SetKubeConfig,
		".docker/config.json": SetDockerConfig, ".ssh/id_rsa.pub": "", ".ssh/authorized_keys": "", ".aws/config": "",
		"proj/.aws/credentials": "", "": "",
	} {
		if got := CredentialSet(tail); got != want {
			t.Errorf("CredentialSet(%q) = %q, want %q", tail, got, want)
		}
	}
	if s := (Proof{Kind: KindRead, Target: TargetCredential, Set: SetSSHPrivateKey}).String(); s != "read/credential/known{ssh_private_key}" {
		t.Errorf("proof key %q", s)
	}
}

// TestGAP2135LegacyOtherHomeSSHCellUnchanged keeps the shipped-default
// 1.0.10 cell beside the source-scoped effect proof row.
func TestGAP2135LegacyOtherHomeSSHCellUnchanged(t *testing.T) {
	tiers := []struct {
		d Deployment
		t Tier
		a Action
		s Severity
	}{
		{PerUser, TierDefault, Alert, SevMedium},
		{PerUser, TierPermissive, Allow, SevMedium},
		{PerUser, TierStrict, Block, SevCritical},
		{Managed, TierDefault, Alert, SevMedium},
		{Managed, TierStrict, Block, SevCritical},
	}
	p := Proof{Kind: KindRead, Target: TargetOtherHomeCredential, Certainty: CertKnown,
		Set: SetSSHPrivateKey, Source: "reader"}
	for _, tier := range tiers {
		out := Decide(Input{Findings: []Finding{{RuleID: RuleFor(p), Severity: SevHigh, Proof: p}},
			Deployment: tier.d, Levels: TierLevels(tier.t), Tier: func() Tier { return tier.t }})
		if out.Action != tier.a || out.Severity != tier.s {
			t.Errorf("%v/%v: %s/%s, want %s/%s", tier.d, tier.t, out.Action, out.Severity, tier.a, tier.s)
		}
	}
}
