// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/effectrules"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

func effTarget(matches ...*semanticpb.ProtectedMatch) *semanticpb.EffectTarget {
	return &semanticpb.EffectTarget{Type: "path", Path: "/x", Protected: matches}
}
func effMatch(set, state string) *semanticpb.ProtectedMatch {
	return &semanticpb.ProtectedMatch{Set: set, State: state}
}

func TestClassifyEffectFacts(t *testing.T) {
	known := []*semanticpb.EffectFact{{
		Kind: "write", TargetState: "known", RoleState: "known",
		Origin: &semanticpb.EffectOrigin{Program: "tee"},
		Target: effTarget(effMatch(effectrules.SetSSHAuthorizedKeys, "known")),
	}}
	unknown := []*semanticpb.EffectFact{{
		Kind: "delete", TargetState: "unknown", RoleState: "known",
		Origin: &semanticpb.EffectOrigin{Program: "rm"},
		Target: effTarget(effMatch(effectrules.SetSSHAuthorizedKeys, "unknown")),
	}}
	clean := []*semanticpb.EffectFact{{
		Kind: "write", TargetState: "known", RoleState: "known",
		Target: &semanticpb.EffectTarget{Type: "path", Path: "/tmp/x"},
	}}
	// A known effect wins even when an unknown one precedes it.
	mixed := append(append([]*semanticpb.EffectFact(nil), unknown...), known...)

	for _, tc := range []struct {
		name  string
		facts []*semanticpb.EffectFact
		want  effectTier
	}{
		{"effect case 1: known protected write", known, effectTierKnown},
		{"effect case 2: unknown protected touch", unknown, effectTierUnknown},
		{"effect case 3: ordinary write is clean", clean, effectTierClean},
		{"effect case 4: known wins over unknown", mixed, effectTierKnown},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got, _, _, _ := classifyEffectFacts(tc.facts)
			if got != tc.want {
				t.Fatalf("tier = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEffectTierAction(t *testing.T) {
	for _, tc := range []struct {
		name            string
		tier            effectTier
		kind            string
		sets            []string
		strictOrManaged bool
		want            string
	}{
		{"known mutation blocks", effectTierKnown, "write", []string{effectrules.SetSSHAuthorizedKeys}, false, guardrailActionBlock},
		{"known credential read alerts", effectTierKnown, "read", []string{effectrules.SetCredentials}, false, guardrailActionAlert},
		{"known shell-rc read is allowed", effectTierKnown, "read", []string{effectrules.SetShellRC}, false, guardrailActionAllow},
		{"unknown alerts in OSS default", effectTierUnknown, "delete", []string{effectrules.SetSSHAuthorizedKeys}, false, guardrailActionAlert},
		{"unknown blocks in strict or managed", effectTierUnknown, "delete", []string{effectrules.SetSSHAuthorizedKeys}, true, guardrailActionBlock},
		{"clean allows", effectTierClean, "write", nil, true, guardrailActionAllow},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := effectTierAction(tc.tier, tc.kind, tc.sets, tc.strictOrManaged); got != tc.want {
				t.Fatalf("action = %q, want %q", got, tc.want)
			}
		})
	}
}

func TestEffectShadowFindingsEnforcement(t *testing.T) {
	// An alert-tier verdict is capped at an alert.
	alertF := effectShadowFindings(EffectShadowResult{
		Tier: string(effectTierUnknown), Action: guardrailActionAlert, Kind: "delete",
		Sets: []string{effectrules.SetSSHAuthorizedKeys},
	}, effectRulesOn)
	if len(alertF) != 1 || alertF[0].enforcement != findingEnforcementAlertOnly {
		t.Fatalf("alert tier enforcement = %+v, want one alert-only finding", alertF)
	}
	if alertF[0].disposition != findingDispositionEffectUnknown {
		t.Fatalf("alert tier disposition = %v, want effect_unknown", alertF[0].disposition)
	}
	// A block-tier known mutation contributes to enforcement and is CRITICAL.
	blockF := effectShadowFindings(EffectShadowResult{
		Tier: string(effectTierKnown), Action: guardrailActionBlock, Kind: "write",
		Sets: []string{effectrules.SetSSHAuthorizedKeys},
	}, effectRulesOn)
	if len(blockF) != 1 || !blockF[0].contributesToEnforcement() || blockF[0].Severity != "CRITICAL" {
		t.Fatalf("block tier finding = %+v, want one enforcing CRITICAL finding", blockF)
	}
	if !blockF[0].proof.authorizes(blockF[0].RuleID) {
		t.Fatalf("block tier proof is not authoritative in ON mode")
	}
	// In shadow the same proof is not authoritative.
	shadowF := effectShadowFindings(EffectShadowResult{
		Tier: string(effectTierKnown), Action: guardrailActionBlock, Kind: "write",
	}, effectRulesShadow)
	if shadowF[0].proof.authorizes(shadowF[0].RuleID) {
		t.Fatalf("shadow proof must not authorize a deny")
	}
	// Clean carries no finding.
	if got := effectShadowFindings(EffectShadowResult{Tier: string(effectTierClean), Action: guardrailActionAllow}, effectRulesOn); got != nil {
		t.Fatalf("clean verdict findings = %+v, want nil", got)
	}
}

func TestComputeEffectShadowKnownMutation(t *testing.T) {
	req := trustedActionRequest{
		Connector: "claudecode",
		Input: actionfacts.Input{
			Tool: "Bash", Command: "echo k >> ~/.ssh/authorized_keys",
			ActiveHome: "/home/u", CWD: "/home/u/work", DialectHint: actionfacts.DialectPOSIX,
		},
	}
	res := computeEffectShadow(req, effectRulesShadow)
	if res.Tier != string(effectTierKnown) {
		t.Fatalf("tier = %q, want known", res.Tier)
	}
	if res.Action != guardrailActionBlock {
		t.Fatalf("action = %q, want block", res.Action)
	}
	if !effectSetContains(res.Sets, effectrules.SetSSHAuthorizedKeys) {
		t.Fatalf("sets = %v, want ssh_authorized_keys", res.Sets)
	}
}
