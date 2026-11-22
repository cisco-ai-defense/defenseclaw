// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

// TestEffectJoinKeepsShadowOnlyFindingsOut (GAP-1796, GAP-1795): the effect
// join is the one place the effect lane's findings enter a call, and a
// finding the tier table records in every cell never enters it: the unknown
// tier on every set, advisory or enforcing (DET111 ruling
// 2026-11-22T17:00Z), any Known write to a shell startup file and a Known
// link placed at a member other than the DefenseClaw state (the T17 sweep
// dotfiles shape). A restricted write to authorized_keys or the DefenseClaw
// state, and a link placed at the state, join.
func TestEffectJoinKeepsShadowOnlyFindingsOut(t *testing.T) {
	finding := func(rule string, kind decide.ProofKind, target decide.TargetClass, advise bool) RuleFinding {
		p := decide.Proof{Kind: kind, Target: target, Certainty: decide.CertKnown, Source: decide.SourceEffects}
		if advise {
			p = p.Advise()
		}
		f := RuleFinding{RuleID: rule, Title: "Effect-model protected-target verdict", Severity: "HIGH", Confidence: 0.9, Proof: p}
		f.proof = newFindingProof(findingProofEffect, rule, true)
		return f
	}
	for _, advise := range []bool{true, false} {
		for _, tc := range []struct {
			f      RuleFinding
			joined bool
		}{
			{finding(decide.RuleEffectUnknown, decide.KindAppend, decide.TargetAutostart, advise), false},
			{finding(decide.RuleEffectUnknown, decide.KindWrite, decide.TargetOther, advise), false},
			{finding(decide.RuleEffectRestricted, decide.KindAppend, decide.TargetAutostart, advise), false},
			{finding(decide.RuleEffectUnknown, decide.KindWrite, decide.TargetAuthorizedKeys, advise), false},
			{finding(decide.RuleEffectUnknown, decide.KindAppend, decide.TargetState, advise), false},
			{finding(decide.RuleEffectRestricted, decide.KindWrite, decide.TargetState, advise), true},
			{finding(decide.RuleEffectRestricted, decide.KindLink, decide.TargetAuthorizedKeys, advise), false},
			{finding(decide.RuleEffectRestricted, decide.KindLink, decide.TargetHookConfig, advise), false},
			{finding(decide.RuleEffectRestricted, decide.KindLink, decide.TargetState, advise), true},
			{finding(decide.RuleEffectRestricted, decide.KindAppend, decide.TargetAuthorizedKeys, advise), true},
		} {
			got := joinEffectFindings(nil, []RuleFinding{tc.f})
			if (len(got) == 1) != tc.joined {
				t.Errorf("%s %s: joined %v, want %v", tc.f.RuleID, tc.f.Proof, len(got) == 1, tc.joined)
			}
		}
	}
}

// TestBenignShellStartupAppendKeepsItsCellFiveTiers (GAP-1795): a benign
// PATH export appended to ~/.bashrc, spelled plainly and as only the effect
// lane resolves it, reaches Decide with no effect-lane finding on the Claude
// Code and Codex hook routes in the five tiers, so it keeps its 1.0.10 cell;
// the same append to authorized_keys keeps a non-allow verdict.
func TestBenignShellStartupAppendKeepsItsCellFiveTiers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home spellings")
	}
	home := t.TempDir()
	for _, f := range []string{".bashrc", ".ssh/authorized_keys", "proj/notes.txt"} {
		p := filepath.Join(home, f)
		if err := os.MkdirAll(filepath.Dir(p), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte("# x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	cwd := filepath.Join(home, "proj")
	var last *decide.Input
	prev := decideRecordHook
	decideRecordHook = func(route, connector string, in decide.Input, out decide.Output) {
		if route == "single" {
			c := in
			last = &c
		}
	}
	t.Cleanup(func() { decideRecordHook = prev })
	for _, tier := range boundedTestTiers {
		for _, route := range r3PosixRoutesForReadRows() {
			api := gap0589TierAPI(t, route.connector, tier.posture, tier.managed, tier.tier)
			for _, command := range []string{
				`echo 'export PATH=$HOME/bin:$PATH' >> ` + home + `/.bashrc`,
				`echo 'export PATH=$HOME/bin:$PATH' >> ${PWD%/proj}/.bashrc`,
			} {
				last = nil
				action, _ := route.decide(t, api, cwd, command)
				if last != nil {
					for _, f := range last.Findings {
						if f.Proof.Source == decide.SourceEffects {
							t.Errorf("%s %s %q: effect finding %s %s reached Decide (%s)", tier.name, route.connector, command, f.RuleID, f.Proof, action)
						}
					}
				}
			}
			if action, _ := route.decide(t, api, cwd, `echo 'ssh-ed25519 AAAAC3x k' >> ${PWD%/proj}/.ssh/authorized_keys`); action == "allow" {
				t.Errorf("%s %s: authorized_keys append variant allowed", tier.name, route.connector)
			}
		}
	}
}
