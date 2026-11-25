// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

// TestEffectFindingNeverHoldsALegacyRuleAcrossReadings (DET111 ruling A at
// every merge; rel-1-0-10:GAP-0998, GAP-0999, GAP-1226): where two readings
// of one call merge by rule id (a nested statement's or twin's findings, a
// simple-command pass), an effect Known read of .git-credentials folds into
// the 1.0.10 PATH-GIT-CREDS finding of the other reading, in both
// directions, so the copy keeps its CRITICAL 1.0.10 finding. Before, the
// enforcing effect proof held the rule id and the alert-only CRITICAL copy
// finding was dropped: the copy fell to the read cell (alert MEDIUM, allow in
// permissive). An effect finding no 1.0.10 finding of the other reading names
// joins as before. A 1.0.10 finding of the same set that may not act on its
// own (no proof that authorizes its rule) never takes the enforcing effect
// read: folded into it, the call fell to allow (rel-1-0-10:GAP-1984).
func TestEffectFindingNeverHoldsALegacyRuleAcrossReadings(t *testing.T) {
	effect := func(set string) RuleFinding {
		p := decide.Proof{Kind: decide.KindRead, Target: decide.TargetCredential, Certainty: decide.CertKnown,
			Set: set, Source: decide.SourceEffects}
		f := RuleFinding{RuleID: decide.RuleFor(p), Title: "Known credential read", Severity: "HIGH", Confidence: 1, Proof: p}
		f.proof = newFindingProof(findingProofEffect, f.RuleID, true)
		return f
	}
	copyAlert := RuleFinding{RuleID: "PATH-GIT-CREDS", Title: "Git credentials file", Severity: "CRITICAL",
		Confidence: 0.9, Proof: decide.Proof{}.Advise()}
	copyBlock := RuleFinding{RuleID: "PATH-GIT-CREDS", Title: "Git credentials file", Severity: "CRITICAL", Confidence: 0.9}
	copyBlock.proof = newFindingProof(findingProofResolvedTarget, "PATH-GIT-CREDS", true)
	// A copy finding with no proof that authorizes its rule: the proof
	// boundary records it, so it cannot carry the block the effect read
	// proves (rel-1-0-10:GAP-1984).
	copyUnproven := RuleFinding{RuleID: "PATH-GIT-CREDS", Title: "Git credentials file", Severity: "CRITICAL", Confidence: 0.9}
	check := func(name string, got []RuleFinding, want RuleFinding, extra int) {
		t.Helper()
		legacy, effects := 0, 0
		for _, f := range got {
			switch {
			case f.Proof.Source == decide.SourceEffects:
				effects++
			case f.RuleID == want.RuleID && f.Severity == want.Severity && f.Proof == want.Proof:
				legacy++
			}
		}
		if legacy != 1 || effects != extra {
			t.Errorf("%s: %d 1.0.10 %s %s findings and %d effect findings, want 1 and %d: %+v",
				name, legacy, want.RuleID, want.Severity, effects, extra, got)
		}
	}
	gitRead := effect(decide.SetGitCredentials)
	check("nested reading after the effect join", withHostTwinFindings([]RuleFinding{gitRead}, []RuleFinding{copyAlert}), copyAlert, 0)
	check("twin of the call", withOverLimitTwinFindings([]RuleFinding{gitRead}, []RuleFinding{copyAlert}), copyAlert, 0)
	check("enforcing twin finding", withTwinProvenBlocks([]RuleFinding{gitRead}, []RuleFinding{copyBlock}), copyBlock, 0)
	check("effect finding of the twin", withTwinProvenBlocks([]RuleFinding{copyAlert}, []RuleFinding{gitRead}), copyAlert, 0)
	check("simple-command pass", withSimpleCommandFindings([]RuleFinding{gitRead}, []RuleFinding{copyAlert}), copyAlert, 0)
	// The fold never lowers the call (DET111 ruling on GAP-1984, owner
	// R-NOLOSS): the enforcing effect read stays where the twin finding of
	// the same set may not act on its own.
	if got := withTwinProvenBlocks([]RuleFinding{gitRead}, []RuleFinding{copyUnproven}); !hasEffectFinding(got) {
		t.Errorf("unproven twin finding: the effect read folded into a finding that cannot act: %+v", got)
	}
	// Another file class: the effect read stands beside the 1.0.10 finding.
	awsRead := effect(decide.SetAWSCredentials)
	check("other class", withHostTwinFindings([]RuleFinding{awsRead}, []RuleFinding{copyAlert}), copyAlert, 1)
}

// TestFetchedScriptLegacyFindingFold keeps the plain 1.0.10 pipe cell
// singular while leaving a new effects-only source-to-interpreter proof live.
func TestFetchedScriptLegacyFindingFold(t *testing.T) {
	effect := RuleFinding{RuleID: "CMD-PIPE-CURL", Severity: "HIGH",
		Proof: advisoryProof, proof: newFindingProof(findingProofEffect, "CMD-PIPE-CURL", true)}
	legacy := RuleFinding{RuleID: "CMD-PIPE-CURL", Severity: "HIGH", Proof: advisoryProof}
	tests := []struct {
		name  string
		prior RuleFinding
		want  int
	}{
		{"same legacy cell", legacy, 1},
		{"lower legacy cell", RuleFinding{RuleID: "CMD-PIPE-CURL", Severity: "LOW", Proof: advisoryProof}, 2},
		{"different rule", RuleFinding{RuleID: "CMD-PIPE-WGET", Severity: "HIGH", Proof: advisoryProof}, 2},
		{"effects source", effect, 2},
		{"floor reading", RuleFinding{RuleID: "CMD-PIPE-CURL", Severity: "HIGH", Proof: advisoryProof, floorRaiseOnly: true}, 2},
		{"recorded legacy", RuleFinding{RuleID: "CMD-PIPE-CURL", Severity: "HIGH", Proof: recordProof}, 2},
		{"unproven enforcing", RuleFinding{RuleID: "CMD-PIPE-CURL", Severity: "HIGH", Proof: enforcingProof}, 2},
		{"another profile", RuleFinding{RuleID: "CMD-PIPE-CURL", Severity: "HIGH", Proof: advisoryProof, profile: "member-a"}, 2},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := joinEffectFindings([]RuleFinding{tc.prior}, []RuleFinding{effect})
			if len(got) != tc.want {
				t.Fatalf("joined findings=%d, want %d", len(got), tc.want)
			}
		})
	}
	if got := joinEffectFindings(nil, []RuleFinding{effect}); len(got) != 1 {
		t.Fatalf("effects-only proof lost: %v", got)
	}
}
