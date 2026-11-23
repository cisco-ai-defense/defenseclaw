// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import "github.com/defenseclaw/defenseclaw/internal/guardrail/decide"

// joinEffectFindings is the call's findings with the effect lane's joined
// (raise only). An effect finding whose protected set a 1.0.10 finding of
// the call names is folded into that finding (decide.FoldsIntoLegacy, DET111
// ruling A), unless that finding cannot carry the action the effect finding
// proves (foldTargetsFor): the rule naming the set already grades it with
// its own 1.0.10 cell, so the effect finding adds no action and no verdict
// severity. Every other effect finding joins and its tier table row
// decides, except one the
// table records in every cell (decide.ShadowOnly: the effect unknown tier,
// a write to a set whose 1.0.10 rule is decided by content), which never
// enters the call. The fold reads the same decide findings Decide and the
// verdict severity read.
func joinEffectFindings(findings, effect []RuleFinding) []RuleFinding {
	if len(effect) == 0 {
		return findings
	}
	for _, f := range effect {
		if d := decideFinding(f); decide.ShadowOnly(d) || decide.FoldsIntoLegacy(d, foldTargetsFor(f, findings)) {
			continue
		}
		findings = append(findings, f)
	}
	return findings
}

// findingEnforcementRank orders what a finding may do to the call: an
// enforcing proof that authorizes its own rule (3) over an alert-only
// finding (2) over one that may neither block nor alert on its own (1: the
// proof boundary records it, applyTrustedActionProofBoundary).
func findingEnforcementRank(f RuleFinding) int {
	switch {
	case f.contributesToEnforcement() && f.proof.authorizes(f.RuleID):
		return 3
	case f.contributesToAlertOnly():
		return 2
	default:
		return 1
	}
}

// foldTargetsFor is the findings of other an effect finding f may fold into
// (DET111 ruling A, bounded by the owner no-loss rule R-NOLOSS 2026-11-23: a
// fold never lowers the call). A 1.0.10 finding that grades the set at
// least as high as f (verdict severity) but may neither block nor alert on
// its own (rank 1, no proof that authorizes its rule) cannot carry the
// action f proves: folded into it, the call fell to allow under a CRITICAL
// finding. A new reading adds such a finding beside f (the decoded
// -EncodedCommand body with control blanks, GAP-1199; an evaluated loop
// header, GAP-1550; the nested decoded persistence finding of gap-1576
// f11/f12), so f stands beside it (rel-1-0-10:GAP-1984). A 1.0.10 finding
// that grades the set lower than f still takes f (its own 1.0.10 cell,
// ruling A), and so does one that acts on its own.
func foldTargetsFor(f RuleFinding, other []RuleFinding) []decide.Finding {
	strong := findingEnforcementRank(f) > 1
	_, sev := verdictSeverity(f)
	var out []decide.Finding
	for _, g := range other {
		if g.Proof.Source == decide.SourceEffects {
			continue
		}
		if _, gs := verdictSeverity(g); strong && gs >= sev && findingEnforcementRank(g) == 1 {
			continue
		}
		out = append(out, decideFinding(g))
	}
	return out
}

// withEffectsFoldedEitherWay applies the same fold where two readings of
// one call merge by rule id (a twin, a nested statement, a simple-command
// pass): an effect finding of either list whose protected set a 1.0.10
// finding of the other names is folded into that finding. Merged by rule id
// instead, the effect finding held the id (an enforcing Known proof outranks
// the 1.0.10 alert-only finding), so its read cell replaced the 1.0.10 copy
// verdict of the same rule: an effect finding never replaces or lowers a
// 1.0.10 finding (DET111 ruling A; rel-1-0-10:GAP-0998, GAP-0999, GAP-1226).
func withEffectsFoldedEitherWay(a, b []RuleFinding) ([]RuleFinding, []RuleFinding) {
	if !hasEffectFinding(a) && !hasEffectFinding(b) {
		return a, b
	}
	return withoutEffectsFoldedInto(a, b), withoutEffectsFoldedInto(b, a)
}

func hasEffectFinding(findings []RuleFinding) bool {
	for _, f := range findings {
		if f.Proof.Source == decide.SourceEffects {
			return true
		}
	}
	return false
}

// withEffectsFoldedIntoCall is the call's findings without the effect
// findings a 1.0.10 finding of the same call folds (decide.FoldsIntoLegacy).
// The effect join (joinEffectFindings) runs inside the rule dispatch, before
// the readings beside it add their 1.0.10 findings (the agent hook config
// guard's tamper.agent_hook_config_write, a proved state write's
// tamper.detector_state_write, a twin or a second reading of the call): an
// effect finding those name stood beside them, added its own rule id and
// graded the set above the rule naming it (DET111 ruling A;
// rel-1-0-10:GAP-1243, GAP-1308). The fold runs once more on the final list
// of the call, so every route keeps the 1.0.10 rule set.
func withEffectsFoldedIntoCall(findings []RuleFinding) []RuleFinding {
	return withoutEffectsFoldedInto(findings, findings)
}

// withoutEffectsFoldedInto is findings without the effect findings a 1.0.10
// finding of other folds (decide.FoldsIntoLegacy).
func withoutEffectsFoldedInto(findings, other []RuleFinding) []RuleFinding {
	if !hasEffectFinding(findings) {
		return findings
	}
	kept := findings[:0:0]
	for _, f := range findings {
		if f.Proof.Source == decide.SourceEffects && decide.FoldsIntoLegacy(decideFinding(f), foldTargetsFor(f, other)) {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}
