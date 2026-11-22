// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import "github.com/defenseclaw/defenseclaw/internal/guardrail/decide"

// joinEffectFindings is the call's findings with the effect lane's joined
// (raise only). An effect finding whose protected set a 1.0.10 finding of
// the call names is folded into that finding (decide.FoldsIntoLegacy, DET111
// ruling A): the rule naming the set already grades it with its own 1.0.10
// cell, so the effect finding adds no action and no verdict severity. Every
// other effect finding joins and its tier table row decides, except one the
// table records in every cell (decide.ShadowOnly: the effect unknown tier,
// a write to a set whose 1.0.10 rule is decided by content), which never
// enters the call. The fold reads the same decide findings Decide and the
// verdict severity read.
func joinEffectFindings(findings, effect []RuleFinding) []RuleFinding {
	if len(effect) == 0 {
		return findings
	}
	call := decideFindings(findings)
	for _, f := range effect {
		if d := decideFinding(f); decide.ShadowOnly(d) || decide.FoldsIntoLegacy(d, call) {
			continue
		}
		findings = append(findings, f)
	}
	return findings
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

// withoutEffectsFoldedInto is findings without the effect findings a 1.0.10
// finding of other folds (decide.FoldsIntoLegacy).
func withoutEffectsFoldedInto(findings, other []RuleFinding) []RuleFinding {
	if !hasEffectFinding(findings) {
		return findings
	}
	call := decideFindings(other)
	kept := findings[:0:0]
	for _, f := range findings {
		if f.Proof.Source == decide.SourceEffects && decide.FoldsIntoLegacy(decideFinding(f), call) {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}
