// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

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
		if redundantFetchedScriptFinding(f, findings) {
			continue
		}
		if d := decideFinding(f); decide.ShadowOnly(d) || foldsClassEffectIntoLegacy(f, findings) || decide.FoldsIntoLegacy(d, foldTargetsFor(f, findings)) {
			continue
		}
		findings = append(findings, f)
	}
	return findings
}

// redundantFetchedScriptFinding keeps the one legacy fetch-to-shell alert
// when it already enforces the same rule at least as strongly as the effects
// proof. The added proof remains for spellings the legacy reader misses.
func redundantFetchedScriptFinding(f RuleFinding, findings []RuleFinding) bool {
	if f.proof.kind != findingProofEffect || !f.Proof.Advisory() ||
		(f.RuleID != "CMD-PIPE-CURL" && f.RuleID != "CMD-PIPE-WGET") {
		return false
	}
	for _, prior := range findings {
		if !strings.EqualFold(prior.RuleID, f.RuleID) || prior.profile != f.profile ||
			isEffectFinding(prior) || prior.floorRaiseOnly || findingEnforcementRank(prior) < 2 {
			continue
		}
		if decide.ParseSeverity(prior.Severity) >= decide.ParseSeverity(f.Severity) {
			return true
		}
	}
	return false
}

// isEffectFinding uses the private gateway proof as well as the Decide
// proof. T23b grades a Known credential mutation with its class rule's
// severity-only cell and clears the Decide proof, but keeps the trusted
// effects provenance in findingProofEffect.
func isEffectFinding(f RuleFinding) bool {
	return f.Proof.Source == decide.SourceEffects || f.proof.kind == findingProofEffect
}

// foldsClassEffectIntoLegacy folds that severity-only class finding into
// the same 1.0.10 rule when an original reading actually made it. T23b
// clears the Decide proof only for the Known class mutation; the private
// effects proof keeps its provenance. A new floor reading and another
// effects finding cannot stand in for 1.0.10 (GAP-1984).
func foldsClassEffectIntoLegacy(f RuleFinding, other []RuleFinding) bool {
	if f.proof.kind != findingProofEffect || !f.proof.authorizes(f.RuleID) || !f.Proof.IsZero() {
		return false
	}
	for _, g := range other {
		if isEffectFinding(g) || g.floorRaiseOnly {
			continue
		}
		if strings.EqualFold(f.RuleID, g.RuleID) {
			return true
		}
	}
	return false
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
//
// Fold targets are the findings of 1.0.10's own readings. A finding of a
// reading 1.0.10 did not have (floorRaiseOnly: the -EncodedCommand body
// read past its blanks, GAP-1199; an evaluated loop-header group, GAP-1550)
// raises the call but takes no effect finding: folded into it, the effect
// finding's CRITICAL fell to that reading's HIGH while the plain spelling
// kept it (DET111 ruling 2, rel-1-0-10:GAP-1984).
func foldTargetsFor(f RuleFinding, other []RuleFinding) []decide.Finding {
	strong := findingEnforcementRank(f) > 1
	_, sev := verdictSeverity(f)
	var out []decide.Finding
	for _, g := range other {
		if isEffectFinding(g) || g.floorRaiseOnly {
			continue
		}
		if _, gs := verdictSeverity(g); strong && gs >= sev && findingEnforcementRank(g) == 1 {
			continue
		}
		out = append(out, decideFinding(g))
	}
	return out
}

// withFloorRaiseOnlyMark is findings, each marked floorRaiseOnly, when
// request is a reading made through a reading 1.0.10 did not have
// (actionfacts.Input.FloorRaiseOnly); from is the first finding the reading
// made (the findings before it are the caller's). The marked list is a copy:
// the dispatch memo keeps the reading's own.
func withFloorRaiseOnlyMark(request trustedActionRequest, findings []RuleFinding, from int) []RuleFinding {
	if !request.Input.FloorRaiseOnly || from >= len(findings) {
		return findings
	}
	marked := slices.Clone(findings)
	for i := from; i < len(marked); i++ {
		marked[i].floorRaiseOnly = true
	}
	return marked
}

// withFloorRaiseOnlyOf is replacement standing for replaced, a finding of
// the same rule: it is floorRaiseOnly only when both are, so a 1.0.10
// reading's finding stays a fold target when a new reading proves its rule
// more strongly.
//
// An effects-lane finding is no 1.0.10 reading's finding: a reading 1.0.10
// did not have that takes its slot (the GAP-1550 foreach header's
// tamper.detector_state_write in the place of the Known state write finding
// of the same rule, GAP-1478) stays floorRaiseOnly. Made a fold target, it
// took the effect finding of the call: the CRITICAL
// effect.protected_target_restricted fell to its HIGH (rel-1-0-10:GAP-1984).
func withFloorRaiseOnlyOf(replacement, replaced RuleFinding) RuleFinding {
	if isEffectFinding(replaced) {
		return replacement
	}
	replacement.floorRaiseOnly = replacement.floorRaiseOnly && replaced.floorRaiseOnly
	return replacement
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
		if isEffectFinding(f) {
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
		if isEffectFinding(f) && (foldsClassEffectIntoLegacy(f, other) || decide.FoldsIntoLegacy(decideFinding(f), foldTargetsFor(f, other))) {
			continue
		}
		kept = append(kept, f)
	}
	return kept
}

// readingRuleSlot is where a 1.0.10 reading's finding of ruleID goes in
// findings. held reports that a finding of a 1.0.10 reading (not the effect
// lane's) already carries the rule: the reading adds nothing. Otherwise
// index is the effects-lane finding of the same rule, or -1 when none.
//
// A Known protected write finding names the plain spelling's rule
// (decide.RuleFor, GAP-1478). A reading that dedups by rule id (the agent
// hook config guard, the non-shell tool effects, a link or CMD twin)
// dropped its own 1.0.10 finding beside it, so
// the effect lane had no 1.0.10 finding to fold into and the plain spelling
// echo x > ~/.claude/settings.json carried effect.protected_target_restricted
// beside its rule (GAP-1243, GAP-1308). The reading's finding takes the place
// of the effects-lane finding of its rule instead: the call then holds the
// finding the plain spelling held before the Known write finding existed,
// and the effect lane folds into it as it does for the plain spelling
// (decide.FoldsIntoLegacy, DET111 ruling A). Where no 1.0.10 reading fires,
// the effects-lane findings stand (R-NOLOSS).
func readingRuleSlot(findings []RuleFinding, ruleID string) (index int, held bool) {
	index = -1
	for i, f := range findings {
		if f.RuleID != ruleID {
			continue
		}
		if !isEffectFinding(f) {
			return -1, true
		}
		if index < 0 {
			index = i
		}
	}
	return index, false
}

// withReadingFinding is findings with f, the finding of a 1.0.10 reading,
// in the slot readingRuleSlot gives it. findings is changed in place when f
// takes an effects-lane finding's slot: callers pass their own copy.
func withReadingFinding(findings []RuleFinding, f RuleFinding) []RuleFinding {
	switch index, held := readingRuleSlot(findings, f.RuleID); {
	case held:
		return findings
	case index >= 0:
		findings[index] = f
		return findings
	}
	return append(findings, f)
}
