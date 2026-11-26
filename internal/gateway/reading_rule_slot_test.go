// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/decide"
)

// TestReadingFindingTakesTheEffectsSlotOfItsRule: a 1.0.10 reading that
// adds a rule the call holds only by an effects-lane finding (a Known
// protected write names the plain spelling's rule, GAP-1478) puts its own
// finding in that slot, so the effect lane folds into it as it does for the
// plain spelling; a rule a 1.0.10 finding holds adds nothing, and a new rule
// is appended (GAP-1243, GAP-1308).
func TestReadingFindingTakesTheEffectsSlotOfItsRule(t *testing.T) {
	const rule = agentHookConfigWriteRuleID
	effect := RuleFinding{RuleID: rule, Title: "effect", Proof: decide.Proof{Source: decide.SourceEffects}}
	reading := RuleFinding{RuleID: rule, Title: "reading"}
	other := RuleFinding{RuleID: "effect.protected_target_restricted", Proof: decide.Proof{Source: decide.SourceEffects}}

	got := withReadingFinding([]RuleFinding{other, effect}, reading)
	if len(got) != 2 || got[1].Title != "reading" || got[0].RuleID != other.RuleID {
		t.Fatalf("effects slot: got %+v, want the reading in the effects finding's slot", got)
	}
	held := RuleFinding{RuleID: rule, Title: "held"}
	if got := withReadingFinding([]RuleFinding{held, effect}, reading); len(got) != 2 || got[0].Title != "held" || got[1].Title != "effect" {
		t.Fatalf("held: got %+v, want the list unchanged", got)
	}
	if got := withReadingFinding([]RuleFinding{other}, reading); len(got) != 2 || got[1].Title != "reading" {
		t.Fatalf("new rule: got %+v, want it appended", got)
	}
	if i, held := readingRuleSlot(nil, rule); i != -1 || held {
		t.Fatalf("empty: got %d %v", i, held)
	}
}

// TestFloorRaiseOnlyReadingKeepsItsMarkInAnEffectsSlot (rel-1-0-10:GAP-1984
// with the GAP-1478 Known write finding): a finding of a reading 1.0.10 did
// not have stays floorRaiseOnly when it takes the slot of an effects-lane
// finding, and so is no fold target for the effect lane; in the slot of a
// 1.0.10 reading's finding it takes that finding's standing.
func TestFloorRaiseOnlyReadingKeepsItsMarkInAnEffectsSlot(t *testing.T) {
	newReading := RuleFinding{RuleID: "tamper.detector_state_write", floorRaiseOnly: true}
	known := RuleFinding{RuleID: decide.RuleStateWrite, Proof: decide.Proof{Source: decide.SourceEffects}}
	if got := withFloorRaiseOnlyOf(newReading, known); !got.floorRaiseOnly {
		t.Fatal("a new reading in an effects-lane slot lost its floorRaiseOnly mark")
	}
	old := RuleFinding{RuleID: "tamper.detector_state_write"}
	if got := withFloorRaiseOnlyOf(newReading, old); got.floorRaiseOnly {
		t.Fatal("a new reading in a 1.0.10 reading's slot kept floorRaiseOnly")
	}
	effect := RuleFinding{RuleID: decide.RuleEffectRestricted, Proof: decide.Proof{Source: decide.SourceEffects}}
	if got := foldTargetsFor(effect, []RuleFinding{withFloorRaiseOnlyOf(newReading, known)}); len(got) != 0 {
		t.Fatalf("fold targets %v: a floorRaiseOnly finding is a fold target", got)
	}
}
