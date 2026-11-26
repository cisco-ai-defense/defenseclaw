// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"cmp"
	"context"
	"slices"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semantic"
	"github.com/defenseclaw/defenseclaw/internal/guardrail/semanticpb"
)

// guestViewEvals keeps, for one placed reading of a hook (placedReader),
// what the semantic rules of a rule generation made of it: its projection,
// its enforcement projection, whether each rule's owner is eligible for it,
// and each rule's result on the two projections. A hook judges the placed
// readings of the call and of its twins (the here-string pipe twin, the
// state twin, the reading twin), mostly the same readings by text and
// folder: rd-hs-45-0 judged four lists of about 1,130 placed readings with
// every rule, and the copy-mode actor took 1.3 times its laptop's time
// (rel-1-0-10:GAP-2226, substrate-1 GAP-0502). Each of these is a function
// of the reading's facts alone, and a placed reading's facts are the ones
// the memo keeps for its text and folder, so a later judgment of the same
// reading takes them from here. Everything else runs as before: the budget
// is charged the same cost for a kept result, and the rules already
// matched, the owners a finding excludes and the budget's end are read
// live. A nil *guestViewEvals keeps nothing.
//
// Keeping must cost next to nothing where a reading is judged once (a
// here-string fan's one placed list): the first table lives in the
// reading, eligibility is two bits a rule, the enforcement projection is
// made only for a matched rule, and the results are a sorted array of
// small values, so a first judgment adds a few allocations a reading, not
// one a rule.
type guestViewEvals struct {
	mu    sync.Mutex
	first guestViewEvalTable
	more  []*guestViewEvalTable
}

// guestViewEvalTable is a guestViewEvals for one rule generation, by rule
// index (generation.semanticRules). A nil table keeps nothing: each read
// is made afresh.
type guestViewEvalTable struct {
	generation *compiledRulePackCategories
	// eligible holds two bits a rule: the owner was read, and it is
	// eligible. Made at the first read.
	eligible []uint64

	projected      bool
	projection     *semanticpb.Facts
	projectionCode semantic.ProjectionCode

	enforcement *guestKeptEnforcement

	// results are the complete results (semantic.EvalOK) by slot
	// (guestKeptSlot), in slot order.
	results []guestKeptEval
}

// guestKeptEnforcement is a reading's enforcement projection
// (actionfacts.Facts.EnforcementProjection) and its semantic projection.
type guestKeptEnforcement struct {
	facts      actionfacts.Facts
	projection *semanticpb.Facts
	code       semantic.ProjectionCode
}

// guestKeptEval is one rule's complete result on one of a reading's
// projections.
type guestKeptEval struct {
	slot   int
	result semantic.Result
}

// guestKeptSlot is the slot of rule rule's result on a reading's
// projection, or on its enforcement projection.
func guestKeptSlot(rule int, enforcement bool) int {
	if enforcement {
		return 2*rule + 1
	}
	return 2 * rule
}

// lock returns the table of generation, locked; unlock it with unlock. nil
// for a nil evals.
func (evals *guestViewEvals) lock(generation *compiledRulePackCategories) *guestViewEvalTable {
	if evals == nil {
		return nil
	}
	evals.mu.Lock()
	if evals.first.generation == nil {
		evals.first.generation = generation
	}
	if evals.first.generation == generation {
		return &evals.first
	}
	for _, table := range evals.more {
		if table.generation == generation {
			return table
		}
	}
	table := &guestViewEvalTable{generation: generation}
	evals.more = append(evals.more, table)
	return table
}

// unlock ends a lock.
func (evals *guestViewEvals) unlock() {
	if evals != nil {
		evals.mu.Unlock()
	}
}

// project is semantic.Project(*view). The reads take the reading by
// pointer: a reading is a 1.5 KB struct, and a copy of it for each rule of
// each placed view made herestr-cd-touch, whose readings are judged once,
// slower than with no table.
func (table *guestViewEvalTable) project(view *actionfacts.Facts) (*semanticpb.Facts, semantic.ProjectionCode) {
	if table == nil {
		return semantic.Project(*view)
	}
	if !table.projected {
		table.projection, table.projectionCode = semantic.Project(*view)
		table.projected = true
	}
	return table.projection, table.projectionCode
}

// enforcementOf is view.EnforcementProjection() and its projection.
func (table *guestViewEvalTable) enforcementOf(view *actionfacts.Facts) (actionfacts.Facts, *semanticpb.Facts, semantic.ProjectionCode) {
	if table == nil {
		facts := view.EnforcementProjection()
		projection, code := semantic.Project(facts)
		return facts, projection, code
	}
	if table.enforcement == nil {
		kept := &guestKeptEnforcement{facts: view.EnforcementProjection()}
		kept.projection, kept.code = semantic.Project(kept.facts)
		table.enforcement = kept
	}
	return table.enforcement.facts, table.enforcement.projection, table.enforcement.code
}

// eligibleFor is candidate.owner.eligible(*view), candidate being rule
// rule of the table's generation.
func (table *guestViewEvalTable) eligibleFor(rule int, candidate *compiledSemanticRule, view *actionfacts.Facts) bool {
	if table == nil {
		return candidate.owner.eligible(*view)
	}
	if table.eligible == nil {
		table.eligible = make([]uint64, (2*len(table.generation.semanticRules)+63)/64)
	}
	word, bit := (2*rule)/64, uint((2*rule)%64)
	if table.eligible[word]&(1<<bit) == 0 {
		table.eligible[word] |= 1 << bit
		if candidate.owner.eligible(*view) {
			table.eligible[word] |= 1 << (bit + 1)
		}
	}
	return table.eligible[word]&(1<<(bit+1)) != 0
}

// result is the complete result kept in slot; false where none is, and for
// a nil table.
func (table *guestViewEvalTable) result(slot int) (semantic.Result, bool) {
	if table == nil {
		return semantic.Result{}, false
	}
	at, found := slices.BinarySearchFunc(table.results, slot, func(kept guestKeptEval, slot int) int { return cmp.Compare(kept.slot, slot) })
	if !found {
		return semantic.Result{}, false
	}
	return table.results[at].result, true
}

// keep puts a complete result in slot; a nil table keeps nothing.
func (table *guestViewEvalTable) keep(slot int, result semantic.Result) {
	if table == nil {
		return
	}
	if n := len(table.results); n == 0 || table.results[n-1].slot < slot {
		// A first judgment reads the rules in order.
		table.results = append(table.results, guestKeptEval{slot: slot, result: result})
		return
	}
	at, found := slices.BinarySearchFunc(table.results, slot, func(kept guestKeptEval, slot int) int { return cmp.Compare(kept.slot, slot) })
	if found {
		table.results[at].result = result
		return
	}
	table.results = slices.Insert(table.results, at, guestKeptEval{slot: slot, result: result})
}

// evalKept is eval with kept, the table of a placed reading
// (guestViewEvals), and slot, the slot of the same rule's result on the
// same projection: a complete result already there stands for a new
// evaluation, and the budget is charged its cost as for a new one; a new
// complete result is put there. A done ctx is always evaluated afresh, as
// eval does. A nil kept is eval.
func (b *trustedActionBudget) evalKept(ctx context.Context, candidate compiledSemanticRule, view int, projection *semanticpb.Facts, kept *guestViewEvalTable, slot int) (result semantic.Result, code semantic.EvalCode, ok bool) {
	if kept == nil {
		return b.eval(ctx, candidate, view, projection)
	}
	key := trustedActionEvalKey{expression: candidate.rule.Expression, view: view}
	if hit, cached := b.evals[key]; cached {
		return hit.result, hit.code, true
	}
	if b.spent() {
		return semantic.Result{}, code, false
	}
	if hit, found := kept.result(slot); found && !contextDone(ctx.Done()) {
		result, code = hit, semantic.EvalOK
	} else {
		result, code = candidate.program.EvalBool(ctx, projection)
		if code == semantic.EvalOK {
			kept.keep(slot, result)
		}
	}
	b.consumed += result.Cost
	if b.evals != nil && code == semantic.EvalOK {
		b.evals[key] = trustedActionEval{result: result, code: code}
	}
	if b.consumed > trustedActionDispatchMaxCost {
		b.reached = true
		return semantic.Result{}, code, false
	}
	return result, code, true
}
