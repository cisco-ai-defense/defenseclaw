// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
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
type guestViewEvals struct {
	mu     sync.Mutex
	tables []*guestViewEvalTable
}

// guestViewEvalTable is a guestViewEvals for one rule generation, by rule
// index (generation.semanticRules). A nil table keeps nothing: each read
// is made afresh.
type guestViewEvalTable struct {
	generation *compiledRulePackCategories
	// eligible is 0 where the rule's owner was not read yet, 1 eligible, 2
	// not.
	eligible []uint8

	projected      bool
	projection     *semanticpb.Facts
	projectionCode semantic.ProjectionCode

	enforcementProjected  bool
	enforcementFacts      actionfacts.Facts
	enforcementProjection *semanticpb.Facts
	enforcementCode       semantic.ProjectionCode

	results []*guestKeptEval
}

// guestKeptEval is one rule's complete result (semantic.EvalOK) on one of a
// reading's projections.
type guestKeptEval struct {
	rule        int
	enforcement bool
	ok          bool
	result      semantic.Result
}

// lock returns the table of generation, locked; unlock it with unlock. nil
// for a nil evals.
func (evals *guestViewEvals) lock(generation *compiledRulePackCategories) *guestViewEvalTable {
	if evals == nil {
		return nil
	}
	evals.mu.Lock()
	for _, table := range evals.tables {
		if table.generation == generation {
			return table
		}
	}
	table := &guestViewEvalTable{generation: generation, eligible: make([]uint8, len(generation.semanticRules))}
	evals.tables = append(evals.tables, table)
	return table
}

// unlock ends a lock.
func (evals *guestViewEvals) unlock() {
	if evals != nil {
		evals.mu.Unlock()
	}
}

// project is semantic.Project(view).
func (table *guestViewEvalTable) project(view actionfacts.Facts) (*semanticpb.Facts, semantic.ProjectionCode) {
	if table == nil {
		return semantic.Project(view)
	}
	if !table.projected {
		table.projection, table.projectionCode = semantic.Project(view)
		table.projected = true
	}
	return table.projection, table.projectionCode
}

// enforcement is view.EnforcementProjection() and its projection.
func (table *guestViewEvalTable) enforcement(view actionfacts.Facts) (actionfacts.Facts, *semanticpb.Facts, semantic.ProjectionCode) {
	if table == nil {
		facts := view.EnforcementProjection()
		projection, code := semantic.Project(facts)
		return facts, projection, code
	}
	if !table.enforcementProjected {
		table.enforcementFacts = view.EnforcementProjection()
		table.enforcementProjection, table.enforcementCode = semantic.Project(table.enforcementFacts)
		table.enforcementProjected = true
	}
	return table.enforcementFacts, table.enforcementProjection, table.enforcementCode
}

// eligibleFor is candidate.owner.eligible(view), candidate being rule rule
// of the table's generation.
func (table *guestViewEvalTable) eligibleFor(rule int, candidate compiledSemanticRule, view actionfacts.Facts) bool {
	if table == nil {
		return candidate.owner.eligible(view)
	}
	if table.eligible[rule] == 0 {
		table.eligible[rule] = 2
		if candidate.owner.eligible(view) {
			table.eligible[rule] = 1
		}
	}
	return table.eligible[rule] == 1
}

// kept is the slot of rule rule's result on the reading's projection, or
// on its enforcement projection; nil for a nil table.
func (table *guestViewEvalTable) kept(rule int, enforcement bool) *guestKeptEval {
	if table == nil {
		return nil
	}
	for _, kept := range table.results {
		if kept.rule == rule && kept.enforcement == enforcement {
			return kept
		}
	}
	kept := &guestKeptEval{rule: rule, enforcement: enforcement}
	table.results = append(table.results, kept)
	return kept
}

// evalKept is eval with kept, the slot of the same rule's result on the
// same projection of a placed reading (guestViewEvals): a complete result
// already there stands for a new evaluation, and the budget is charged its
// cost as for a new one; a new complete result is put there. A done ctx
// is always evaluated afresh, as eval does.
func (b *trustedActionBudget) evalKept(ctx context.Context, candidate compiledSemanticRule, view int, projection *semanticpb.Facts, kept *guestKeptEval) (result semantic.Result, code semantic.EvalCode, ok bool) {
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
	if kept.ok && !contextDone(ctx.Done()) {
		result, code = kept.result, semantic.EvalOK
	} else {
		result, code = candidate.program.EvalBool(ctx, projection)
		if code == semantic.EvalOK {
			kept.ok, kept.result = true, result
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
