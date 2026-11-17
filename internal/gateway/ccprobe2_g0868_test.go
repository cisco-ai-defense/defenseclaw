// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// s7-probe2 old-API probe for rel-1-0-10:GAP-0868: the rel hook-route tests of the fix,
// copied with only the rel test helpers the pre-fix sha 92aa1caeb8 lacks (renamed),
// so the file compiles on the pre-fix tree and on rel. Scratch, test-only branch.

package gateway

import (
	"context"
	"testing"
	"time"
)

// TestDecisionPrepassUnderJudgeLoad (review round 3, P3-1): System One
// answers before the judge's own gates, so with every judge slot busy or the
// hook judge budget spent a confident block still stands as System One's own
// CRITICAL block (GAP-0867), and the model is asked once.
func TestCCP2G0868_DecisionPrepassUnderJudgeLoad(t *testing.T) {
	for _, tc := range []struct {
		name  string
		setup func(a *APIServer) context.Context
	}{
		{"all judge slots busy", func(a *APIServer) context.Context {
			a.hookJudgeSemOnce.Do(func() { a.hookJudgeSem = make(chan struct{}) })
			return context.Background()
		}},
		{"hook judge budget under the judge minimum", func(*APIServer) context.Context {
			// 800 ms left: too little for the judge (1 s minimum), a quarter
			// of it (200 ms) for the decision model.
			return withHookJudgeBudget(context.Background(), time.Now().Add(800*time.Millisecond))
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			a, hits := prepassServer(t, 0, "block", 0.02)
			v := a.runHookJudge(tc.setup(a), "tool_call", "tool_call", "codex", prepassArgs, "Bash", nil)
			if v == nil || v.Severity != "CRITICAL" || v.Action != guardrailActionBlock || !hasFinding(v.Findings, decisionModelFindingID) {
				t.Fatalf("verdict = %+v, want the CRITICAL decision-model block", v)
			}
			if hits.Load() != 1 {
				t.Fatalf("decision model asked %d times, want 1", hits.Load())
			}
		})
	}
	// A fully spent hook judge budget leaves no time for either: the rule
	// verdict, and the decision model is not asked (review round 4, P4-1).
	spentSrv, spentHits := prepassServer(t, 0, "block", 0.02)
	if v := spentSrv.runHookJudge(withHookJudgeBudget(context.Background(), time.Now()), "tool_call", "tool_call", "codex", prepassArgs, "Bash", nil); v != nil || spentHits.Load() != 0 {
		t.Fatalf("spent budget: verdict %+v, %d requests; want the rule verdict and no request", v, spentHits.Load())
	}
	// An unsure answer keeps cascade 2's ask when the judge cannot run: a
	// judge that does not answer never lowers anything (GAP-0868).
	a, _ := prepassServer(t, 0, "allow", 0.55)
	a.hookJudgeSemOnce.Do(func() { a.hookJudgeSem = make(chan struct{}) })
	if v := a.runHookJudge(context.Background(), "tool_call", "tool_call", "codex", prepassArgs, "Bash", nil); v == nil || !v.decisionConfirm || v.Severity != "HIGH" {
		t.Fatalf("unsure call with no judge slot = %+v, want cascade 2's HIGH confirm", v)
	}
}
