// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
	"time"
)

// TestDecisionBudgetWithoutAWindow (review round 4, P4-1): a call with no
// answer window and no deadline is capped as if the default hook window had
// just started (a quarter of it in cascade 3), the shared hook judge budget
// caps it too, and a spent budget skips the model.
func TestDecisionBudgetWithoutAWindow(t *testing.T) {
	srv := fakeDecisionModel(t, "allow", 0.99, nil)
	defer srv.Close()
	dm := testDecisionModel(t, srv.URL, "")
	dm.timeout = 30 * time.Second
	if got, want := dm.budget(context.Background()), hookJudgeAnswerWindow/decisionBudgetShare; got != want {
		t.Fatalf("unbounded cascade-3 budget = %s, want %s (a quarter of the default window)", got, want)
	}
	dm.alone = true
	if got := dm.budget(context.Background()); got != hookJudgeAnswerWindow {
		t.Fatalf("unbounded cascade-2 budget = %s, want %s", got, hookJudgeAnswerWindow)
	}
	dm.alone = false
	shared := withHookJudgeBudget(context.Background(), time.Now().Add(2*time.Second))
	if got := dm.budget(shared); got > 501*time.Millisecond || got < 400*time.Millisecond {
		t.Fatalf("budget with 2 s of shared hook judge time = %s, want about 500 ms", got)
	}
	spent := withHookJudgeBudget(context.Background(), time.Now())
	if got := dm.decide(spent, decisionModelState{}); !got.skipped {
		t.Fatalf("spent hook judge budget: %+v, want the model skipped", got)
	}
}

// TestDecisionModelInflightLimit (review round 4, P4-2): with every request
// slot taken the call skips the model (no request, the judge or the rule
// verdict decides) and the breaker is not touched.
func TestDecisionModelInflightLimit(t *testing.T) {
	srv, hits := countingDecisionServer(t, "block", 0.02)
	dm := testDecisionModel(t, srv.URL, "")
	if cap(dm.inflight) != decisionMaxInflight {
		t.Fatalf("inflight cap = %d, want %d", cap(dm.inflight), decisionMaxInflight)
	}
	for range decisionMaxInflight {
		dm.inflight <- struct{}{}
	}
	got := dm.decide(context.Background(), decisionModelState{})
	if !got.skipped || got.route != decisionEscalate || hits.Load() != 0 {
		t.Fatalf("full semaphore: %+v (requests %d), want a skip with no request", got, hits.Load())
	}
	for range decisionMaxInflight {
		<-dm.inflight
	}
	if got := dm.decide(context.Background(), decisionModelState{}); got.skipped || got.route != decisionBlock {
		t.Fatalf("after the slots free: %+v, want the model answer", got)
	}
	if dm.failures != 0 {
		t.Fatalf("a capacity skip counted as a breaker failure: %d", dm.failures)
	}

	// On the hook lane a full semaphore leaves no floor: the call is
	// decided as when the judge cannot run (here: no judge slot either).
	a, ahits := prepassServer(t, 0, "block", 0.02)
	j := a.hookJudge.Load()
	for range decisionMaxInflight {
		j.decision.inflight <- struct{}{}
	}
	a.hookJudgeSemOnce.Do(func() { a.hookJudgeSem = make(chan struct{}) })
	if v := a.runHookJudge(context.Background(), "tool_call", "tool_call", "codex", prepassArgs, "Bash", nil); v != nil {
		t.Fatalf("decision model and judge both at capacity: %+v, want the rule verdict (nil)", v)
	}
	if ahits.Load() != 0 {
		t.Fatalf("decision model asked %d times at capacity", ahits.Load())
	}
}
