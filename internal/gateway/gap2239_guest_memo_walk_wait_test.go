// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// The rule dispatch reads a copy-mode call's guest plan with the hook's wait
// for walk slots on its input, and the sandbox hook-config guard reads the
// same call without one: they share one plan and one split, and the analysis
// cache still tells the two inputs apart (rel-1-0-10:GAP-2239).
func TestGAP2239GuestPlanAndSplitIgnoreTheWalkWait(t *testing.T) {
	sent := actionfacts.Input{
		Tool: "Bash", Command: "for i in 1; do $C; f0(){ :;}; f1(){ :;}; cd .cache; echo x > k; done",
		CWD: "/sandbox", ActiveHome: "/sandbox", DialectHint: actionfacts.DialectPOSIX,
	}
	waited := sent
	waited.CredentialWalkBudget = actionfacts.NewCredentialWalkBudget(context.Background())
	facts := actionfacts.Analyze(sent)
	if facts.Authoritative() {
		t.Fatal("the call must take the guest plan's split passes")
	}

	memo := &guestReadingMemo{}
	first := memo.plan(waited, facts)
	if again := memo.plan(sent, facts); again != first {
		t.Fatal("the plan without the walk wait was made again; want the dispatch's plan")
	}
	if len(memo.plans) != 1 {
		t.Fatalf("plans kept = %d, want 1", len(memo.plans))
	}
	for _, budget := range []bool{true, false} {
		got, gotCut := first.placements(budget)
		want, wantCut := newGuestPlacementPlan(sent, facts, nil, nil).placements(budget)
		if !reflect.DeepEqual(got, want) || gotCut != wantCut {
			t.Fatalf("placements(%t) = %v %t, want the plan made on its own: %v %t", budget, got, gotCut, want, wantCut)
		}
	}
	other := sent
	other.CWD = "/sandbox/src"
	if memo.plan(other, facts) == first {
		t.Fatal("a call in another folder shares the plan")
	}

	splits := &guestReadingMemo{}
	want := actionfacts.SimpleCommands(sent, facts)
	if got := splits.simpleCommands(waited, facts); !reflect.DeepEqual(got, want) {
		t.Fatalf("split = %v, want %v", got, want)
	}
	if got := splits.simpleCommands(sent, facts); !reflect.DeepEqual(got, want) || len(splits.splits) != 1 {
		t.Fatalf("split = %v (%d kept), want %v from the one kept", got, len(splits.splits), want)
	}

	readings := &guestReadingMemo{}
	readings.analyze(waited)
	readings.analyze(sent)
	if len(readings.readings) != 2 {
		t.Fatalf("readings kept = %d, want 2: the facts carry the wait to their credential walk", len(readings.readings))
	}
}
