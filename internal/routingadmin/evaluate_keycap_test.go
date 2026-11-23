// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingadmin

import (
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"
)

func localKeyCount(l *Ledger, prefix string) int {
	seen := map[string]bool{}
	for _, r := range l.LocalRows() {
		if strings.HasPrefix(r.Key, prefix) {
			seen[r.Key] = true
		}
	}
	return len(seen)
}

// TestBatchBudgetKeyFloodBounded: a launcher that mints a new batch id for
// every call cannot grow one budget past DefaultKeyCap keys in memory.
func TestBatchBudgetKeyFloodBounded(t *testing.T) {
	l := NewLedgerClock(func() time.Time { return now })
	for i := 0; i < DefaultKeyCap+1500; i++ {
		l.Charge([]string{batchKey("nightly", "eng-web", testPersonKey, fmt.Sprintf("run-%d", i))}, 0.01, now)
	}
	if n := localKeyCount(l, "batch:nightly:"); n > DefaultKeyCap {
		t.Fatalf("batch keys held for one budget: %d (cap %d)", n, DefaultKeyCap)
	}
	// An actor flood is bounded the same way, and another budget is untouched.
	for i := 0; i < DefaultKeyCap+10; i++ {
		l.Charge([]string{fmt.Sprintf("actor:act:%d", i)}, 0.01, now)
	}
	l.Charge([]string{"connector:c:openai"}, 1, now)
	if n := localKeyCount(l, "actor:act:"); n > DefaultKeyCap {
		t.Fatalf("actor keys held: %d", n)
	}
	if n := localKeyCount(l, "connector:c:"); n != 1 {
		t.Fatalf("connector key count %d, want 1", n)
	}
}

// TestBatchBudgetKeyCapKeepsRecent: the least recently charged key goes; a
// key charged again stays; the evicted budget reports it once.
func TestBatchBudgetKeyCapKeepsRecent(t *testing.T) {
	l := seededLedger("nightly")
	l.SetKeyCap(3)
	k := func(i int) string { return batchKey("nightly", "eng-web", testPersonKey, fmt.Sprintf("run-%d", i)) }
	for i := 0; i < 3; i++ {
		l.Charge([]string{k(i)}, 1, now)
	}
	l.Charge([]string{k(0)}, 1, now) // run-0 is now the most recent
	l.Charge([]string{k(3)}, 1, now) // evicts run-1, the least recent
	// run-1 left the keys; its spend still counts (GAP-0811).
	if l.LocalKeys("nightly") != 3 || spendOf(l, k(1)) != 1 {
		t.Fatalf("run-1 should be evicted with its spend kept: keys %d spend %v", l.LocalKeys("nightly"), spendOf(l, k(1)))
	}
	if spendOf(l, k(0)) != 2 || spendOf(l, k(3)) != 1 {
		t.Fatalf("recent keys lost: %v %v", spendOf(l, k(0)), spendOf(l, k(3)))
	}
	if !takeEvicted(l, "nightly") || takeEvicted(l, "nightly") {
		t.Fatalf("CapState must report the eviction once")
	}
	if takeEvicted(l, "other") {
		t.Fatalf("another budget reported an eviction")
	}
}

// takeEvicted is the eviction half of CapState for budget id.
func takeEvicted(l *Ledger, id string) bool {
	evicted, _ := l.CapState("batch:" + id + ":x")
	return evicted
}

func spendOf(l *Ledger, key string) float64 {
	v, _ := l.Spend(key, "day", now)
	return v
}

// TestBatchBudgetEvictionWarns: the verdict of a budget that lost keys
// carries one budget_keys_evicted warning, then none.
func TestBatchBudgetEvictionWarns(t *testing.T) {
	p := Compile(nil, batchBudgets, false)
	l := seededLedger(p.BudgetIDs()...)
	l.SetKeyCap(2)
	for i := 0; i < 4; i++ {
		l.Charge([]string{batchKey("nightly", "eng-web", testPersonKey, fmt.Sprintf("run-%d", i))}, 0.01, now)
	}
	r := batchCall("eng-web", "a1", "run-9", testPersonKey)
	if v := p.Evaluate(r, l, now); !slices.Contains(v.Warnings, "budget_keys_evicted:nightly") {
		t.Fatalf("first verdict: %+v", v.Warnings)
	}
	if v := p.Evaluate(r, l, now); slices.Contains(v.Warnings, "budget_keys_evicted:nightly") {
		t.Fatalf("second verdict repeats the warning: %+v", v.Warnings)
	}
}
