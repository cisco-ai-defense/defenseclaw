// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingadmin

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// retireRuntime is a runtime with one batch budget, a key cap of 2 and a
// real counter file (the cluster leader stores spend the same way).
func retireRuntime(t *testing.T) (*Runtime, *LocalCounter) {
	t.Helper()
	c := NewLocalCounter(t.TempDir())
	t.Cleanup(func() { _ = c.Close() })
	rt := NewRuntime()
	rt.For(adapterConfig(nil, batchBudgets))
	rt.mu.Lock()
	rt.local = c
	rt.mu.Unlock()
	rt.Ledger().SetKeyCap(2)
	return rt, c
}

// counterSpend is key's spend today as another replica reads it.
func counterSpend(t *testing.T, c *LocalCounter, key string) float64 {
	t.Helper()
	rows, err := c.Totals(context.Background(), "epoch-other-replica", time.Now().AddDate(0, 0, -1), nil)
	if err != nil {
		t.Fatal(err)
	}
	var v float64
	for _, r := range rows {
		if r.Key == key {
			v += r.USD
		}
	}
	return v
}

// TestEvictedKeySpendStaysCounted (GAP-0811): a key the cap evicts keeps
// its spend on the leader and on this replica, whether it is charged again,
// was never pushed, or just sits evicted (then it never counts twice).
func TestEvictedKeySpendStaysCounted(t *testing.T) {
	ctx := context.Background()
	k := func(b string) string { return batchKey("nightly", "eng-web", testPersonKey, b) }
	near := func(a, b float64) bool { return a-b < 1e-9 && b-a < 1e-9 }
	t.Run("charged again", func(t *testing.T) {
		rt, c := retireRuntime(t)
		rt.Charge([]string{k("run-A")}, 9, time.Now())
		rt.SyncOnce(ctx)
		rt.Charge([]string{k("run-B")}, 0.01, time.Now())
		rt.Charge([]string{k("run-C")}, 0.01, time.Now()) // evicts run-A
		rt.Charge([]string{k("run-A")}, 1, time.Now())
		rt.SyncOnce(ctx)
		own, _ := rt.Ledger().Spend(k("run-A"), "day", time.Now())
		if other := counterSpend(t, c, k("run-A")); !near(other, 10) || !near(own, 10) {
			t.Fatalf("run-A spent 10: another replica reads %.2f, this one %.2f", other, own)
		}
	})
	t.Run("never pushed", func(t *testing.T) {
		rt, c := retireRuntime(t)
		rt.SyncOnce(ctx) // seeded, nothing pushed yet
		rt.Charge([]string{k("run-A")}, 9, time.Now())
		rt.Charge([]string{k("run-B")}, 0.01, time.Now())
		rt.Charge([]string{k("run-C")}, 0.01, time.Now()) // evicts run-A before any push
		if own, _ := rt.Ledger().Spend(k("run-A"), "day", time.Now()); !near(own, 9) {
			t.Fatalf("evicted unpushed spend left this replica: %.2f", own)
		}
		rt.SyncOnce(ctx)
		if other := counterSpend(t, c, k("run-A")); !near(other, 9) {
			t.Fatalf("evicted unpushed spend never reached the counter: %.2f", other)
		}
	})
	t.Run("not counted twice", func(t *testing.T) {
		rt, c := retireRuntime(t)
		rt.Charge([]string{k("run-A")}, 9, time.Now())
		rt.SyncOnce(ctx)
		rt.Charge([]string{k("run-B")}, 0.01, time.Now())
		rt.Charge([]string{k("run-C")}, 0.01, time.Now())
		rt.SyncOnce(ctx)
		rt.SyncOnce(ctx)
		own, _ := rt.Ledger().Spend(k("run-A"), "day", time.Now())
		if other := counterSpend(t, c, k("run-A")); !near(other, 9) || !near(own, 9) {
			t.Fatalf("run-A spent 9: another replica reads %.2f, this one %.2f", other, own)
		}
	})
}

// TestUnknownCostBoundsActorAndBatch (GAP-0812): a call of unknown cost
// (a cut stream, an unpriced model) makes the actor and batch budgets of
// that caller unknown, like the person's own: a managed cluster denies, so
// an agent with no person is still bounded.
func TestUnknownCostBoundsActorAndBatch(t *testing.T) {
	for _, scope := range []string{"user", "actor", "batch"} {
		p := Compile(nil, []config.RoutingBudget{{ID: "b", Scope: scope, Subject: "*", Period: "day", LimitUSD: 10, OnExceed: "deny"}}, true)
		l := seededLedger(p.BudgetIDs()...)
		r := batchCall("eng-web", "a1", "run-7", testPersonKey)
		v := p.Evaluate(r, l, now)
		l.MarkUnknown(v.ChargeKeys, now)
		if code := denyCode(p.Evaluate(r, l, now)); code == "" {
			t.Errorf("scope %s: an unpriced call left the budget open on a managed cluster (keys %v)", scope, v.ChargeKeys)
		}
	}
	// A group budget others share stays open.
	p := Compile(nil, []config.RoutingBudget{{ID: "g", Scope: "group", Subject: "*", Period: "day", LimitUSD: 10, OnExceed: "deny"}}, true)
	l := seededLedger(p.BudgetIDs()...)
	r := batchCall("eng-web", "a1", "run-7", testPersonKey)
	l.MarkUnknown(p.Evaluate(r, l, now).ChargeKeys, now)
	if code := denyCode(p.Evaluate(r, l, now)); code == "budget_cost_unknown:g" {
		t.Errorf("one caller's unpriced call blocked a shared group budget")
	}
}

// TestLedgerKeepsOnlyBudgetWindows (GAP-0814): the ledger keeps the days a
// budget window reads (a week that starts in the previous month included)
// and drops older ones, so a long-lived replica's push stays small.
func TestLedgerKeepsOnlyBudgetWindows(t *testing.T) {
	day := func(m time.Month, d int) time.Time { return time.Date(2026, m, d, 12, 0, 0, 0, time.UTC) }
	clock := day(time.December, 1)
	l := NewLedgerClock(func() time.Time { return clock })
	for _, at := range []time.Time{day(time.October, 20), day(time.November, 29), day(time.November, 30), clock} {
		l.Charge([]string{"user:d:p:1"}, 1, at)
	}
	clock = day(time.December, 2) // a Wednesday: the week started Mon 11-30
	l.Charge([]string{"user:d:p:1"}, 1, clock)
	got := map[string]bool{}
	for _, r := range l.LocalRows() {
		got[r.Day] = true
	}
	if got["2026-10-20"] || got["2026-11-29"] || !got["2026-11-30"] || !got["2026-12-01"] || !got["2026-12-02"] {
		t.Fatalf("kept days %v, want 2026-11-30 .. 2026-12-02", got)
	}
}

// BenchmarkBatchBudgetCharge is the batch budget work of one model call:
// the check before the upstream call and the charge after it, in memory.
func BenchmarkBatchBudgetCharge(b *testing.B) {
	p := Compile(nil, batchBudgets, true)
	l := seededLedger(p.BudgetIDs()...)
	r := batchCall("eng-web", "a1", "run-7", testPersonKey)
	b.ReportAllocs()
	for b.Loop() {
		v := p.Evaluate(r, l, now)
		l.Charge(v.ChargeKeys, 0.0001, now)
	}
}
