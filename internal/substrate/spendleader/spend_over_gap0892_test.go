// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package spendleader

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
)

const overPerson = "p:0123456789abcdef"

var overBudgets = []config.RoutingBudget{{ID: "nightly", Scope: "batch", Subject: "*", Period: "day", LimitUSD: 10, OnExceed: "deny"}}

// overCall is a call of batch run from agent a1 of eng-web for overPerson.
func overCall(run string) routingadmin.Request {
	a := &engine.Actor{Key: "substrate:eng-web/a1", Person: true, Atespace: "eng-web", Template: "eng-web/claude", BatchID: run}
	c := routingadmin.Caller{Verified: true, Key: overPerson, Match: func(config.ProfileMatch) routingadmin.MatchState { return routingadmin.No }}
	return routingadmin.Request{Caller: c, Connector: "claudecode", Actor: a}
}

func overKey(run string) string {
	return routingadmin.ActorBudgetKey("batch", "nightly", overCall(run).Actor, overPerson)
}

func overDeny(v routingadmin.Verdict) string {
	if v.Deny == nil {
		return ""
	}
	return v.Deny.Code
}

// overReplica is a gateway replica on the leader c, with a key cap of 2.
func overReplica(t *testing.T, c *Client) *routingadmin.Runtime {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	rt := routingadmin.NewRuntime()
	cfg := &config.Config{}
	cfg.Routing.Admin = &config.RoutingAdminConfig{Budgets: overBudgets}
	rt.For(cfg)
	rt.Ledger().SetKeyCap(2)
	rt.SetCounters(ctx, routingadmin.NewLeaderCounter(c), nil, time.Hour)
	for deadline := time.Now().Add(10 * time.Second); !rt.Ledger().Seeded("nightly"); {
		if time.Now().After(deadline) {
			t.Fatal("the first sync never read the leader")
		}
		time.Sleep(10 * time.Millisecond)
	}
	return rt
}

// TestBlockedBatchStaysBlockedAfterEviction (GAP-0892, RV5 PROBE-E): in a
// cluster the by-key read named only the keys this replica held, so a
// blocked batch whose key the cap evicted and stored read as 0 spend and was
// allowed again after each eviction. The leader now also names the keys at
// or over the limit, and the replica keeps them blocked.
func TestBlockedBatchStaysBlockedAfterEviction(t *testing.T) {
	c, stop := startLeader(t, t.TempDir())
	defer stop()
	ctx := context.Background()
	day := time.Now().UTC().Format(time.DateOnly)
	if err := c.SpendPush(ctx, "epoch-other-replica", []routingadmin.SeedRow{{Day: day, Key: overKey("run-A"), USD: 12}}); err != nil {
		t.Fatal(err)
	}
	rt := overReplica(t, c)
	l := rt.Ledger()
	p := routingadmin.Compile(nil, overBudgets, true)
	rt.Charge([]string{overKey("run-A")}, 0.5, time.Now())
	rt.SyncOnce(ctx)
	if got := overDeny(p.Evaluate(overCall("run-A"), l, time.Now())); got != "budget_exceeded:nightly" {
		t.Fatalf("held key (12.5 of 10): %q", got)
	}
	for cycle := 0; cycle < 3; cycle++ {
		// Two other batches evict run-A; its spend is stored and let go.
		rt.Charge([]string{overKey(fmt.Sprintf("run-B%d", cycle))}, 0.01, time.Now())
		rt.Charge([]string{overKey(fmt.Sprintf("run-C%d", cycle))}, 0.01, time.Now())
		rt.SyncOnce(ctx)
		rt.SyncOnce(ctx)
		own, _ := l.Spend(overKey("run-A"), "day", time.Now())
		if got := overDeny(p.Evaluate(overCall("run-A"), l, time.Now())); got != "budget_exceeded:nightly" {
			t.Fatalf("cycle %d: a blocked batch (12.5 of 10) is allowed after its key was evicted and stored: own %.2f, verdict %q", cycle, own, got)
		}
	}
	// A batch under the limit is not named and still runs.
	if got := overDeny(p.Evaluate(overCall("run-B0"), l, time.Now())); got != "" {
		t.Fatalf("a batch under its limit: %q", got)
	}
}

// TestOverLimitKeysPastTheCap (GAP-0892): past the key cap of keys at or
// over the limit, a managed deny budget refuses a key it does not hold
// (budget_unavailable); OSS deny is never refused for it; at the cap every
// over-limit key is named and blocked.
func TestOverLimitKeysPastTheCap(t *testing.T) {
	day := time.Now().UTC().Format(time.DateOnly)
	for _, tc := range []struct {
		name string
		over int
	}{
		{name: "at-cap", over: 2},
		{name: "past-cap", over: 3},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c, stop := startLeader(t, t.TempDir())
			defer stop()
			ctx := context.Background()
			var rows []routingadmin.SeedRow
			for i := 0; i < tc.over; i++ {
				rows = append(rows, routingadmin.SeedRow{Day: day, Key: overKey(fmt.Sprintf("run-%d", i)), USD: 11})
			}
			if err := c.SpendPush(ctx, "epoch-other-replica", rows); err != nil {
				t.Fatal(err)
			}
			rt := overReplica(t, c)
			rt.SyncOnce(ctx)
			l := rt.Ledger()
			managed := routingadmin.Compile(nil, overBudgets, true)
			oss := routingadmin.Compile(nil, overBudgets, false)
			for i := 0; i < tc.over; i++ {
				run := fmt.Sprintf("run-%d", i)
				m, o := overDeny(managed.Evaluate(overCall(run), l, time.Now())), overDeny(oss.Evaluate(overCall(run), l, time.Now()))
				if tc.over <= 2 && (m != "budget_exceeded:nightly" || o != "budget_exceeded:nightly") {
					t.Errorf("%s at the cap: managed %q, OSS %q, want budget_exceeded", run, m, o)
				}
				if tc.over > 2 && m != "budget_exceeded:nightly" && m != "budget_unavailable:nightly" {
					t.Errorf("%s past the cap: managed %q, want blocked", run, m)
				}
				if o == "budget_unavailable:nightly" {
					t.Errorf("%s: OSS deny refused as unavailable", run)
				}
			}
			// A new batch: refused by a managed deny budget only past the cap.
			m, o := overDeny(managed.Evaluate(overCall("run-new"), l, time.Now())), overDeny(oss.Evaluate(overCall("run-new"), l, time.Now()))
			want := ""
			if tc.over > 2 {
				want = "budget_unavailable:nightly"
			}
			if m != want || o != "" {
				t.Errorf("new batch: managed %q (want %q), OSS %q (want none)", m, want, o)
			}
		})
	}
}

// TestSpendTotalsOverValidated (GAP-0892): an over query names an actor or
// batch budget prefix, a date, a positive limit and a max within maxKeys.
func TestSpendTotalsOverValidated(t *testing.T) {
	c, stop := startLeader(t, t.TempDir())
	defer stop()
	ctx := context.Background()
	day := time.Now().UTC().Format(time.DateOnly)
	for _, o := range []SpendOver{
		{Prefix: "user:nightly:", Since: day, Limit: 1, Max: 1},
		{Prefix: "batch:nightly", Since: day, Limit: 1, Max: 1},
		{Prefix: "batch:nightly:", Since: "today", Limit: 1, Max: 1},
		{Prefix: "batch:nightly:", Since: day, Limit: 0, Max: 1},
		{Prefix: "batch:nightly:", Since: day, Limit: 1, Max: 0},
		{Prefix: "batch:nightly:", Since: day, Limit: 1, Max: maxKeys + 1},
	} {
		in := SpendTotalsRequest{Epoch: "epoch-bbbb", Since: day, ByKey: true, Over: []SpendOver{o}}
		var out SpendTotalsAnswer
		if err := c.call(ctx, MethodSpendTotals, in, &out); err == nil {
			t.Errorf("over %+v: accepted", o)
		}
	}
}
