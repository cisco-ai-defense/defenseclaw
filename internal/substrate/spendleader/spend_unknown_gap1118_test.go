// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package spendleader

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
	"github.com/defenseclaw/defenseclaw/internal/substrate/leader"
)

// substrate-1:GAP-1118: the unknown-cost mark of an actor or batch key was
// replica-local. Each gateway replica learned it only from a call of unknown
// cost it served itself, so every other replica served one more such call of
// the key before it refused budget_cost_unknown. The marks now go through the
// leader on each sync, as known spend does.
func TestUnknownCostMarkReachesEveryReplica(t *testing.T) {
	c, stop := startLeader(t, t.TempDir())
	defer stop()
	ctx := context.Background()
	a, b := overReplica(t, c), overReplica(t, c)
	p := routingadmin.Compile(nil, overBudgets, true)
	call := overCall("run-U")
	now := time.Now()
	first := p.Evaluate(call, a.Ledger(), now)
	if first.Deny != nil || len(first.ChargeKeys) == 0 {
		t.Fatalf("first call: %+v", first)
	}
	// Replica a served a call of the batch whose cost is unknown (a stream
	// cut after the provider began answering).
	a.Add("call-1", first.ChargeKeys, 0, false, now)
	if got := overDeny(p.Evaluate(call, a.Ledger(), time.Now())); got != "budget_cost_unknown:nightly" {
		t.Fatalf("replica a after its own unknown-cost call: %q", got)
	}
	a.SyncOnce(ctx)
	b.SyncOnce(ctx)
	if got := overDeny(p.Evaluate(call, b.Ledger(), time.Now())); got != "budget_cost_unknown:nightly" {
		t.Fatalf("replica b one sync after replica a's unknown-cost call: %q, want budget_cost_unknown:nightly", got)
	}
	// Another batch of the same person is not marked.
	if got := overDeny(p.Evaluate(overCall("run-V"), b.Ledger(), time.Now())); got != "" {
		t.Fatalf("an unmarked batch: %q", got)
	}
}

// A leader of a release without SpendUnknown (an upgrade under way) answers
// unknown_method: the replicas keep their own marks and known spend still
// adds up across them.
func TestUnknownCostMarkOldLeaderKeepsSync(t *testing.T) {
	svc := &Service{Counter: routingadmin.NewLocalCounter(t.TempDir())}
	defer func() { _ = svc.Counter.Close() }()
	srv := &leader.Server{IsLeader: func() bool { return true }}
	srv.HandleRead(MethodSpendPush, leader.Typed(svc.spendPush))
	srv.HandleRead(MethodSpendTotals, leader.Typed(svc.spendTotals))
	srv.HandleRead(MethodSpendSums, leader.Typed(svc.spendSums))
	hs := httptest.NewServer(srv)
	defer hs.Close()
	c := &Client{Leader: &leader.Client{BaseURL: hs.URL, HTTP: hs.Client(), Retry: 300 * time.Millisecond}}
	if _, err := c.SpendUnknown(context.Background(), "epoch-aaaa", nil); err == nil {
		t.Fatal("an old leader must refuse the method")
	}
	ctx := context.Background()
	a, b := overReplica(t, c), overReplica(t, c)
	p := routingadmin.Compile(nil, overBudgets, true)
	now := time.Now()
	first := p.Evaluate(overCall("run-U"), a.Ledger(), now)
	a.Add("call-1", first.ChargeKeys, 0, false, now)
	a.Charge(p.Evaluate(overCall("run-K"), a.Ledger(), now).ChargeKeys, 12, now)
	a.SyncOnce(ctx)
	b.SyncOnce(ctx)
	if got := overDeny(p.Evaluate(overCall("run-U"), a.Ledger(), time.Now())); got != "budget_cost_unknown:nightly" {
		t.Fatalf("replica a keeps its own mark: %q", got)
	}
	if got := overDeny(p.Evaluate(overCall("run-K"), b.Ledger(), time.Now())); got != "budget_exceeded:nightly" {
		t.Fatalf("known spend still crosses replicas: %q", got)
	}
}

// The leader keeps a key's latest mark, counts a mark dated after its clock
// from now, drops marks past UnknownTTL and refuses keys that are not a
// user, actor or batch key.
func TestSpendUnknownLeaderRules(t *testing.T) {
	now := time.Date(2026, 11, 27, 12, 0, 0, 0, time.UTC)
	s := &Service{Now: func() time.Time { return now }}
	ctx := context.Background()
	if _, err := s.spendUnknown(ctx, SpendUnknownRequest{Epoch: "epoch-aaaa", Marks: []SpendMark{{Key: "group:g:x", At: now.Unix()}}}); err == nil {
		t.Fatal("a group key is never marked")
	}
	out, err := s.spendUnknown(ctx, SpendUnknownRequest{Epoch: "epoch-aaaa", Marks: []SpendMark{
		{Key: "actor:agent:k1", At: now.Add(-time.Minute).Unix()},
		{Key: "batch:nightly:k2", At: now.Add(time.Hour).Unix()},
		{Key: "user:day:k3", At: now.Add(-routingadmin.UnknownTTL - time.Second).Unix()},
	}})
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int64{}
	for _, m := range out.Marks {
		got[m.Key] = m.At
	}
	if len(got) != 2 || got["actor:agent:k1"] != now.Add(-time.Minute).Unix() || got["batch:nightly:k2"] != now.Unix() {
		t.Fatalf("marks: %+v", out.Marks)
	}
	// An older mark of a key never replaces a newer one; another epoch reads them.
	out, _ = s.spendUnknown(ctx, SpendUnknownRequest{Epoch: "epoch-bbbb", Marks: []SpendMark{{Key: "actor:agent:k1", At: now.Add(-5 * time.Minute).Unix()}}})
	for _, m := range out.Marks {
		if m.Key == "actor:agent:k1" && m.At != now.Add(-time.Minute).Unix() {
			t.Fatalf("an older mark replaced a newer one: %+v", m)
		}
	}
	now = now.Add(routingadmin.UnknownTTL)
	if out, _ = s.spendUnknown(ctx, SpendUnknownRequest{Epoch: "epoch-bbbb"}); len(out.Marks) != 0 {
		t.Fatalf("marks past UnknownTTL: %+v", out.Marks)
	}
}
