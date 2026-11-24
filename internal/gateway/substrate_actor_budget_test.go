// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

func actorBudgetConfig() *config.Config {
	cfg := &config.Config{}
	cfg.Routing.Admin = &config.RoutingAdminConfig{Budgets: []config.RoutingBudget{
		{ID: "agent", Scope: "actor", Subject: "*", Period: "day", LimitUSD: 10, OnExceed: "deny"},
		{ID: "nightly", Scope: "batch", Subject: "*", Period: "day", LimitUSD: 20, OnExceed: "deny"},
		{ID: "daily", Scope: "user", Subject: "*", Period: "day", LimitUSD: 50, OnExceed: "warn"},
	}}
	return cfg
}

// TestSubstrateActorBudgetCell: the BUDGET cell of one agent is the highest
// used share of the actor, batch and per-person budgets that count its calls,
// "over" once one is used up, and "" when nothing is known.
func TestSubstrateActorBudgetCell(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	isolatedRoutingAdminRuntimeAt(t, now)
	cfg := actorBudgetConfig()
	if routingAdminRuntime.For(cfg) == nil {
		t.Fatal("evaluator")
	}
	routingAdminRuntime.Ledger().ApplyRemote([]string{"agent", "nightly", "daily"}, nil, now)
	person := registry.Person{Kind: "user", Issuer: "https://idp.example", Subject: "alice"}
	reg := registry.Registration{Key: "reg-1", Atespace: "eng-web", BatchID: "run-7", Person: person}
	if got := substrateActorBudget(cfg, reg, now); got != "0 %" {
		t.Fatalf("no spend yet: cell %q, want 0 %%", got)
	}
	actor := &engine.Actor{Key: reg.Key, Atespace: reg.Atespace, BatchID: reg.BatchID, Person: true}
	routingAdminRuntime.Charge([]string{routingadmin.ActorBudgetKey("actor", "agent", actor, person.Key())}, 8, now)
	if got := substrateActorBudget(cfg, reg, now); got != "80 %" {
		t.Fatalf("actor at 8 of 10: cell %q, want 80 %%", got)
	}
	other := reg
	other.Key = "reg-2"
	if got := substrateActorBudget(cfg, other, now); got == "80 %" {
		t.Fatalf("another agent shares the first agent's actor budget: %q", got)
	}
	routingAdminRuntime.Charge([]string{routingadmin.ActorBudgetKey("batch", "nightly", actor, person.Key())}, 21, now)
	if got := substrateActorBudget(cfg, reg, now); got != "over" {
		t.Fatalf("batch used up: cell %q, want over", got)
	}
	if got := substrateActorBudget(&config.Config{}, reg, now); got != "" {
		t.Fatalf("no budgets: cell %q, want empty", got)
	}
	if got := substrateActorBudget(cfg, registry.Registration{}, now); got != "" {
		t.Fatalf("no key: cell %q, want empty", got)
	}
}
