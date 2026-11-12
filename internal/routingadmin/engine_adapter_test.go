// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingadmin

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
)

func adapterConfig(rules []config.RoutingAdminRule, budgets []config.RoutingBudget) *config.Config {
	cfg := &config.Config{}
	cfg.Routing.Models = []config.RoutingModelBackend{
		{Name: "fast", Provider: "openai", Model: "gpt-mini"},
		{Name: "local", Provider: "vllm", Model: "qwen"},
	}
	cfg.Routing.Admin = &config.RoutingAdminConfig{Rules: rules, Budgets: budgets}
	return cfg
}

func TestRuntimeForCompilesPerGeneration(t *testing.T) {
	rt := NewRuntime()
	if rt.For(nil) != nil || rt.For(&config.Config{}) != nil || rt.For(adapterConfig(nil, nil)) != nil {
		t.Fatal("no rules or budgets: no evaluator")
	}
	if rt.Ledger() != nil {
		t.Fatal("no ledger without budgets")
	}
	cfg := adapterConfig([]config.RoutingAdminRule{{ID: "c", Match: config.RoutingAdminMatch{Categories: []string{"code"}}, Allow: []string{"local"}}}, nil)
	ev := rt.For(cfg)
	if ev == nil || !ev.Active() || !ev.NeedsCategory() || rt.For(cfg) != ev {
		t.Fatalf("evaluator %v", ev)
	}
	withBudget := adapterConfig(nil, []config.RoutingBudget{{ID: "d", Scope: "user", Subject: "*", Period: "day", LimitUSD: 1, OnExceed: "warn"}})
	if ev2 := rt.For(withBudget); ev2 == nil || ev2.NeedsCategory() || rt.Ledger() == nil {
		t.Fatal("budget generation makes the ledger")
	}
}

func TestRuntimeSeedsNewBudgets(t *testing.T) {
	rt := NewRuntime()
	done := make(chan []string, 1)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt.SetSeeder(ctx, func(context.Context, time.Time) ([]SeedRow, error) {
		done <- nil
		return nil, nil
	})
	rt.For(adapterConfig(nil, []config.RoutingBudget{{ID: "d", Scope: "user", Subject: "*", Period: "day", LimitUSD: 1, OnExceed: "warn"}}))
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("seed not started")
	}
	deadline := time.Now().Add(5 * time.Second)
	for !rt.Ledger().Seeded("d") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !rt.Ledger().Seeded("d") {
		t.Fatal("budget d not seeded")
	}
}

func TestAdapterEvaluateAndGate(t *testing.T) {
	rules := []config.RoutingAdminRule{{ID: "local-high", Match: config.RoutingAdminMatch{SeverityAtLeast: "HIGH"}, Allow: []string{"local"}, Default: "local"}}
	budgets := []config.RoutingBudget{{ID: "d", Scope: "user", Subject: "*", Period: "day", LimitUSD: 1, OnExceed: "downgrade:fast"}}
	rt := NewRuntime()
	ev := rt.For(adapterConfig(rules, budgets))
	rt.Ledger().ApplySeed([]string{"d"}, nil)
	floor := engine.Policy{AllowedAliases: []string{"fast", "local"}, DefaultAlias: "fast"}

	v := ev.Evaluate(context.Background(), floor, engine.Request{Connector: "claude-code", Severity: "HIGH"}, "", false)
	if !slices.Equal(v.Policy.AllowedAliases, []string{"local"}) || v.Policy.DefaultAlias != "local" || !v.Bind {
		t.Fatalf("narrowed %+v", v)
	}
	if !slices.Equal(v.ChargeKeys, []string{"user:d:*:" + OwnerKey}) {
		t.Fatalf("an OSS request without identity is the owner: %v", v.ChargeKeys)
	}
	if !slices.Equal(floor.AllowedAliases, []string{"fast", "local"}) {
		t.Fatal("the input policy must not change")
	}
	if d := ev.Gate(v, engine.GateTarget{Provider: "anthropic", Model: "opus"}, false); d != nil {
		t.Fatalf("OSS gate never denies: %v", d)
	}
	rt.Charge(v.ChargeKeys, 2, time.Now())
	v = ev.Evaluate(context.Background(), engine.Policy{}, engine.Request{Connector: "codex"}, "", false)
	if !slices.Equal(v.Force, []string{"fast"}) {
		t.Fatalf("downgrade: %+v", v)
	}

	managed := &evaluator{policy: Compile(rules, budgets, true), ledger: rt.Ledger(), catalog: map[string]Target{"fast": {"openai", "gpt-mini"}, "local": {"vllm", "qwen"}}}
	mv := managed.Evaluate(context.Background(), engine.Policy{}, engine.Request{Caller: engine.Caller{Verified: true, Key: "1001"}, Connector: "codex"}, "", false)
	if !slices.Equal(mv.ChargeKeys, []string{"user:d:*:1001"}) {
		t.Fatalf("managed verified key: %v", mv.ChargeKeys)
	}
	rt.Charge(mv.ChargeKeys, 2, time.Now())
	mv = managed.Evaluate(context.Background(), engine.Policy{}, engine.Request{Caller: engine.Caller{Verified: true, Key: "1001"}, Connector: "codex"}, "", false)
	if d := managed.Gate(mv, engine.GateTarget{Provider: "anthropic", Model: "opus"}, true); d == nil || d.Code != "budget_downgrade_unavailable:d" {
		t.Fatalf("managed exit on the original upstream is held to the downgrade: %v", d)
	}
	if d := managed.Gate(mv, engine.GateTarget{Alias: "fast"}, true); d != nil {
		t.Fatalf("the downgrade alias passes: %v", d)
	}
	unverified := managed.Evaluate(context.Background(), engine.Policy{}, engine.Request{Caller: engine.Caller{Key: "1002"}, Connector: "codex"}, "", false)
	if len(unverified.ChargeKeys) != 0 {
		t.Fatalf("a managed unverified caller is never charged: %v", unverified.ChargeKeys)
	}
}

func TestToEngineVerdictKeepsNothingAllowed(t *testing.T) {
	for _, tc := range []struct {
		name    string
		floor   []string
		allowed []string
		want    []string
	}{
		{"contradicting profiles, no rule limit", []string{}, nil, []string{}},
		{"contradicting profiles, rule limit", []string{}, []string{"fast"}, []string{}},
		{"no floor, rule allows nothing", nil, []string{}, []string{}},
		{"no floor, no rule limit", nil, nil, nil},
		{"floor and rule", []string{"fast", "local"}, []string{"local"}, []string{"local"}},
	} {
		got := ToEngineVerdict(engine.Policy{AllowedAliases: tc.floor}, Verdict{Allowed: tc.allowed}).Policy.AllowedAliases
		if (got == nil) != (tc.want == nil) || !slices.Equal(got, tc.want) {
			t.Fatalf("%s: got %#v, want %#v", tc.name, got, tc.want)
		}
	}
}

func TestCallerFromEngine(t *testing.T) {
	c := CallerFromEngine(engine.Caller{Verified: true, Key: "S-1-5-21-1", GroupsUnknown: true,
		Matches: func(config.ProfileMatch) engine.Tri { return engine.Maybe }}, true)
	if c.Key != "S-1-5-21-1" || c.Unconfirmed != "groups" || c.Match(config.ProfileMatch{}) != Maybe {
		t.Fatalf("%+v", c)
	}
	if c := CallerFromEngine(engine.Caller{Key: "spoofed"}, true); c.Verified || c.Key != "" {
		t.Fatalf("unverified managed caller keeps no key: %+v", c)
	}
	if c := CallerFromEngine(engine.Caller{Verified: true, Key: "1001"}, false); c.Key != OwnerKey {
		t.Fatalf("every OSS caller is the owner: %+v", c)
	}
}
