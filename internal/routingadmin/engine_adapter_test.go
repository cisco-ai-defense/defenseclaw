// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingadmin

import (
	"context"
	"errors"
	"slices"
	"strings"
	"sync"
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

type fakeCounter struct {
	mu     sync.Mutex
	pushed map[string][]SeedRow
	totals []SeedRow
	err    error
}

func (f *fakeCounter) Push(_ context.Context, epoch string, rows []SeedRow) error {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.pushed == nil {
		f.pushed = map[string][]SeedRow{}
	}
	f.pushed[epoch] = append([]SeedRow(nil), rows...)
	return f.err
}

func (f *fakeCounter) Totals(context.Context, string, time.Time, []string) ([]SeedRow, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.totals, f.err
}

func (f *fakeCounter) pushedRows() int {
	f.mu.Lock()
	defer f.mu.Unlock()
	n := 0
	for _, rows := range f.pushed {
		n += len(rows)
	}
	return n
}

func dailyBudget() []config.RoutingBudget {
	return []config.RoutingBudget{{ID: "d", Scope: "user", Subject: "*", Period: "day", LimitUSD: 1, OnExceed: "warn"}}
}

func TestRuntimeSyncsAndFallsBackToTheDevice(t *testing.T) {
	today := time.Now().UTC().Format(time.DateOnly)
	rt := NewRuntime()
	local := &fakeCounter{totals: []SeedRow{{Day: today, Key: "user:d:*:owner", USD: 3}}}
	fleet := &fakeCounter{totals: []SeedRow{{Day: today, Key: "user:d:*:owner", USD: 9}}}
	rt.For(adapterConfig(nil, dailyBudget()))
	rt.mu.Lock()
	rt.local, rt.fleet = local, fleet
	rt.mu.Unlock()
	rt.Charge([]string{"user:d:*:owner"}, 1, time.Now())
	rt.SyncOnce(context.Background())
	if got, ok := rt.Ledger().Spend("user:d:*:owner", "day", time.Now()); !ok || got != 10 {
		t.Fatalf("fleet spend + local: %v %v", got, ok)
	}
	if local.pushedRows() != 1 || fleet.pushedRows() != 1 {
		t.Fatal("this process's spend goes to both counters")
	}
	fleet.mu.Lock()
	fleet.err = errors.New("store unreachable")
	fleet.mu.Unlock()
	rt.SyncOnce(context.Background())
	if got, _ := rt.Ledger().Spend("user:d:*:owner", "day", time.Now()); got != 4 {
		t.Fatalf("fleet outage falls back to this device: %v", got)
	}
	if state := rt.Ledger().SeedState([]string{"d"}); !strings.Contains(state, "counting this device only") {
		t.Fatalf("state %q", state)
	}
}

func TestRuntimeSyncLoopStartsOnlyWithBudgets(t *testing.T) {
	rt := NewRuntime()
	local := &fakeCounter{}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	rt.SetCounters(ctx, local, nil, time.Hour)
	rt.For(adapterConfig([]config.RoutingAdminRule{{ID: "r", Match: config.RoutingAdminMatch{Connectors: []string{"codex"}}, Allow: []string{"fast"}}}, nil))
	rt.mu.Lock()
	running := rt.syncing
	rt.mu.Unlock()
	if running {
		t.Fatal("no budgets: no sync goroutine")
	}
	rt.For(adapterConfig(nil, dailyBudget()))
	deadline := time.Now().Add(5 * time.Second)
	for !rt.Ledger().Seeded("d") && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if !rt.Ledger().Seeded("d") {
		t.Fatal("budget d not synced")
	}
	rt.Charge([]string{"user:d:*:owner"}, 2, time.Now())
	cancel()
	deadline = time.Now().Add(5 * time.Second)
	for local.pushedRows() == 0 && time.Now().Before(deadline) {
		time.Sleep(10 * time.Millisecond)
	}
	if local.pushedRows() == 0 {
		t.Fatal("the last spend is stored when the gateway stops")
	}
}

func TestLocalCounterKeepsEarlierProcesses(t *testing.T) {
	c := NewLocalCounter(t.TempDir())
	defer c.Close()
	today := time.Now().UTC().Format(time.DateOnly)
	old := time.Now().UTC().AddDate(0, 0, -70).Format(time.DateOnly)
	ctx := context.Background()
	if err := c.Push(ctx, "p1", []SeedRow{{Day: today, Key: "k", USD: 2}, {Day: old, Key: "k", USD: 50}}); err != nil {
		t.Fatal(err)
	}
	if err := c.Push(ctx, "p1", []SeedRow{{Day: today, Key: "k", USD: 3}}); err != nil { // absolute, not added
		t.Fatal(err)
	}
	if err := c.Push(ctx, "p2", []SeedRow{{Day: today, Key: "k", USD: 4}}); err != nil {
		t.Fatal(err)
	}
	rows, err := c.Totals(ctx, "p2", time.Now().AddDate(0, 0, -LedgerDays), nil)
	if err != nil || len(rows) != 1 || rows[0].USD != 3 {
		t.Fatalf("other epochs only, old days pruned: %+v %v", rows, err)
	}
	rows, _ = c.Totals(ctx, "p3", time.Now().AddDate(0, 0, -LedgerDays), nil)
	if len(rows) != 1 || rows[0].USD != 7 {
		t.Fatalf("a new process sees both: %+v", rows)
	}
}

func TestAdapterEvaluateAndGate(t *testing.T) {
	rules := []config.RoutingAdminRule{{ID: "local-high", Match: config.RoutingAdminMatch{SeverityAtLeast: "HIGH"}, Allow: []string{"local"}, Default: "local"}}
	budgets := []config.RoutingBudget{{ID: "d", Scope: "user", Subject: "*", Period: "day", LimitUSD: 1, OnExceed: "downgrade:fast"}}
	rt := NewRuntime()
	ev := rt.For(adapterConfig(rules, budgets))
	rt.Ledger().ApplyRemote([]string{"d"}, nil, time.Now())
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

type mapKeys struct{ to, from map[string]string }

func (m mapKeys) ToFleet(k string) (string, bool)   { v, ok := m.to[k]; return v, ok }
func (m mapKeys) FromFleet(k string) (string, bool) { v, ok := m.from[k]; return v, ok }
func (m mapKeys) Wanted() []string                  { return []string{"group:g:hX"} }

func TestRuntimeTranslatesKeysForTheFleet(t *testing.T) {
	today := time.Now().UTC().Format(time.DateOnly)
	rt := NewRuntime()
	rt.For(adapterConfig(nil, dailyBudget()))
	fleet := &recordingFleet{totals: []SeedRow{{Day: today, Key: "user:d:*:ak1:1:abc", USD: 5}, {Day: today, Key: "user:d:*:ak1:1:other", USD: 50}}}
	keys := mapKeys{to: map[string]string{"user:d:*:1001": "user:d:*:ak1:1:abc"}, from: map[string]string{"user:d:*:ak1:1:abc": "user:d:*:1001"}}
	rt.mu.Lock()
	rt.local, rt.fleet, rt.keys = &fakeCounter{}, fleet, keys
	rt.mu.Unlock()
	rt.Charge([]string{"user:d:*:1001", "user:d:*:1002"}, 1, time.Now())
	rt.SyncOnce(context.Background())
	if got, _ := rt.Ledger().Spend("user:d:*:1001", "day", time.Now()); got != 6 {
		t.Fatalf("own key in the fleet form, mapped back: %v", got)
	}
	if got, _ := rt.Ledger().Spend("user:d:*:1002", "day", time.Now()); got != 1 {
		t.Fatalf("a user without a join key counts on this device only: %v", got)
	}
	if len(fleet.pushed) != 1 || fleet.pushed[0].Key != "user:d:*:ak1:1:abc" {
		t.Fatalf("only fleet-form keys leave the device: %+v", fleet.pushed)
	}
	if !slices.Equal(fleet.asked, []string{"group:g:hX", "user:d:*:ak1:1:abc"}) {
		t.Fatalf("asked %v", fleet.asked)
	}
}

type recordingFleet struct {
	pushed []SeedRow
	asked  []string
	totals []SeedRow
}

func (f *recordingFleet) Push(_ context.Context, _ string, rows []SeedRow) error {
	f.pushed = append([]SeedRow(nil), rows...)
	return nil
}

func (f *recordingFleet) Totals(_ context.Context, _ string, _ time.Time, keys []string) ([]SeedRow, error) {
	f.asked = keys
	return f.totals, nil
}
