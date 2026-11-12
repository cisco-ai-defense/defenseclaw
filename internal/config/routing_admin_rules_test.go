// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"math"
	"strings"
	"testing"
)

func routingAdminTestAliases() map[string]struct{} {
	return map[string]struct{}{"fast": {}, "coder": {}, "local": {}}
}

func TestValidateRoutingAdminRulesAcceptsThePlanExample(t *testing.T) {
	rules := []RoutingAdminRule{
		{ID: "secrets-stay-local", Match: RoutingAdminMatch{SeverityAtLeast: "high"}, Allow: []string{"local"}, Default: "local"},
		{ID: "contractors-no-cloud", Match: RoutingAdminMatch{Groups: []string{`DCLAB\contractors`}}, Action: "deny", Message: "Contractors may not use cloud models. Contact IT."},
		{ID: "code-to-coder", Match: RoutingAdminMatch{Categories: []string{"code"}, Connectors: []string{"codex", "claudecode"}}, Allow: []string{"coder", "fast"}, Default: "coder"},
		{ID: "default-only", Match: RoutingAdminMatch{Agents: []string{"agt-0123456789abcdef"}}, Default: "fast"},
	}
	budgets := []RoutingBudget{
		{ID: "per-user-daily", Scope: "user", Subject: "*", Period: "day", LimitUSD: 20, OnExceed: "downgrade:fast,local"},
		{ID: "eng-month", Scope: "group", Subject: `DCLAB\eng`, Period: "month", LimitUSD: 5000, OnExceed: "deny"},
		{ID: "codex-week", Scope: "connector", Subject: "codex", Period: "week", LimitUSD: 0.5, OnExceed: "warn"},
	}
	if err := ValidateRoutingAdminRules(rules, budgets, &RoutingVisibility{UsersSee: "none"}, routingAdminTestAliases()); err != nil {
		t.Fatalf("ValidateRoutingAdminRules: %v", err)
	}
	if err := ValidateRoutingAdminRules(nil, nil, nil, nil); err != nil {
		t.Fatalf("absent keys must validate: %v", err)
	}
}

func TestValidateRoutingAdminRulesRefusals(t *testing.T) {
	ok := RoutingAdminRule{ID: "r", Match: RoutingAdminMatch{Connectors: []string{"codex"}}, Allow: []string{"fast"}}
	okBudget := RoutingBudget{ID: "b", Scope: "user", Subject: "*", Period: "day", LimitUSD: 1, OnExceed: "warn"}
	rule := func(edit func(*RoutingAdminRule)) []RoutingAdminRule { r := ok; edit(&r); return []RoutingAdminRule{r} }
	budget := func(edit func(*RoutingBudget)) []RoutingBudget { b := okBudget; edit(&b); return []RoutingBudget{b} }
	cases := []struct {
		name    string
		rules   []RoutingAdminRule
		budgets []RoutingBudget
		vis     *RoutingVisibility
		want    string
	}{
		{"bad id", rule(func(r *RoutingAdminRule) { r.ID = "Bad ID" }), nil, nil, "rules[0].id"},
		{"duplicate id", []RoutingAdminRule{ok, ok}, nil, nil, "used by an earlier rule"},
		{"empty match", rule(func(r *RoutingAdminRule) { r.Match = RoutingAdminMatch{} }), nil, nil, "needs at least one of"},
		{"blank group", rule(func(r *RoutingAdminRule) { r.Match.Groups = []string{" "} }), nil, nil, "match.groups: an entry is empty"},
		{"bad agent", rule(func(r *RoutingAdminRule) { r.Match.Agents = []string{"bob"} }), nil, nil, "not an agent identity"},
		{"bad category", rule(func(r *RoutingAdminRule) { r.Match.Categories = []string{"Code!"} }), nil, nil, "match.categories"},
		{"bad severity", rule(func(r *RoutingAdminRule) { r.Match.SeverityAtLeast = "NONE" }), nil, nil, "severity_at_least"},
		{"bad action", rule(func(r *RoutingAdminRule) { r.Action = "allow" }), nil, nil, "must be constrain or deny"},
		{"deny with allow", rule(func(r *RoutingAdminRule) { r.Action = "deny" }), nil, nil, "remove allow and default"},
		{"message without deny", rule(func(r *RoutingAdminRule) { r.Message = "no" }), nil, nil, "only used by a deny rule"},
		{"message not printable", rule(func(r *RoutingAdminRule) { r.Action, r.Allow, r.Message = "deny", nil, "a\nb" }), nil, nil, "printable"},
		{"message too long", rule(func(r *RoutingAdminRule) { r.Action, r.Allow, r.Message = "deny", nil, strings.Repeat("x", 513) }), nil, nil, "512 characters"},
		{"empty allow", rule(func(r *RoutingAdminRule) { r.Allow = []string{} }), nil, nil, "allow is empty"},
		{"no-op constrain", rule(func(r *RoutingAdminRule) { r.Allow = nil }), nil, nil, "changes nothing"},
		{"unknown allow alias", rule(func(r *RoutingAdminRule) { r.Allow = []string{"gpt"} }), nil, nil, "allow[0] \"gpt\" is not an alias"},
		{"default outside allow", rule(func(r *RoutingAdminRule) { r.Default = "coder" }), nil, nil, "not in its allow list"},
		{"unknown default", rule(func(r *RoutingAdminRule) { r.Allow, r.Default = nil, "gpt" }), nil, nil, "default \"gpt\" is not an alias"},
		{"budget duplicate", nil, []RoutingBudget{okBudget, okBudget}, nil, "used by an earlier budget"},
		{"budget scope", nil, budget(func(b *RoutingBudget) { b.Scope = "team" }), nil, "must be user, group or connector"},
		{"group star", nil, budget(func(b *RoutingBudget) { b.Scope = "group" }), nil, "names one group"},
		{"connector name", nil, budget(func(b *RoutingBudget) { b.Scope, b.Subject = "connector", "Claude Code" }), nil, "must be a connector name"},
		{"spaced action", rule(func(r *RoutingAdminRule) { r.Action = " deny" }), nil, nil, "must be constrain or deny"},
		{"spaced severity", rule(func(r *RoutingAdminRule) { r.Match.SeverityAtLeast = " high" }), nil, nil, "severity_at_least"},
		{"empty group list", rule(func(r *RoutingAdminRule) { r.Match.Groups = []string{} }), nil, nil, "match.groups is empty"},
		{"spaced downgrade", nil, budget(func(b *RoutingBudget) { b.OnExceed = "downgrade: fast" }), nil, "is not an alias"},
		{"spaced visibility", nil, nil, &RoutingVisibility{UsersSee: " own"}, "own or none"},
		{"subject spaces", nil, budget(func(b *RoutingBudget) { b.Subject = " *" }), nil, "without surrounding spaces"},
		{"period", nil, budget(func(b *RoutingBudget) { b.Period = "year" }), nil, "day, week or month"},
		{"limit zero", nil, budget(func(b *RoutingBudget) { b.LimitUSD = 0 }), nil, "limit_usd"},
		{"limit NaN", nil, budget(func(b *RoutingBudget) { b.LimitUSD = math.NaN() }), nil, "limit_usd"},
		{"limit huge", nil, budget(func(b *RoutingBudget) { b.LimitUSD = 2e7 }), nil, "limit_usd"},
		{"on_exceed", nil, budget(func(b *RoutingBudget) { b.OnExceed = "block" }), nil, "warn, deny or downgrade"},
		{"downgrade empty", nil, budget(func(b *RoutingBudget) { b.OnExceed = "downgrade:" }), nil, "is not an alias"},
		{"downgrade unknown", nil, budget(func(b *RoutingBudget) { b.OnExceed = "downgrade:fast,gpt" }), nil, "\"gpt\" is not an alias"},
		{"downgrade twice", nil, budget(func(b *RoutingBudget) { b.OnExceed = "downgrade:fast,fast" }), nil, "twice"},
		{"visibility", nil, nil, &RoutingVisibility{UsersSee: "all"}, "own or none"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := ValidateRoutingAdminRules(tc.rules, tc.budgets, tc.vis, routingAdminTestAliases())
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("got %v, want an error containing %q", err, tc.want)
			}
		})
	}
	many := make([]RoutingAdminRule, RoutingAdminMaxRules+1)
	if err := ValidateRoutingAdminRules(many, nil, nil, nil); err == nil || !strings.Contains(err.Error(), "more than 256") {
		t.Fatalf("rule bound: %v", err)
	}
	manyBudgets := make([]RoutingBudget, RoutingAdminMaxBudgets+1)
	if err := ValidateRoutingAdminRules(nil, manyBudgets, nil, nil); err == nil || !strings.Contains(err.Error(), "more than 64") {
		t.Fatalf("budget bound: %v", err)
	}
}

func TestRoutingBudgetOnExceedAction(t *testing.T) {
	action, aliases := RoutingBudget{OnExceed: "downgrade:fast,local"}.OnExceedAction()
	if action != "downgrade" || len(aliases) != 2 || aliases[0] != "fast" || aliases[1] != "local" {
		t.Fatalf("got %q %q", action, aliases)
	}
	if action, aliases := (RoutingBudget{OnExceed: "downgrade: fast"}).OnExceedAction(); action != "downgrade" || aliases[0] != " fast" {
		t.Fatalf("on_exceed is exact: got %q %q", action, aliases)
	}
	if action, aliases := (RoutingBudget{OnExceed: "deny"}).OnExceedAction(); action != "deny" || aliases != nil {
		t.Fatalf("got %q %q", action, aliases)
	}
	var vis *RoutingVisibility
	if vis.EffectiveUsersSee() != "own" || (&RoutingVisibility{UsersSee: "none"}).EffectiveUsersSee() != "none" {
		t.Fatal("users_see default")
	}
}

func TestRoutingAdminMatchSelectors(t *testing.T) {
	m := RoutingAdminMatch{Groups: []string{"g"}, Connectors: []string{"codex"}, Categories: []string{"code"}}
	if m.Empty() || !m.NamesIdentity() {
		t.Fatal("selectors")
	}
	if got := m.Identity(); len(got.Groups) != 1 || len(got.Connectors) != 1 {
		t.Fatalf("Identity = %+v", got)
	}
	if (RoutingAdminMatch{SeverityAtLeast: "HIGH"}).Empty() || (RoutingAdminMatch{Categories: []string{"x"}}).NamesIdentity() {
		t.Fatal("severity/category only")
	}
	if (RoutingAdminRule{Action: " deny "}).IsDeny() || !(RoutingAdminRule{Action: "deny"}).IsDeny() {
		t.Fatal("IsDeny is exact")
	}
}

func TestValidateRoutingAdminFailClosed(t *testing.T) {
	code := RoutingAdminRule{ID: "code", Match: RoutingAdminMatch{Categories: []string{"code"}}, Allow: []string{"coder", "fast"}}
	chat := RoutingAdminRule{ID: "chat", Match: RoutingAdminMatch{Categories: []string{"chat"}}, Allow: []string{"fast"}}
	if err := validateRoutingAdminFailClosed([]RoutingAdminRule{code, chat}, nil); err != nil {
		t.Fatalf("shared alias fast: %v", err)
	}
	chat.Allow = []string{"local"}
	err := validateRoutingAdminFailClosed([]RoutingAdminRule{code, chat}, nil)
	if err == nil || !strings.Contains(err.Error(), "code, chat") {
		t.Fatalf("disjoint category rules: %v", err)
	}
	if err := validateRoutingAdminFailClosed([]RoutingAdminRule{code}, []string{"local"}); err == nil {
		t.Fatal("a category rule disjoint from the floor must be refused")
	}
	deny := RoutingAdminRule{ID: "d", Match: RoutingAdminMatch{Categories: []string{"x"}}, Action: "deny"}
	if err := validateRoutingAdminFailClosed([]RoutingAdminRule{deny}, []string{"local"}); err != nil {
		t.Fatalf("deny rules and the floor alone: %v", err)
	}
}
