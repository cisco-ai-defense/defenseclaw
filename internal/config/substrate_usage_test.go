// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
	"time"
)

// TestSubstrateUsageKeys: substrate.usage is on by default with a 5 s push,
// and the push interval is bounded to 1s-30s.
func TestSubstrateUsageKeys(t *testing.T) {
	var u SubstrateUsageConfig
	if !u.UsageEnabled() || u.EffectiveSyncInterval() != 5*time.Second {
		t.Fatalf("defaults: enabled=%v interval=%v, want true 5s", u.UsageEnabled(), u.EffectiveSyncInterval())
	}
	off := false
	u = SubstrateUsageConfig{Enabled: &off, SyncInterval: "12s"}
	if u.UsageEnabled() || u.EffectiveSyncInterval() != 12*time.Second {
		t.Fatalf("set: enabled=%v interval=%v", u.UsageEnabled(), u.EffectiveSyncInterval())
	}
	for _, bad := range []string{"500ms", "31s", "five", "-1s"} {
		s := validSubstrate()
		s.Usage.SyncInterval = bad
		if err := s.Validate(); err == nil || !strings.Contains(err.Error(), "usage.sync_interval") {
			t.Errorf("sync_interval %q: err %v, want a usage.sync_interval refusal", bad, err)
		}
	}
	for _, doc := range []string{
		"config_version: 9\nsubstrate: {usage: {enabled: false, sync_interval: 10s}}\n",
	} {
		if err := ValidateV8SchemaBytes("ok.yaml", []byte(doc)); err != nil {
			t.Errorf("schema refused %q: %v", doc, err)
		}
	}
	if err := ValidateV8SchemaBytes("bad.yaml", []byte("config_version: 9\nsubstrate: {usage: {interval: 10s}}\n")); err == nil {
		t.Error("schema accepted an unknown substrate.usage key")
	}
}

func clusterRoutingConfig(substrate bool, admin *RoutingAdminConfig) *Config {
	c := &Config{}
	c.Substrate.Enabled = substrate
	c.Routing.Enabled = true
	c.Routing.Models = []RoutingModelBackend{{Name: "sonnet"}}
	c.Routing.Admin = admin
	return c
}

// TestRoutingAdminMatchSubstrateConfig: match.substrate is a rule selector
// on a cluster, validated like the profile selector, and refused off one.
func TestRoutingAdminMatchSubstrateConfig(t *testing.T) {
	rule := RoutingAdminRule{ID: "contractors-sonnet", Match: RoutingAdminMatch{Substrate: &ProfileMatchSubstrate{Atespaces: []string{"ctr-main"}}},
		Allow: []string{"sonnet"}, Default: "sonnet"}
	admin := &RoutingAdminConfig{Rules: []RoutingAdminRule{rule}}
	if err := clusterRoutingConfig(true, admin).validateRoutingAdminRules(); err != nil {
		t.Fatalf("cluster rule with match.substrate refused: %v", err)
	}
	if err := clusterRoutingConfig(false, admin).validateRoutingAdminRules(); err == nil || !strings.Contains(err.Error(), "needs substrate.enabled") {
		t.Fatalf("laptop rule with match.substrate: err %v, want needs substrate.enabled", err)
	}
	bad := rule
	bad.Match.Substrate = &ProfileMatchSubstrate{Atespaces: []string{"Bad_NS"}}
	if err := clusterRoutingConfig(true, &RoutingAdminConfig{Rules: []RoutingAdminRule{bad}}).validateRoutingAdminRules(); err == nil || !strings.Contains(err.Error(), "match.substrate") {
		t.Fatalf("bad atespace: err %v", err)
	}
	if (RoutingAdminMatch{Substrate: &ProfileMatchSubstrate{}}).Empty() != true {
		t.Fatal("an empty substrate selector must leave the match empty")
	}
	doc := "config_version: 9\nrouting: {admin: {rules: [{id: r, match: {substrate: {atespaces: [ctr-main]}}, default: sonnet}]}}\n"
	if err := ValidateV8SchemaBytes("ok.yaml", []byte(doc)); err != nil {
		t.Fatalf("schema refused match.substrate: %v", err)
	}
}

// TestBudgetScopeActorConfig: scope actor is one limit per actor (subject *),
// cluster only.
func TestBudgetScopeActorConfig(t *testing.T) {
	b := RoutingBudget{ID: "actor-runaway", Scope: "actor", Subject: "*", Period: "day", LimitUSD: 20, OnExceed: "downgrade:sonnet"}
	admin := &RoutingAdminConfig{Budgets: []RoutingBudget{b}}
	if err := ValidateRoutingAdminRules(nil, admin.Budgets, nil, map[string]struct{}{"sonnet": {}}); err != nil {
		t.Fatalf("actor budget refused: %v", err)
	}
	if err := clusterRoutingConfig(false, admin).validateRoutingAdminSubstrate(); err == nil || !strings.Contains(err.Error(), "needs substrate.enabled") {
		t.Fatalf("laptop actor budget: err %v", err)
	}
	b.Subject = "alice"
	if err := ValidateRoutingAdminRules(nil, []RoutingBudget{b}, nil, map[string]struct{}{"sonnet": {}}); err == nil || !strings.Contains(err.Error(), "set subject *") {
		t.Fatalf("actor budget with a subject: err %v", err)
	}
	if err := ValidateV8SchemaBytes("bad.yaml", []byte("config_version: 9\nrouting: {admin: {budgets: [{id: a, scope: actor, subject: bob, period: day, limit_usd: 1, on_exceed: deny}]}}\n")); err == nil {
		t.Fatal("schema accepted an actor budget with a named subject")
	}
}

// TestBudgetWarnAtPercentConfig: warn_at_percent is 0-99, 80 by default on
// deny and downgrade budgets, and 0 on warn budgets.
func TestBudgetWarnAtPercentConfig(t *testing.T) {
	pct := func(n int) *int { return &n }
	deny := RoutingBudget{ID: "d", Scope: "user", Subject: "*", Period: "day", LimitUSD: 50, OnExceed: "deny"}
	if got := deny.EffectiveWarnAtPercent(); got != 80 {
		t.Fatalf("deny default %d, want 80", got)
	}
	deny.WarnAtPercent = pct(0)
	if got := deny.EffectiveWarnAtPercent(); got != 0 {
		t.Fatalf("explicit 0 -> %d", got)
	}
	warn := RoutingBudget{ID: "w", Scope: "user", Subject: "*", Period: "day", LimitUSD: 50, OnExceed: "warn", WarnAtPercent: pct(50)}
	if got := warn.EffectiveWarnAtPercent(); got != 0 {
		t.Fatalf("a warn budget ignores warn_at_percent, got %d", got)
	}
	for _, n := range []int{-1, 100} {
		b := deny
		b.WarnAtPercent = pct(n)
		if err := ValidateRoutingAdminRules(nil, []RoutingBudget{b}, nil, nil); err == nil || !strings.Contains(err.Error(), "warn_at_percent") {
			t.Errorf("warn_at_percent %d: err %v", n, err)
		}
	}
	if err := ValidateV8SchemaBytes("ok.yaml", []byte("config_version: 9\nrouting: {admin: {budgets: [{id: a, scope: user, subject: \"*\", period: day, limit_usd: 1, on_exceed: deny, warn_at_percent: 90}]}}\n")); err != nil {
		t.Fatalf("schema refused warn_at_percent: %v", err)
	}
}

// TestRoutingBudgetStoreRefusedOnCluster: a cluster counts through its
// leader; the fleet budget store is for managed devices.
func TestRoutingBudgetStoreRefusedOnCluster(t *testing.T) {
	c := clusterRoutingConfig(true, &RoutingAdminConfig{BudgetStore: &RoutingBudgetStoreConfig{URL: "https://store.example.com"}})
	if err := c.validateRoutingAdminRules(); err == nil || !strings.Contains(err.Error(), "counts through its leader") {
		t.Fatalf("budget_store on a cluster: err %v", err)
	}
}

// TestBudgetScopeBatchConfig: scope batch is one limit per batch (subject
// *), cluster only like actor, and the schema agrees.
func TestBudgetScopeBatchConfig(t *testing.T) {
	b := RoutingBudget{ID: "nightly", Scope: "batch", Subject: "*", Period: "day", LimitUSD: 20, OnExceed: "deny"}
	admin := &RoutingAdminConfig{Budgets: []RoutingBudget{b}}
	if err := ValidateRoutingAdminRules(nil, admin.Budgets, nil, nil); err != nil {
		t.Fatalf("batch budget refused: %v", err)
	}
	if err := clusterRoutingConfig(false, admin).validateRoutingAdminSubstrate(); err == nil || !strings.Contains(err.Error(), "batch counts Agent Substrate") {
		t.Fatalf("laptop batch budget: err %v", err)
	}
	if err := clusterRoutingConfig(true, admin).validateRoutingAdminSubstrate(); err != nil {
		t.Fatalf("cluster batch budget: %v", err)
	}
	b.Subject = "run-7"
	if err := ValidateRoutingAdminRules(nil, []RoutingBudget{b}, nil, nil); err == nil || !strings.Contains(err.Error(), "set subject *") {
		t.Fatalf("batch budget with a subject: err %v", err)
	}
	if err := ValidateV8SchemaBytes("ok.yaml", []byte("config_version: 9\nrouting: {admin: {budgets: [{id: a, scope: batch, subject: \"*\", period: day, limit_usd: 1, on_exceed: deny}]}}\n")); err != nil {
		t.Fatalf("schema refused scope batch: %v", err)
	}
	if err := ValidateV8SchemaBytes("bad.yaml", []byte("config_version: 9\nrouting: {admin: {budgets: [{id: a, scope: batch, subject: bob, period: day, limit_usd: 1, on_exceed: deny}]}}\n")); err == nil {
		t.Fatal("schema accepted a batch budget with a named subject")
	}
}
