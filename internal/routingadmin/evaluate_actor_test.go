// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingadmin

import (
	"context"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
)

const testPersonKey = "p:0123456789abcdef"

// actorCall is a call from actor uid in atespace ns; person false is an
// attributed actor (no person, no verified caller).
func actorCall(ns, uid string, person bool) Request {
	a := &engine.Actor{Key: "substrate:" + ns + "/" + uid, Person: person, Atespace: ns, Template: ns + "/claude"}
	c := Caller{}
	if person {
		c = Caller{Verified: true, Key: testPersonKey, Match: func(config.ProfileMatch) MatchState { return No }}
	}
	return Request{Caller: c, Connector: "claudecode", Actor: a}
}

// ossHost is a laptop call on OSS: CallerFromEngine gives the owner key.
func ossHost() Request {
	return Request{Caller: CallerFromEngine(engine.Caller{}, false), Connector: "claudecode"}
}

// TestRoutingAdminTenantEnforcesDenyOnOSS: on an OSS cluster a deny rule,
// a deny budget and an allow list refuse an actor call (D4-1), while the
// same policy on an OSS laptop call still only warns.
func TestRoutingAdminTenantEnforcesDenyOnOSS(t *testing.T) {
	rules := []config.RoutingAdminRule{{ID: "no-codex", Match: config.RoutingAdminMatch{Connectors: []string{"claudecode"}}, Action: "deny"}}
	p := Compile(rules, nil, false)
	if v := p.Evaluate(actorCall("eng-web", "a1", true), nil, now); !v.Enforce || denyCode(v) != "rule_deny:no-codex" {
		t.Fatalf("actor deny rule on OSS: %+v", v)
	}
	if v := p.Evaluate(ossHost(), nil, now); v.Enforce || v.Deny != nil || !slices.Contains(v.Warnings, "rule_deny_not_enforced:no-codex") {
		t.Fatalf("laptop deny rule on OSS stays a warning: %+v", v)
	}

	budgets := []config.RoutingBudget{{ID: "day-per-person", Scope: "user", Subject: "*", Period: "day", LimitUSD: 50, OnExceed: "deny"}}
	p = Compile(nil, budgets, false)
	l := seededLedger(p.BudgetIDs()...)
	l.Charge([]string{"user:day-per-person:*:" + testPersonKey, "user:day-per-person:*:" + OwnerKey}, 50, now)
	if v := p.Evaluate(actorCall("eng-web", "a1", true), l, now); denyCode(v) != "budget_exceeded:day-per-person" {
		t.Fatalf("actor deny budget on OSS: %+v", v)
	}
	if v := p.Evaluate(ossHost(), l, now); v.Deny != nil || !slices.Contains(v.Warnings, "budget_deny_not_enforced:day-per-person") {
		t.Fatalf("laptop deny budget on OSS stays a warning: %+v", v)
	}
	// Unknown spend still only warns on an OSS cluster (D4-2).
	if v := p.Evaluate(actorCall("eng-web", "a1", true), testLedger(), now); v.Deny != nil || !slices.Contains(v.Warnings, "budget_spend_unknown:day-per-person") {
		t.Fatalf("OSS actor with unseeded spend: %+v", v)
	}

	catalog := map[string]Target{"fast": {Provider: "openai", Model: "gpt-mini"}}
	bound := Verdict{Bind: true, Allowed: []string{"fast"}, BindRuleIDs: []string{"ctr"}, Enforce: true}
	if d, _ := Gate(bound, Target{Provider: "anthropic", Model: "claude"}, catalog, bound.Enforce); d == nil || d.Code != "routing_admin_denied" {
		t.Fatalf("actor allow list on OSS: %v", d)
	}

	// Through the engine adapter: an engine caller with an actor is
	// enforced and keyed per person on an OSS config.
	ev := NewRuntimeClock(func() time.Time { return now }).For(adapterConfig(rules, nil))
	actor := engine.Caller{Verified: true, Key: testPersonKey, Actor: actorCall("eng-web", "a1", true).Actor}
	if v := ev.Evaluate(context.Background(), engine.Policy{}, engine.Request{Caller: actor, Connector: "claudecode"}, "", false); !v.Enforce || v.Deny == nil || v.Deny.Code != "rule_deny:no-codex" {
		t.Fatalf("adapter actor verdict: %+v", v)
	}
	if v := ev.Evaluate(context.Background(), engine.Policy{}, engine.Request{Connector: "claudecode"}, "", false); v.Enforce || v.Deny != nil {
		t.Fatalf("adapter laptop verdict: %+v", v)
	}
}

// TestRoutingAdminMatchSubstrateAtespace: match.substrate selects actor
// calls only, with the profile matcher (an atespace glob only on an owned
// atespace, E3), and an unknown template is Maybe, not a match.
func TestRoutingAdminMatchSubstrateAtespace(t *testing.T) {
	sub := func(m config.ProfileMatchSubstrate) config.RoutingAdminMatch {
		return config.RoutingAdminMatch{Substrate: &m}
	}
	rules := []config.RoutingAdminRule{{ID: "contractors-fast", Match: sub(config.ProfileMatchSubstrate{Atespaces: []string{"ctr-*"}}), Allow: []string{"fast"}, Default: "fast"}}
	p := Compile(rules, nil, false)
	p.SetLauncherAtespaces(map[string][]string{"contractors": {"ctr-main"}})
	if v := p.Evaluate(actorCall("ctr-main", "a1", true), nil, now); !slices.Equal(v.RuleIDs, []string{"contractors-fast"}) || !slices.Equal(v.Allowed, []string{"fast"}) || !v.Bind {
		t.Fatalf("owned atespace glob: %+v", v)
	}
	if v := p.Evaluate(actorCall("ctr-other", "a1", true), nil, now); v.RuleIDs != nil || v.Bind {
		t.Fatalf("a glob never matches an atespace DefenseClaw does not own: %+v", v)
	}
	if v := p.Evaluate(ossHost(), nil, now); v.RuleIDs != nil || v.Bind || v.Warnings != nil {
		t.Fatalf("match.substrate never selects a laptop call: %+v", v)
	}
	if v := p.Evaluate(actorCall("ctr-main", "a2", false), nil, now); !slices.Equal(v.RuleIDs, []string{"contractors-fast"}) {
		t.Fatalf("an attributed actor matches by atespace: %+v", v)
	}

	tmpl := []config.RoutingAdminRule{{ID: "no-legacy", Match: sub(config.ProfileMatchSubstrate{Atespaces: []string{"eng-web"}, Templates: []string{"eng-web/legacy"}}), Action: "deny"}}
	unknown := actorCall("eng-web", "a1", true)
	unknown.Actor.Template = ""
	if v := Compile(tmpl, nil, true).Evaluate(unknown, nil, now); denyCode(v) != "identity_unconfirmed:template" {
		t.Fatalf("managed: an unknown template fails closed: %+v", v)
	}
	if v := Compile(tmpl, nil, false).Evaluate(unknown, nil, now); v.Deny != nil || !slices.Contains(v.Warnings, "identity_unconfirmed") {
		t.Fatalf("OSS cluster: an unknown template warns: %+v", v)
	}
	other := unknown
	other.Actor = &engine.Actor{Key: "substrate:ops/a9", Person: true, Atespace: "ops"}
	if v := Compile(tmpl, nil, true).Evaluate(other, nil, now); v.Deny != nil || v.Warnings != nil {
		t.Fatalf("the atespace key proves No even with no template: %+v", v)
	}
	if v := Compile(tmpl, nil, false).Evaluate(actorCall("eng-web", "a1", true), nil, now); v.Deny != nil {
		t.Fatalf("template eng-web/claude is not eng-web/legacy: %+v", v)
	}
	legacy := actorCall("eng-web", "a1", true)
	legacy.Actor.Template = "eng-web/legacy"
	if v := Compile(tmpl, nil, false).Evaluate(legacy, nil, now); denyCode(v) != "rule_deny:no-legacy" {
		t.Fatalf("template match denies on an OSS cluster: %+v", v)
	}
}

// TestBudgetScopeActorKeyPerRegistration: scope actor gives every actor
// registration its own limit (a new actor a new limit), the person budget
// follows the person across actors, and an attributed actor is charged only
// to actor and connector budgets.
func TestBudgetScopeActorKeyPerRegistration(t *testing.T) {
	budgets := []config.RoutingBudget{
		{ID: "actor-runaway", Scope: "actor", Subject: "*", Period: "day", LimitUSD: 20, OnExceed: "downgrade:fast"},
		{ID: "day-per-person", Scope: "user", Subject: "*", Period: "day", LimitUSD: 50, OnExceed: "deny"},
		{ID: "eng", Scope: "group", Subject: "eng", Period: "day", LimitUSD: 500, OnExceed: "warn"},
	}
	p := Compile(nil, budgets, false)
	l := seededLedger(p.BudgetIDs()...)
	a1, a2 := actorCall("eng-web", "a1", true), actorCall("eng-web", "a2", true)
	k1, k2 := "actor:actor-runaway:"+shortHash(a1.Actor.Key), "actor:actor-runaway:"+shortHash(a2.Actor.Key)
	person := "user:day-per-person:*:" + testPersonKey
	if v := p.Evaluate(a1, l, now); !slices.Equal(v.ChargeKeys, []string{k1, person}) {
		t.Fatalf("actor a1 keys: %+v", v)
	}
	if v := p.Evaluate(a2, l, now); !slices.Equal(v.ChargeKeys, []string{k2, person}) || k1 == k2 {
		t.Fatalf("actor a2 keys: %+v", v)
	}
	if v := p.Evaluate(ossHost(), l, now); slices.ContainsFunc(v.ChargeKeys, func(k string) bool { return strings.HasPrefix(k, "actor:") }) {
		t.Fatalf("a laptop call has no actor key: %+v", v)
	}
	attributed := actorCall("eng-web", "a3", false)
	if v := p.Evaluate(attributed, l, now); !slices.Equal(v.ChargeKeys, []string{"actor:actor-runaway:" + shortHash(attributed.Actor.Key)}) || v.Warnings != nil {
		t.Fatalf("attributed actor: only its actor key, no unconfirmed warning: %+v", v)
	}
	l.Charge([]string{k1}, 20, now)
	if v := p.Evaluate(a1, l, now); !slices.Equal(v.Force, []string{"fast"}) || v.ForceBudget != "actor-runaway" {
		t.Fatalf("a1 over its actor limit is downgraded: %+v", v)
	}
	if v := p.Evaluate(a2, l, now); v.Force != nil {
		t.Fatalf("a2 has its own actor limit: %+v", v)
	}
}

// TestBudgetWarnAtPercent: a deny or downgrade budget warns at
// warn_at_percent of its limit (default 80, 0 off); a warn budget ignores it.
func TestBudgetWarnAtPercent(t *testing.T) {
	pct := func(n int) *int { return &n }
	budgets := []config.RoutingBudget{
		{ID: "deny-default", Scope: "connector", Subject: "*", Period: "day", LimitUSD: 10, OnExceed: "deny"},
		{ID: "down-50", Scope: "connector", Subject: "*", Period: "day", LimitUSD: 10, OnExceed: "downgrade:fast", WarnAtPercent: pct(50)},
		{ID: "deny-off", Scope: "connector", Subject: "*", Period: "day", LimitUSD: 10, OnExceed: "deny", WarnAtPercent: pct(0)},
		{ID: "warn-only", Scope: "connector", Subject: "*", Period: "day", LimitUSD: 10, OnExceed: "warn", WarnAtPercent: pct(10)},
	}
	for _, managed := range []bool{false, true} {
		p := Compile(nil, budgets, managed)
		l := seededLedger(p.BudgetIDs()...)
		req := Request{Caller: caller("eng1"), Connector: "codex"}
		v := p.Evaluate(req, l, now)
		keys := v.ChargeKeys
		if v.Warnings != nil {
			t.Fatalf("no spend: %+v", v)
		}
		l.Charge(keys, 4.5, now)
		if v := p.Evaluate(req, l, now); v.Warnings != nil {
			t.Fatalf("under every share: %+v", v)
		}
		l.Charge(keys, 0.5, now) // 5.00
		if v := p.Evaluate(req, l, now); !slices.Equal(v.Warnings, []string{"budget_warn:down-50"}) || v.Force != nil || v.Deny != nil {
			t.Fatalf("at 50%%: %+v", v)
		}
		l.Charge(keys, 3, now) // 8.00
		if v := p.Evaluate(req, l, now); !slices.Equal(v.Warnings, []string{"budget_warn:deny-default", "budget_warn:down-50"}) || v.Deny != nil {
			t.Fatalf("at 80%% (managed %v): %+v", managed, v)
		}
		l.Charge(keys, 1.5, now) // 9.50: deny-off and warn-only never warn below the limit
		if v := p.Evaluate(req, l, now); slices.Contains(v.Warnings, "budget_warn:deny-off") || slices.Contains(v.Warnings, "budget_warn:warn-only") {
			t.Fatalf("off and warn budgets: %+v", v)
		}
	}
}
