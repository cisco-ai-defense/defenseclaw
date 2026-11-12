// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingadmin

import (
	"context"
	"errors"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

var now = time.Date(2026, 11, 18, 15, 0, 0, 0, time.UTC) // a Wednesday

// caller is a verified member of the given groups, named user.
func caller(user string, groups ...string) Caller {
	return Caller{Verified: true, Key: "uid:" + user, Match: func(m config.ProfileMatch) MatchState {
		for _, u := range m.Users {
			if u == user {
				return Yes
			}
		}
		for _, want := range m.Groups {
			if slices.Contains(groups, want) {
				return Yes
			}
		}
		return No
	}}
}

func maybeCaller() Caller {
	return Caller{Verified: true, Key: "uid:mac", Unconfirmed: "groups", Match: func(config.ProfileMatch) MatchState { return Maybe }}
}

var planRules = []config.RoutingAdminRule{
	{ID: "secrets-local", Match: config.RoutingAdminMatch{SeverityAtLeast: "HIGH"}, Allow: []string{"local"}, Default: "local"},
	{ID: "contractors", Match: config.RoutingAdminMatch{Groups: []string{"contractors"}}, Action: "deny", Message: "No cloud models for contractors."},
	{ID: "code", Match: config.RoutingAdminMatch{Categories: []string{"code"}, Connectors: []string{"codex"}}, Allow: []string{"coder", "fast", "local"}, Default: "coder"},
}

func TestEvaluateRules(t *testing.T) {
	for _, managed := range []bool{false, true} {
		p := Compile(planRules, nil, managed)
		cases := []struct {
			name     string
			req      Request
			allowed  []string
			defaults []string
			deny     string
			warnings []string
			rules    []string
		}{
			{name: "no rule matches", req: Request{Caller: caller("eng1", "eng"), Connector: "claudecode", Severity: "LOW"}},
			{name: "severity narrows", req: Request{Caller: caller("eng1", "eng"), Connector: "claudecode", Severity: "critical"},
				allowed: []string{"local"}, defaults: []string{"local"}, rules: []string{"secrets-local"}},
			{name: "route-only has no severity", req: Request{Caller: caller("eng1", "eng"), Connector: "claudecode"}},
			{name: "category and connector", req: Request{Caller: caller("eng1"), Connector: "codex", Category: "code"},
				allowed: []string{"coder", "fast", "local"}, defaults: []string{"coder"}, rules: []string{"code"}},
			{name: "all matching rules intersect", req: Request{Caller: caller("eng1"), Connector: "codex", Category: "code", Severity: "HIGH"},
				allowed: []string{"local"}, defaults: []string{"local", "coder"}, rules: []string{"secrets-local", "code"}},
			{name: "other connector", req: Request{Caller: caller("eng1"), Connector: "claudecode", Category: "code"}},
			{name: "group deny", req: Request{Caller: caller("ctr1", "contractors"), Connector: "codex"},
				deny:     map[bool]string{true: "rule_deny:contractors"}[managed],
				warnings: map[bool][]string{false: {"rule_deny_not_enforced:contractors"}}[managed], rules: []string{"contractors"}},
		}
		for _, tc := range cases {
			t.Run(map[bool]string{false: "oss/", true: "managed/"}[managed]+tc.name, func(t *testing.T) {
				v := p.Evaluate(tc.req, nil, now)
				if !reflect.DeepEqual(v.Allowed, tc.allowed) || !reflect.DeepEqual(v.Defaults, tc.defaults) ||
					!reflect.DeepEqual(v.RuleIDs, tc.rules) || !reflect.DeepEqual(v.Warnings, tc.warnings) {
					t.Fatalf("got %+v", v)
				}
				if got := denyCode(v); got != tc.deny {
					t.Fatalf("deny = %q, want %q", got, tc.deny)
				}
				if v.Deny != nil && v.Deny.Message != "No cloud models for contractors." {
					t.Fatalf("message %q", v.Deny.Message)
				}
				if v.Bind != (tc.allowed != nil) {
					t.Fatalf("bind %v", v.Bind)
				}
			})
		}
	}
}

func TestEvaluateUnknownFacts(t *testing.T) {
	category := Request{Caller: caller("eng1"), Connector: "codex", ClassifierFailed: true}
	if v := Compile(planRules, nil, false).Evaluate(category, nil, now); v.Allowed != nil || !slices.Contains(v.Warnings, "category_unknown") {
		t.Fatalf("oss classifier failure: %+v", v)
	}
	if v := Compile(planRules, nil, true).Evaluate(category, nil, now); !slices.Equal(v.Allowed, []string{"coder", "fast", "local"}) {
		t.Fatalf("managed classifier failure must narrow: %+v", v)
	}
	unconfirmed := Request{Caller: maybeCaller(), Connector: "claudecode"}
	if v := Compile(planRules, nil, false).Evaluate(unconfirmed, nil, now); v.Deny != nil || !slices.Contains(v.Warnings, "identity_unconfirmed") {
		t.Fatalf("oss maybe: %+v", v)
	}
	if v := Compile(planRules, nil, true).Evaluate(unconfirmed, nil, now); denyCode(v) != "identity_unconfirmed:groups" {
		t.Fatalf("managed maybe on a deny rule must deny: %+v", v)
	}
	if v := Compile(planRules, nil, true).Evaluate(Request{Connector: "claudecode"}, nil, now); denyCode(v) != "identity_unconfirmed:unverified" {
		t.Fatalf("managed unverified caller and a group deny rule: %+v", v)
	}
	constrain := []config.RoutingAdminRule{{ID: "eng-coder", Match: config.RoutingAdminMatch{Groups: []string{"eng"}}, Allow: []string{"coder"}}}
	if v := Compile(constrain, nil, true).Evaluate(unconfirmed, nil, now); v.Deny != nil || !slices.Equal(v.Allowed, []string{"coder"}) {
		t.Fatalf("managed maybe on a constrain rule applies it: %+v", v)
	}
	if Compile(nil, nil, true) != nil {
		t.Fatal("no rules and no budgets compile to nil")
	}
	var none *Policy
	if v := none.Evaluate(category, nil, now); !reflect.DeepEqual(v, Verdict{}) {
		t.Fatalf("nil policy: %+v", v)
	}
}

func testLedger() *Ledger {
	l := NewLedger()
	l.now = func() time.Time { return now }
	return l
}

func seededLedger(ids ...string) *Ledger {
	l := testLedger()
	l.ApplySeed(ids, nil)
	return l
}

func day(t time.Time) string { return t.UTC().Format(time.DateOnly) }

func TestEvaluateBudgets(t *testing.T) {
	budgets := []config.RoutingBudget{
		{ID: "daily", Scope: "user", Subject: "*", Period: "day", LimitUSD: 10, OnExceed: "downgrade:fast,local"},
		{ID: "eng", Scope: "group", Subject: "eng", Period: "month", LimitUSD: 100, OnExceed: "deny"},
		{ID: "codex", Scope: "connector", Subject: "codex", Period: "week", LimitUSD: 5, OnExceed: "warn"},
	}
	req := Request{Caller: caller("eng1", "eng"), Connector: "codex"}
	userKey, groupKey, connKey := "user:daily:*:uid:eng1", "group:eng:"+shortHash("eng"), "connector:codex:codex"
	for _, managed := range []bool{false, true} {
		p := Compile(nil, budgets, managed)
		l := seededLedger(p.BudgetIDs()...)
		v := p.Evaluate(req, l, now)
		if !slices.Equal(v.ChargeKeys, []string{userKey, groupKey, connKey}) || v.Deny != nil || v.Force != nil || v.Warnings != nil {
			t.Fatalf("under budget: %+v", v)
		}
		l.Charge([]string{connKey}, 5, now.Add(-48*time.Hour)) // Monday: same week
		if v := p.Evaluate(req, l, now); !slices.Equal(v.Warnings, []string{"budget_warn:codex"}) {
			t.Fatalf("warn: %+v", v)
		}
		l.Charge([]string{userKey}, 10, now)
		v = p.Evaluate(req, l, now)
		if !slices.Equal(v.Force, []string{"fast", "local"}) || v.ForceBudget != "daily" || !slices.Contains(v.Warnings, "budget_downgrade:daily") {
			t.Fatalf("downgrade wins over warn: %+v", v)
		}
		if v := p.Evaluate(Request{Caller: caller("eng2", "eng"), Connector: "claudecode"}, l, now); v.Force != nil {
			t.Fatalf("another user has their own daily limit: %+v", v)
		}
		l.Charge([]string{groupKey}, 100, now.AddDate(0, 0, -17)) // Nov 1
		v = p.Evaluate(req, l, now)
		if managed && denyCode(v) != "budget_exceeded:eng" {
			t.Fatalf("managed deny: %+v", v)
		}
		if !managed && (v.Deny != nil || !slices.Contains(v.Warnings, "budget_deny_not_enforced:eng") || v.ForceBudget != "daily" ||
			!slices.Contains(v.Warnings, "budget_warn:codex")) {
			t.Fatalf("oss deny is a warning and the downgrade still applies: %+v", v)
		}
	}
}

func TestEvaluateDowngradeHonoursRules(t *testing.T) {
	rules := []config.RoutingAdminRule{{ID: "local-only", Match: config.RoutingAdminMatch{Connectors: []string{"codex"}}, Allow: []string{"local"}}}
	budgets := []config.RoutingBudget{{ID: "d", Scope: "connector", Subject: "*", Period: "day", LimitUSD: 1, OnExceed: "downgrade:fast"}}
	for _, managed := range []bool{false, true} {
		p := Compile(rules, budgets, managed)
		l := seededLedger("d")
		l.Charge([]string{"connector:d:codex"}, 2, now)
		v := p.Evaluate(Request{Caller: caller("u"), Connector: "codex"}, l, now)
		if managed && denyCode(v) != "budget_downgrade_unavailable:d" {
			t.Fatalf("managed: %+v", v)
		}
		if !managed && (v.Force != nil || !slices.Contains(v.Warnings, "budget_downgrade_unavailable:d")) {
			t.Fatalf("oss: %+v", v)
		}
	}
}

func TestEvaluateBudgetSpendUnknown(t *testing.T) {
	deny := []config.RoutingBudget{{ID: "d", Scope: "user", Subject: "*", Period: "day", LimitUSD: 1, OnExceed: "deny"}}
	req := Request{Caller: caller("u"), Connector: "codex"}
	if v := Compile(nil, deny, true).Evaluate(req, testLedger(), now); denyCode(v) != "budget_unavailable:d" {
		t.Fatalf("managed unseeded deny budget fails closed: %+v", v)
	}
	if v := Compile(nil, deny, false).Evaluate(req, testLedger(), now); v.Deny != nil || !slices.Contains(v.Warnings, "budget_spend_unknown:d") {
		t.Fatalf("oss unseeded: %+v", v)
	}
	if v := Compile(nil, deny, true).Evaluate(Request{Connector: "codex"}, seededLedger("d"), now); denyCode(v) != "identity_unconfirmed:unverified" {
		t.Fatalf("managed per-user deny budget and an unverified caller: %+v", v)
	}
}

func TestGate(t *testing.T) {
	catalog := map[string]Target{"local": {Provider: "vllm", Model: "qwen"}, "fast": {Provider: "openai", Model: "gpt-mini"}}
	bound := Verdict{Bind: true, Allowed: []string{"local"}, BindRuleIDs: []string{"secrets-local"}}
	if d, w := Gate(bound, Target{Provider: "VLLM", Model: "qwen"}, catalog, true); d != nil || w != "" {
		t.Fatalf("original is an allowed entry: %v %q", d, w)
	}
	if d, _ := Gate(bound, Target{Provider: "anthropic", Model: "claude"}, catalog, true); d == nil || d.Code != "routing_admin_denied" {
		t.Fatalf("managed bind: %v", d)
	}
	if d, w := Gate(bound, Target{Provider: "anthropic", Model: "claude"}, catalog, false); d != nil || w != "rule_allow_not_enforced:secrets-local" {
		t.Fatalf("oss bind: %v %q", d, w)
	}
	if d, w := Gate(Verdict{}, Target{Provider: "anthropic"}, catalog, true); d != nil || w != "" {
		t.Fatalf("no rule: %v %q", d, w)
	}
	refused := Verdict{Deny: &Deny{Code: "budget_exceeded:x"}}
	if d, _ := Gate(refused, Target{}, catalog, true); d == nil || d.Code != "budget_exceeded:x" {
		t.Fatalf("deny passes through: %v", d)
	}
}

func TestGateHoldsTheDowngrade(t *testing.T) {
	catalog := map[string]Target{"fast": {Provider: "openai", Model: "gpt-mini"}}
	v := Verdict{Force: []string{"fast"}, ForceBudget: "daily"}
	if d, w := Gate(v, Target{Provider: "openai", Model: "gpt-mini"}, catalog, true); d != nil || w != "" {
		t.Fatalf("downgraded target: %v %q", d, w)
	}
	if d, _ := Gate(v, Target{Provider: "anthropic", Model: "opus"}, catalog, true); d == nil || d.Code != "budget_downgrade_unavailable:daily" {
		t.Fatalf("managed retry on the original upstream must be held to the downgrade: %v", d)
	}
	if d, w := Gate(v, Target{Provider: "anthropic", Model: "opus"}, catalog, false); d != nil || w != "budget_downgrade_not_enforced:daily" {
		t.Fatalf("oss: %v %q", d, w)
	}
	empty := Verdict{Bind: true, Allowed: []string{}, BindRuleIDs: []string{"a", "b"}, RuleIDs: []string{"a", "x", "b"}}
	if d, _ := Gate(empty, Target{Provider: "openai", Model: "gpt-mini"}, catalog, true); d == nil || !strings.Contains(d.Message, "rule a, b)") {
		t.Fatalf("bind with nothing allowed names only the binding rules: %v", d)
	}
}

func TestMaybeCallerIsNeverChargedToANamedBudget(t *testing.T) {
	budgets := []config.RoutingBudget{
		{ID: "alice", Scope: "user", Subject: "alice", Period: "day", LimitUSD: 5, OnExceed: "deny"},
		{ID: "eng", Scope: "group", Subject: "eng", Period: "day", LimitUSD: 5, OnExceed: "downgrade:fast"},
	}
	p := Compile(nil, budgets, true)
	l := seededLedger("alice", "eng")
	unverified := Request{Connector: "codex"}
	if v := p.Evaluate(unverified, l, now); v.Deny != nil || len(v.ChargeKeys) != 0 {
		t.Fatalf("under the limits an unconfirmed caller passes uncharged: %+v", v)
	}
	if v := p.Evaluate(Request{Caller: caller("alice"), Connector: "codex"}, l, now); !slices.Equal(v.ChargeKeys, []string{"user:alice:=" + shortHash("alice")}) {
		t.Fatalf("alice herself is charged: %+v", v)
	}
	l.Charge([]string{"group:eng:" + shortHash("eng")}, 6, now)
	if v := p.Evaluate(Request{Caller: maybeCaller(), Connector: "codex"}, l, now); !slices.Equal(v.Force, []string{"fast"}) || len(v.ChargeKeys) != 0 {
		t.Fatalf("an unconfirmed member is held to the reached group limit, uncharged: %+v", v)
	}
	l.Charge([]string{"user:alice:=" + shortHash("alice")}, 6, now)
	if v := p.Evaluate(unverified, l, now); denyCode(v) != "identity_unconfirmed:unverified" {
		t.Fatalf("a reached named deny budget refuses an unconfirmed caller: %+v", v)
	}
}

func TestDefiniteDenyMessageWins(t *testing.T) {
	rules := []config.RoutingAdminRule{
		{ID: "maybe-deny", Match: config.RoutingAdminMatch{Groups: []string{"x"}}, Action: "deny"},
		{ID: "codex-deny", Match: config.RoutingAdminMatch{Connectors: []string{"codex"}}, Action: "deny", Message: "No Codex here."},
	}
	v := Compile(rules, nil, true).Evaluate(Request{Caller: maybeCaller(), Connector: "codex"}, nil, now)
	if denyCode(v) != "rule_deny:codex-deny" || v.Deny.Message != "No Codex here." {
		t.Fatalf("got %+v", v.Deny)
	}
}

func TestLedgerWindowsAndSeed(t *testing.T) {
	l := testLedger()
	key := "user:m:*:abc"
	if _, ok := l.Spend(key, "day", now); ok {
		t.Fatal("unseeded budget must report not loaded")
	}
	l.Charge([]string{key}, 1, now) // a live charge before the seed is kept
	l.ApplySeed([]string{"m"}, []SeedRow{
		{Day: day(now), Key: key, USD: 2},
		{Day: day(now.AddDate(0, 0, -2)), Key: key, USD: 4},   // Monday
		{Day: day(now.AddDate(0, 0, -3)), Key: key, USD: 8},   // Sunday, last week
		{Day: day(now.AddDate(0, 0, -18)), Key: key, USD: 16}, // October
		{Day: day(now), Key: "user:other:*:abc", USD: 100},    // budget not being seeded
		{Day: "2026/11/18", Key: key, USD: 1000},              // not a UTC date: skipped
	})
	for period, want := range map[string]float64{"day": 3, "week": 7, "month": 15} {
		if got, ok := l.Spend(key, period, now); !ok || got != want {
			t.Fatalf("%s spend = %v %v, want %v", period, got, ok, want)
		}
	}
	l.ApplySeed([]string{"m", "other"}, []SeedRow{{Day: day(now), Key: key, USD: 50}, {Day: day(now), Key: "user:other:*:abc", USD: 3}})
	if got, _ := l.Spend(key, "day", now); got != 3 {
		t.Fatalf("a budget is seeded once: %v", got)
	}
	if got, _ := l.Spend("user:other:*:abc", "day", now); got != 3 {
		t.Fatalf("budget added later: %v", got)
	}
	l.Charge([]string{key}, -5, now)
	l.Charge([]string{key}, 0, now)
	if got, _ := l.Spend(key, "day", now); got != 3 {
		t.Fatalf("non-positive charges are ignored: %v", got)
	}
	l.Charge([]string{key}, 1, now.AddDate(0, 0, 70)) // a clock step: counted today, prunes nothing
	if got, _ := l.Spend(key, "day", now); got != 4 {
		t.Fatalf("future-dated charge: %v", got)
	}
	later := now.AddDate(0, 0, 70)
	l.now = func() time.Time { return later }
	l.Charge([]string{key}, 1, later) // a new wall-clock day prunes days older than 62
	if got, _ := l.Spend(key, "month", now); got != 0 {
		t.Fatalf("pruned: %v", got)
	}
}

func TestLedgerSeedLoopRetries(t *testing.T) {
	l := testLedger()
	calls := 0
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
	defer cancel()
	l.SeedLoop(ctx, []string{"m"}, func() time.Time { return now }, func(_ context.Context, since time.Time) ([]SeedRow, error) {
		calls++
		if want := now.AddDate(0, 0, -LedgerDays).Truncate(24 * time.Hour); !since.Equal(want) {
			t.Errorf("since %v, want %v", since, want)
		}
		if calls == 1 {
			if got := l.SeedState([]string{"m"}); got != "seeding" {
				t.Errorf("state before the first answer: %q", got)
			}
			return nil, errors.New("store busy")
		}
		if got := l.SeedState([]string{"m"}); got != "failed: store busy" {
			t.Errorf("state after a failure: %q", got)
		}
		return []SeedRow{{Day: day(now), Key: "user:m:*:x", USD: 1}}, nil
	})
	if calls != 2 || !l.Seeded("m") || l.SeedState([]string{"m"}) != "seeded" {
		t.Fatalf("calls %d seeded %v", calls, l.Seeded("m"))
	}
}

func TestLedgerConcurrentCharges(t *testing.T) {
	l := seededLedger("c")
	var wg sync.WaitGroup
	for i := 0; i < 50; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for j := 0; j < 100; j++ {
				l.Charge([]string{"connector:c:codex"}, 0.01, now)
				l.Spend("connector:c:codex", "day", now)
			}
		}()
	}
	wg.Wait()
	if got, _ := l.Spend("connector:c:codex", "day", now); got < 49.99 || got > 50.01 {
		t.Fatalf("spend %v", got)
	}
}

func TestNextReset(t *testing.T) {
	cases := map[string]string{"day": "2026-11-19T00:00:00Z", "week": "2026-11-23T00:00:00Z", "month": "2026-12-01T00:00:00Z"}
	for period, want := range cases {
		if got := NextReset(period, now).Format(time.RFC3339); got != want {
			t.Fatalf("%s: %s, want %s", period, got, want)
		}
	}
	dec := time.Date(2026, 12, 31, 23, 0, 0, 0, time.UTC)
	if got := NextReset("month", dec).Format(time.RFC3339); got != "2027-01-01T00:00:00Z" {
		t.Fatalf("year rollover: %s", got)
	}
}

func TestDecisionsRing(t *testing.T) {
	var d Decisions
	for i := 0; i < DecisionsSize+10; i++ {
		owner := "uid:a"
		if i%2 == 1 {
			owner = "uid:b"
		}
		d.Record(DecisionEntry{RequestID: "r" + strconv.Itoa(i), CallerKey: owner, Outcome: "applied", RuleIDs: []string{"x"}})
	}
	recent := d.Recent("uid:a", false, 5)
	if len(recent) != 5 || recent[0].CallerKey != "uid:a" {
		t.Fatalf("recent own: %+v", recent)
	}
	if len(d.Recent("uid:a", true, 1000)) != DecisionsSize {
		t.Fatal("admin sees the whole ring")
	}
	if len(d.Recent("", false, 5)) != 0 {
		t.Fatal("an unverified caller reads nothing")
	}
	last := d.Recent("uid:b", false, 1)[0]
	if _, ok := d.Find(last.RequestID, "uid:a", false); ok {
		t.Fatal("another user's decision must be not found")
	}
	if e, ok := d.Find(last.RequestID, "uid:b", false); !ok || e.RequestID != last.RequestID {
		t.Fatal("own decision")
	}
	if _, ok := d.Find(last.RequestID, "", true); !ok {
		t.Fatal("admin finds any decision")
	}
}

func denyCode(v Verdict) string {
	if v.Deny == nil {
		return ""
	}
	return v.Deny.Code
}
