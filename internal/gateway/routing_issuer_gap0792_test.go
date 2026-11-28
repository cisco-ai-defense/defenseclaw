// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

const (
	gap0792IdpA = "https://idp-a.example"
	gap0792IdpB = "https://idp-b.example"
)

// gap0792Base is the profile matcher as it sees an OIDC person: a bare
// users entry matches the subject (it knows no issuer).
func gap0792Base(p registry.Person) func(config.ProfileMatch) engine.Tri {
	return func(m config.ProfileMatch) engine.Tri {
		if len(m.Users) > 0 && !slices.Contains(m.Users, p.Subject) {
			return engine.No
		}
		if len(m.Groups) > 0 && !slices.ContainsFunc(m.Groups, func(g string) bool { return slices.Contains(p.Groups, g) }) {
			return engine.No
		}
		return engine.Yes
	}
}

func gap0792Match(m config.ProfileMatch, p registry.Person, issuers []string) engine.Tri {
	return routingIssuerMatch(m, p, issuers, gap0792Base(p))
}

// GAP-0792 points 1, 2, 4: users:[alice] does not match alice at a second
// issuer, idp-b#alice matches only idp-b, a host call keeps bare names.
func TestGAP0792IssuerQualifiedUsers(t *testing.T) {
	two := []string{gap0792IdpA, gap0792IdpB}
	aliceA := registry.Person{Kind: "user", Issuer: gap0792IdpA, Subject: "alice", Groups: []string{"eng"}}
	aliceB := registry.Person{Kind: "user", Issuer: gap0792IdpB, Subject: "alice", Groups: []string{"eng"}}
	hostAlice := registry.Person{Subject: "alice"}
	bare := config.ProfileMatch{Users: []string{"alice"}}
	qualB := config.ProfileMatch{Users: []string{gap0792IdpB + "#alice"}}
	cases := []struct {
		name    string
		m       config.ProfileMatch
		p       registry.Person
		issuers []string
		want    engine.Tri
	}{
		{"bare alice, primary issuer", bare, aliceA, two, engine.Yes},
		{"bare alice, second issuer", bare, aliceB, two, engine.No},
		{"bare alice, one issuer", bare, aliceB, []string{gap0792IdpB}, engine.Yes},
		{"bare alice, host call", bare, hostAlice, two, engine.Yes},
		{"idp-b#alice, idp-b", qualB, aliceB, two, engine.Yes},
		{"idp-b#alice, idp-a", qualB, aliceA, two, engine.No},
		{"idp-b#alice, one issuer idp-a", qualB, aliceA, []string{gap0792IdpA}, engine.No},
		{"idp-b#alice, host call", qualB, hostAlice, two, engine.No},
		{"idp-b#alice and group eng", config.ProfileMatch{Users: qualB.Users, Groups: []string{"eng"}}, aliceB, two, engine.Yes},
		{"idp-b#alice and group ops", config.ProfileMatch{Users: qualB.Users, Groups: []string{"ops"}}, aliceB, two, engine.No},
		{"groups only, second issuer", config.ProfileMatch{Groups: []string{"eng"}}, aliceB, two, engine.Yes},
	}
	for _, c := range cases {
		got := gap0792Match(c.m, c.p, c.issuers)
		if c.p.Issuer == "" {
			// A host call: no bound person, the profile matcher sees the
			// host account alice.
			got = routingIssuerMatch(c.m, registry.Person{}, c.issuers, gap0792Base(c.p))
		}
		if got != c.want {
			t.Errorf("%s: got %v, want %v", c.name, got, c.want)
		}
	}
}

// GAP-0792 points 3, 4: a bare and a qualified named budget of alice keep
// separate spend, each charged only for its own person, and the budget view
// key (BudgetChargeKey) is the key the evaluator charges.
func TestGAP0792QualifiedBudgetsKeepSeparateSpend(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	budgets := []config.RoutingBudget{
		{ID: "alice-a", Scope: "user", Subject: "alice", Period: "day", LimitUSD: 10, OnExceed: "warn"},
		{ID: "alice-b", Scope: "user", Subject: gap0792IdpB + "#alice", Period: "day", LimitUSD: 10, OnExceed: "warn"},
	}
	p := routingadmin.Compile(nil, budgets, true)
	ledger := routingadmin.NewLedgerClock(func() time.Time { return now })
	ledger.ApplyRemote(p.BudgetIDs(), nil, now)
	two := []string{gap0792IdpA, gap0792IdpB}
	charge := func(person registry.Person, usd float64) []string {
		c := engine.Caller{Verified: true, Key: person.Key(), Matches: func(m config.ProfileMatch) engine.Tri { return gap0792Match(m, person, two) }}
		v := p.Evaluate(routingadmin.Request{Caller: routingadmin.CallerFromEngine(c, true), Actor: &engine.Actor{Key: "reg-" + person.Issuer, Person: true}}, ledger, now)
		ledger.Charge(v.ChargeKeys, usd, now)
		return v.ChargeKeys
	}
	keyA, keyB := routingadmin.BudgetChargeKey(budgets[0]), routingadmin.BudgetChargeKey(budgets[1])
	if keyA == keyB {
		t.Fatalf("one key %q for both people", keyA)
	}
	if got := charge(registry.Person{Kind: "user", Issuer: gap0792IdpA, Subject: "alice"}, 3); !slices.Equal(got, []string{keyA}) {
		t.Fatalf("alice at idp-a charged %v, want only %q", got, keyA)
	}
	if got := charge(registry.Person{Kind: "user", Issuer: gap0792IdpB, Subject: "alice"}, 5); !slices.Equal(got, []string{keyB}) {
		t.Fatalf("alice at idp-b charged %v, want only %q", got, keyB)
	}
	if s, _ := ledger.Spend(keyA, "day", now); s != 3 {
		t.Fatalf("alice-a spend %v, want 3", s)
	}
	if s, _ := ledger.Spend(keyB, "day", now); s != 5 {
		t.Fatalf("alice-b spend %v, want 5", s)
	}
}
