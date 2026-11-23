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

package config

import (
	"slices"
	"strings"
	"testing"
)

// GAP-0792: an issuer#subject users entry or named user budget subject
// must name a subject; a qualified entry with one is accepted.
func TestGAP0792QualifiedUserNeedsSubject(t *testing.T) {
	if err := validateRoutingAdminMatch("routing.admin.rules[0].match", RoutingAdminMatch{Users: []string{"https://idp-b.example#"}}); err == nil {
		t.Fatal("issuer with no subject accepted in users")
	}
	if err := validateRoutingAdminMatch("routing.admin.rules[0].match", RoutingAdminMatch{Users: []string{"https://idp-b.example#alice", "dom#user"}}); err != nil {
		t.Fatalf("qualified entry refused: %v", err)
	}
	b := RoutingBudget{ID: "b", Scope: RoutingBudgetScopeUser, Subject: "https://idp-b.example#", Period: "day", LimitUSD: 1, OnExceed: "warn"}
	if err := validateRoutingBudget("routing.admin.budgets[0]", b, nil); err == nil {
		t.Fatal("issuer with no subject accepted as a budget subject")
	}
	b.Subject = "https://idp-b.example#alice"
	if err := validateRoutingBudget("routing.admin.budgets[0]", b, nil); err != nil {
		t.Fatalf("qualified budget subject refused: %v", err)
	}
}

// GAP-0792 point 2: config load (and doctor, from the Python mirror) warn
// about bare names when more than one person issuer is trusted.
func TestGAP0792BareNameWarnings(t *testing.T) {
	const idpA, idpB = "https://idp-a.example", "https://idp-b.example"
	cfg := &Config{}
	cfg.Substrate.Enabled = true
	cfg.Substrate.Identity.OIDC.Issuer = idpA
	cfg.Routing.Admin = &RoutingAdminConfig{
		Rules:   []RoutingAdminRule{{ID: "r1", Match: RoutingAdminMatch{Users: []string{"alice", idpB + "#bob", "uid:1001"}}}},
		Budgets: []RoutingBudget{{ID: "b1", Scope: "user", Subject: "carol"}, {ID: "b2", Scope: "user", Subject: "*"}},
	}
	// One issuer: no bare-name warning; idp-b#bob names an issuer that is
	// not trusted (GAP-0895).
	if w := cfg.RoutingAdminIssuerWarnings(); len(w) != 1 || !strings.Contains(w[0], "routing_admin_unknown_issuer") {
		t.Fatalf("one issuer: warnings %v", w)
	}
	cfg.Substrate.Identity.WorkloadOIDC = []SubstrateWorkloadOIDCConfig{{Issuer: idpB}}
	w := cfg.RoutingAdminIssuerWarnings()
	has := func(s string, subs ...string) bool {
		for _, sub := range subs {
			if !strings.Contains(s, sub) {
				return false
			}
		}
		return true
	}
	if len(w) != 2 || !has(w[0], "rule r1", `"alice"`, idpA) || !has(w[1], "budget b1", `"carol"`) {
		t.Fatalf("two issuers: warnings %v", w)
	}
	if got := cfg.PersonIssuers(); !slices.Equal(got, []string{idpA, idpB}) {
		t.Fatalf("issuers %v", got)
	}
	if _, _, ok := SplitQualifiedUser("dom#user"); ok {
		t.Fatal("a host name with # is not issuer-qualified")
	}
}
