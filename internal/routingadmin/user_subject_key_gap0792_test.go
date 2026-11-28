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

package routingadmin

import (
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-0792 point 3: the evaluator (Compile) and the budget views
// (BudgetChargeKey) key a named user budget with one function: a bare name
// keeps the key it had before (no spend reset on upgrade), a qualified
// subject keys on its person id, and the two never share a key.
func TestGAP0792UserSubjectKeyParity(t *testing.T) {
	bare := config.RoutingBudget{ID: "mine", Scope: "user", Subject: "alice", Period: "day", LimitUSD: 10, OnExceed: "warn"}
	qual := config.RoutingBudget{ID: "mine", Scope: "user", Subject: "https://idp-b.example#alice", Period: "day", LimitUSD: 10, OnExceed: "warn"}
	if got, want := BudgetChargeKey(bare), "user:mine:="+shortHash("alice"); got != want {
		t.Fatalf("bare key %q, want the pre-upgrade key %q", got, want)
	}
	if BudgetChargeKey(bare) == BudgetChargeKey(qual) {
		t.Fatal("alice and idp-b#alice share a key")
	}
	for _, b := range []config.RoutingBudget{bare, qual} {
		p := Compile(nil, []config.RoutingBudget{b}, true)
		c := Caller{Verified: true, Key: "oidc:x", Match: func(m config.ProfileMatch) MatchState {
			if slices.Equal(m.Users, []string{b.Subject}) {
				return Yes
			}
			return No
		}}
		v := p.Evaluate(Request{Caller: c}, seededLedger(p.BudgetIDs()...), now)
		if k := BudgetChargeKey(b); !slices.Equal(v.ChargeKeys, []string{k}) {
			t.Fatalf("%s: charged %v, view key %q", b.Subject, v.ChargeKeys, k)
		}
	}
}
