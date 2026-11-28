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
	"fmt"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/routing/engine"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
)

// GAP-0848: an administrator's budget view of an actor budget names the
// retired keys waiting to be stored and the bound; a user's view never
// does, and a budget with none has no retired_keys.
func TestGAP0848BudgetViewRetiredKeys(t *testing.T) {
	now := time.Date(2026, 11, 23, 12, 0, 0, 0, time.UTC)
	isolatedRoutingAdminRuntimeAt(t, now)
	cfg := actorBudgetConfig()
	if routingAdminRuntime.For(cfg) == nil {
		t.Fatal("evaluator")
	}
	l := routingAdminRuntime.Ledger()
	l.ApplyRemote([]string{"agent", "nightly", "daily"}, nil, now)
	l.SetKeyCap(1)
	for i := 0; i < 3; i++ {
		a := &engine.Actor{Key: fmt.Sprintf("reg-%d", i), Atespace: "eng", Person: true}
		routingAdminRuntime.Charge([]string{routingadmin.ActorBudgetKey("actor", "agent", a, "oidc:x")}, 1, now)
	}
	byID := func(admin bool) map[string]routingBudgetView {
		out := map[string]routingBudgetView{}
		for _, v := range routingBudgetViews(cfg, "uid:1001", admin, routingadmin.Caller{}, now) {
			out[v.ID] = v
		}
		return out
	}
	views := byID(true)
	r := views["agent"].RetiredKeys
	// Three keys at a bound of 1: one live, one retired waiting, one
	// dropped past the retired bound.
	if r == nil || r.Waiting != 1 || r.Dropped != 1 || r.Cap != 1 {
		t.Fatalf("admin view of agent: retired_keys %+v, want 1 waiting, 1 dropped, cap 1", r)
	}
	if views["nightly"].RetiredKeys != nil || views["daily"].RetiredKeys != nil {
		t.Fatal("budgets with no retired keys show retired_keys")
	}
	for id, v := range byID(false) {
		if v.RetiredKeys != nil {
			t.Fatalf("user view of %s shows retired_keys", id)
		}
	}
}
