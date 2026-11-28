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
	"context"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// GAP-1856 (review follow-up): a request still pinned to the generation
// before a reload compiles that generation after the reload applied the new
// one. It keeps its own evaluator but must not put back the budgets the
// reload removed (restarting their sync loop), nor stop the loop of budgets a
// reload added.
func TestGAP1856InFlightOldGenerationKeepsTheReload(t *testing.T) {
	isolatedRoutingAdminRuntime(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	local := &readCountingSpend{}
	routingAdminRuntime.SetCounters(ctx, local, nil, 0)
	s := &Sidecar{}
	r := &engineRouter{}
	budget := []config.RoutingBudget{{ID: "b-warn", Scope: "user", Subject: "*", Period: "day", LimitUSD: 50, OnExceed: "warn"}}
	for name, removed := range map[string]*config.Config{
		"budgets removed":       budgetReloadConfig(nil),
		"routing.admin removed": {DataDir: "unused"},
	} {
		old := budgetReloadConfig(budget)
		s.applyRoutingAdmin(old)
		if r.adminFor(old) == nil || !kickedReads(local) {
			t.Fatalf("%s: no evaluator or no budget sync loop with a budget", name)
		}
		var wg sync.WaitGroup
		for range 8 {
			wg.Add(1)
			go func() {
				defer wg.Done()
				for range 200 {
					if r.adminFor(old) == nil {
						t.Errorf("%s: a request pinned to the old generation lost its evaluator", name)
						return
					}
				}
			}()
		}
		s.applyRoutingAdmin(removed)
		wg.Wait()
		// One more old-generation request after the reload (the review's
		// scenario), then the next one on the new generation.
		if r.adminFor(old) == nil {
			t.Fatalf("%s: the old generation's request lost its evaluator", name)
		}
		if kickedReads(local) {
			t.Fatalf("%s: an old-generation request after the reload restarted the removed budgets' sync loop (%d reads)", name, local.reads.Load())
		}
		r.adminFor(removed)
		if kickedReads(local) {
			t.Fatalf("%s: the sync loop runs on the new generation", name)
		}
	}
	noAdmin := &config.Config{DataDir: "unused"}
	s.applyRoutingAdmin(noAdmin)
	added := budgetReloadConfig(budget)
	s.applyRoutingAdmin(added)
	r.adminFor(noAdmin)
	if !kickedReads(local) {
		t.Fatal("a request pinned to the generation without routing.admin stopped the sync loop of the budgets the reload added")
	}
}
