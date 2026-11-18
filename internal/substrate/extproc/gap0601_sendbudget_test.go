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

package extproc

import (
	"context"
	"slices"
	"testing"
	"time"
)

// GAP-0601 follow-up (balanced defaults): a send's chain check waits
// chain.send_budget (250 ms), so a slow but healthy leader (GAP-0564) still
// answers a git push or fetch; only a leader that is down or slower than the
// budget gets the refusal.
func TestSendBudgetSlowHealthyLeaderGAP0601(t *testing.T) {
	ctx := context.Background()
	slow := 60 * time.Millisecond
	clear := newHarness(t, func(_ *Config, o *Options) { o.ChainChecker = fakeChecker{delay: slow} })
	if v := clear.eng.DecideHeaders(ctx, postBody("eng-web", "example.com")); !v.Allow ||
		slices.ContainsFunc(v.Findings, func(f string) bool { return f == "chain_unchecked:"+uncheckedTimeout }) {
		t.Fatalf("slow healthy leader, clear: POST want allowed on the verdict: %+v", v)
	}
	// A GET keeps the 20 ms budget: unchecked, allowed with an alert.
	if v := clear.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/")); !v.Allow || !v.Alert ||
		!slices.Contains(v.Findings, "chain_unchecked:"+uncheckedTimeout) {
		t.Fatalf("slow healthy leader, GET: %+v", v)
	}
	hit := newHarness(t, func(_ *Config, o *Options) {
		o.ChainChecker = fakeChecker{delay: slow, v: ChainVerdict{Deny: true, Rule: "secret_read_then_egress"}}
	})
	if v := hit.eng.DecideHeaders(ctx, postBody("eng-web", "example.com")); v.Allow || v.Category != CategoryChainEgress {
		t.Fatalf("slow healthy leader, hit: POST want chain_egress: %+v", v)
	}
}

func TestSendBudgetIsBoundedGAP0601(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, func(_ *Config, o *Options) { o.ChainChecker = fakeChecker{delay: 2 * time.Second} })
	start := time.Now()
	v := h.eng.DecideHeaders(ctx, postBody("eng-web", "example.com"))
	wantSendRefused(t, "leader slower than send_budget", v, uncheckedTimeout)
	if d := time.Since(start); d < 200*time.Millisecond || d > 900*time.Millisecond {
		t.Fatalf("send check took %s, want about send_budget 250ms", d)
	}
	// A longer check_budget wins over a shorter send_budget.
	h = newHarness(t, func(c *Config, o *Options) {
		o.ChainChecker = fakeChecker{delay: 300 * time.Millisecond}
		c.Chain.CheckBudget, c.Chain.SendBudget = 450*time.Millisecond, 100*time.Millisecond
	})
	if v := h.eng.DecideHeaders(ctx, postBody("eng-web", "example.com")); !v.Allow {
		t.Fatalf("check_budget 450ms over send_budget 100ms, 300ms leader: %+v", v)
	}
}

// The leader down keeps the refusal, without waiting for send_budget.
func TestSendBudgetLeaderDownStillRefusedGAP0601(t *testing.T) {
	ctx := context.Background()
	h, clock := outageHarness(t, false)
	if v := h.eng.DecideHeaders(ctx, req("eng-web", "GET", "example.com", "/")); !v.Allow {
		t.Fatalf("lookup up: %+v", v)
	}
	leaderDown(h)
	*clock = clock.Add(5 * time.Minute)
	wantSendRefused(t, "leader down", h.eng.DecideHeaders(ctx, postBody("eng-web", "example.com")), uncheckedLookup)
}

func TestSendBudgetConfigGAP0601(t *testing.T) {
	cfg, err := ParseConfig([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	if cfg.Chain.SendBudget != 250*time.Millisecond || cfg.Chain.CheckBudget != 20*time.Millisecond {
		t.Fatalf("defaults: check %s send %s", cfg.Chain.CheckBudget, cfg.Chain.SendBudget)
	}
	if _, err := ParseConfig([]byte(testConfig + "\nchain:\n  send_budget: 600ms\n")); err == nil {
		t.Fatal("send_budget 600ms accepted, want at most 500ms")
	}
}
