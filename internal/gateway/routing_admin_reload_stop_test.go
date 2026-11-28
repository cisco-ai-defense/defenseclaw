// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
)

// readCountingSpend is a device spend counter that counts its reads.
type readCountingSpend struct{ reads atomic.Int64 }

func (c *readCountingSpend) Push(context.Context, string, []routingadmin.SeedRow) error {
	return nil
}

func (c *readCountingSpend) Totals(context.Context, string, time.Time, []string) ([]routingadmin.SeedRow, error) {
	c.reads.Add(1)
	return nil, nil
}

func budgetReloadConfig(budgets []config.RoutingBudget) *config.Config {
	cfg := &config.Config{DataDir: "unused"}
	cfg.Routing.Models = []config.RoutingModelBackend{{Name: "fast", Provider: "openai", Model: "gpt-mini"}}
	cfg.Routing.Admin = &config.RoutingAdminConfig{Budgets: budgets}
	return cfg
}

// kickedReads reports whether asking the sync loop to sync now reads the
// spend counter again: true while a loop runs, false once it stopped.
func kickedReads(c *readCountingSpend) bool {
	settled := c.reads.Load()
	for {
		time.Sleep(50 * time.Millisecond)
		n := c.reads.Load()
		if n == settled {
			break
		}
		settled = n
	}
	for range 20 {
		routingAdminRuntime.Kick()
		time.Sleep(10 * time.Millisecond)
		if c.reads.Load() != settled {
			return true
		}
	}
	return false
}

// GAP-1856: a hot reload that removes every budget stops the budget sync
// loop when it applies, with no routed request after it; a reload that adds
// budgets back starts it again, also with no request. The sync interval is
// the 30 s default here, so a read within the test comes from the loop
// answering a kick.
func TestRoutingAdminReloadStopsAndStartsBudgetSync(t *testing.T) {
	isolatedRoutingAdminRuntime(t)
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	local := &readCountingSpend{}
	routingAdminRuntime.SetCounters(ctx, local, nil, 0)
	s := &Sidecar{}
	budget := []config.RoutingBudget{{ID: "b-warn", Scope: "user", Subject: "*", Period: "day", LimitUSD: 50, OnExceed: "warn"}}
	withBudget := budgetReloadConfig(budget)
	s.applyRoutingAdmin(withBudget)
	// A routed request with this generation (what started the loop before).
	routingAdminRuntime.For(withBudget)
	if !kickedReads(local) {
		t.Fatal("no budget sync loop runs with a budget")
	}
	for name, removed := range map[string]*config.Config{
		"budgets removed":       budgetReloadConfig(nil),
		"routing.admin removed": {DataDir: "unused"},
	} {
		s.applyRoutingAdmin(removed)
		if kickedReads(local) {
			t.Fatalf("%s: the budget sync loop still reads the spend counter after the reload, with no routed request (%d reads)", name, local.reads.Load())
		}
		s.applyRoutingAdmin(budgetReloadConfig(budget))
		if !kickedReads(local) {
			t.Fatalf("%s: a reload that adds a budget back did not start the sync loop", name)
		}
	}
}
