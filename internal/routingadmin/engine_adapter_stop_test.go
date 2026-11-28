// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingadmin

import (
	"context"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

type countingCounter struct {
	fakeCounter
	reads atomic.Int64
}

func (c *countingCounter) Totals(ctx context.Context, epoch string, since time.Time, keys []string) ([]SeedRow, error) {
	c.reads.Add(1)
	return c.fakeCounter.Totals(ctx, epoch, since, keys)
}

// readsGrow waits until the counter was read more than n times.
func readsGrow(t *testing.T, c *countingCounter, n int64) {
	t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for c.reads.Load() <= n && time.Now().Before(deadline) {
		time.Sleep(5 * time.Millisecond)
	}
	if c.reads.Load() <= n {
		t.Fatalf("the sync loop did not read the counter (%d reads)", c.reads.Load())
	}
}

// readsSettle reports whether the counter goes quiet for 150 ms within 5 s.
func readsSettle(c *countingCounter) bool {
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		n := c.reads.Load()
		time.Sleep(150 * time.Millisecond)
		if c.reads.Load() == n {
			return true
		}
	}
	return false
}

// A hot reload that removes every budget (routing.admin gone, or rules
// only) stops the sync loop after its last push: no more counter reads,
// spend writes or fleet requests. Budgets again restart it
// (rel-1-0-10:GAP-1716).
func TestRuntimeSyncLoopStopsWhenBudgetsAreRemoved(t *testing.T) {
	rulesOnly := adapterConfig([]config.RoutingAdminRule{{ID: "r", Match: config.RoutingAdminMatch{Connectors: []string{"codex"}}, Allow: []string{"fast"}}}, nil)
	for name, off := range map[string]*config.Config{"no routing.admin": {}, "rules only": rulesOnly} {
		t.Run(name, func(t *testing.T) {
			rt := NewRuntime()
			local := &countingCounter{}
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			rt.SetCounters(ctx, local, nil, 2*time.Millisecond)
			rt.For(adapterConfig(nil, dailyBudget()))
			readsGrow(t, local, 2)
			rt.Charge([]string{"user:d:*:owner"}, 2, time.Now())
			rt.For(off)
			if !readsSettle(local) {
				t.Fatalf("the sync loop still reads the counter after the budgets were removed (%d reads)", local.reads.Load())
			}
			if local.pushedRows() == 0 {
				t.Fatal("the spend so far is stored when the budgets go")
			}
			rt.For(adapterConfig(nil, dailyBudget()))
			readsGrow(t, local, local.reads.Load()+2)
		})
	}
}
