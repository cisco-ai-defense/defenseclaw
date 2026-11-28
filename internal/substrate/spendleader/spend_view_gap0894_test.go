// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package spendleader

import (
	"context"
	"fmt"
	"math"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
)

// viewReplica is a gateway replica on the leader c that syncs every 20 ms.
func viewReplica(t *testing.T, c *Client) *routingadmin.Runtime {
	t.Helper()
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	rt := routingadmin.NewRuntime()
	cfg := &config.Config{}
	cfg.Routing.Admin = &config.RoutingAdminConfig{Budgets: overBudgets}
	rt.For(cfg)
	rt.SetInterval(20 * time.Millisecond)
	rt.SetCounters(ctx, routingadmin.NewLeaderCounter(c), nil, 20*time.Millisecond)
	return rt
}

func eventually(t *testing.T, what string, ok func() (bool, string)) {
	t.Helper()
	var last string
	for deadline := time.Now().Add(10 * time.Second); time.Now().Before(deadline); time.Sleep(20 * time.Millisecond) {
		var done bool
		if done, last = ok(); done {
			return
		}
	}
	t.Fatalf("%s: %s", what, last)
}

// TestAdminViewSumsEveryReplica (GAP-0894, RV5 F3): each replica holds
// only its own actor and batch keys, so the admin view (routing budgets
// list, doctor, the budget gauges) showed one replica's spend. With two
// replicas, each now shows the cluster's sum of a batch budget.
func TestAdminViewSumsEveryReplica(t *testing.T) {
	c, stop := startLeader(t, t.TempDir())
	defer stop()
	a, b := viewReplica(t, c), viewReplica(t, c)
	now := time.Now()
	a.Charge([]string{overKey("run-1")}, 4, now)
	a.Charge([]string{overKey("run-2")}, 11, now)
	b.Charge([]string{overKey("run-3")}, 2, now)
	for name, rt := range map[string]*routingadmin.Runtime{"a": a, "b": b} {
		l := rt.Ledger()
		eventually(t, "replica "+name+" view", func() (bool, string) {
			total, known := l.SpendPrefix("batch:nightly:", "day", time.Now())
			snap, _ := l.Snapshot("batch:nightly:", "day", 10, time.Now())
			return known && math.Abs(total-17) < 1e-6 && snap.Subjects == 3 && snap.Exceeded == 1,
				fmt.Sprintf("total %.2f subjects %d exceeded %d (want 17, 3, 1)", total, snap.Subjects, snap.Exceeded)
		})
	}
}

// TestActorListReadsListedKeys (GAP-0894): the substrate actor list reads
// the keys of the agents it lists from the leader, so an agent another
// replica runs shows its spend.
func TestActorListReadsListedKeys(t *testing.T) {
	c, stop := startLeader(t, t.TempDir())
	defer stop()
	a, b := viewReplica(t, c), viewReplica(t, c)
	a.Charge([]string{overKey("run-1")}, 4, time.Now())
	b.Charge([]string{overKey("run-1")}, 1, time.Now())
	eventually(t, "replica b reads run-1", func() (bool, string) {
		b.ReadViewKeys(context.Background(), []string{overKey("run-1"), overKey("run-none"), "user:x:*:p"})
		v, known := b.Ledger().ViewSpend(overKey("run-1"), "day", time.Now())
		n, _ := b.Ledger().ViewSpend(overKey("run-none"), "day", time.Now())
		return known && math.Abs(v-5) < 1e-6 && n == 0, fmt.Sprintf("run-1 %.2f (want 5), run-none %.2f", v, n)
	})
}

// TestSpendSumsValidated (GAP-0894): a sum names an actor or batch budget
// prefix, a date and a positive limit.
func TestSpendSumsValidated(t *testing.T) {
	c, stop := startLeader(t, t.TempDir())
	defer stop()
	day := time.Now().UTC().Format(time.DateOnly)
	for _, s := range [][]SpendOver{nil, {{Prefix: "user:x:", Since: day, Limit: 1}}, {{Prefix: "batch:x:", Since: "x", Limit: 1}}, {{Prefix: "batch:x:", Since: day}}} {
		var out SpendSumsAnswer
		if err := c.call(context.Background(), MethodSpendSums, SpendSumsRequest{Epoch: "epoch-bbbb", Sums: s}, &out); err == nil {
			t.Errorf("sums %+v: accepted", s)
		}
	}
}
