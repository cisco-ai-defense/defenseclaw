// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingadmin

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

// TestGAP0941ExceededFollowsTheCurrentLimit (RV6 P6): the leader's sums
// were read with limit 10 (one key at 15, exceeded). After the limit is
// raised to 20 the admin view shows 0 exceeded at once, not for up to two
// intervals; lowered below the old limit it shows at least the old count.
func TestGAP0941ExceededFollowsTheCurrentLimit(t *testing.T) {
	rt := NewRuntime()
	cfg := &config.Config{}
	cfg.Routing.Admin = &config.RoutingAdminConfig{Budgets: []config.RoutingBudget{
		{ID: "nightly", Scope: "batch", Subject: "*", Period: "day", LimitUSD: 10, OnExceed: "deny"}}}
	rt.For(cfg)
	l := rt.Ledger()
	now := time.Now().UTC()
	day := now.Truncate(24 * time.Hour)
	l.SetPrefixSums([]SumQuery{{Prefix: "batch:nightly:", Since: day, Limit: 10}},
		[]PrefixSum{{Prefix: "batch:nightly:", Total: 27, Peak: 15, Subjects: 2, Exceeded: 2}}, now.Add(time.Minute))
	l.ApplyRemote([]string{"nightly"}, nil, now)
	for _, c := range []struct {
		limit float64
		want  int
	}{
		{10, 2}, // the read's own limit
		{20, 0}, // raised above the highest key (the probe: 10 -> 20, peak 15)
		{15, 1}, // raised to the highest key: at least that one
		{5, 2},  // lowered: every key over 10 is over 5
		{0, 0},  // SpendPrefix: no limit, nothing counted
	} {
		snap, ok := l.Snapshot("batch:nightly:", "day", c.limit, now)
		if !ok || snap.Exceeded != c.want || snap.Peak != 15 || snap.Subjects != 2 {
			t.Errorf("limit %v: %+v (ok %v), want exceeded %d", c.limit, snap, ok, c.want)
		}
	}
}
