// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package spendleader

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
)

// TestSpendPushChunksAndTotalsPage (GAP-0814): a replica with more rows
// than one request carries still stores them all, and another replica reads
// them all back, page by page.
func TestSpendPushChunksAndTotalsPage(t *testing.T) {
	c, stop := startLeader(t, t.TempDir())
	defer stop()
	ctx := context.Background()
	day := time.Now().UTC().Format(time.DateOnly)
	const n = 2*maxSpendRows + 5000
	rows := make([]routingadmin.SeedRow, n)
	for i := range rows {
		rows[i] = routingadmin.SeedRow{Day: day, Key: fmt.Sprintf("actor:b:%06d", i), USD: 0.5}
	}
	if err := c.SpendPush(ctx, "epoch-aaaa", rows); err != nil {
		t.Fatalf("push of %d rows: %v", n, err)
	}
	got, err := c.SpendTotals(ctx, "epoch-bbbb", time.Now().AddDate(0, 0, -1), nil)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	var sum float64
	for _, r := range got {
		if seen[r.Key] {
			t.Fatalf("row %s read twice", r.Key)
		}
		seen[r.Key] = true
		sum += r.USD
	}
	if len(got) != n || sum != 0.5*n {
		t.Fatalf("read %d rows (sum %.1f), want %d (%.1f)", len(got), sum, n, 0.5*n)
	}
}
