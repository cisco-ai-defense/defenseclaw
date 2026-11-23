// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package spendleader

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/routingadmin"
)

// TestOldClientGetsEveryRow (GAP-0847, RV4 PROBE-D): a 1.0.10 replica asks
// without page and reads the whole answer, today's rows included.
func TestOldClientGetsEveryRow(t *testing.T) {
	c, stop := startLeader(t, t.TempDir())
	defer stop()
	ctx := context.Background()
	yday := time.Now().UTC().AddDate(0, 0, -1).Format(time.DateOnly)
	today := time.Now().UTC().Format(time.DateOnly)
	var rows []routingadmin.SeedRow
	for i := 0; i < maxSpendRows; i++ {
		rows = append(rows, routingadmin.SeedRow{Day: yday, Key: fmt.Sprintf("actor:b:%06d", i), USD: 0.5})
	}
	for i := 0; i < 5000; i++ {
		rows = append(rows, routingadmin.SeedRow{Day: today, Key: fmt.Sprintf("user:d:*:p:%06d", i), USD: 1})
	}
	if err := c.SpendPush(ctx, "epoch-aaaa", rows); err != nil {
		t.Fatal(err)
	}
	var out SpendTotalsAnswer
	old := SpendTotalsRequest{Epoch: "epoch-bbbb", Since: yday}
	if err := c.call(ctx, MethodSpendTotals, old, &out); err != nil {
		t.Fatal(err)
	}
	n := 0
	for _, r := range out.Rows {
		if r.Day == today {
			n++
		}
	}
	if len(out.Rows) != len(rows) || n != 5000 || out.More {
		t.Fatalf("old client read %d rows (%d of today's 5000, more %v), want %d", len(out.Rows), n, out.More, len(rows))
	}
}

// TestSpendChunksBoundedByBytes (GAP-0853): rows with keys of maxKeyLen are
// pushed and read in chunks under the body limit.
func TestSpendChunksBoundedByBytes(t *testing.T) {
	c, stop := startLeader(t, t.TempDir())
	defer stop()
	ctx := context.Background()
	day := time.Now().UTC().Format(time.DateOnly)
	rows := make([]routingadmin.SeedRow, maxSpendRows)
	for i := range rows {
		k := fmt.Sprintf("user:b:*:%06d:", i)
		rows[i] = routingadmin.SeedRow{Day: day, Key: k + strings.Repeat("x", maxKeyLen-len(k)), USD: 1}
	}
	if err := c.SpendPush(ctx, "epoch-aaaa", rows); err != nil {
		t.Fatalf("push of %d long-key rows: %v", len(rows), err)
	}
	got, err := c.SpendTotals(ctx, "epoch-bbbb", time.Now().AddDate(0, 0, -1), nil)
	if err != nil || len(got) != len(rows) {
		t.Fatalf("read %d rows, want %d: %v", len(got), len(rows), err)
	}
}

// TestSpendTotalsByKeyList (GAP-0849): with a key list the read holds every
// uncapped row and only the listed capped keys, in requests of at most
// maxKeys keys, each row once.
func TestSpendTotalsByKeyList(t *testing.T) {
	c, stop := startLeader(t, t.TempDir())
	defer stop()
	ctx := context.Background()
	day := time.Now().UTC().Format(time.DateOnly)
	var rows []routingadmin.SeedRow
	var keys []string
	for i := 0; i < maxKeys+10; i++ {
		k := fmt.Sprintf("actor:b:%06d", i)
		keys = append(keys, k)
		rows = append(rows, routingadmin.SeedRow{Day: day, Key: k, USD: 1})
	}
	for i := 0; i < 3000; i++ { // other replicas' launcher keys
		rows = append(rows, routingadmin.SeedRow{Day: day, Key: fmt.Sprintf("batch:n:other-%06d", i), USD: 1})
	}
	rows = append(rows, routingadmin.SeedRow{Day: day, Key: "user:d:*:p", USD: 7}, routingadmin.SeedRow{Day: day, Key: "group:g:eng", USD: 2})
	if err := c.SpendPush(ctx, "epoch-aaaa", rows); err != nil {
		t.Fatal(err)
	}
	got, err := c.SpendTotals(ctx, "epoch-bbbb", time.Now().AddDate(0, 0, -1), keys)
	if err != nil {
		t.Fatal(err)
	}
	seen := map[string]bool{}
	for _, r := range got {
		if seen[r.Key] || strings.HasPrefix(r.Key, "batch:") {
			t.Fatalf("row %s read twice or not asked for", r.Key)
		}
		seen[r.Key] = true
	}
	if len(got) != len(keys)+2 || !seen["user:d:*:p"] || !seen["group:g:eng"] {
		t.Fatalf("read %d rows, want %d", len(got), len(keys)+2)
	}
	if got, err := c.SpendTotals(ctx, "epoch-bbbb", time.Now().AddDate(0, 0, -1), []string{}); err != nil || len(got) != 2 {
		t.Fatalf("no capped keys: %d rows (%v), want the 2 uncapped", len(got), err)
	}
}
