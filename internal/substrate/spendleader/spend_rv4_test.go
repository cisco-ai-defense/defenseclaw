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

// TestSpendTotalsAlwaysPaged (GAP-0940): no release has a spend leader, so
// there is no older replica to answer in one piece and no older leader to
// tolerate: every read is paged, and the leader still refuses a field it
// does not know (the removed "page" too), never ignoring it.
func TestSpendTotalsAlwaysPaged(t *testing.T) {
	c, stop := startLeader(t, t.TempDir())
	defer stop()
	ctx := context.Background()
	yday := time.Now().UTC().AddDate(0, 0, -1).Format(time.DateOnly)
	var rows []routingadmin.SeedRow
	for i := 0; i < maxSpendRows+10; i++ {
		rows = append(rows, routingadmin.SeedRow{Day: yday, Key: fmt.Sprintf("user:d:*:p:%06d", i), USD: 0.5})
	}
	if err := c.SpendPush(ctx, "epoch-aaaa", rows); err != nil {
		t.Fatal(err)
	}
	var out SpendTotalsAnswer
	if err := c.call(ctx, MethodSpendTotals, SpendTotalsRequest{Epoch: "epoch-bbbb", Since: yday}, &out); err != nil {
		t.Fatal(err)
	}
	if len(out.Rows) != maxSpendRows || !out.More {
		t.Fatalf("first page: %d rows (more %v), want %d and more", len(out.Rows), out.More, maxSpendRows)
	}
	got, err := c.SpendTotals(ctx, "epoch-bbbb", time.Now().AddDate(0, 0, -1), nil)
	if err != nil || len(got) != len(rows) {
		t.Fatalf("paged read: %d rows, %v; want %d", len(got), err, len(rows))
	}
	type withPage struct {
		SpendTotalsRequest
		Page bool `json:"page"`
	}
	err = c.call(ctx, MethodSpendTotals, withPage{SpendTotalsRequest{Epoch: "epoch-bbbb", Since: yday}, true}, &out)
	if err == nil || !strings.Contains(err.Error(), "decode") {
		t.Fatalf("unknown field page: %v, want a decode refusal", err)
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
