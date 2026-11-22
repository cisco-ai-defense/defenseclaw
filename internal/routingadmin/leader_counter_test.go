// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingadmin

import (
	"context"
	"errors"
	"testing"
	"time"
)

// memRPC is a leader that keeps LocalCounter files, as the real one does.
type memRPC struct {
	c    *LocalCounter
	down bool
}

func (m *memRPC) SpendPush(ctx context.Context, epoch string, rows []SeedRow) error {
	if m.down {
		return errors.New("leader did not answer")
	}
	return m.c.Push(ctx, epoch, rows)
}

func (m *memRPC) SpendTotals(ctx context.Context, epoch string, since time.Time, keys []string) ([]SeedRow, error) {
	if m.down {
		return nil, errors.New("leader did not answer")
	}
	return m.c.Totals(ctx, epoch, since, keys)
}

// TestLeaderCounterSumsReplicas: two replicas (two epochs) charge one key; each
// reads the other's spend through the leader and never its own twice.
func TestLeaderCounterSumsReplicas(t *testing.T) {
	leader := &memRPC{c: NewLocalCounter(t.TempDir())}
	defer leader.c.Close()
	day := time.Now().UTC().Format(time.DateOnly)
	a, b := NewLeaderCounter(leader), NewLeaderCounter(leader)
	ctx := context.Background()
	since := time.Now().AddDate(0, 0, -2)
	if err := a.Push(ctx, "epoch-a", []SeedRow{{Day: day, Key: "user:day:p:1", USD: 1.5}}); err != nil {
		t.Fatal(err)
	}
	if err := b.Push(ctx, "epoch-b", []SeedRow{{Day: day, Key: "user:day:p:1", USD: 2}}); err != nil {
		t.Fatal(err)
	}
	// absolute totals: a re-send of a's later total replaces its earlier one
	if err := a.Push(ctx, "epoch-a", []SeedRow{{Day: day, Key: "user:day:p:1", USD: 2.5}}); err != nil {
		t.Fatal(err)
	}
	ra, err := a.Totals(ctx, "epoch-a", since, nil)
	if err != nil || len(ra) != 1 || ra[0].USD != 2 {
		t.Fatalf("a reads b only: %+v %v", ra, err)
	}
	rb, _ := b.Totals(ctx, "epoch-b", since, nil)
	if len(rb) != 1 || rb[0].USD != 2.5 {
		t.Fatalf("b reads a only, at its latest total: %+v", rb)
	}
}

// TestLeaderCounterStaleSpendIsUnknown: a leader that stops answering keeps the
// last totals for 3 x the interval, then the budget reads as not loaded; OSS
// warns and managed refuses with budget_unavailable (D4-2).
func TestLeaderCounterStaleSpendIsUnknown(t *testing.T) {
	now := time.Date(2026, 11, 22, 12, 0, 0, 0, time.UTC)
	clock := &now
	l := NewLedgerClock(func() time.Time { return *clock })
	l.SetStaleAfter(15 * time.Second)
	l.ApplyRemote([]string{"day"}, []SeedRow{{Day: "2026-11-22", Key: "user:day:p:1", USD: 3}}, now)
	if v, ok := l.Spend("user:day:p:1", "day", now.Add(10*time.Second)); !ok || v != 3 {
		t.Fatalf("fresh: %v %v", v, ok)
	}
	if _, ok := l.Spend("user:day:p:1", "day", now.Add(16*time.Second)); ok {
		t.Fatal("stale remote spend must read as not loaded")
	}
	l.ApplyRemote([]string{"day"}, nil, now.Add(20*time.Second))
	if _, ok := l.Spend("user:day:p:1", "day", now.Add(21*time.Second)); !ok {
		t.Fatal("a new answer makes the spend known again")
	}
	// a device (no stale window) keeps the last totals
	d := NewLedgerClock(func() time.Time { return *clock })
	d.ApplyRemote([]string{"day"}, nil, now)
	if _, ok := d.Spend("user:day:p:1", "day", now.Add(48*time.Hour)); !ok {
		t.Fatal("no stale window: totals stay")
	}
}
