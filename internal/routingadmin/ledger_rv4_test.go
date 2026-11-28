// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingadmin

import (
	"context"
	"errors"
	"fmt"
	"math"
	"slices"
	"strings"
	"testing"
	"time"
)

// hookCounter runs before on each push (store: also store the rows when
// before fails, as a lost ack does).
type hookCounter struct {
	*LocalCounter
	before func(epoch string) (store bool, err error)
}

func (h *hookCounter) Push(ctx context.Context, epoch string, rows []SeedRow) error {
	if h.before != nil {
		store, err := h.before(epoch)
		if err != nil {
			if store {
				_ = h.LocalCounter.Push(ctx, epoch, rows)
			}
			return err
		}
	}
	return h.LocalCounter.Push(ctx, epoch, rows)
}

func hookRuntime(t *testing.T) (*Runtime, *hookCounter) {
	rt, c := retireRuntime(t)
	h := &hookCounter{LocalCounter: c}
	rt.mu.Lock()
	rt.local = h
	rt.mu.Unlock()
	return rt, h
}

func rk(b string) string { return batchKey("nightly", "eng-web", testPersonKey, b) }

func isRetiredEpoch(epoch string) bool { return strings.Contains(epoch, ".r") }

// ownSpend is key's spend today on this replica.
func ownSpend(l *Ledger, key string) float64 {
	v, _ := l.Spend(key, "day", time.Now())
	return v
}

func near(a, b float64) bool { return math.Abs(a-b) < 1e-6 }

// TestRetiredDrainsUnderChurnAtKeyCap (GAP-0845, RV4 PROBE-A at the real
// 4096-key cap): new agents evict keys while every retired push is in
// flight. Each acked generation drains, nothing counts twice here, and
// another replica reads the true spend.
func TestRetiredDrainsUnderChurnAtKeyCap(t *testing.T) {
	ctx := context.Background()
	rt, h := hookRuntime(t)
	l := rt.Ledger()
	l.SetKeyCap(DefaultKeyCap)
	rt.Charge([]string{rk("run-A")}, 9, time.Now())
	for i := 1; i < DefaultKeyCap; i++ {
		rt.Charge([]string{rk(fmt.Sprintf("live-%d", i))}, 0.01, time.Now())
	}
	rt.SyncOnce(ctx)
	rt.Charge([]string{rk("fan-0")}, 0.01, time.Now()) // evicts run-A
	n := 0
	h.before = func(epoch string) (bool, error) {
		if isRetiredEpoch(epoch) {
			for i := 0; i < 50; i++ { // fan-out: 50 first calls evict 50 keys
				n++
				rt.Charge([]string{rk(fmt.Sprintf("fan-%d", n))}, 0.01, time.Now())
			}
		}
		return false, nil
	}
	for round := 0; round < 5; round++ {
		rt.SyncOnce(ctx)
		if waiting, _ := l.RetiredKeys("nightly"); waiting > 50 {
			t.Fatalf("round %d: %d retired keys wait, want at most the 50 evicted during the push", round, waiting)
		}
		if own := ownSpend(l, rk("run-A")); !near(own, 9) {
			t.Fatalf("round %d: run-A reads %.2f here, true 9", round, own)
		}
	}
	if other := counterSpend(t, h.LocalCounter, rk("run-A")); !near(other, 9) {
		t.Fatalf("another replica reads run-A %.2f, true 9", other)
	}
	// Every key's spend is counted once, here and on the counter.
	var want = 9 + 0.01*float64(DefaultKeyCap-1+1+n)
	h.before = nil
	rt.SyncOnce(ctx)
	snap, _ := l.Snapshot("batch:nightly:", "day", 0, time.Now())
	if !near(snap.Total, want) {
		t.Fatalf("here the budget totals %.4f, want %.4f", snap.Total, want)
	}
	var other float64
	rows, err := h.Totals(ctx, "epoch-other-replica", time.Now().AddDate(0, 0, -1), nil)
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range rows {
		other += r.USD
	}
	if !near(other, want) {
		t.Fatalf("another replica totals %.4f, want %.4f", other, want)
	}
}

// TestFailedRetiredPushKeepsStoredSpend (GAP-0846, RV4 PROBE-B): the retired
// push fails and the process-epoch push succeeds: a re-charged evicted key
// still reads its whole spend on another replica.
func TestFailedRetiredPushKeepsStoredSpend(t *testing.T) {
	ctx := context.Background()
	rt, h := hookRuntime(t)
	rt.Charge([]string{rk("run-A")}, 9, time.Now())
	rt.SyncOnce(ctx)
	rt.Charge([]string{rk("run-B")}, 0.01, time.Now())
	rt.Charge([]string{rk("run-C")}, 0.01, time.Now()) // evicts run-A
	rt.Charge([]string{rk("run-A")}, 1, time.Now())    // re-add
	h.before = func(epoch string) (bool, error) {
		if isRetiredEpoch(epoch) {
			return false, errors.New("leader busy")
		}
		return false, nil
	}
	rt.SyncOnce(ctx)
	if other := counterSpend(t, h.LocalCounter, rk("run-A")); !near(other, 10) {
		t.Fatalf("retired push failed: another replica reads run-A %.2f, true 10", other)
	}
	h.before = nil
	rt.SyncOnce(ctx)
	if other := counterSpend(t, h.LocalCounter, rk("run-A")); !near(other, 10) {
		t.Fatalf("after the retired push: another replica reads run-A %.2f, true 10", other)
	}
	if own := ownSpend(rt.Ledger(), rk("run-A")); !near(own, 10) {
		t.Fatalf("here run-A reads %.2f, true 10", own)
	}
}

// TestRotateAfterFailedRetiredPush (GAP-0850, RV4 PROBE-C): the retired push
// fails at a writer rotation; the old epoch's rows are still set once the
// generation is stored, so nothing counts twice for the window.
func TestRotateAfterFailedRetiredPush(t *testing.T) {
	for _, recharge := range []float64{0, 1} {
		t.Run(fmt.Sprintf("recharge-%v", recharge), func(t *testing.T) {
			ctx := context.Background()
			rt, h := hookRuntime(t)
			rt.SetFleet(&writerFleet{id: "d-old"}, nil)
			rt.Charge([]string{rk("run-A")}, 9, time.Now())
			rt.push(ctx)
			rt.Charge([]string{rk("run-B")}, 0.01, time.Now())
			rt.Charge([]string{rk("run-C")}, 0.01, time.Now()) // evicts run-A
			if recharge > 0 {
				rt.Charge([]string{rk("run-A")}, recharge, time.Now()) // evicts run-B
			}
			h.before = func(epoch string) (bool, error) {
				if isRetiredEpoch(epoch) {
					return false, errors.New("leader busy")
				}
				return false, nil
			}
			rt.SetFleet(&writerFleet{id: "d-new"}, nil)
			h.before = nil
			for i := 0; i < 3; i++ {
				rt.push(ctx)
			}
			if other := counterSpend(t, h.LocalCounter, rk("run-A")); !near(other, 9+recharge) {
				t.Fatalf("another replica reads run-A %.2f after rotation, true %.2f", other, 9+recharge)
			}
		})
	}
}

// TestRetiredKeysBounded (GAP-0848): with every push refused, at most keyCap
// retired keys wait per budget. Past it an OSS (or warn, downgrade) budget
// drops the oldest, warns budget_keys_evicted and counts it, never blocks; a
// managed deny budget keeps them and refuses new keys (budget_unavailable).
func TestRetiredKeysBounded(t *testing.T) {
	for _, managed := range []bool{false, true} {
		t.Run(fmt.Sprintf("managed-%v", managed), func(t *testing.T) {
			p := Compile(nil, batchBudgets, managed)
			l := seededLedger(p.BudgetIDs()...)
			l.SetKeyCap(2)
			l.SetHoldFull(p.HoldFullIDs())
			for i := 0; i < 8; i++ {
				l.Charge([]string{batchKey("nightly", "eng-web", testPersonKey, fmt.Sprintf("run-%d", i))}, 0.01, now)
			}
			waiting, dropped := l.RetiredKeys("nightly")
			fresh := p.Evaluate(batchCall("eng-web", "a1", "run-new", testPersonKey), l, now)
			live := p.Evaluate(batchCall("eng-web", "a1", "run-7", testPersonKey), l, now)
			if denyCode(live) != "" {
				t.Fatalf("a live key is refused: %+v", live)
			}
			if !managed {
				if waiting != 2 || dropped != 4 {
					t.Fatalf("waiting %d dropped %d, want 2 and 4", waiting, dropped)
				}
				if denyCode(fresh) != "" || !slices.Contains(fresh.Warnings, "budget_keys_evicted:nightly") {
					t.Fatalf("OSS new key: %+v", fresh)
				}
				return
			}
			if waiting != 6 || dropped != 0 {
				t.Fatalf("managed deny: waiting %d dropped %d, want 6 and 0", waiting, dropped)
			}
			if denyCode(fresh) != "budget_unavailable:nightly" {
				t.Fatalf("managed deny new key at the bound: %+v", fresh)
			}
		})
	}
}

// TestCappedReadByKeyList (GAP-0849): the cluster read asks for this
// process's capped keys only, so other replicas' launcher keys never make it
// too large; uncapped keys come in full.
func TestCappedReadByKeyList(t *testing.T) {
	rt, c := retireRuntime(t)
	l := rt.Ledger()
	rt.Charge([]string{rk("run-A")}, 1, time.Now())
	rt.Charge([]string{rk("run-B")}, 1, time.Now())
	rt.Charge([]string{rk("run-C")}, 1, time.Now()) // evicts run-A (retired)
	want := []string{rk("run-A"), rk("run-B"), rk("run-C")}
	slices.Sort(want)
	if got := l.CappedKeys(); !slices.Equal(got, want) {
		t.Fatalf("capped keys %v", got)
	}
	day := time.Now().UTC().Format(time.DateOnly)
	if err := c.Push(context.Background(), "epoch-other-replica", []SeedRow{
		{Day: day, Key: rk("run-B"), USD: 2}, {Day: day, Key: rk("elsewhere"), USD: 5}, {Day: day, Key: "user:u:*:p", USD: 3}}); err != nil {
		t.Fatal(err)
	}
	rows, err := c.TotalsPage(context.Background(), "epoch-self", time.Now().AddDate(0, 0, -1), TotalsQuery{ByKey: true, Keys: l.CappedKeys()})
	if err != nil {
		t.Fatal(err)
	}
	var keys []string
	for _, r := range rows {
		keys = append(keys, r.Key)
	}
	if want := []string{rk("run-B"), "user:u:*:p"}; !slices.Equal(keys, want) {
		t.Fatalf("by-key read %v", keys)
	}
}
