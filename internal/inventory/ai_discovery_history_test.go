// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func newHistoryTestService(t *testing.T) *ContinuousDiscoveryService {
	t.Helper()
	dir := t.TempDir()
	svc := NewContinuousDiscoveryServiceWithOptions(AIDiscoveryOptions{
		Enabled: true, DataDir: dir, HomeDir: dir, ScanRoots: []string{dir},
	}, nil)
	t.Cleanup(func() { _ = svc.Close() })
	if svc.InventoryStore() == nil {
		t.Fatal("test requires an inventory store")
	}
	return svc
}

func TestHistoryRetentionDaysDefaultsToObservabilityWindow(t *testing.T) {
	svc := newHistoryTestService(t)
	if got := svc.HistoryRetentionDays(); got != config.ObservabilityV8DefaultRetentionDays {
		t.Fatalf("default retention = %d, want %d", got, config.ObservabilityV8DefaultRetentionDays)
	}
	svc.SetHistoryRetentionDays(30)
	svc.SetHistoryRetentionDays(-1) // ignored
	if got := svc.HistoryRetentionDays(); got != 30 {
		t.Fatalf("retention = %d, want 30", got)
	}
	svc.SetHistoryRetentionDays(0)
	if got := svc.HistoryRetentionDays(); got != 0 {
		t.Fatalf("retention = %d, want 0 (unbounded)", got)
	}
}

func TestSweepHistoryCadenceAndWindow(t *testing.T) {
	svc := newHistoryTestService(t)
	start := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	now := start
	svc.historySweep.now = func() time.Time { return now }
	st := svc.InventoryStore()
	for i, age := range []int{40, 20, 10} {
		recordHistoryScan(t, st, []string{"d40", "d20", "d10"}[i], start.Add(-time.Duration(age)*24*time.Hour), 1, "")
	}
	recordHistoryScan(t, st, "latest", start.Add(-time.Hour), 1, "")
	scans := func() int { return countRows(t, st, `SELECT COUNT(*) FROM ai_scans`) }
	ctx := context.Background()
	svc.historySweep.markStarted(start)

	// Retention 0 keeps history unbounded even when a sweep is due.
	svc.SetHistoryRetentionDays(0)
	now = start.Add(inventoryHistorySweepStartupDelay)
	if !svc.sweepHistoryIfDue(ctx) || scans() != 4 {
		t.Fatalf("unbounded sweep pruned history: %d scans", scans())
	}

	// At most one sweep per interval.
	svc.SetHistoryRetentionDays(30)
	now = now.Add(inventoryHistorySweepInterval - time.Minute)
	if svc.sweepHistoryIfDue(ctx) {
		t.Fatal("sweep ran before the interval elapsed")
	}
	now = now.Add(time.Minute)
	if !svc.sweepHistoryIfDue(ctx) || scans() != 3 {
		t.Fatalf("30-day sweep left %d scans, want 3", scans())
	}

	// A reload that narrows the window applies on the next due sweep.
	svc.SetHistoryRetentionDays(config.ObservabilityV8DefaultRetentionDays)
	now = now.Add(inventoryHistorySweepInterval)
	if !svc.sweepHistoryIfDue(ctx) || scans() != 1 {
		t.Fatalf("7-day sweep left %d scans, want only the latest", scans())
	}

	// Never concurrent with itself.
	now = now.Add(inventoryHistorySweepInterval)
	svc.historySweep.running.Store(true)
	if svc.sweepHistoryIfDue(ctx) {
		t.Fatal("sweep ran while another sweep was in flight")
	}
	svc.historySweep.running.Store(false)
}

func TestSweepHistoryWaitsForStartupDelay(t *testing.T) {
	svc := newHistoryTestService(t)
	start := time.Date(2026, 9, 1, 12, 0, 0, 0, time.UTC)
	now := start
	svc.historySweep.now = func() time.Time { return now }
	svc.historySweep.markStarted(start)
	now = start.Add(inventoryHistorySweepStartupDelay - time.Second)
	if svc.sweepHistoryIfDue(context.Background()) {
		t.Fatal("sweep ran before the startup delay")
	}
	now = start.Add(inventoryHistorySweepStartupDelay)
	if !svc.sweepHistoryIfDue(context.Background()) {
		t.Fatal("first sweep did not run after the startup delay")
	}
}

func TestStartHistoryRetentionStopsBeforeStoreClose(t *testing.T) {
	svc := newHistoryTestService(t)
	stop := svc.startHistoryRetention(context.Background())
	done := make(chan struct{})
	go func() { stop(); close(done) }()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("history sweeper did not stop")
	}
}
