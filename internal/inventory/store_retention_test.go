// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// recordHistoryScan writes one scan with signalCount component signals at
// scannedAt. padding inflates evidence so compaction tests have pages to free.
func recordHistoryScan(t *testing.T, st *InventoryStore, id string, scannedAt time.Time, signalCount int, padding string) {
	t.Helper()
	report := AIDiscoveryReport{Summary: AIDiscoverySummary{
		ScanID: id, ScannedAt: scannedAt, Source: "test", PrivacyMode: "enhanced", Result: "ok",
		TotalSignals: signalCount, ActiveSignals: signalCount,
	}}
	for i := 0; i < signalCount; i++ {
		report.Signals = append(report.Signals, AISignal{
			Fingerprint: fmt.Sprintf("fp-%d", i), SignalID: fmt.Sprintf("sig-%d", i),
			SignatureID: "ai-sdks", Name: "openai", Vendor: "OpenAI", Product: "openai",
			Category: SignalPackageDependency, Detector: "package_manifest", State: AIStateSeen,
			Confidence: 0.9, LastSeen: scannedAt,
			Component: &AIComponent{Ecosystem: "pypi", Name: fmt.Sprintf("pkg-%d", i)},
			Evidence:  []AIEvidence{{Type: "package", Basename: "requirements.txt" + padding}},
		})
	}
	if err := st.RecordScan(context.Background(), report, ConfidenceParams{}); err != nil {
		t.Fatalf("record %s: %v", id, err)
	}
}

func countRows(t *testing.T, st *InventoryStore, query string, args ...any) int {
	t.Helper()
	var n int
	if err := st.db.QueryRow(query, args...).Scan(&n); err != nil {
		t.Fatalf("%s: %v", query, err)
	}
	return n
}

func setPruneBatch(t *testing.T, n int) {
	t.Helper()
	prev := inventoryPruneBatchScans
	inventoryPruneBatchScans = n
	t.Cleanup(func() { inventoryPruneBatchScans = prev })
}

func TestPruneScanHistoryKeepsLatestAndCascades(t *testing.T) {
	setPruneBatch(t, 2)
	st, err := NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	for i, age := range []int{12, 11, 10, 9, 8} {
		recordHistoryScan(t, st, fmt.Sprintf("old-%d", i), now.Add(-time.Duration(age)*24*time.Hour), 3, "")
	}
	recordHistoryScan(t, st, "recent", now.Add(-time.Hour), 3, "")

	got, err := st.PruneScanHistory(context.Background(), now.Add(-7*24*time.Hour), time.Minute)
	if err != nil || got.ScansDeleted != 5 || !got.Drained {
		t.Fatalf("prune = %+v, %v; want 5 deleted, drained", got, err)
	}
	if n := countRows(t, st, `SELECT COUNT(*) FROM ai_scans`); n != 1 {
		t.Fatalf("scans left = %d, want 1", n)
	}
	// ON DELETE CASCADE only fires with foreign_keys(ON) on the pooled
	// connection; orphaned child rows would keep the file growing.
	for _, table := range []string{"ai_signals", "ai_confidence_snapshots"} {
		if n := countRows(t, st, `SELECT COUNT(*) FROM `+table+` WHERE scan_id <> 'recent'`); n != 0 {
			t.Fatalf("%s kept %d rows of pruned scans", table, n)
		}
		if n := countRows(t, st, `SELECT COUNT(*) FROM `+table+` WHERE scan_id = 'recent'`); n != 3 {
			t.Fatalf("%s rows of the kept scan = %d, want 3", table, n)
		}
	}

	// A machine that was off for longer than the window keeps its newest scan.
	got, err = st.PruneScanHistory(context.Background(), now.Add(time.Hour), time.Minute)
	if err != nil || got.ScansDeleted != 0 || !got.Drained {
		t.Fatalf("prune past latest = %+v, %v", got, err)
	}
	if n := countRows(t, st, `SELECT COUNT(*) FROM ai_scans WHERE scan_id = 'recent'`); n != 1 {
		t.Fatal("latest scan was pruned")
	}
}

func TestPruneScanHistoryBudgetAndContextResume(t *testing.T) {
	setPruneBatch(t, 2)
	st, err := NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	now := time.Now().UTC()
	for i := 0; i < 6; i++ {
		recordHistoryScan(t, st, fmt.Sprintf("old-%d", i), now.Add(-time.Duration(30-i)*24*time.Hour), 1, "")
	}
	cutoff := now.Add(-7 * 24 * time.Hour)

	canceled, cancel := context.WithCancel(context.Background())
	cancel()
	if got, err := st.PruneScanHistory(canceled, cutoff, time.Minute); !errors.Is(err, context.Canceled) || got.ScansDeleted != 0 {
		t.Fatalf("canceled prune = %+v, %v", got, err)
	}

	// An exhausted budget stops after one batch, oldest first.
	got, err := st.PruneScanHistory(context.Background(), cutoff, 0)
	if err != nil || got.ScansDeleted != 2 || got.Drained {
		t.Fatalf("budgeted prune = %+v, %v; want 2 deleted, not drained", got, err)
	}
	if n := countRows(t, st, `SELECT COUNT(*) FROM ai_scans WHERE scan_id IN ('old-0', 'old-1')`); n != 0 {
		t.Fatal("budgeted prune did not remove the oldest scans first")
	}
	got, err = st.PruneScanHistory(context.Background(), cutoff, time.Minute)
	if err != nil || got.ScansDeleted != 3 || !got.Drained {
		t.Fatalf("resumed prune = %+v, %v; want 3 deleted, drained", got, err)
	}
}

func TestNewInventoryStoreUsesIncrementalAutoVacuum(t *testing.T) {
	st, err := NewInventoryStore(filepath.Join(t.TempDir(), "inventory.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	if mode := countRows(t, st, `PRAGMA auto_vacuum`); mode != sqliteAutoVacuumIncremental {
		t.Fatalf("auto_vacuum = %d, want incremental", mode)
	}
	now := time.Now().UTC()
	padding := strings.Repeat("x", 2048)
	for i := 0; i < 20; i++ {
		recordHistoryScan(t, st, fmt.Sprintf("old-%d", i), now.Add(-30*24*time.Hour+time.Duration(i)*time.Minute), 10, padding)
	}
	pruned, err := st.PruneScanHistory(context.Background(), now, time.Minute)
	if err != nil || pruned.ScansDeleted != 19 {
		t.Fatalf("prune = %+v, %v", pruned, err)
	}
	compacted, err := st.CompactScanHistory(context.Background(), pruned)
	if err != nil || compacted.ReleasedPages == 0 || compacted.Vacuumed {
		t.Fatalf("compact = %+v, %v; want released pages", compacted, err)
	}
	if free := countRows(t, st, `PRAGMA freelist_count`); free != 0 {
		t.Fatalf("freelist after incremental vacuum = %d", free)
	}
}

// newLegacyInventoryStore opens an inventory DB whose file predates the
// auto_vacuum DSN setting (auto_vacuum=NONE).
func newLegacyInventoryStore(t *testing.T) (*InventoryStore, string) {
	t.Helper()
	dbPath := filepath.Join(t.TempDir(), "inventory.db")
	legacy, err := sql.Open("sqlite", dbPath+"?_pragma=journal_mode(WAL)")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := legacy.Exec(`CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at DATETIME NOT NULL)`); err != nil {
		t.Fatal(err)
	}
	_ = legacy.Close()
	st, err := NewInventoryStore(dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = st.Close() })
	if mode := countRows(t, st, `PRAGMA auto_vacuum`); mode != sqliteAutoVacuumNone {
		t.Fatalf("legacy auto_vacuum = %d, want none", mode)
	}
	now := time.Now().UTC()
	padding := strings.Repeat("x", 4096)
	for i := 0; i < 40; i++ {
		recordHistoryScan(t, st, fmt.Sprintf("old-%02d", i), now.Add(-30*24*time.Hour+time.Duration(i)*time.Minute), 10, padding)
	}
	return st, dbPath
}

func fileSize(t *testing.T, path string) int64 {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		if os.IsNotExist(err) {
			return 0
		}
		t.Fatal(err)
	}
	return info.Size()
}

func TestCompactScanHistoryConvertsLegacyDatabaseAfterDrain(t *testing.T) {
	prevMin := inventoryVacuumMinFreeBytes
	inventoryVacuumMinFreeBytes = 0
	t.Cleanup(func() { inventoryVacuumMinFreeBytes = prevMin })
	setPruneBatch(t, 10)
	st, dbPath := newLegacyInventoryStore(t)
	cutoff := time.Now().UTC()

	partial, err := st.PruneScanHistory(context.Background(), cutoff, 0)
	if err != nil || partial.Drained {
		t.Fatalf("partial prune = %+v, %v", partial, err)
	}
	if got, err := st.CompactScanHistory(context.Background(), partial); err != nil || got.Vacuumed {
		t.Fatalf("compaction before drain = %+v, %v; want no VACUUM", got, err)
	}
	drained, err := st.PruneScanHistory(context.Background(), cutoff, time.Minute)
	if err != nil || !drained.Drained {
		t.Fatalf("drain = %+v, %v", drained, err)
	}
	before := fileSize(t, dbPath)
	got, err := st.CompactScanHistory(context.Background(), drained)
	if err != nil || !got.Vacuumed {
		t.Fatalf("compaction after drain = %+v, %v; want VACUUM", got, err)
	}
	if mode := countRows(t, st, `PRAGMA auto_vacuum`); mode != sqliteAutoVacuumIncremental {
		t.Fatalf("auto_vacuum after conversion = %d, want incremental", mode)
	}
	if after := fileSize(t, dbPath); after >= before/2 {
		t.Fatalf("file size %d -> %d; want the drained file to shrink", before, after)
	}
	if wal := fileSize(t, dbPath+"-wal"); wal != 0 {
		t.Fatalf("wal size after checkpoint = %d, want truncated", wal)
	}
	if n := countRows(t, st, `SELECT COUNT(*) FROM ai_signals`); n != 10 {
		t.Fatalf("signals of the kept scan after VACUUM = %d, want 10", n)
	}
}

func TestCompactScanHistorySkipsVacuumWithoutDiskHeadroom(t *testing.T) {
	prevMin, prevFree := inventoryVacuumMinFreeBytes, inventoryDiskFree
	inventoryVacuumMinFreeBytes = 0
	inventoryDiskFree = func(string) (uint64, bool) { return 1, true }
	t.Cleanup(func() { inventoryVacuumMinFreeBytes, inventoryDiskFree = prevMin, prevFree })
	st, _ := newLegacyInventoryStore(t)
	drained, err := st.PruneScanHistory(context.Background(), time.Now().UTC(), time.Minute)
	if err != nil || !drained.Drained {
		t.Fatalf("drain = %+v, %v", drained, err)
	}
	got, err := st.CompactScanHistory(context.Background(), drained)
	if err != nil || got.Vacuumed || !strings.Contains(got.Skipped, "free disk space") {
		t.Fatalf("compaction = %+v, %v; want a disk-space skip", got, err)
	}
	if mode := countRows(t, st, `PRAGMA auto_vacuum`); mode != sqliteAutoVacuumNone {
		t.Fatalf("auto_vacuum = %d after skipped conversion", mode)
	}
}

func TestCompactScanHistoryChecksTempVolumeHeadroom(t *testing.T) {
	prevMin, prevFree, prevTemp := inventoryVacuumMinFreeBytes, inventoryDiskFree, inventoryVacuumTempDir
	inventoryVacuumMinFreeBytes = 0
	inventoryVacuumTempDir = func() string { return "temp-volume" }
	inventoryDiskFree = func(dir string) (uint64, bool) {
		if dir == "temp-volume" {
			return 1, true // e.g. a small tmpfs
		}
		return 1 << 50, true
	}
	t.Cleanup(func() {
		inventoryVacuumMinFreeBytes, inventoryDiskFree, inventoryVacuumTempDir = prevMin, prevFree, prevTemp
	})
	st, _ := newLegacyInventoryStore(t)
	drained, err := st.PruneScanHistory(context.Background(), time.Now().UTC(), time.Minute)
	if err != nil || !drained.Drained {
		t.Fatalf("drain = %+v, %v", drained, err)
	}
	got, err := st.CompactScanHistory(context.Background(), drained)
	if err != nil || got.Vacuumed || !strings.Contains(got.Skipped, "temporary-file") {
		t.Fatalf("compaction = %+v, %v; want a temp-volume skip", got, err)
	}
}

func TestCompactScanHistoryBacksOffAfterFailedVacuum(t *testing.T) {
	prevMin, prevVacuum := inventoryVacuumMinFreeBytes, inventoryVacuum
	inventoryVacuumMinFreeBytes = 0
	attempts := 0
	inventoryVacuum = func(context.Context, *sql.Conn) error {
		attempts++
		return errors.New("database or disk is full")
	}
	t.Cleanup(func() { inventoryVacuumMinFreeBytes, inventoryVacuum = prevMin, prevVacuum })
	st, dbPath := newLegacyInventoryStore(t)
	drained, err := st.PruneScanHistory(context.Background(), time.Now().UTC(), time.Minute)
	if err != nil || !drained.Drained || drained.ScansDeleted == 0 {
		t.Fatalf("drain = %+v, %v", drained, err)
	}
	if fileSize(t, dbPath+"-wal") == 0 {
		t.Fatal("expected the prune to leave WAL frames")
	}

	if _, err := st.CompactScanHistory(context.Background(), drained); err == nil || attempts != 1 {
		t.Fatalf("failed vacuum: err=%v attempts=%d; want an error after one attempt", err, attempts)
	}
	if wal := fileSize(t, dbPath+"-wal"); wal != 0 {
		t.Fatalf("wal size after failed vacuum = %d, want truncated", wal)
	}
	got, err := st.CompactScanHistory(context.Background(), ScanHistoryPrune{Drained: true})
	if err != nil || got.Vacuumed || got.Skipped != "" || attempts != 1 {
		t.Fatalf("sweep inside backoff = %+v, %v, attempts=%d; want a silent no-op", got, err, attempts)
	}

	inventoryVacuum = prevVacuum
	st.vacuumRetryAfter.Store(time.Now().Add(-time.Second).UnixNano())
	if got, err := st.CompactScanHistory(context.Background(), ScanHistoryPrune{Drained: true}); err != nil || !got.Vacuumed {
		t.Fatalf("sweep after backoff = %+v, %v; want VACUUM", got, err)
	}
}
