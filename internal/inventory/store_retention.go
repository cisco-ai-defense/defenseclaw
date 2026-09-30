// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"database/sql"
	"fmt"
	"path/filepath"
	"time"
)

// Retention tuning. Variables rather than constants so tests can exercise
// batching and the compaction thresholds without multi-gigabyte fixtures.
var (
	// inventoryPruneBatchScans bounds one prune transaction. A scan carries
	// a few hundred ai_signals rows, so a batch stays well under a second
	// and RecordScan never waits long for the single pooled connection.
	inventoryPruneBatchScans = 100
	// inventoryVacuumMinFreeBytes and inventoryVacuumMinFreeRatio gate the
	// one-time VACUUM of a legacy auto_vacuum=NONE database: rewriting the
	// file is only worth it when most of it is reusable free pages.
	inventoryVacuumMinFreeBytes int64 = 64 << 20
	inventoryVacuumMinFreeRatio       = 0.5
	// inventoryDiskFree reports the bytes available on the volume holding
	// dir; ok=false means the platform could not tell and the check is
	// skipped.
	inventoryDiskFree = diskFreeBytes
)

// SQLite auto_vacuum modes as reported by PRAGMA auto_vacuum.
const (
	sqliteAutoVacuumNone        = 0
	sqliteAutoVacuumIncremental = 2
)

// ScanHistoryPrune reports one bounded retention pass over ai_scans.
type ScanHistoryPrune struct {
	// ScansDeleted counts ai_scans rows removed; their ai_signals and
	// ai_confidence_snapshots rows go with them via ON DELETE CASCADE.
	ScansDeleted int
	// Drained is true once no scan older than the cutoff remains apart
	// from the retained latest scan. False means the budget or context
	// ended the pass and the next sweep continues where this one stopped.
	Drained bool
}

// PruneScanHistory deletes scans recorded before cutoff, oldest first, in
// transactions of at most inventoryPruneBatchScans scans. The most recent
// scan is always kept, even when it is older than cutoff, so a machine that
// was switched off for longer than the window still reports its last-known
// inventory and history.
//
// The pass stops after budget has elapsed (checked between batches, so at
// least one batch runs) or when ctx ends; a large backlog is therefore
// drained across several sweeps instead of holding the single writer
// connection for minutes. A non-nil error is returned only for ctx
// cancellation or a failed batch; the counts reflect the batches that
// committed before it.
func (s *InventoryStore) PruneScanHistory(ctx context.Context, cutoff time.Time, budget time.Duration) (ScanHistoryPrune, error) {
	var out ScanHistoryPrune
	if s == nil || s.db == nil {
		out.Drained = true
		return out, nil
	}
	started := time.Now()
	cutoff = cutoff.UTC()
	for {
		if err := ctx.Err(); err != nil {
			return out, err
		}
		// scanned_at is indexed (idx_ai_scans_scanned_at), so both the
		// oldest-first page and the latest-scan exclusion are index walks.
		res, err := s.execDB(ctx, "inventory_prune", `DELETE FROM ai_scans WHERE scan_id IN (
			SELECT scan_id FROM ai_scans
			WHERE scanned_at < ?
			  AND scan_id <> (SELECT scan_id FROM ai_scans ORDER BY scanned_at DESC, scan_id DESC LIMIT 1)
			ORDER BY scanned_at
			LIMIT ?)`,
			cutoff, inventoryPruneBatchScans,
		)
		if err != nil {
			return out, fmt.Errorf("inventory store: prune scans: %w", err)
		}
		n, _ := res.RowsAffected()
		out.ScansDeleted += int(n)
		if n < int64(inventoryPruneBatchScans) {
			out.Drained = true
			return out, nil
		}
		if time.Since(started) >= budget {
			return out, nil
		}
	}
}

// ScanHistoryCompaction reports the space-reclaim step that follows a prune.
type ScanHistoryCompaction struct {
	// Vacuumed is true when a legacy auto_vacuum=NONE file was rewritten
	// with VACUUM and switched to incremental auto-vacuum.
	Vacuumed bool
	// ReleasedPages counts free pages returned to the filesystem by
	// PRAGMA incremental_vacuum.
	ReleasedPages int64
	// Skipped explains why a warranted VACUUM did not run (for example,
	// too little free disk space). Empty otherwise.
	Skipped string
}

// CompactScanHistory returns pages freed by PruneScanHistory to the
// filesystem. Deleting rows only moves pages to SQLite's freelist, so
// without this the file never shrinks:
//
//   - auto_vacuum=INCREMENTAL (new databases): PRAGMA incremental_vacuum
//     truncates the freelist.
//   - auto_vacuum=NONE (databases created before this setting): once the
//     backlog is drained and free pages dominate the file, a one-time VACUUM
//     rewrites it and switches it to INCREMENTAL. VACUUM needs about twice
//     the live data size in free disk space (the rewrite lands in the WAL
//     and a temporary copy), so it is skipped with a diagnostic when the
//     volume is short.
//
// A WAL checkpoint(TRUNCATE) follows any change so the -wal file does not
// stay at the size of the deletes. All statements run on one pinned
// connection outside any transaction; the pool has a single connection, so
// other writers wait rather than race the VACUUM.
func (s *InventoryStore) CompactScanHistory(ctx context.Context, prune ScanHistoryPrune) (ScanHistoryCompaction, error) {
	var out ScanHistoryCompaction
	if s == nil || s.db == nil {
		return out, nil
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return out, fmt.Errorf("inventory store: compact: %w", err)
	}
	defer conn.Close() //nolint:errcheck

	mode, err := pragmaInt64(ctx, conn, "auto_vacuum")
	if err != nil {
		return out, err
	}
	switch mode {
	case sqliteAutoVacuumIncremental:
		free, err := pragmaInt64(ctx, conn, "freelist_count")
		if err != nil {
			return out, err
		}
		if free > 0 {
			if _, err := conn.ExecContext(ctx, `PRAGMA incremental_vacuum`); err != nil {
				return out, fmt.Errorf("inventory store: incremental vacuum: %w", err)
			}
			out.ReleasedPages = free
		}
	case sqliteAutoVacuumNone:
		if prune.Drained {
			out.Vacuumed, out.Skipped, err = s.convertToIncrementalVacuum(ctx, conn)
			if err != nil {
				return out, err
			}
		}
	}
	if prune.ScansDeleted > 0 || out.Vacuumed || out.ReleasedPages > 0 {
		// busy=1 (a reader in another process pinned the WAL) is not an
		// error; the next sweep's checkpoint finishes the truncation.
		var busy, logPages, checkpointed int64
		if err := conn.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &logPages, &checkpointed); err != nil {
			return out, fmt.Errorf("inventory store: wal checkpoint: %w", err)
		}
	}
	return out, nil
}

// convertToIncrementalVacuum runs the one-time VACUUM that switches a
// legacy auto_vacuum=NONE database to INCREMENTAL, when the freelist is
// large enough to justify rewriting the file.
func (s *InventoryStore) convertToIncrementalVacuum(ctx context.Context, conn *sql.Conn) (bool, string, error) {
	pageSize, err := pragmaInt64(ctx, conn, "page_size")
	if err != nil {
		return false, "", err
	}
	pageCount, err := pragmaInt64(ctx, conn, "page_count")
	if err != nil {
		return false, "", err
	}
	free, err := pragmaInt64(ctx, conn, "freelist_count")
	if err != nil {
		return false, "", err
	}
	if pageCount <= 0 || float64(free) < inventoryVacuumMinFreeRatio*float64(pageCount) ||
		free*pageSize < inventoryVacuumMinFreeBytes {
		return false, "", nil
	}
	live := uint64(pageCount-free) * uint64(pageSize)
	if avail, ok := inventoryDiskFree(filepath.Dir(s.path)); ok && avail < 2*live {
		return false, fmt.Sprintf(
			"compaction needs about %d MiB free disk space and %d MiB is available",
			(2*live)>>20, avail>>20,
		), nil
	}
	// The DSN already requests INCREMENTAL on every connection; repeat it
	// on this pinned connection so the VACUUM below is guaranteed to apply
	// it. Keep VACUUM's temporary copy on disk rather than in the
	// connection's temp_store(MEMORY) so a large rewrite cannot balloon the
	// gateway's memory.
	for _, q := range []string{`PRAGMA auto_vacuum = INCREMENTAL`, `PRAGMA temp_store = FILE`} {
		if _, err := conn.ExecContext(ctx, q); err != nil {
			return false, "", fmt.Errorf("inventory store: prepare vacuum: %w", err)
		}
	}
	defer conn.ExecContext(context.WithoutCancel(ctx), `PRAGMA temp_store = MEMORY`) //nolint:errcheck
	if _, err := conn.ExecContext(ctx, `VACUUM`); err != nil {
		return false, "", fmt.Errorf("inventory store: vacuum: %w", err)
	}
	return true, "", nil
}

func pragmaInt64(ctx context.Context, conn *sql.Conn, name string) (int64, error) {
	var v int64
	if err := conn.QueryRowContext(ctx, "PRAGMA "+name).Scan(&v); err != nil {
		return 0, fmt.Errorf("inventory store: read %s: %w", name, err)
	}
	return v, nil
}
