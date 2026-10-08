// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
)

const historicalEvidencePurgeMigrationDescription = "privacy: purge pre-cutover audit evidence"

// purgeHistoricalEvidence removes every finding and audit-event row that was
// present when this migration began. Store.applyMigration wraps this helper and
// the schema-version insert in one transaction, so an upgrade exposes either
// the complete destructive cutoff or the complete pre-upgrade history.
//
// These are active tables, not retired schema: current writers and queries keep
// using them after the one-time row purge. Validate the mandatory affected
// schema before deleting anything, then remove scan children before their
// parent so SQLite foreign keys and the v8 scan integrity trigger remain
// enforced. The migration-1 findings table may be absent on a partial
// pre-cutover database; absence is treated only as already-empty cleanup, not
// as a compatibility promise. A present table is purged.
func purgeHistoricalEvidence(ex dbExecer) error {
	if ex == nil {
		return fmt.Errorf("audit: historical evidence purge has no database")
	}

	findingsPresent, err := tableExists(ex, "findings")
	if err != nil {
		return fmt.Errorf("audit: verify historical evidence table findings: %w", err)
	}
	for _, table := range [...]string{"scan_findings", "scan_results", "audit_events"} {
		present, err := tableExists(ex, table)
		if err != nil {
			return fmt.Errorf("audit: verify historical evidence table %s: %w", table, err)
		}
		if !present {
			return fmt.Errorf("audit: mandatory historical evidence table %s is missing", table)
		}
	}

	statements := []string{"DELETE FROM scan_findings", "DELETE FROM scan_results", "DELETE FROM audit_events"}
	if findingsPresent {
		statements = append([]string{"DELETE FROM findings"}, statements...)
	}
	for _, statement := range statements {
		if _, err := ex.Exec(statement); err != nil {
			return fmt.Errorf("audit: purge pre-cutover evidence with %q: %w", statement, err)
		}
	}
	return nil
}

// reclaimPurgedHistory gives back the disk space the one-time purge freed. A
// 0.x audit.db has no auto_vacuum, so the purge left the file at full size
// (1.1 GB holding a few rows) next to the upgrade's rollback copy of it, and
// doctor then asked for a manual stop, sqlite3 VACUUM and start (GAP-1522).
// VACUUM rewrites only the rows that are left, and it switches the file to
// the incremental auto_vacuum a new database gets, so retention reclaims
// later deletes too. The checkpoint shrinks the file now: this store never
// checkpoints automatically. Best effort: on failure the database stays
// correct, only larger.
func (s *Store) reclaimPurgedHistory() {
	ctx := context.Background()
	conn, err := s.db.Conn(ctx)
	if err != nil {
		fmt.Fprintf(s.progressOut(), "[audit] could not reclaim the space of the purged history: %v\n", err)
		return
	}
	defer conn.Close() //nolint:errcheck -- returns the connection to the pool.
	fmt.Fprintln(s.progressOut(), "[audit] reclaiming the disk space of the purged pre-1.0 history")
	// auto_vacuum is per connection until VACUUM applies it, so both run on conn.
	for _, statement := range []string{`PRAGMA auto_vacuum=INCREMENTAL`, `VACUUM`} {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			fmt.Fprintf(s.progressOut(), "[audit] could not reclaim the space of the purged history (%s): %v\n", statement, err)
			return
		}
	}
	var busy, frames, checkpointed int
	if err := conn.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &frames, &checkpointed); err != nil || busy != 0 {
		fmt.Fprintf(s.progressOut(), "[audit] the purged history's space is reclaimed at the next checkpoint (busy=%d err=%v)\n", busy, err)
	}
}
