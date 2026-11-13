// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"database/sql"
	"fmt"
)

// audit_hook_rows names the correlation semantic event of every local hook
// row (hook_decision, connector-hook, connector-hook-synthetic), keyed by the
// row's audit_events id. The readers that count a decision once find the
// hook_decision rows that are their decision's only local hook row (a benign
// per-user allow since 1.0.10, #1384) here, with two index lookups per row,
// instead of reading the projected record of every hook row of the store.
// On a grown managed store (670,000 audit rows, 4 GiB) the projected-record
// form read about 1.1 GB that 1.0.9 never read, and a cold-cache Overview
// count took 89-262 s instead of 17 s (rel-1-0-10:GAP-0316).
//
// A trigger keeps the table, so it holds every hook row written since the
// store first opened with it, by any writer: this gateway, the Python CLI,
// and a 1.0.9 binary after a rollback (the trigger lives in the schema). The
// foreign key removes a row with its audit row, so retention needs no change
// (every audit connection runs with foreign_keys=ON, 1.0.9 too). Rows
// written before the table existed are not in it; they are 1.0.9 rows, and
// 1.0.9 always kept the connector-hook row of a decision, so none of them is
// ever its decision's only hook row (the lone count of the grown 1.0.9 store
// is 0). No index over audit_events is built and no row is rewritten, so the
// upgrade costs one CREATE TABLE, one CREATE INDEX on the empty table and one
// CREATE TRIGGER: about 90 ms on the 6.4 GB store. A 1.0.9 binary opens the
// store as before: it applies migrations only up to its own count and reads
// columns and tables by name. A Secure Client store keeps main's schema (and
// keeps every connector-hook row), so it has neither the table nor the
// trigger, and no hook_decision row is ever alone there.
const (
	hookRowsTable   = "audit_hook_rows"
	hookRowsIndex   = "idx_audit_hook_rows_semantic"
	hookRowsTrigger = "trg_audit_hook_rows_insert"
)

var hookRowTrackingDDL = []string{
	`CREATE TABLE IF NOT EXISTS ` + hookRowsTable + ` (
		audit_event_id TEXT PRIMARY KEY REFERENCES audit_events(id) ON DELETE CASCADE,
		semantic_event_id TEXT NOT NULL,
		connector_hook INTEGER NOT NULL CHECK (connector_hook IN (0, 1))
	) WITHOUT ROWID`,
	`CREATE INDEX IF NOT EXISTS ` + hookRowsIndex + ` ON ` + hookRowsTable + `(semantic_event_id, connector_hook)`,
	`CREATE TRIGGER IF NOT EXISTS ` + hookRowsTrigger + ` AFTER INSERT ON audit_events
		WHEN NEW.action IN ('` + hookDecisionEventName + `','` + string(ActionConnectorHook) + `','` +
		string(ActionConnectorHookSynthetic) + `') AND ` + hookRowSemanticEventSQL("NEW.projected_record_json") + ` IS NOT NULL
		BEGIN
			INSERT OR REPLACE INTO ` + hookRowsTable + ` (audit_event_id, semantic_event_id, connector_hook)
			VALUES (NEW.id, ` + hookRowSemanticEventSQL("NEW.projected_record_json") + `,
				NEW.action <> '` + hookDecisionEventName + `');
		END`,
}

// ensureHookRowTracking creates audit_hook_rows and its trigger after the
// migrations, without moving the schema version (as trimUnreadAuditIndexes
// does), or drops them on a Secure Client store.
func (s *Store) ensureHookRowTracking() error {
	if present, err := tableExists(s.db, "audit_events"); err != nil {
		return err
	} else if !present {
		return nil
	}
	statements := hookRowTrackingDDL
	if s.secureClientSchema {
		statements = []string{"DROP TRIGGER IF EXISTS " + hookRowsTrigger, "DROP TABLE IF EXISTS " + hookRowsTable}
	}
	for _, statement := range statements {
		if _, err := s.db.Exec(statement); err != nil {
			return fmt.Errorf("audit: hook row tracking: %w", err)
		}
	}
	return nil
}

// HookRowsTracked reports whether db has audit_hook_rows, the table
// LoneHookDecisionSQL reads.
func HookRowsTracked(db *sql.DB) (bool, error) {
	return tableExists(db, hookRowsTable)
}
