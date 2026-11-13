// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"fmt"
)

// audit_hook_lone lists the hook_decision rows that are their decision's
// only local hook row (a benign per-user allow since 1.0.10, #1384, or the
// fail-mode decision of a call whose connector-hook row could not be
// stored), keyed by the row's audit_events id. The readers that count a
// decision once (LoneHookDecisionSQL, the Python Overview counter) read
// these rows by key instead of the projected record of every hook row of the
// store: on a grown managed store (670,000 audit rows, 4 GiB) that pass read
// about 1.1 GB with a cold page cache (rel-1-0-10:GAP-0316).
//
// The gateway writes the entry itself, in the transaction of its row, only
// for such a row (WithLoneHookDecision, WithLoneHookDecisionAwaitingReport),
// so a hook call that keeps its connector-hook row, every managed call
// among them, pays nothing; a lone row pays one small insert, and nothing
// parses a record. The failure report's connector-hook row of a call whose
// audit write failed removes that call's entry in its own transaction, so
// the call counts once, from that row. A delete trigger
// removes the entry with its audit row on any connection, so retention needs
// no change. Rows written before the table existed are not listed: 1.0.9
// always kept a decision's connector-hook row, so none of its rows is ever
// alone (the lone count of a grown 1.0.9 store is 0), and nothing is
// backfilled. A 1.0.9 binary after a rollback writes no entries and needs
// none (it writes no lone rows); it opens the store as before, since it
// applies migrations only up to its own count and names its tables. The
// upgrade costs one CREATE TABLE, one CREATE INDEX on the empty table and
// one CREATE TRIGGER; no index over audit_events is built and no row is
// rewritten. A Secure Client store keeps main's schema and every
// connector-hook row, so it has neither the table nor the trigger.
const (
	hookLoneTable   = "audit_hook_lone"
	hookLoneIndex   = "idx_audit_hook_lone_semantic"
	hookLoneTrigger = "trg_audit_hook_lone_delete"
)

var hookLoneDDL = []string{
	// semantic_event_id is set only for a fail-mode decision that waits for
	// the failure report's connector-hook row (the partial index holds just
	// those); a row of record stores its key alone, about 57 B.
	`CREATE TABLE IF NOT EXISTS ` + hookLoneTable + ` (
		audit_event_id TEXT PRIMARY KEY,
		semantic_event_id TEXT
	) WITHOUT ROWID`,
	`CREATE INDEX IF NOT EXISTS ` + hookLoneIndex + ` ON ` + hookLoneTable + `(semantic_event_id)
		WHERE semantic_event_id IS NOT NULL`,
	`CREATE TRIGGER IF NOT EXISTS ` + hookLoneTrigger + ` AFTER DELETE ON audit_events
		WHEN OLD.action = '` + hookDecisionEventName + `'
		BEGIN
			DELETE FROM ` + hookLoneTable + ` WHERE audit_event_id = OLD.id;
		END`,
}

// ensureHookLoneTracking creates audit_hook_lone and its delete trigger
// after the migrations, without moving the schema version (as
// trimUnreadAuditIndexes does), or drops them on a Secure Client store.
func (s *Store) ensureHookLoneTracking() error {
	if present, err := tableExists(s.db, "audit_events"); err != nil {
		return err
	} else if !present {
		return nil
	}
	statements := hookLoneDDL
	if s.secureClientSchema {
		statements = []string{"DROP TRIGGER IF EXISTS " + hookLoneTrigger, "DROP TABLE IF EXISTS " + hookLoneTable}
	}
	for _, statement := range statements {
		if _, err := s.db.Exec(statement); err != nil {
			return fmt.Errorf("audit: lone hook decision tracking: %w", err)
		}
	}
	s.hookLoneTracked = !s.secureClientSchema
	return nil
}

// HookRowsTracked reports whether db has audit_hook_lone, the table
// LoneHookDecisionSQL reads.
func HookRowsTracked(db *sql.DB) (bool, error) {
	return tableExists(db, hookLoneTable)
}

type loneHookDecisionKey struct{}

// loneHookDecisionMode is how a hook_decision record written with a ctx is
// listed in audit_hook_lone.
type loneHookDecisionMode int

const (
	_ loneHookDecisionMode = iota // not lone: the zero value
	// loneHookDecisionOfRecord: the row of record of a benign per-user
	// allow. No connector-hook row ever follows it.
	loneHookDecisionOfRecord
	// loneHookDecisionAwaitingReport: the fail-mode decision of a call whose
	// connector-hook row could not be stored. The failure report writes that
	// row later (WithHookFailureReport), which pairs it.
	loneHookDecisionAwaitingReport
)

type hookFailureReportKey struct{}

// WithLoneHookDecision marks the hook_decision record written with ctx as
// the row of record of its decision: its event-history row is listed in
// audit_hook_lone in the same transaction.
func WithLoneHookDecision(ctx context.Context) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, loneHookDecisionKey{}, loneHookDecisionOfRecord)
}

// WithLoneHookDecisionAwaitingReport marks the hook_decision record written
// with ctx as the fail-mode decision of a call whose connector-hook row
// could not be stored: it is listed until the failure report writes that
// row.
func WithLoneHookDecisionAwaitingReport(ctx context.Context) context.Context {
	if ctx == nil {
		return nil
	}
	return context.WithValue(ctx, loneHookDecisionKey{}, loneHookDecisionAwaitingReport)
}

// withHookFailureReport marks the connector-hook rows the failure report
// writes: each pairs the listed fail-mode decision of its semantic event.
func withHookFailureReport(ctx context.Context) context.Context {
	return context.WithValue(ctx, hookFailureReportKey{}, true)
}

// trackHookRowTx keeps audit_hook_lone for one event-history row written in
// tx: a lone hook_decision row is listed, and a failure-report connector-hook
// row removes the listed fail-mode decision of its semantic event. Every
// other row, the whole managed hook path among them, runs no statement.
func (s *Store) trackHookRowTx(ctx context.Context, tx *sql.Tx, action, recordID, semanticEventID string) error {
	// A hook row without a semantic event is never alone (the gateway keeps
	// the connector-hook row of an uncorrelated call), as in the record rule.
	if s == nil || !s.hookLoneTracked || ctx == nil || semanticEventID == "" {
		return nil
	}
	switch action {
	case hookDecisionEventName:
		mode, _ := ctx.Value(loneHookDecisionKey{}).(loneHookDecisionMode)
		switch mode {
		case loneHookDecisionOfRecord:
			_, err := txExecContextObserved(ctx, tx, "audit_hook_lone_insert", s.sqliteBusyObservabilityV8(),
				`INSERT OR REPLACE INTO `+hookLoneTable+` (audit_event_id, semantic_event_id) VALUES (?, NULL)`, recordID)
			return err
		case loneHookDecisionAwaitingReport:
			_, err := txExecContextObserved(ctx, tx, "audit_hook_lone_insert", s.sqliteBusyObservabilityV8(),
				`INSERT OR REPLACE INTO `+hookLoneTable+` (audit_event_id, semantic_event_id) VALUES (?, ?)`,
				recordID, semanticEventID)
			return err
		}
	case string(ActionConnectorHook), string(ActionConnectorHookSynthetic):
		if report, _ := ctx.Value(hookFailureReportKey{}).(bool); !report {
			return nil
		}
		_, err := txExecContextObserved(ctx, tx, "audit_hook_lone_pair", s.sqliteBusyObservabilityV8(),
			`DELETE FROM `+hookLoneTable+` WHERE semantic_event_id = ?`, semanticEventID)
		return err
	}
	return nil
}
