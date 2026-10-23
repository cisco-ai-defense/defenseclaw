// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"time"
)

// The hook delivery journal holds one row per managed hook answer the
// gateway offered and has not audited yet. An audit row is immutable and
// leaves for the remote destinations as it is written, so the gateway
// writes it once the hook's receipt says which answer the agent got. The
// journal row, written before the answer is offered, is what lets the next
// gateway process audit a call whose process died in between. The table is
// created on first use, so only a standalone managed store has it, and the
// schema version does not move: an older binary opened on the store after a
// rollback ignores it.
const hookDeliveryJournalSchema = `CREATE TABLE IF NOT EXISTS hook_delivery_journal (
	id TEXT PRIMARY KEY,
	process_id TEXT NOT NULL,
	created_at TEXT NOT NULL,
	occurrence_json TEXT NOT NULL
)`

// hookDeliveryJournalTime sorts as text in time order (fixed width).
const hookDeliveryJournalTime = "2006-01-02T15:04:05.000000000Z"

// HookDeliveryJournalEntry is one journaled hook occurrence.
type HookDeliveryJournalEntry struct {
	ID         string
	Occurrence []byte
}

// JournalHookDelivery stores the occurrence of an answer about to be offered.
// processID names the gateway process that offers it. It returns nil only
// once the row survives a power loss: the insert commits on the store's
// synchronous=FULL connection, which also makes every earlier commit
// durable.
func (s *Store) JournalHookDelivery(ctx context.Context, id, processID string, occurrence []byte) error {
	if id == "" || processID == "" || len(occurrence) == 0 {
		return errors.New("audit: a hook delivery journal row needs an id, a process and an occurrence")
	}
	release, err := s.acquireReady()
	if err != nil {
		return err
	}
	defer release()
	db, durable := s.db, s.dbPathGuard != nil && !s.dbPathGuard.inMemory
	if durable {
		if db, err = s.durableConn(); err != nil {
			return err
		}
	}
	if _, err := db.ExecContext(ctx, hookDeliveryJournalSchema); err != nil {
		return fmt.Errorf("audit: create the hook delivery journal: %w", err)
	}
	if _, err := db.ExecContext(ctx, `INSERT INTO hook_delivery_journal (id, process_id, created_at, occurrence_json)
		VALUES (?, ?, ?, ?)`, id, processID, time.Now().UTC().Format(hookDeliveryJournalTime), string(occurrence)); err != nil {
		return fmt.Errorf("audit: journal hook delivery: %w", err)
	}
	if durable {
		// The WAL file can be newer than the folder entry the store opened.
		if err := syncAuditDBDir(filepath.Dir(s.dbPath)); err != nil {
			return fmt.Errorf("audit: flush the audit database folder: %w", err)
		}
	}
	return nil
}

// HookDelivery returns the still-journaled occurrence with id. The sandbox
// relay uses it to bind a later acknowledgement to the original hook and
// sandbox, including when the gateway process changed between calls.
func (s *Store) HookDelivery(ctx context.Context, id string) (HookDeliveryJournalEntry, bool, error) {
	release, err := s.acquireReady()
	if err != nil {
		return HookDeliveryJournalEntry{}, false, err
	}
	defer release()
	rows, err := s.queryDB(ctx, "hook_delivery_journal", `SELECT occurrence_json FROM hook_delivery_journal WHERE id = ?`, id)
	if err != nil {
		return HookDeliveryJournalEntry{}, false, err
	}
	defer rows.Close()
	if !rows.Next() {
		return HookDeliveryJournalEntry{}, false, rows.Err()
	}
	var occurrence string
	if err := rows.Scan(&occurrence); err != nil {
		return HookDeliveryJournalEntry{}, false, err
	}
	return HookDeliveryJournalEntry{ID: id, Occurrence: []byte(occurrence)}, true, rows.Err()
}

// UpdateHookDelivery records an answer that was closed after its proposal
// was journaled, before the gateway returns a failed acknowledgement.
func (s *Store) UpdateHookDelivery(ctx context.Context, id string, occurrence []byte) error {
	if id == "" || len(occurrence) == 0 {
		return errors.New("audit: a hook delivery update needs an id and occurrence")
	}
	release, err := s.acquireReady()
	if err != nil {
		return err
	}
	defer release()
	db, durable := s.db, s.dbPathGuard != nil && !s.dbPathGuard.inMemory
	if durable {
		if db, err = s.durableConn(); err != nil {
			return err
		}
	}
	result, err := db.ExecContext(ctx, `UPDATE hook_delivery_journal SET occurrence_json = ? WHERE id = ?`, string(occurrence), id)
	if err != nil {
		return fmt.Errorf("audit: update hook delivery: %w", err)
	}
	if rows, err := result.RowsAffected(); err != nil || rows != 1 {
		return fmt.Errorf("audit: hook delivery %s disappeared during update: rows=%d err=%v", id, rows, err)
	}
	if durable {
		return syncAuditDBDir(filepath.Dir(s.dbPath))
	}
	return nil
}

// ForgetHookDelivery deletes the journal row of an audited occurrence. A
// deletion a crash undoes is harmless: the records of the occurrence carry
// its id, so recovery finds them stored and only deletes the row again.
func (s *Store) ForgetHookDelivery(ctx context.Context, id string) error {
	release, err := s.acquireReady()
	if err != nil {
		return err
	}
	defer release()
	_, err = s.execDB(ctx, "hook_delivery_journal", `DELETE FROM hook_delivery_journal WHERE id = ?`, id)
	if err != nil && strings.Contains(err.Error(), "no such table") {
		return nil
	}
	return err
}

// UnauditedHookDeliveries returns, oldest first, the journal rows that
// processes other than processID left: their gateway stopped between the
// answer and its audit. The rows of processID belong to its live handlers.
func (s *Store) UnauditedHookDeliveries(ctx context.Context, processID string) ([]HookDeliveryJournalEntry, error) {
	release, err := s.acquireReady()
	if err != nil {
		return nil, err
	}
	defer release()
	if exists, err := tableExists(s.db, "hook_delivery_journal"); err != nil || !exists {
		return nil, err
	}
	rows, err := s.queryDB(ctx, "hook_delivery_journal", `SELECT id, occurrence_json FROM hook_delivery_journal
		WHERE process_id <> ? ORDER BY created_at, id`, processID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []HookDeliveryJournalEntry
	for rows.Next() {
		var entry HookDeliveryJournalEntry
		var occurrence string
		if err := rows.Scan(&entry.ID, &occurrence); err != nil {
			return nil, err
		}
		entry.Occurrence = []byte(occurrence)
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}
