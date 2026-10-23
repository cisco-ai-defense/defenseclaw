// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
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

// hookDeliveryJournalBytes is the size of every occurrence in the journal,
// save the row ?. octet_length reads the size from the row header, not the
// text.
const hookDeliveryJournalBytes = `(SELECT COALESCE(SUM(octet_length(occurrence_json)), 0)
	FROM hook_delivery_journal WHERE id <> ?)`

// ErrHookDeliveryJournalFull is the refusal of a journal row, or of a
// larger occurrence for one, when the journal already holds its limit of
// rows or bytes.
var ErrHookDeliveryJournalFull = errors.New("audit: the hook delivery journal is full")

// ErrHookDeliveryOccurrenceTooLarge is the refusal of an occurrence larger
// than HookDeliveryJournalLimits.OccurrenceBytes.
var ErrHookDeliveryOccurrenceTooLarge = errors.New("audit: the hook delivery occurrence is too large to journal")

// HookDeliveryJournalLimits bounds the journal: at most Rows rows, Bytes
// bytes of occurrences in all, and OccurrenceBytes bytes for one occurrence.
type HookDeliveryJournalLimits struct {
	Rows            int
	OccurrenceBytes int
	Bytes           int64
}

func (limits HookDeliveryJournalLimits) check(occurrence []byte) error {
	if limits.Rows <= 0 || limits.OccurrenceBytes <= 0 || limits.Bytes <= 0 {
		return errors.New("audit: the hook delivery journal needs row and byte limits")
	}
	if len(occurrence) > limits.OccurrenceBytes {
		return ErrHookDeliveryOccurrenceTooLarge
	}
	return nil
}

// HookDeliveryJournalEntry is one journaled hook occurrence. The zero entry
// lists the journal from its oldest row (HookDeliveries).
type HookDeliveryJournalEntry struct {
	ID         string
	ProcessID  string
	CreatedAt  string
	Occurrence []byte
}

// JournalHookDelivery stores the occurrence of an answer about to be offered.
// processID names the gateway process that offers it. The journal takes no
// occurrence over limits.OccurrenceBytes (ErrHookDeliveryOccurrenceTooLarge)
// and no row past limits.Rows rows or limits.Bytes bytes
// (ErrHookDeliveryJournalFull): rows pile up only while their records cannot
// be written. It returns nil only once the row survives a power loss: the
// insert commits on the store's synchronous=FULL connection, which also
// makes every earlier commit durable.
func (s *Store) JournalHookDelivery(ctx context.Context, id, processID string, occurrence []byte, limits HookDeliveryJournalLimits) error {
	if id == "" || processID == "" || len(occurrence) == 0 {
		return errors.New("audit: a hook delivery journal row needs an id, a process and an occurrence")
	}
	if err := limits.check(occurrence); err != nil {
		return err
	}
	result, err := s.execHookDeliveryJournal(ctx, true, `INSERT INTO hook_delivery_journal (id, process_id, created_at, occurrence_json)
		SELECT ?, ?, ?, ? WHERE (SELECT COUNT(*) FROM hook_delivery_journal) < ?
			AND `+hookDeliveryJournalBytes+` + ? <= ?`,
		id, processID, time.Now().UTC().Format(hookDeliveryJournalTime), string(occurrence),
		limits.Rows, id, len(occurrence), limits.Bytes)
	if err != nil {
		return fmt.Errorf("audit: journal hook delivery: %w", err)
	}
	if inserted, _ := result.RowsAffected(); inserted == 0 {
		return ErrHookDeliveryJournalFull
	}
	return nil
}

// RecordHookDeliveryVerdict replaces the occurrence of a journal row, as the
// gateway does once it knows the decision the call has, within the same
// limits as JournalHookDelivery. It reports whether the row exists, and
// returns nil only once the new occurrence survives a power loss. On an
// error the row keeps its earlier occurrence.
func (s *Store) RecordHookDeliveryVerdict(ctx context.Context, id string, occurrence []byte, limits HookDeliveryJournalLimits) (bool, error) {
	if id == "" || len(occurrence) == 0 {
		return false, errors.New("audit: a hook delivery verdict needs an id and an occurrence")
	}
	if err := limits.check(occurrence); err != nil {
		return false, err
	}
	// The insert of the row flushed the folder entry of the WAL file, which
	// stays while the store is open: an error here leaves the row as it was.
	result, err := s.execHookDeliveryJournal(ctx, false, `UPDATE hook_delivery_journal SET occurrence_json = ?
		WHERE id = ? AND `+hookDeliveryJournalBytes+` + ? <= ?`,
		string(occurrence), id, id, len(occurrence), limits.Bytes)
	if err != nil && strings.Contains(err.Error(), "no such table") {
		return false, nil
	}
	if err != nil {
		return false, fmt.Errorf("audit: record hook delivery verdict: %w", err)
	}
	if updated, _ := result.RowsAffected(); updated > 0 {
		return true, nil
	}
	exists, err := s.hookDeliveryJournaled(ctx, id)
	if err != nil {
		return false, fmt.Errorf("audit: record hook delivery verdict: %w", err)
	}
	if exists {
		return true, ErrHookDeliveryJournalFull
	}
	return false, nil
}

func (s *Store) hookDeliveryJournaled(ctx context.Context, id string) (bool, error) {
	release, err := s.acquireReady()
	if err != nil {
		return false, err
	}
	defer release()
	rows, err := s.queryDB(ctx, "hook_delivery_journal", `SELECT 1 FROM hook_delivery_journal WHERE id = ?`, id)
	if err != nil {
		return false, err
	}
	defer rows.Close()
	exists := rows.Next()
	return exists, rows.Err()
}

// execHookDeliveryJournal runs one journal write on the durable connection.
// An insert creates the table on first use and flushes the database folder.
func (s *Store) execHookDeliveryJournal(ctx context.Context, insert bool, query string, args ...any) (sql.Result, error) {
	release, err := s.acquireReady()
	if err != nil {
		return nil, err
	}
	defer release()
	db, durable := s.db, s.dbPathGuard != nil && !s.dbPathGuard.inMemory
	if durable {
		if db, err = s.durableConn(); err != nil {
			return nil, err
		}
	}
	if insert {
		if _, err := db.ExecContext(ctx, hookDeliveryJournalSchema); err != nil {
			return nil, fmt.Errorf("create the hook delivery journal: %w", err)
		}
	}
	result, err := db.ExecContext(ctx, query, args...)
	if err != nil {
		return nil, err
	}
	if durable && insert {
		// The WAL file can be newer than the folder entry the store opened.
		if err := syncAuditDBDir(filepath.Dir(s.dbPath)); err != nil {
			return nil, fmt.Errorf("flush the audit database folder: %w", err)
		}
	}
	return result, nil
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

// HookDeliveries returns, oldest first, at most limit journal rows of any
// process that come after the row after. A caller reads the journal in
// batches, each after the last row of the one before.
func (s *Store) HookDeliveries(ctx context.Context, after HookDeliveryJournalEntry, limit int) ([]HookDeliveryJournalEntry, error) {
	if limit <= 0 {
		return nil, errors.New("audit: a hook delivery journal read needs a limit")
	}
	release, err := s.acquireReady()
	if err != nil {
		return nil, err
	}
	defer release()
	if exists, err := tableExists(s.db, "hook_delivery_journal"); err != nil || !exists {
		return nil, err
	}
	rows, err := s.queryDB(ctx, "hook_delivery_journal", `SELECT id, process_id, created_at, occurrence_json
		FROM hook_delivery_journal WHERE created_at > ? OR (created_at = ? AND id > ?)
		ORDER BY created_at, id LIMIT ?`, after.CreatedAt, after.CreatedAt, after.ID, limit)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var entries []HookDeliveryJournalEntry
	for rows.Next() {
		var entry HookDeliveryJournalEntry
		var occurrence string
		if err := rows.Scan(&entry.ID, &entry.ProcessID, &entry.CreatedAt, &occurrence); err != nil {
			return nil, err
		}
		entry.Occurrence = []byte(occurrence)
		entries = append(entries, entry)
	}
	return entries, rows.Err()
}
