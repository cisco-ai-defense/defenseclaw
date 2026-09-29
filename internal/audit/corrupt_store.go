// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/google/uuid"
)

// startupIntegrityCheckTimeout bounds the daemon's startup quick_check. A
// check that does not finish in time is skipped, never treated as corruption.
const startupIntegrityCheckTimeout = 5 * time.Second

// SQLite primary result codes for a damaged database file.
const (
	sqliteCodeCorrupt = 11
	sqliteCodeNotADB  = 26
)

var errCorruptAuditDB = errors.New("database disk image is malformed")

// isSQLiteCorrupt reports whether err says the database file itself is damaged,
// as opposed to busy, missing or not permitted.
func isSQLiteCorrupt(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, errCorruptAuditDB) {
		return true
	}
	var coded sqliteCoded
	if errors.As(err, &coded) {
		switch coded.Code() & 0xff {
		case sqliteCodeCorrupt, sqliteCodeNotADB:
			return true
		}
	}
	message := strings.ToLower(err.Error())
	return strings.Contains(message, "database disk image is malformed") ||
		strings.Contains(message, "file is not a database")
}

// OpenDaemonStore opens and initializes the gateway daemon's audit store. When
// SQLite reports the store corrupt (on open, in a bounded startup quick_check,
// or while migrating), the database and its WAL and SHM files are moved aside
// under a ".corrupt-<time>" name and a new store is created, carrying the
// block/allow list over, so the daemon starts instead of failing. The move is
// refused while another process still has the database open. Only the daemon,
// the store's long-lived owner, calls this; other commands keep failing.
func OpenDaemonStore(dbPath string, warn io.Writer) (*Store, error) {
	store, err := openCheckedStore(dbPath, warn)
	if err == nil || !isSQLiteCorrupt(err) {
		return store, err
	}
	moved, moveErr := quarantineCorruptAuditDB(dbPath)
	if moveErr != nil {
		return nil, fmt.Errorf("%w (the corrupt store was not moved aside: %v)", err, moveErr)
	}
	store, freshErr := NewStore(dbPath)
	if freshErr == nil {
		if freshErr = store.Init(); freshErr != nil {
			_ = store.Close()
		}
	}
	if freshErr != nil {
		return nil, fmt.Errorf("audit: create a new store after moving the corrupt one to %s: %w", moved, freshErr)
	}
	kept, keepErr := store.carryOverActions(moved)
	fmt.Fprintf(warn, "[audit] WARNING: the audit store was corrupt (%v). It was moved to %s and a new store was created; block/allow entries carried over: %d.",
		err, moved, kept)
	if keepErr != nil {
		fmt.Fprintf(warn, " Some entries could not be read (%v): check them with defenseclaw tool list and the skill, plugin and mcp list commands.", keepErr)
	}
	fmt.Fprintf(warn, " Older audit records stay in the moved file; recover them with: sqlite3 %s .recover\n", moved)
	return store, nil
}

func openCheckedStore(dbPath string, warn io.Writer) (*Store, error) {
	store, err := NewStore(dbPath)
	if err != nil {
		return nil, err
	}
	if err := store.startupQuickCheck(warn); err != nil {
		_ = store.Close()
		return nil, err
	}
	if err := store.Init(); err != nil {
		_ = store.Close()
		return nil, err
	}
	return store, nil
}

func (s *Store) startupQuickCheck(warn io.Writer) error {
	if s.dbPath == ":memory:" {
		return nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), startupIntegrityCheckTimeout)
	defer cancel()
	var result string
	err := s.db.QueryRowContext(ctx, "PRAGMA quick_check(1)").Scan(&result)
	switch {
	case err == nil && result == "ok":
		return nil
	case err == nil:
		detail, _, _ := strings.Cut(strings.TrimSpace(strings.TrimPrefix(result, "*** in database main ***")), "\n")
		return fmt.Errorf("audit: startup integrity check failed: %s: %w", detail, errCorruptAuditDB)
	case isSQLiteCorrupt(err):
		return err
	default:
		fmt.Fprintf(warn, "[audit] startup integrity check skipped: %v\n", err)
		return nil
	}
}

// quarantineCorruptAuditDB renames the database and its sidecars to
// "<db>.corrupt-<UTC time>" plus the same suffixes, so the set still opens as
// one database for recovery. Sidecars move first: a new store must never
// replay the old WAL.
func quarantineCorruptAuditDB(dbPath string) (string, error) {
	absolute, err := filepath.Abs(filepath.Clean(dbPath))
	if err != nil {
		return "", err
	}
	if err := auditDBOpenElsewhere(absolute); err != nil {
		return "", err
	}
	moved := absolute + ".corrupt-" + time.Now().UTC().Format("20060102T150405Z")
	if _, err := os.Lstat(moved); err == nil {
		moved += fmt.Sprintf("-%d", os.Getpid())
	}
	for _, suffix := range auditDBSQLiteSidecarSuffixes {
		if err := os.Rename(absolute+suffix, moved+suffix); err != nil && !os.IsNotExist(err) {
			return "", err
		}
	}
	if err := os.Rename(absolute, moved); err != nil {
		return "", err
	}
	return moved, nil
}

// carryOverActions copies the readable block/allow rows of the moved store
// into this new one, so a rebuild never silently lifts a block.
func (s *Store) carryOverActions(movedPath string) (int, error) {
	old, err := openAuditReadOnly(movedPath)
	if err != nil {
		return 0, err
	}
	defer old.Close()
	connector := "''"
	if present, err := hasColumnDB(old, "actions", "connector"); err != nil {
		return 0, err
	} else if present {
		connector = "connector"
	}
	// CAST keeps updated_at's stored text instead of the driver's re-rendering.
	rows, err := old.Query(`SELECT target_type, target_name, source_path, actions_json, reason,
		CAST(updated_at AS TEXT), ` + connector + ` FROM actions`)
	if err != nil {
		return 0, err
	}
	defer rows.Close()
	tx, err := s.db.Begin()
	if err != nil {
		return 0, err
	}
	defer tx.Rollback() //nolint:errcheck
	kept := 0
	for rows.Next() {
		var targetType, targetName, actionsJSON, connectorName string
		var sourcePath, reason, storedAt sql.NullString
		if err := rows.Scan(&targetType, &targetName, &sourcePath, &actionsJSON, &reason, &storedAt, &connectorName); err != nil {
			continue
		}
		var state ActionState
		if targetType == "" || targetName == "" || json.Unmarshal([]byte(actionsJSON), &state) != nil {
			continue
		}
		var updatedAt any = time.Now().UTC()
		if storedAt.Valid && storedAt.String != "" {
			updatedAt = storedAt.String
		}
		result, err := tx.Exec(`INSERT OR IGNORE INTO actions
			(id, target_type, target_name, source_path, actions_json, reason, updated_at, connector)
			VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
			uuid.New().String(), targetType, targetName, sourcePath, actionsJSON, reason, updatedAt, connectorName)
		if err != nil {
			return 0, err
		}
		if changed, _ := result.RowsAffected(); changed > 0 {
			kept++
		}
	}
	readErr := rows.Err()
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return kept, readErr
}
