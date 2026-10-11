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
	"sort"
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
// or while migrating), a store DefenseClaw 0.x wrote is first rebuilt in place
// (rebuildAuditDB). A store that is still damaged is moved aside, with its WAL
// and SHM files, under a ".corrupt-<time>" name and a new store is created,
// carrying the block/allow list over, so the daemon starts instead of failing.
// The move is refused while another process still has the database open. Only
// the daemon, the store's long-lived owner, calls this; other commands keep
// failing.
func OpenDaemonStore(dbPath string, warn io.Writer, opts ...StoreOption) (*Store, error) {
	return openDaemonStore(dbPath, warn, nil, opts...)
}

// UpgradeDaemonStore applies the pending migrations the way OpenDaemonStore
// does, then closes the store. The per-migration notes go nowhere: the
// launcher prints one progress line of its own around the call (GAP-0153).
func UpgradeDaemonStore(dbPath string, warn io.Writer, opts ...StoreOption) error {
	store, err := openDaemonStore(dbPath, warn, io.Discard, opts...)
	if err != nil {
		return err
	}
	return store.Close()
}

func openDaemonStore(dbPath string, warn, progress io.Writer, opts ...StoreOption) (*Store, error) {
	store, err := openCheckedStore(dbPath, warn, progress, opts...)
	if err == nil || !isSQLiteCorrupt(err) {
		return store, err
	}
	// Secure Client keeps the recovery of main (issue #1092).
	preCutover := !secureClientStoreOptions(opts) && preCutoverAuditDB(dbPath)
	if preCutover {
		if rebuildErr := rebuildAuditDB(dbPath, progress, opts...); rebuildErr != nil {
			err = fmt.Errorf("%w; rebuilding it failed: %v", err, rebuildErr)
		} else if rebuilt, retryErr := openCheckedStore(dbPath, warn, progress, opts...); retryErr == nil {
			fmt.Fprintf(warn, "[audit] the audit store DefenseClaw 0.x wrote failed SQLite's integrity check (%v); "+
				"it was rebuilt in place and passes the check now.\n", err)
			return rebuilt, nil
		} else if !isSQLiteCorrupt(retryErr) {
			return nil, retryErr
		} else {
			err = fmt.Errorf("%w (still damaged after a rebuild)", retryErr)
		}
	}
	moved, moveErr := quarantineCorruptAuditDB(dbPath)
	if moveErr != nil {
		return nil, fmt.Errorf("%w (the corrupt store was not moved aside: %v)", err, moveErr)
	}
	store, freshErr := NewStore(dbPath, opts...)
	if freshErr == nil {
		store.progress = progress
		if freshErr = store.Init(); freshErr != nil {
			_ = store.Close()
		}
	}
	if freshErr != nil {
		return nil, fmt.Errorf("audit: create a new store after moving the corrupt one to %s: %w", moved, freshErr)
	}
	kept, keepErr := store.carryOverActions(moved)
	writeCarryOverNote(moved, kept, keepErr, preCutover)
	if preCutover {
		archived := MovedCorruptStore{Path: moved, CarryOverKnown: true, CarriedOver: kept, PreCutover: true}
		if keepErr != nil {
			archived.CarryOverError = keepErr.Error()
		}
		fmt.Fprintf(warn, "[audit] WARNING: the audit store DefenseClaw 0.x wrote is damaged (%v) and could not be rebuilt, "+
			"so it was kept as an archive in %s and a new store was created. %s Read the archive with: sqlite3 %s .recover; "+
			"delete it and its -wal/-shm files when you no longer need it.\n", err, moved, archived.BlockAllowSummary(), moved)
		return store, nil
	}
	fmt.Fprintf(warn, "[audit] WARNING: the audit store was corrupt (%v). It was moved to %s and a new store was created; block/allow entries carried over: %d.",
		err, moved, kept)
	if keepErr != nil {
		fmt.Fprintf(warn, " Some entries could not be read (%v): %s", keepErr, ReviewBlockAllowListsHint)
	}
	fmt.Fprintf(warn, " Older audit records stay in the moved file; recover them with: sqlite3 %s .recover\n", moved)
	return store, nil
}

// ReviewBlockAllowListsHint tells the operator where to check and re-create
// block/allow entries that a corrupt store lost.
const ReviewBlockAllowListsHint = "check your MCP, skill, plugin and tool block/allow entries with defenseclaw mcp list, skill list, plugin list and tool list, and block or allow them again."

// carryOverNoteSuffix names the small JSON note next to a moved store that
// records how many block/allow entries reached the new store, so start, status
// and doctor report what happened instead of assuming they were kept.
const carryOverNoteSuffix = ".carryover.json"

type carryOverNote struct {
	CarriedOver int    `json:"carried_over"`
	Error       string `json:"error,omitempty"`
	// PreCutover marks a store DefenseClaw 0.x wrote: 1.0 does not carry its
	// history over in any case, so the moved file is an archive. Doctor reads
	// it too (cli/defenseclaw/commands/cmd_doctor.py).
	PreCutover bool `json:"pre_1_0,omitempty"`
}

func writeCarryOverNote(moved string, kept int, keepErr error, preCutover bool) {
	note := carryOverNote{CarriedOver: kept, PreCutover: preCutover}
	if keepErr != nil {
		note.Error = keepErr.Error()
	}
	if encoded, err := json.Marshal(note); err == nil {
		_ = os.WriteFile(moved+carryOverNoteSuffix, encoded, 0o600)
	}
}

func readCarryOverNote(moved string) (carryOverNote, bool) {
	var note carryOverNote
	encoded, err := os.ReadFile(moved + carryOverNoteSuffix)
	if err != nil || json.Unmarshal(encoded, &note) != nil {
		return carryOverNote{}, false
	}
	return note, true
}

func openCheckedStore(dbPath string, warn, progress io.Writer, opts ...StoreOption) (*Store, error) {
	store, err := NewStore(dbPath, opts...)
	if err != nil {
		return nil, err
	}
	store.progress = progress
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

// MovedCorruptStore is an audit store OpenDaemonStore moved aside as corrupt.
type MovedCorruptStore struct {
	Path    string
	MovedAt time.Time
	// CarryOverKnown is false for stores moved by a gateway that kept no note.
	CarryOverKnown bool
	CarriedOver    int
	// CarryOverError says why some or all block/allow entries were not read.
	CarryOverError string
	// PreCutover is set for a store DefenseClaw 0.x wrote: an archive of the
	// history 1.0 does not carry over, not a 1.0 history that was lost.
	PreCutover bool
}

// BlockAllowSummary says what happened to the block/allow lists of a moved
// store, for start, status and doctor.
func (store MovedCorruptStore) BlockAllowSummary() string {
	if store.PreCutover {
		summary := "1.0 starts a new audit history after a 0.x upgrade in any case, and block/allow lists live in " +
			"config.yaml, so they are not affected"
		switch {
		case store.CarryOverError != "":
			return summary + "; some entries of the archive could not be read, so " + ReviewBlockAllowListsHint
		case store.CarriedOver > 0:
			return summary + "; " + blockAllowEntriesCarriedOver(store.CarriedOver) + " from the archive as well."
		}
		return summary + "."
	}
	switch {
	case !store.CarryOverKnown:
		return "a new store was started; DefenseClaw cannot tell whether the old block/allow entries were carried over (the store was moved by an earlier version that kept no record), so " +
			ReviewBlockAllowListsHint
	case store.CarryOverError == "":
		return "a new store was started and " + blockAllowEntriesCarriedOver(store.CarriedOver) + "."
	case store.CarriedOver == 0:
		return "a new store was started, but the old block/allow lists could not be read, so 0 entries were carried over and earlier blocks no longer apply; " +
			ReviewBlockAllowListsHint
	default:
		return "a new store was started and " + blockAllowEntriesCarriedOver(store.CarriedOver) +
			", but some could not be read; " + ReviewBlockAllowListsHint
	}
}

// blockAllowEntriesCarriedOver says "1 block/allow entry was carried over" or
// "N block/allow entries were carried over" (GAP-2053).
func blockAllowEntriesCarriedOver(count int) string {
	if count == 1 {
		return "1 block/allow entry was carried over"
	}
	return fmt.Sprintf("%d block/allow entries were carried over", count)
}

const movedCorruptStoreTimeLayout = "20060102T150405Z"

// MovedCorruptStores lists the stores moved aside next to dbPath, oldest
// first, so start and status can tell the operator instead of only the log.
func MovedCorruptStores(dbPath string) []MovedCorruptStore {
	if dbPath == "" || dbPath == ":memory:" {
		return nil
	}
	absolute, err := filepath.Abs(filepath.Clean(dbPath))
	if err != nil {
		return nil
	}
	names, _ := filepath.Glob(absolute + ".corrupt-*")
	var stores []MovedCorruptStore
	for _, name := range names {
		if hasAuditDBSidecarSuffix(name) || strings.HasSuffix(name, carryOverNoteSuffix) {
			continue
		}
		stamp := strings.TrimPrefix(name, absolute+".corrupt-")
		if len(stamp) < len(movedCorruptStoreTimeLayout) {
			continue
		}
		movedAt, err := time.Parse(movedCorruptStoreTimeLayout, stamp[:len(movedCorruptStoreTimeLayout)])
		if err != nil {
			continue
		}
		if info, err := os.Lstat(name); err != nil || !info.Mode().IsRegular() {
			continue
		}
		store := MovedCorruptStore{Path: name, MovedAt: movedAt}
		if note, ok := readCarryOverNote(name); ok {
			store.CarryOverKnown, store.CarriedOver, store.CarryOverError = true, note.CarriedOver, note.Error
			store.PreCutover = note.PreCutover
		}
		stores = append(stores, store)
	}
	sort.Slice(stores, func(i, j int) bool { return stores[i].MovedAt.Before(stores[j].MovedAt) })
	return stores
}

func hasAuditDBSidecarSuffix(name string) bool {
	for _, suffix := range auditDBSQLiteSidecarSuffixes {
		if strings.HasSuffix(name, suffix) {
			return true
		}
	}
	return false
}

// preCutoverAuditDB reports whether dbPath is a store DefenseClaw 0.x wrote:
// its one-time purge of the pre-1.0 history is still pending. The caller
// holds no connection to dbPath.
func preCutoverAuditDB(dbPath string) bool {
	absolute, err := filepath.Abs(filepath.Clean(dbPath))
	if err != nil {
		return false
	}
	db, err := openAuditReadOnly(absolute)
	if err != nil {
		return false
	}
	defer db.Close() //nolint:errcheck -- read-only handle.
	var version int
	if err := db.QueryRow(`SELECT COALESCE(MAX(version), 0) FROM schema_version`).Scan(&version); err != nil {
		return false
	}
	for index, m := range migrations {
		if m.description == historicalEvidencePurgeMigrationDescription {
			return version > 0 && version <= index
		}
	}
	return false
}

// rebuildAuditDB rewrites every table and index of the store from a full read
// (VACUUM), in place. 0.8.x closed its own descriptors of audit.db while
// SQLite held POSIX locks through them (fixed in 1.0 by #672), so a gateway,
// a hook and the CLI could write at the same time. The stores that left fail
// quick_check ("Rowid N out of order") but still read in full, and VACUUM
// writes them anew. The caller checks the store again before it uses it.
func rebuildAuditDB(dbPath string, progress io.Writer, opts ...StoreOption) error {
	absolute, err := filepath.Abs(filepath.Clean(dbPath))
	if err != nil {
		return err
	}
	if err := auditDBOpenElsewhere(absolute); err != nil {
		return err
	}
	store, err := NewStore(dbPath, opts...)
	if err != nil {
		return err
	}
	defer store.Close() //nolint:errcheck -- the caller reopens and checks the store.
	store.progress = progress
	fmt.Fprintln(store.migrationProgress(), "[audit] rebuilding the 0.x audit store, which failed SQLite's integrity check")
	ctx := context.Background()
	conn, err := store.db.Conn(ctx)
	if err != nil {
		return err
	}
	defer conn.Close() //nolint:errcheck -- returns the connection to the pool.
	if _, err := conn.ExecContext(ctx, `VACUUM`); err != nil {
		return err
	}
	// Give back the WAL the rebuild wrote; best effort, the store is correct either way.
	var busy, frames, checkpointed int
	_ = conn.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &frames, &checkpointed)
	return nil
}

func secureClientStoreOptions(opts []StoreOption) bool {
	var probe Store
	for _, opt := range opts {
		opt(&probe)
	}
	return probe.secureClientSchema
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
	kept, unreadable := 0, 0
	for rows.Next() {
		var targetType, targetName, actionsJSON, connectorName string
		var sourcePath, reason, storedAt sql.NullString
		if err := rows.Scan(&targetType, &targetName, &sourcePath, &actionsJSON, &reason, &storedAt, &connectorName); err != nil {
			unreadable++
			continue
		}
		var state ActionState
		if targetType == "" || targetName == "" || json.Unmarshal([]byte(actionsJSON), &state) != nil {
			unreadable++
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
	if unreadable > 0 && readErr == nil {
		readErr = fmt.Errorf("damaged entries skipped: %d", unreadable)
	} else if unreadable > 0 {
		readErr = fmt.Errorf("%w; damaged entries skipped: %d", readErr, unreadable)
	}
	if err := tx.Commit(); err != nil {
		return 0, err
	}
	return kept, readErr
}
