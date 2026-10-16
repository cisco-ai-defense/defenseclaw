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

// SQLite primary result codes used to classify an integrity probe result.
const (
	sqliteCodeReadOnly = 8
	sqliteCodeCorrupt  = 11
	sqliteCodeNotADB   = 26
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
// A cold rollback journal present beside a corrupt store moves with it. A hot
// rollback journal makes the read-only probe inconclusive; SQLite rolls it back
// during the normal writable open, so it is not archived. If the store is then
// corrupt, the start warning reports that its pre-existing journal was not
// preserved.
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
	// A failed writable SQLite open can checkpoint or delete a damaged store's
	// WAL as its last connection closes. Check an existing store read-only first,
	// before any connection with journal_mode(WAL) is allowed to open it.
	sidecars, err := probeExistingAuditStore(dbPath, warn)
	if err != nil && !isSQLiteCorrupt(err) {
		return nil, err
	}
	var store *Store
	if err == nil {
		store, err = openCheckedStore(dbPath, warn, progress, opts...)
	}
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
	store, freshErr := newCorruptRecoveryStore(dbPath, opts...)
	if freshErr == nil {
		store.progress = progress
		if freshErr = initCorruptRecoveryStore(store); freshErr != nil {
			freshErr = errors.Join(freshErr, store.Close())
		}
	}
	if freshErr != nil {
		if restoreErr := restoreAuditStoreAfterFailedCreation(dbPath, moved); restoreErr != nil {
			return nil, fmt.Errorf("audit: create a new store after moving the corrupt one to %s: %w; original store could not be restored: %v", moved, freshErr, restoreErr)
		}
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
		warnLostArchiveSidecars(warn, sidecars, moved)
		return store, nil
	}
	fmt.Fprintf(warn, "[audit] WARNING: the audit store was corrupt (%v). It was moved to %s%s and a new store was created; block/allow entries carried over: %d.",
		err, moved, archivedSidecarDescription(moved), kept)
	if keepErr != nil {
		fmt.Fprintf(warn, " Some entries could not be read (%v): %s", keepErr, ReviewBlockAllowListsHint)
	}
	fmt.Fprintf(warn, " Older audit records stay in the moved file; recover them with: sqlite3 %s .recover\n", moved)
	warnLostArchiveSidecars(warn, sidecars, moved)
	return store, nil
}

// probeExistingAuditStore validates the same path and sidecar trust boundary
// as NewStore, then runs a bounded integrity check without a writable SQLite
// connection. Every descriptor is closed before a possible Windows rename.
// A hot rollback journal cannot be recovered read-only, so that probe result
// is inconclusive; SQLite rolls it back in the writable open, and a later
// corruption warning reports that the journal was not archived.
// The seam lets tests make the probe fail before any file can be moved.
var probeExistingAuditStore = readOnlyAuditStoreProbe

type auditSidecarAtStart struct {
	suffix string
	size   int64
}

// readOnlyAuditStoreProbe identifies corruption before a writable connection
// can consume a damaged WAL. A hot rollback journal yields SQLITE_READONLY;
// the probe leaves it unchanged and lets SQLite's writable open roll it back.
// If corruption remains, the start warning says the journal was not archived.
func readOnlyAuditStoreProbe(dbPath string, warn io.Writer) ([]auditSidecarAtStart, error) {
	if dbPath == ":memory:" || strings.TrimSpace(dbPath) == "" {
		return nil, nil
	}
	absolute, err := filepath.Abs(filepath.Clean(dbPath))
	if err != nil {
		return nil, err
	}
	info, err := os.Lstat(absolute)
	if errors.Is(err, os.ErrNotExist) || (err == nil && !info.Mode().IsRegular()) {
		return nil, nil // NewStore retains its existing missing/unsafe-path handling.
	}
	if err != nil {
		return nil, err
	}
	var sidecars []auditSidecarAtStart
	for _, suffix := range auditDBSQLiteSidecarSuffixes {
		if sidecar, err := os.Lstat(absolute + suffix); err == nil {
			sidecars = append(sidecars, auditSidecarAtStart{suffix: suffix, size: sidecar.Size()})
		} else if !errors.Is(err, os.ErrNotExist) {
			return nil, fmt.Errorf("audit: inspect SQLite sidecar %s: %w", suffix, err)
		}
	}
	prepared, err := prepareAuditDatabasePath(absolute, auditDBPathHooks{})
	if err != nil {
		return nil, err
	}
	defer prepared.close()
	db, err := openAuditReadOnlyPreservingSHM(prepared.path, "")
	if err != nil {
		return nil, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), startupIntegrityCheckTimeout)
	defer cancel()
	checkErr := quickCheckAuditDB(ctx, db)
	validationErr := prepared.validateAfterOpen()
	closeErr := db.Close()
	if validationErr != nil || closeErr != nil {
		return nil, errors.Join(validationErr, closeErr)
	}
	if checkErr != nil && !isSQLiteCorrupt(checkErr) {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || isSQLiteBusy(checkErr) {
			fmt.Fprintf(warn, "[audit] startup integrity check skipped: %v\n", checkErr)
			return sidecars, nil
		}
		cause := ""
		var coded sqliteCoded
		if errors.As(checkErr, &coded) && coded.Code()&0xff == sqliteCodeReadOnly {
			cause = " (a hot rollback journal is a common cause)"
		}
		fmt.Fprintf(warn, "[audit] read-only probe could not read the store%s: %v; the normal open and its integrity check follow.\n", cause, checkErr)
		return sidecars, nil
	}
	return sidecars, checkErr
}

func archivedSidecarDescription(moved string) string {
	var names []string
	for _, suffix := range auditDBSQLiteSidecarSuffixes {
		if _, err := os.Lstat(moved + suffix); err == nil {
			names = append(names, suffix)
		}
	}
	if len(names) == 0 {
		return ""
	}
	if len(names) == 1 {
		return " together with its " + names[0] + " file"
	}
	return " together with its " + strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1] + " files"
}

func warnLostArchiveSidecars(warn io.Writer, before []auditSidecarAtStart, moved string) {
	for _, sidecar := range before {
		archived, err := os.Lstat(moved + sidecar.suffix)
		if err != nil {
			if sidecar.suffix == "-journal" && errors.Is(err, os.ErrNotExist) {
				fmt.Fprintf(warn, "[audit] WARNING: the pre-existing -journal sidecar was not preserved in %s (SQLite may have consumed it during rollback recovery): %v.\n", moved, err)
			} else {
				fmt.Fprintf(warn, "[audit] WARNING: the pre-existing %s sidecar could not be verified in %s: %v.\n", sidecar.suffix, moved, err)
			}
		} else if sidecar.suffix != "-shm" && archived.Size() != sidecar.size {
			fmt.Fprintf(warn, "[audit] WARNING: the pre-existing %s sidecar changed size from %d to %d before it reached %s; its original bytes were not preserved.\n",
				sidecar.suffix, sidecar.size, archived.Size(), moved)
		}
	}
}

// A fresh-store constructor can fail after creating audit.db. Remove only
// that new set, then return the archived set to its original names. If a move
// back fails, put the already restored files beside the archive again, so a
// new database can never be paired with an old WAL.
var newCorruptRecoveryStore = NewStore
var initCorruptRecoveryStore = (*Store).Init
var removeCorruptRecoveryFile = os.Remove

func restoreAuditStoreAfterFailedCreation(dbPath, moved string) error {
	absolute, err := filepath.Abs(filepath.Clean(dbPath))
	if err != nil {
		return err
	}
	for _, suffix := range append(auditDBSQLiteSidecarSuffixes[:], "") {
		err := removeCorruptRecoveryFile(absolute + suffix)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			err = removeCorruptRecoveryFile(absolute + suffix) // a transient refusal must not strand the old store.
		}
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			return fmt.Errorf("remove incomplete new store %s: %w", absolute+suffix, err)
		}
	}
	var done []string
	for _, suffix := range append(auditDBSQLiteSidecarSuffixes[:], "") {
		err := renameAuditStoreFile(moved+suffix, absolute+suffix)
		if err != nil && !errors.Is(err, os.ErrNotExist) {
			err = renameAuditStoreFile(moved+suffix, absolute+suffix)
		}
		if err != nil {
			if suffix != "" && errors.Is(err, os.ErrNotExist) {
				continue
			}
			for i := len(done) - 1; i >= 0; i-- {
				if backErr := renameAuditStoreFile(absolute+done[i], moved+done[i]); backErr != nil {
					err = fmt.Errorf("%w; %s could not be returned to archive: %v", err, absolute+done[i], backErr)
				}
			}
			return err
		}
		done = append(done, suffix)
	}
	return nil
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
	err := quickCheckAuditDB(ctx, s.db)
	if isSQLiteCorrupt(err) {
		return err
	}
	if err != nil {
		fmt.Fprintf(warn, "[audit] startup integrity check skipped: %v\n", err)
	}
	return nil
}

func quickCheckAuditDB(ctx context.Context, db *sql.DB) error {
	var result string
	if err := db.QueryRowContext(ctx, "PRAGMA quick_check(1)").Scan(&result); err != nil {
		return err
	}
	if result == "ok" {
		return nil
	}
	detail, _, _ := strings.Cut(strings.TrimSpace(strings.TrimPrefix(result, "*** in database main ***")), "\n")
	return fmt.Errorf("audit: startup integrity check failed: %s: %w", detail, errCorruptAuditDB)
}

// An ordinary read-only connection can still rebuild an existing SHM index.
// SQLite's readonly_shm URI option reads the existing index without writing
// it. It cannot initialize a missing SHM, so use the ordinary read-only path
// when there was no SHM to preserve.
func openAuditReadOnlyPreservingSHM(dbPath, extra string) (*sql.DB, error) {
	if _, err := os.Lstat(dbPath + "-shm"); err == nil {
		extra = "&readonly_shm=1" + extra
	} else if !errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Errorf("audit: inspect SQLite SHM: %w", err)
	}
	return openAuditReadOnlyWith(dbPath, extra)
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
	db, err := openAuditReadOnlySchemaTolerant(absolute)
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

// schemaTolerantQuery turns on writable_schema for a connection, so SQLite
// skips a schema entry it would refuse instead of failing every statement.
// 0.8.x stores can carry one: the same concurrent writers leave an orphan
// quarantine_records index ("malformed database schema
// (sqlite_autoindex_quarantine_records_1) - orphan index", GAP-1576), and a
// 0.8.10 store started after a rollback to it gets one within minutes. The
// tables stay intact and read in full, and a VACUUM writes the store anew from
// the table definitions, the dropped index included.
const schemaTolerantQuery = "&_pragma=writable_schema(1)"

// schemaTolerantPragmas open a store for its rebuild: writable_schema and
// the busy timeout only, because SQLite refuses most other audit pragmas
// (journal_mode, synchronous and more) on such a schema even with
// writable_schema on. The store keeps the WAL mode its header records, and
// the caller reopens it with the full audit pragmas after the rebuild.
const schemaTolerantPragmas = "?_pragma=writable_schema(1)&_pragma=busy_timeout(5000)"

// openAuditReadOnlySchemaTolerant opens a store read-only without rewriting
// its SHM index; when SQLite refuses its schema as damaged it opens it again
// with schemaTolerantQuery.
func openAuditReadOnlySchemaTolerant(dbPath string) (*sql.DB, error) {
	db, err := openAuditReadOnlyPreservingSHM(dbPath, "")
	if err != nil {
		return nil, err
	}
	var entries int
	if probeErr := db.QueryRow(`SELECT count(*) FROM sqlite_schema`).Scan(&entries); !isSQLiteCorrupt(probeErr) {
		return db, nil
	}
	_ = db.Close()
	return openAuditReadOnlyPreservingSHM(dbPath, schemaTolerantQuery)
}

// rebuildAuditDB rewrites every table and index of the store from a full read
// (VACUUM), in place, with writable_schema on so a refused schema entry
// (schemaTolerantQuery) does not stop it. 0.8.x closed its own descriptors of audit.db while
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
	store, err := newStoreWithHooks(dbPath, auditDBPathHooks{schemaTolerant: true}, opts...)
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
	// VACUUM copies only the tables SQLite could load: a table among the
	// skipped entries would be dropped, so such a store is moved aside whole
	// instead.
	if err := everySchemaTableReads(ctx, conn); err != nil {
		return err
	}
	if _, err := conn.ExecContext(ctx, `VACUUM`); err != nil {
		return err
	}
	// Give back the WAL the rebuild wrote; best effort, the store is correct either way.
	var busy, frames, checkpointed int
	_ = conn.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &frames, &checkpointed)
	return nil
}

// everySchemaTableReads checks that each table sqlite_schema lists can be
// read on conn.
func everySchemaTableReads(ctx context.Context, conn *sql.Conn) error {
	rows, err := conn.QueryContext(ctx, `SELECT name FROM sqlite_schema WHERE type = 'table' AND name NOT LIKE 'sqlite\_%' ESCAPE '\'`)
	if err != nil {
		return err
	}
	var names []string
	for rows.Next() {
		var name string
		if err := rows.Scan(&name); err != nil {
			_ = rows.Close()
			return err
		}
		names = append(names, name)
	}
	if err := errors.Join(rows.Err(), rows.Close()); err != nil {
		return err
	}
	for _, name := range names {
		// NOT INDEXED: the index of a skipped entry has no root page, and
		// VACUUM reads the table itself.
		quoted := `"` + strings.ReplaceAll(name, `"`, `""`) + `"`
		rows, err := conn.QueryContext(ctx, `SELECT 1 FROM `+quoted+` NOT INDEXED LIMIT 1`)
		if err == nil {
			for rows.Next() {
			}
			err = errors.Join(rows.Err(), rows.Close())
		}
		if err != nil {
			return fmt.Errorf("table %s cannot be read: %w", name, err)
		}
	}
	return nil
}

func secureClientStoreOptions(opts []StoreOption) bool {
	var probe Store
	for _, opt := range opts {
		opt(&probe)
	}
	return probe.secureClientSchema
}

// renameAuditStoreFile is os.Rename; tests make one step fail.
var renameAuditStoreFile = os.Rename

// quarantineCorruptAuditDB renames the database and its sidecars to
// "<db>.corrupt-<UTC time>" plus the same suffixes, so the set still opens as
// one database for recovery. Sidecars move first: a new store must never
// replay the old WAL. The set moves as one unit: a rename that fails puts
// back what moved, so the database is never separated from its WAL
// (rel-1-0-2:GAP-0491, as the installers' rollback quarantine).
func quarantineCorruptAuditDB(dbPath string) (string, error) {
	absolute, err := filepath.Abs(filepath.Clean(dbPath))
	if err != nil {
		return "", err
	}
	if err := auditDBOpenElsewhere(absolute); err != nil {
		return "", err
	}
	base := absolute + ".corrupt-" + time.Now().UTC().Format("20060102T150405Z")
	moved := base
	for {
		collision := false
		for _, suffix := range append(auditDBSQLiteSidecarSuffixes[:], "") {
			if _, err := os.Lstat(moved + suffix); err == nil {
				collision = true
				break
			} else if !errors.Is(err, os.ErrNotExist) {
				return "", fmt.Errorf("inspect archive destination %s: %w", moved+suffix, err)
			}
		}
		if !collision {
			break
		}
		moved = base + "-" + uuid.NewString()
	}
	var done []string
	for _, suffix := range append(auditDBSQLiteSidecarSuffixes[:], "") {
		err := renameAuditStoreFile(absolute+suffix, moved+suffix)
		if err == nil {
			done = append(done, suffix)
			continue
		}
		if suffix != "" && errors.Is(err, os.ErrNotExist) {
			continue
		}
		for i := len(done) - 1; i >= 0; i-- {
			backErr := renameAuditStoreFile(moved+done[i], absolute+done[i])
			if backErr != nil {
				backErr = renameAuditStoreFile(moved+done[i], absolute+done[i])
			}
			if backErr != nil {
				err = fmt.Errorf("%w; %s could not be moved back: %v", err, moved+done[i], backErr)
			}
		}
		return "", err
	}
	return moved, nil
}

// carryOverActions copies the readable block/allow rows of the moved store
// into this new one, so a rebuild never silently lifts a block.
func (s *Store) carryOverActions(movedPath string) (int, error) {
	old, err := openAuditReadOnlySchemaTolerant(movedPath)
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
