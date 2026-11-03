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
	"io/fs"
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
	sqliteCodeProtocol = 15
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
	probe, err := probeExistingAuditStore(dbPath, warn)
	if err != nil && !isSQLiteCorrupt(err) {
		return nil, err
	}
	sidecars := probe.sidecars
	var store *Store
	if err == nil {
		afterAuditStoreProbe(dbPath)
		store, err = openCheckedStore(dbPath, warn, progress, probe.checked, opts...)
	}
	if err == nil || !isSQLiteCorrupt(err) {
		return store, err
	}
	// Secure Client keeps the recovery of main (issue #1092).
	preCutover := !secureClientStoreOptions(opts) && preCutoverAuditDB(dbPath)
	if preCutover {
		if rebuildErr := rebuildAuditDB(dbPath, progress, opts...); rebuildErr != nil {
			err = fmt.Errorf("%w; rebuilding it failed: %v", err, rebuildErr)
		} else if rebuilt, retryErr := openCheckedStore(dbPath, warn, progress, nil, opts...); retryErr == nil {
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
			"so it was kept as an archive in %s%s and a new store was created. %s "+
			"Delete the archive and its -wal, -shm and -journal files when you no longer need them. %s\n",
			err, moved, archivedSidecarDescription(moved), archived.BlockAllowSummary(), ArchiveRecoveryHint(moved))
		warnLostArchiveSidecars(warn, sidecars, moved)
		return store, nil
	}
	fmt.Fprintf(warn, "[audit] WARNING: the audit store was corrupt (%v). It was moved to %s%s and a new store was created; block/allow entries carried over: %d.",
		err, moved, archivedSidecarDescription(moved), kept)
	if keepErr != nil {
		fmt.Fprintf(warn, " Some entries could not be read (%v): %s", keepErr, ReviewBlockAllowListsHint)
	}
	fmt.Fprintf(warn, " Older audit records stay in the moved file. %s\n", ArchiveRecoveryHint(moved))
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

// auditStoreProbe is what the read-only probe found: the SQLite sidecars
// beside the store at start, and checked, the files its quick_check read and
// found intact. A skipped or inconclusive check checked nothing (nil).
type auditStoreProbe struct {
	sidecars []auditSidecarAtStart
	checked  *auditCheckedFiles
}

// auditCheckedFiles names the store files a quick_check read: the database
// leaf the check's path guard held open, and the -wal as it was when the
// check ended (absent is a state too). openCheckedStore skips its own check
// only for these files unchanged (sameAs).
type auditCheckedFiles struct {
	db  os.FileInfo
	wal auditFileState
}

type auditFileState struct {
	present bool
	size    int64
	modTime time.Time
}

func auditFileStateOf(path string) (auditFileState, error) {
	info, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return auditFileState{}, nil
	}
	if err != nil {
		return auditFileState{}, err
	}
	return auditFileState{present: true, size: info.Size(), modTime: info.ModTime()}, nil
}

// sameAs reports whether the store the writable open holds (its path guard's
// pinned leaf, and the -wal beside it now) is the file set the probe checked:
// the same file (os.SameFile), with the same size and modification time,
// and a -wal of the same size and modification time. A store renamed into
// place after the probe, or a -wal another process wrote since, is not.
func (checked *auditCheckedFiles) sameAs(store *Store) bool {
	if checked == nil || store == nil || store.dbPathGuard == nil || store.dbPathGuard.pinned == nil {
		return false
	}
	db, err := store.dbPathGuard.pinned.Stat()
	if err != nil || !os.SameFile(checked.db, db) || db.Size() != checked.db.Size() || !db.ModTime().Equal(checked.db.ModTime()) {
		return false
	}
	wal, err := auditFileStateOf(store.dbPathGuard.path + "-wal")
	return err == nil && wal.present == checked.wal.present && wal.size == checked.wal.size && wal.modTime.Equal(checked.wal.modTime)
}

// afterAuditStoreProbe runs between the probe and the writable open, and
// duringAuditStoreProbeCheck right after the probe's quick_check; tests change
// the store files there.
var (
	afterAuditStoreProbe       = func(string) {}
	duringAuditStoreProbeCheck = func(string) {}
)

// unchangedSince reports whether db and wal, read after the probe's
// connection closed, are the files as they were before it opened (checked
// holds that earlier state): the same leaf with the same size and mtime, and
// the same -wal. A -wal that was absent before and is absent or empty after
// is unchanged: the read-only open may create an empty one, which holds no
// frames. Anything else was written while the check ran, possibly after its
// read snapshot, so the check did not read it.
func (checked *auditCheckedFiles) unchangedSince(db os.FileInfo, wal auditFileState) bool {
	if !os.SameFile(checked.db, db) || db.Size() != checked.db.Size() || !db.ModTime().Equal(checked.db.ModTime()) {
		return false
	}
	if !checked.wal.present {
		return !wal.present || wal.size == 0
	}
	return wal.present && wal.size == checked.wal.size && wal.modTime.Equal(checked.wal.modTime)
}

// readOnlyAuditStoreProbe identifies corruption before a writable connection
// can consume a damaged WAL. A hot rollback journal yields SQLITE_READONLY;
// the probe leaves it unchanged and lets SQLite's writable open roll it back.
// If corruption remains, the start warning says the journal was not archived.
// Any other read failure with a populated WAL refuses the start, so a failing
// writable open cannot consume that WAL.
func readOnlyAuditStoreProbe(dbPath string, warn io.Writer) (auditStoreProbe, error) {
	if dbPath == ":memory:" || strings.TrimSpace(dbPath) == "" {
		return auditStoreProbe{}, nil
	}
	absolute, err := filepath.Abs(filepath.Clean(dbPath))
	if err != nil {
		return auditStoreProbe{}, err
	}
	info, err := os.Lstat(absolute)
	if errors.Is(err, os.ErrNotExist) || (err == nil && !info.Mode().IsRegular()) {
		return auditStoreProbe{}, nil // NewStore retains its existing missing/unsafe-path handling.
	}
	if err != nil {
		return auditStoreProbe{}, err
	}
	var sidecars []auditSidecarAtStart
	for _, suffix := range auditDBSQLiteSidecarSuffixes {
		if sidecar, err := os.Lstat(absolute + suffix); err == nil {
			sidecars = append(sidecars, auditSidecarAtStart{suffix: suffix, size: sidecar.Size()})
		} else if !errors.Is(err, os.ErrNotExist) {
			return auditStoreProbe{}, fmt.Errorf("audit: inspect SQLite sidecar %s: %w", suffix, err)
		}
	}
	prepared, err := prepareAuditDatabasePath(absolute, auditDBPathHooks{})
	if err != nil {
		return auditStoreProbe{}, err
	}
	defer prepared.close()
	// The files as they are before the check reads them: a writer that appends
	// while the check runs adds frames it may not read (review round 2).
	var before *auditCheckedFiles
	if prepared.pinned != nil {
		leaf, leafErr := prepared.pinned.Stat()
		wal, walErr := auditFileStateOf(absolute + "-wal")
		if leafErr == nil && walErr == nil {
			before = &auditCheckedFiles{db: leaf, wal: wal}
		}
	}
	db, err := openAuditReadOnlyPreservingSHM(prepared.path, "")
	if err != nil {
		return auditStoreProbe{}, err
	}
	ctx, cancel := context.WithTimeout(context.Background(), startupIntegrityCheckTimeout)
	defer cancel()
	checkErr := quickCheckAuditDB(ctx, db)
	duringAuditStoreProbeCheck(absolute)
	validationErr := prepared.validateAfterOpen()
	closeErr := db.Close()
	var checked *auditCheckedFiles
	if checkErr == nil && validationErr == nil && closeErr == nil && prepared.pinned != nil {
		// The -wal is read once the check's connection is closed: its last
		// close can still change it.
		leaf, leafErr := prepared.pinned.Stat()
		wal, walErr := auditFileStateOf(absolute + "-wal")
		if leafErr == nil && walErr == nil && before != nil && before.unchangedSince(leaf, wal) {
			checked = &auditCheckedFiles{db: leaf, wal: wal}
		}
	}
	if validationErr != nil || closeErr != nil {
		return auditStoreProbe{}, errors.Join(validationErr, closeErr)
	}
	if checkErr != nil && !isSQLiteCorrupt(checkErr) {
		if errors.Is(ctx.Err(), context.DeadlineExceeded) || isTransientSQLiteProbeError(checkErr) {
			fmt.Fprintf(warn, "[audit] startup integrity check skipped: %v\n", checkErr)
			return auditStoreProbe{sidecars: sidecars}, nil
		}
		cause := ""
		var coded sqliteCoded
		if errors.As(checkErr, &coded) && coded.Code()&0xff == sqliteCodeReadOnly {
			cause = " (a hot rollback journal is a common cause)"
		}
		if cause == "" && hasPopulatedWAL(sidecars) {
			// The writable open would most likely fail the same way, and its
			// last connection would checkpoint or delete the WAL as it closed
			// (rel-1-0-2:GAP-0609). Refuse before any writable connection.
			return auditStoreProbe{}, fmt.Errorf("audit: the audit store %s could not be read (%w); the gateway did not open it for writing, "+
				"so its -wal file keeps its records. Copy the store with its -wal and -shm files before you inspect it, "+
				"and run defenseclaw doctor", absolute, checkErr)
		}
		fmt.Fprintf(warn, "[audit] read-only probe could not read the store%s: %v; the normal open and its integrity check follow.\n", cause, checkErr)
		return auditStoreProbe{sidecars: sidecars}, nil
	}
	return auditStoreProbe{sidecars: sidecars, checked: checked}, checkErr
}

// isTransientSQLiteProbeError reports contention a later open does not
// hit: a busy or locked store, including the extended codes, or the WAL
// locking protocol giving up while another process recovers the log.
func isTransientSQLiteProbeError(err error) bool {
	if isSQLiteBusy(err) {
		return true
	}
	var coded sqliteCoded
	if errors.As(err, &coded) {
		switch coded.Code() & 0xff {
		case sqliteCodeBusy, sqliteCodeLocked, sqliteCodeProtocol:
			return true
		}
	}
	return false
}

func hasPopulatedWAL(sidecars []auditSidecarAtStart) bool {
	for _, sidecar := range sidecars {
		if sidecar.suffix == "-wal" && sidecar.size > 0 {
			return true
		}
	}
	return false
}

func archivedSidecarDescription(moved string) string {
	return describeArchivedSidecars(archivedSidecars(moved))
}

func archivedSidecars(moved string) []string {
	var names []string
	for _, suffix := range auditDBSQLiteSidecarSuffixes {
		if _, err := os.Lstat(moved + suffix); err == nil {
			names = append(names, suffix)
		}
	}
	return names
}

func describeArchivedSidecars(names []string) string {
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

// openCheckedStore opens the store and runs its startup quick_check, unless
// the read-only probe has just read the same files and found them intact
// (checked.sameAs). quick_check reads every page, so each run makes the
// start slower by the size of the store: the probe and this second check took
// 1.3 s of a 300 MB store's open on Linux (the probe 0.26 s of it), and a
// Windows per-user restart took 6.6 s at 11 MB and 9.2 s at 272 MB (rel-1-0-6
// GAP-0332). A store replaced or a -wal written between the probe and this
// open is checked again, as every store was before. Secure Client keeps the
// second check of main (#1092).
func openCheckedStore(dbPath string, warn, progress io.Writer, checked *auditCheckedFiles, opts ...StoreOption) (*Store, error) {
	store, err := NewStore(dbPath, opts...)
	if err != nil {
		return nil, err
	}
	store.progress = progress
	if store.secureClientSchema || !checked.sameAs(store) {
		if err := store.startupQuickCheck(warn); err != nil {
			_ = store.Close()
			return nil, err
		}
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
	err := writableStartupQuickCheck(ctx, s.db)
	if isSQLiteCorrupt(err) {
		return err
	}
	if err != nil {
		fmt.Fprintf(warn, "[audit] startup integrity check skipped: %v\n", err)
	}
	return nil
}

// writableStartupQuickCheck is the check of the writable open
// (startupQuickCheck); tests count its runs.
var writableStartupQuickCheck = quickCheckAuditDB

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
	// Sidecars lists the -wal, -shm and -journal files archived with it.
	Sidecars []string
}

// SidecarDescription names the files archived with the store, for example
// " together with its -wal and -shm files", or "" when there are none.
func (store MovedCorruptStore) SidecarDescription() string {
	return describeArchivedSidecars(store.Sidecars)
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
		store := MovedCorruptStore{Path: name, MovedAt: movedAt, Sidecars: archivedSidecars(name)}
		if note, ok := readCarryOverNote(name); ok {
			store.CarryOverKnown, store.CarriedOver, store.CarryOverError = true, note.CarriedOver, note.Error
			store.PreCutover = note.PreCutover
		}
		stores = append(stores, store)
	}
	// Glob returns the names sorted, so stores moved in the same second keep
	// their name order.
	sort.SliceStable(stores, func(i, j int) bool { return stores[i].MovedAt.Before(stores[j].MovedAt) })
	return stores
}

// ReportedMovedCorruptStores keeps the stores that carry the note the gateway
// writes next to every store it moves, oldest first. Only when none has one
// are all stores kept: then they were moved by an earlier version that kept no
// note. A file that only has an archive's name is no record of a move, and
// start and status pointed recovery at such a file instead of the real
// archive, which moved to a new name because that one was taken
// (rel-1-0-3:GAP-0106).
func ReportedMovedCorruptStores(stores []MovedCorruptStore) []MovedCorruptStore {
	var recorded []MovedCorruptStore
	for _, store := range stores {
		if store.CarryOverKnown {
			recorded = append(recorded, store)
		}
	}
	if len(recorded) == 0 {
		return stores
	}
	return recorded
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

// renameAuditStoreFile moves one file of an audit set and never replaces an
// existing destination (renameNoReplace); tests make one step fail.
var renameAuditStoreFile = renameNoReplace

// quarantineNow stamps an archive name; tests pin it.
var quarantineNow = time.Now

// quarantineNameAttempts bounds the archive names tried when other files
// take them first.
const quarantineNameAttempts = 3

// quarantineCorruptAuditDB renames the database and its sidecars to
// "<db>.corrupt-<UTC time>" plus the same suffixes, so the set still opens as
// one database for recovery. Sidecars move first: a new store must never
// replay the old WAL. The set moves as one unit: a rename that fails puts
// back what moved, so the database is never separated from its WAL
// (rel-1-0-2:GAP-0491, as the installers' rollback quarantine). No move
// replaces an existing file, so a name another start took between the check
// and the move is never overwritten; the set then tries a new name
// (rel-1-0-2:GAP-0614).
func quarantineCorruptAuditDB(dbPath string) (string, error) {
	absolute, err := filepath.Abs(filepath.Clean(dbPath))
	if err != nil {
		return "", err
	}
	if err := auditDBOpenElsewhere(absolute); err != nil {
		return "", err
	}
	base := absolute + ".corrupt-" + quarantineNow().UTC().Format(movedCorruptStoreTimeLayout)
	moved := base
	for attempt := 1; ; attempt++ {
		taken, err := archiveNameTaken(moved)
		if err != nil {
			return "", err
		}
		if !taken {
			restored, moveErr := moveAuditSetAside(absolute, moved)
			if moveErr == nil {
				return moved, nil
			}
			if !restored || !errors.Is(moveErr, fs.ErrExist) {
				return "", moveErr
			}
			// Another file took the name after the check; the set is back
			// at its own name, so try a new one.
		}
		if attempt == quarantineNameAttempts {
			return "", fmt.Errorf("no free archive name next to %s after %d attempts", absolute, attempt)
		}
		moved = base + "-" + uuid.NewString()
	}
}

// archiveNameTaken reports whether any file of the set named moved exists:
// an orphan sidecar must never pair with another store.
func archiveNameTaken(moved string) (bool, error) {
	for _, suffix := range append(auditDBSQLiteSidecarSuffixes[:], "") {
		if _, err := os.Lstat(moved + suffix); err == nil {
			return true, nil
		} else if !errors.Is(err, os.ErrNotExist) {
			return false, fmt.Errorf("inspect archive destination %s: %w", moved+suffix, err)
		}
	}
	return false, nil
}

// moveAuditSetAside moves the set at absolute to moved. A step that fails puts
// back what moved, so the database is never separated from its WAL; restored
// says whether that worked.
func moveAuditSetAside(absolute, moved string) (bool, error) {
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
		restored := true
		for i := len(done) - 1; i >= 0; i-- {
			backErr := renameAuditStoreFile(moved+done[i], absolute+done[i])
			if backErr != nil {
				backErr = renameAuditStoreFile(moved+done[i], absolute+done[i])
			}
			if backErr != nil {
				restored = false
				err = fmt.Errorf("%w; %s could not be moved back: %v", err, moved+done[i], backErr)
			}
		}
		return restored, err
	}
	return true, nil
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
