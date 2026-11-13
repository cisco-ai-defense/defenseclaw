// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"
)

// CompactMethod is how a compaction gives the free pages of audit.db back to
// the disk.
type CompactMethod string

const (
	// CompactNothing: the store has no free pages and already uses
	// incremental auto_vacuum; only the WAL is checkpointed.
	CompactNothing CompactMethod = "none"
	// CompactVacuum rewrites the store (VACUUM) and switches it to
	// incremental auto_vacuum, so later retention deletes give their pages
	// back without another rewrite. A store created before 1.0, or one a
	// manual sqlite3 VACUUM rewrote, has auto_vacuum off.
	CompactVacuum CompactMethod = "vacuum"
	// CompactIncremental truncates the free pages of a store that already
	// uses incremental auto_vacuum (PRAGMA incremental_vacuum): no full
	// rewrite and no temporary copy.
	CompactIncremental CompactMethod = "incremental"
)

// compactSpaceMargin is free space a compaction keeps on top of what it
// writes, so the disk is not left full for the gateway (32 MiB start floor)
// and its WAL.
const compactSpaceMargin = 64 << 20

// exclusiveLockingQuery opens a connection in SQLite's exclusive locking
// mode: its first write transaction takes an exclusive lock on the file,
// which SQLite grants only when no other connection has the file open and
// keeps until the connection closes. The WAL index then lives in the
// connection's memory, and its close checkpoints and removes the WAL.
const exclusiveLockingQuery = "?_pragma=locking_mode(EXCLUSIVE)&"

// ErrCompactStoreInUse: a gateway, a defenseclaw command or a sqlite3 shell
// has the audit database open. A compaction needs it alone.
var ErrCompactStoreInUse = errors.New("another process has the audit database open")

// ErrCompactNoStore: there is no audit database at the path.
var ErrCompactNoStore = errors.New("no audit database")

// ErrCompactStoreDamaged: the store failed SQLite's integrity check. A
// compaction never rewrites a damaged store; the gateway's own recovery
// (doctor, defenseclaw-gateway restart) handles it.
var ErrCompactStoreDamaged = errors.New("the audit database failed SQLite's integrity check")

// compactIntegrityBudget bounds the integrity check before a rewrite. A
// check that does not finish in time is reported, not failed: VACUUM reads
// every page itself and rolls back on a damaged one.
var compactIntegrityBudget = 5 * time.Minute

// CompactSpaceError refuses a compaction the disk has no room for.
type CompactSpaceError struct {
	Dir        string
	Need, Free uint64
}

func (e *CompactSpaceError) Error() string {
	return fmt.Sprintf("not enough free disk space in %s to compact the audit database: it needs about %d MiB "+
		"(the copy SQLite writes, its WAL and a %d MiB margin) and %d MiB are free",
		e.Dir, mib(e.Need), compactSpaceMargin>>20, mib(e.Free))
}

// CompactOptions configure CompactStore.
type CompactOptions struct {
	// DryRun only inspects the store, read-only: it reports what a
	// compaction would do and reclaim and changes nothing. It works beside
	// a running gateway.
	DryRun bool
	// FreeDiskBytes reports the free space of a directory. A compaction
	// needs room for what it writes (CompactReport.NeedBytes); nil or an
	// error leaves the free space unknown and skips the check (SQLite still
	// fails cleanly on a full disk). A known 0 refuses.
	FreeDiskBytes func(dir string) (uint64, error)
	// ServiceOwned compacts a managed store that the gateway service owns
	// as an administrator who is not that service (managed Windows). The
	// store, its folders and its sidecars must pass the managed service
	// runtime file checks (validateServiceOwnedAuditDB), which need no
	// gateway token and change no ACL; the caller has checked that the
	// service is stopped.
	ServiceOwned bool
}

// CompactReport describes one compaction, or with DryRun what one would do.
type CompactReport struct {
	Path   string        `json:"path"`
	DryRun bool          `json:"dry_run"`
	Method CompactMethod `json:"method"`
	// AutoVacuumBefore and AutoVacuumAfter are "none", "full" or
	// "incremental" (After is empty on a dry run).
	AutoVacuumBefore string `json:"auto_vacuum_before"`
	AutoVacuumAfter  string `json:"auto_vacuum_after,omitempty"`
	// LiveBytes are the pages that hold data, FreeBytes the pages retention
	// deleted that the file still holds.
	LiveBytes int64 `json:"live_bytes"`
	FreeBytes int64 `json:"free_bytes"`
	// FileBytes and WALBytes are audit.db and audit.db-wal on disk.
	FileBytesBefore int64 `json:"file_bytes_before"`
	WALBytesBefore  int64 `json:"wal_bytes_before"`
	FileBytesAfter  int64 `json:"file_bytes_after,omitempty"`
	WALBytesAfter   int64 `json:"wal_bytes_after,omitempty"`
	// NeedBytes is the free disk space the method needs, DiskFreeBytes what
	// the disk has when DiskFreeKnown.
	NeedBytes     uint64 `json:"need_free_disk_bytes"`
	DiskFreeBytes uint64 `json:"disk_free_bytes"`
	DiskFreeKnown bool   `json:"disk_free_known"`
	// IntegrityCheck is the result of SQLite's quick_check before a rewrite:
	// "ok", "skipped" (nothing to rewrite, or a dry run) or "unfinished"
	// (compactIntegrityBudget ran out).
	IntegrityCheck string `json:"integrity_check"`
}

// ReclaimableBytes is about what the compaction gives back: the free pages
// and the WAL.
func (r CompactReport) ReclaimableBytes() int64 {
	return r.FreeBytes + r.WALBytesBefore
}

// ReclaimedBytes is how much smaller audit.db and its WAL are now.
func (r CompactReport) ReclaimedBytes() int64 {
	if r.DryRun {
		return 0
	}
	before, after := r.FileBytesBefore+r.WALBytesBefore, r.FileBytesAfter+r.WALBytesAfter
	if after >= before {
		return 0
	}
	return before - after
}

// CompactStore gives the free pages of the audit database at path back to
// the disk (issue #1440): SQLite keeps a file at its largest size after
// retention deletes rows. It replaces the manual stop, sqlite3 VACUUM, start
// that doctor printed: sqlite3 is often not installed (Windows), and a plain
// VACUUM keeps auto_vacuum off, so the next retention pass again left free
// pages.
//
// The store must have no other connection: the path is opened through the
// store's custody checks (owner, mode, parents, sidecars) with SQLite's
// exclusive locking mode, and a write transaction claims the file before
// anything is changed. SQLite grants that claim only when no other
// connection, in this or another process, has the file open, and refuses
// every other opener while it is held, so a gateway started during the
// compaction cannot write beside it. Re-running it is safe: a compact store
// is only checkpointed. With ServiceOwned (managed Windows, an administrator
// compacting the stopped gateway service's store) the managed service runtime
// file checks replace the custody open, which needs the service's token.
func CompactStore(path string, opts CompactOptions) (CompactReport, error) {
	absolute, err := compactStorePath(path)
	if err != nil {
		return CompactReport{}, err
	}
	if opts.DryRun {
		return inspectCompaction(absolute, opts)
	}
	// No connection is opened while another process holds a SQLite lock
	// (Linux and macOS; on Windows the claim below refuses).
	if err := auditDBOpenElsewhere(absolute); err != nil {
		return CompactReport{}, fmt.Errorf("%w: %w", ErrCompactStoreInUse, err)
	}
	if opts.ServiceOwned {
		if err := validateServiceOwnedAuditDB(absolute, false); err != nil {
			return CompactReport{}, err
		}
	}
	// The integrity and space checks read the store through the read-only
	// handle, which never checkpoints or removes the WAL: a store that
	// fails them is left exactly as it was.
	planned, err := planCompaction(absolute, opts)
	if err != nil {
		return planned, err
	}
	if planned.DiskFreeKnown && planned.DiskFreeBytes < planned.NeedBytes {
		return planned, &CompactSpaceError{Dir: filepath.Dir(absolute), Need: planned.NeedBytes, Free: planned.DiskFreeBytes}
	}
	opened, revalidate, err := openCompactConnection(absolute, opts)
	if err != nil {
		if isSQLiteBusy(err) {
			return CompactReport{}, ErrCompactStoreInUse
		}
		return CompactReport{}, err
	}
	defer opened.Close() //nolint:errcheck -- closed below; this covers the error returns.
	ctx := context.Background()
	conn, err := opened.Conn(ctx)
	if err != nil {
		return CompactReport{}, err
	}
	defer conn.Close() //nolint:errcheck -- closed below; this covers the error returns.
	if err := claimExclusive(ctx, conn); err != nil {
		return CompactReport{}, err
	}
	// The files SQLite opened for the claim pass the same checks.
	if err := revalidate(); err != nil {
		return CompactReport{}, err
	}
	report, err := readCompaction(ctx, conn, absolute, opts)
	if err != nil {
		return CompactReport{}, err
	}
	report.IntegrityCheck = planned.IntegrityCheck
	if report.DiskFreeKnown && report.DiskFreeBytes < report.NeedBytes {
		return report, &CompactSpaceError{Dir: filepath.Dir(absolute), Need: report.NeedBytes, Free: report.DiskFreeBytes}
	}
	switch report.Method {
	case CompactVacuum:
		err = vacuumInDirectory(ctx, conn, filepath.Dir(absolute))
	case CompactIncremental:
		_, err = conn.ExecContext(ctx, `PRAGMA incremental_vacuum`)
	}
	if err != nil {
		// VACUUM and incremental_vacuum roll back on failure.
		return report, fmt.Errorf("compact the audit database (%s): %w", report.Method, err)
	}
	if busy, err := checkpointTruncate(ctx, conn); err != nil || busy != 0 {
		return report, fmt.Errorf("compact the audit database: checkpoint the WAL (busy=%d): %w", busy, err)
	}
	var mode int
	if err := conn.QueryRowContext(ctx, `PRAGMA auto_vacuum`).Scan(&mode); err != nil {
		return report, fmt.Errorf("compact the audit database: read auto_vacuum: %w", err)
	}
	report.AutoVacuumAfter = autoVacuumName(mode)
	// The exclusive connection's close checkpoints and removes the WAL.
	if err := errors.Join(conn.Close(), opened.Close()); err != nil {
		return report, fmt.Errorf("compact the audit database: close: %w", err)
	}
	report.FileBytesAfter, report.WALBytesAfter = compactFileSizes(absolute)
	return report, nil
}

// openCompactConnection opens the store in exclusive locking mode: through
// the store's custody checks, or for ServiceOwned through a plain open after
// validateServiceOwnedAuditDB, which revalidate repeats on the same file.
func openCompactConnection(absolute string, opts CompactOptions) (*hardenedAuditSQLite, func() error, error) {
	if !opts.ServiceOwned {
		opened, err := openHardenedAuditSQLite(absolute, auditDBPathHooks{exclusive: true})
		if err != nil {
			return nil, nil, err
		}
		return opened, opened.prepared.validateAfterOpen, nil
	}
	before, err := os.Lstat(absolute)
	if err != nil {
		return nil, nil, fmt.Errorf("audit: inspect %s: %w", absolute, err)
	}
	db, err := openSQLiteWithPragmas(absolute, exclusiveLockingQuery+strings.TrimPrefix(auditPragmasFor(false), "?"))
	if err != nil {
		return nil, nil, err
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		return nil, nil, fmt.Errorf("audit: open %s: %w", absolute, err)
	}
	revalidate := func() error {
		if err := validateServiceOwnedAuditDB(absolute, true); err != nil {
			return err
		}
		after, err := os.Lstat(absolute)
		if err != nil || !os.SameFile(before, after) {
			return fmt.Errorf("audit: %s changed while compact opened it", absolute)
		}
		return nil
	}
	return &hardenedAuditSQLite{DB: db}, revalidate, nil
}

// planCompaction reads the store read-only, picks the method and runs a
// bounded quick_check before a rewrite.
func planCompaction(absolute string, opts CompactOptions) (CompactReport, error) {
	db, err := OpenReadOnlyDB(absolute)
	if err != nil {
		if isSQLiteBusy(err) {
			// A compaction claim, or a writer in exclusive mode, holds it.
			return CompactReport{}, ErrCompactStoreInUse
		}
		return CompactReport{}, err
	}
	defer db.Close() //nolint:errcheck -- read-only handle.
	conn, err := db.Conn(context.Background())
	if err != nil {
		return CompactReport{}, err
	}
	defer conn.Close() //nolint:errcheck -- returns the connection to the pool.
	report, err := readCompaction(context.Background(), conn, absolute, opts)
	if err != nil {
		if isSQLiteBusy(err) {
			return report, ErrCompactStoreInUse
		}
		if isSQLiteCorrupt(err) {
			return report, fmt.Errorf("%w: %w", ErrCompactStoreDamaged, err)
		}
		return report, err
	}
	report.IntegrityCheck = "skipped"
	if report.Method == CompactNothing {
		return report, nil
	}
	ctx, cancel := context.WithTimeout(context.Background(), compactIntegrityBudget)
	defer cancel()
	var result string
	err = conn.QueryRowContext(ctx, `PRAGMA quick_check(1)`).Scan(&result)
	switch {
	case ctx.Err() != nil:
		report.IntegrityCheck = "unfinished"
	case err != nil && isSQLiteCorrupt(err):
		return report, fmt.Errorf("%w: %w", ErrCompactStoreDamaged, err)
	case err != nil:
		return report, fmt.Errorf("audit: check %s: %w", absolute, err)
	case result != "ok":
		return report, fmt.Errorf("%w: quick_check: %s", ErrCompactStoreDamaged, result)
	default:
		report.IntegrityCheck = "ok"
	}
	return report, nil
}

// compactStorePath resolves path and refuses one that holds no file.
func compactStorePath(path string) (string, error) {
	if strings.TrimSpace(path) == "" || path == ":memory:" {
		return "", errors.New("audit: database path is required")
	}
	absolute, err := filepath.Abs(filepath.Clean(path))
	if err != nil {
		return "", errors.New("audit: normalize database path")
	}
	info, err := os.Lstat(absolute)
	if errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("%w at %s", ErrCompactNoStore, absolute)
	}
	if err != nil {
		return "", fmt.Errorf("audit: inspect %s: %w", absolute, err)
	}
	if !info.Mode().IsRegular() {
		return "", fmt.Errorf("audit: %s is not an audit database file", absolute)
	}
	return absolute, nil
}

// claimExclusive takes the write lock in exclusive locking mode, which SQLite
// then keeps until the connection closes.
func claimExclusive(ctx context.Context, conn *sql.Conn) error {
	if _, err := conn.ExecContext(ctx, `BEGIN IMMEDIATE`); err != nil {
		if isSQLiteBusy(err) {
			return ErrCompactStoreInUse
		}
		return fmt.Errorf("audit: lock the database for compaction: %w", err)
	}
	if _, err := conn.ExecContext(ctx, `COMMIT`); err != nil {
		return fmt.Errorf("audit: lock the database for compaction: %w", err)
	}
	return nil
}

// inspectCompaction is the dry run: the store is read through the read-only
// review handle, which never writes, migrates or takes the store from a
// running gateway.
func inspectCompaction(absolute string, opts CompactOptions) (CompactReport, error) {
	db, err := OpenReadOnlyDB(absolute)
	if err != nil {
		return CompactReport{}, err
	}
	defer db.Close() //nolint:errcheck -- read-only handle.
	ctx := context.Background()
	conn, err := db.Conn(ctx)
	if err != nil {
		return CompactReport{}, err
	}
	defer conn.Close() //nolint:errcheck -- returns the connection to the pool.
	report, err := readCompaction(ctx, conn, absolute, opts)
	report.DryRun = true
	report.IntegrityCheck = "skipped"
	return report, err
}

// readCompaction reads the page counts and file sizes and picks the method.
func readCompaction(ctx context.Context, conn *sql.Conn, absolute string, opts CompactOptions) (CompactReport, error) {
	report := CompactReport{Path: absolute}
	var schemaTables int
	if err := conn.QueryRowContext(ctx, `SELECT COUNT(*) FROM sqlite_master WHERE type = 'table' AND name = 'schema_version'`).Scan(&schemaTables); err != nil {
		return report, fmt.Errorf("audit: read %s: %w", absolute, err)
	}
	if schemaTables == 0 {
		return report, fmt.Errorf("audit: %s is not an initialized audit database", absolute)
	}
	var pageSize, pages, free int64
	var mode int
	for _, pragma := range []struct {
		name string
		into any
	}{{"page_size", &pageSize}, {"page_count", &pages}, {"freelist_count", &free}, {"auto_vacuum", &mode}} {
		if err := conn.QueryRowContext(ctx, `PRAGMA `+pragma.name).Scan(pragma.into); err != nil {
			return report, fmt.Errorf("audit: read PRAGMA %s: %w", pragma.name, err)
		}
	}
	report.AutoVacuumBefore = autoVacuumName(mode)
	report.LiveBytes, report.FreeBytes = (pages-free)*pageSize, free*pageSize
	report.FileBytesBefore, report.WALBytesBefore = compactFileSizes(absolute)
	switch {
	case mode != 2:
		// VACUUM writes a copy of the live pages to a temporary file in
		// the database folder, then the same pages to the WAL.
		report.Method = CompactVacuum
		report.NeedBytes = uint64(2*report.LiveBytes) + compactSpaceMargin
	case free > 0:
		// incremental_vacuum moves at most one live page into each free
		// page, through the WAL.
		report.Method = CompactIncremental
		report.NeedBytes = uint64(min(report.FreeBytes, report.LiveBytes)) + compactSpaceMargin
	default:
		report.Method = CompactNothing
	}
	if opts.FreeDiskBytes != nil {
		if freeDisk, err := opts.FreeDiskBytes(filepath.Dir(absolute)); err == nil {
			report.DiskFreeBytes, report.DiskFreeKnown = freeDisk, true
		}
	}
	return report, nil
}

// vacuumInDirectory runs the VACUUM with its temporary copy in dir instead
// of memory (the store's temp_store) or the system temp folder: the copy is
// as large as the live data and holds audit history, which stays in the
// store's own private folder and is counted by the space check.
func vacuumInDirectory(ctx context.Context, conn *sql.Conn, dir string) error {
	if err := setCompactTempDirectory(ctx, conn, dir); err != nil {
		return err
	}
	// temp_store_directory is process-wide in SQLite: put it back.
	defer conn.ExecContext(ctx, `PRAGMA temp_store_directory=''`) //nolint:errcheck -- the process ends after a compaction.
	return vacuumToIncrementalAutoVacuum(ctx, conn)
}

// setCompactTempDirectory puts SQLite's temporary files on disk in dir and
// reads the setting back: the space check counted the VACUUM copy on that
// disk, so a setting SQLite ignored refuses the rewrite.
func setCompactTempDirectory(ctx context.Context, conn *sql.Conn, dir string) error {
	quoted := "'" + strings.ReplaceAll(dir, "'", "''") + "'"
	for _, statement := range []string{`PRAGMA temp_store=FILE`, `PRAGMA temp_store_directory=` + quoted} {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("%s: %w", statement, err)
		}
	}
	var got string
	var store int
	if err := conn.QueryRowContext(ctx, `PRAGMA temp_store_directory`).Scan(&got); err != nil || got != dir {
		return fmt.Errorf("audit: SQLite did not take the temporary folder %s (got %q): %v", dir, got, err)
	}
	if err := conn.QueryRowContext(ctx, `PRAGMA temp_store`).Scan(&store); err != nil || store != 1 {
		return fmt.Errorf("audit: SQLite did not put temporary files on disk (temp_store=%d): %v", store, err)
	}
	return nil
}

// vacuumToIncrementalAutoVacuum rewrites the store with only the rows that
// are left and switches it to the incremental auto_vacuum a new store gets,
// so retention gives later deletes back too. auto_vacuum is per connection
// until VACUUM applies it, so both run on conn.
func vacuumToIncrementalAutoVacuum(ctx context.Context, conn *sql.Conn) error {
	for _, statement := range []string{`PRAGMA auto_vacuum=INCREMENTAL`, `VACUUM`} {
		if _, err := conn.ExecContext(ctx, statement); err != nil {
			return fmt.Errorf("%s: %w", statement, err)
		}
	}
	return nil
}

// checkpointTruncate copies the WAL into the store and empties it; busy is
// nonzero when another connection kept it from finishing.
func checkpointTruncate(ctx context.Context, conn *sql.Conn) (int, error) {
	var busy, frames, checkpointed int
	err := conn.QueryRowContext(ctx, `PRAGMA wal_checkpoint(TRUNCATE)`).Scan(&busy, &frames, &checkpointed)
	return busy, err
}

func autoVacuumName(mode int) string {
	switch mode {
	case 0:
		return "none"
	case 1:
		return "full"
	case 2:
		return "incremental"
	}
	return fmt.Sprintf("unknown (%d)", mode)
}

// compactFileSizes returns the sizes of audit.db and its WAL (0 when absent).
func compactFileSizes(absolute string) (int64, int64) {
	size := func(path string) int64 {
		if info, err := os.Stat(path); err == nil {
			return info.Size()
		}
		return 0
	}
	return size(absolute), size(absolute + "-wal")
}

func mib(bytes uint64) uint64 { return (bytes + (1<<20 - 1)) >> 20 }
