// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

// compactHolderPathEnv names the store TestCompactHolderProcess keeps open.
const compactHolderPathEnv = "DEFENSECLAW_TEST_COMPACT_HOLD"

// prunedStoreWithoutAutoVacuum builds what issue #1440 found: an initialized
// store with auto_vacuum off (created before 1.0, or rewritten by a manual
// sqlite3 VACUUM) whose retention deleted most rows, so the file keeps its
// size. It returns the path and the number of rows left.
func prunedStoreWithoutAutoVacuum(t *testing.T) (string, int) {
	t.Helper()
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	for _, statement := range []string{
		`PRAGMA auto_vacuum=NONE`, `VACUUM`,
		`CREATE TABLE compact_filler (id INTEGER PRIMARY KEY, body BLOB NOT NULL)`,
		`WITH RECURSIVE n(i) AS (SELECT 1 UNION ALL SELECT i + 1 FROM n WHERE i < 3000)
			INSERT INTO compact_filler (body) SELECT randomblob(4000) FROM n`,
		`DELETE FROM compact_filler WHERE id % 10 != 0`,
	} {
		if _, err := store.db.Exec(statement); err != nil {
			t.Fatalf("%s: %v", statement, err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	return path, 300
}

func compactPragma(t *testing.T, path, pragma string) int64 {
	t.Helper()
	db, err := OpenReadOnlyDB(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer db.Close() //nolint:errcheck
	var value int64
	if err := db.QueryRow(`PRAGMA ` + pragma).Scan(&value); err != nil {
		t.Fatalf("PRAGMA %s: %v", pragma, err)
	}
	return value
}

func compactRows(t *testing.T, path string) int {
	t.Helper()
	db, err := OpenReadOnlyDB(path)
	if err != nil {
		t.Fatalf("open %s: %v", path, err)
	}
	defer db.Close() //nolint:errcheck
	var rows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM compact_filler`).Scan(&rows); err != nil {
		t.Fatalf("count rows: %v", err)
	}
	return rows
}

func roomyDisk(string) (uint64, error) { return 1 << 40, nil }

func TestCompactStoreShrinksAPrunedStoreAndSwitchesItToIncrementalAutoVacuum(t *testing.T) {
	path, rows := prunedStoreWithoutAutoVacuum(t)
	if mode := compactPragma(t, path, "auto_vacuum"); mode != 0 {
		t.Fatalf("fixture auto_vacuum = %d, want 0 (none)", mode)
	}
	if free := compactPragma(t, path, "freelist_count"); free == 0 {
		t.Fatal("fixture has no free pages")
	}
	before, _ := compactFileSizes(path)

	dry, err := CompactStore(path, CompactOptions{DryRun: true, FreeDiskBytes: roomyDisk})
	if err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if !dry.DryRun || dry.Method != CompactVacuum || dry.AutoVacuumBefore != "none" || dry.FreeBytes <= 0 || dry.ReclaimedBytes() != 0 {
		t.Fatalf("dry run report = %+v", dry)
	}
	if size, _ := compactFileSizes(path); size != before || compactPragma(t, path, "auto_vacuum") != 0 {
		t.Fatalf("dry run changed the store: size %d -> %d", before, size)
	}

	report, err := CompactStore(path, CompactOptions{FreeDiskBytes: roomyDisk})
	if err != nil {
		t.Fatalf("CompactStore: %v", err)
	}
	if report.Method != CompactVacuum || report.AutoVacuumAfter != "incremental" {
		t.Fatalf("report = %+v", report)
	}
	after, wal := compactFileSizes(path)
	if after >= before/2 || wal != 0 || report.FileBytesAfter != after || report.ReclaimedBytes() < before/2 {
		t.Fatalf("store %d -> %d bytes (wal %d), report %+v", before, after, wal, report)
	}
	if mode := compactPragma(t, path, "auto_vacuum"); mode != 2 {
		t.Fatalf("auto_vacuum after compaction = %d, want 2 (incremental)", mode)
	}
	if got := compactRows(t, path); got != rows {
		t.Fatalf("rows after compaction = %d, want %d", got, rows)
	}

	// Re-running finds nothing to reclaim and changes nothing.
	again, err := CompactStore(path, CompactOptions{FreeDiskBytes: roomyDisk})
	if err != nil || again.Method != CompactNothing || again.ReclaimedBytes() != 0 {
		t.Fatalf("second run = %+v, %v", again, err)
	}

	// The store now gives later deletes back without a rewrite.
	store, err := NewStore(path)
	if err != nil {
		t.Fatalf("reopen: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("reopen Init: %v", err)
	}
	if _, err := store.db.Exec(`DELETE FROM compact_filler WHERE id % 20 != 0`); err != nil {
		t.Fatalf("delete: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	incremental, err := CompactStore(path, CompactOptions{FreeDiskBytes: roomyDisk})
	if err != nil || incremental.Method != CompactIncremental || incremental.ReclaimedBytes() <= 0 {
		t.Fatalf("incremental run = %+v, %v", incremental, err)
	}
	if free := compactPragma(t, path, "freelist_count"); free != 0 {
		t.Fatalf("free pages after the incremental run = %d", free)
	}
	if got := compactRows(t, path); got != rows/2 {
		t.Fatalf("rows after the incremental run = %d, want %d", got, rows/2)
	}
}

func TestCompactStoreRefusesWhileTheStoreIsOpenInThisProcess(t *testing.T) {
	path, _ := prunedStoreWithoutAutoVacuum(t)
	writer, err := NewStore(path)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := writer.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	defer writer.Close() //nolint:errcheck
	before, _ := compactFileSizes(path)

	if _, err := CompactStore(path, CompactOptions{FreeDiskBytes: roomyDisk}); !errors.Is(err, ErrCompactStoreInUse) {
		t.Fatalf("CompactStore beside an open writer = %v, want ErrCompactStoreInUse", err)
	}
	if size, _ := compactFileSizes(path); size != before || compactPragma(t, path, "auto_vacuum") != 0 {
		t.Fatalf("a refused compaction changed the store (size %d -> %d)", before, size)
	}
	// The writer still writes.
	if _, err := writer.db.Exec(`INSERT INTO compact_filler (body) VALUES (x'00')`); err != nil {
		t.Fatalf("writer after the refusal: %v", err)
	}
	// A dry run still reports beside the writer.
	if dry, err := CompactStore(path, CompactOptions{DryRun: true}); err != nil || dry.Method != CompactVacuum {
		t.Fatalf("dry run beside the writer = %+v, %v", dry, err)
	}
}

func TestCompactStoreRefusesWhileAnotherProcessHasTheStoreOpen(t *testing.T) {
	path, _ := prunedStoreWithoutAutoVacuum(t)
	ready := path + ".held"
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	holder := exec.CommandContext(ctx, os.Args[0], "-test.run=^TestCompactHolderProcess$")
	holder.Env = append(os.Environ(), compactHolderPathEnv+"="+path)
	stdin, err := holder.StdinPipe()
	if err != nil {
		t.Fatal(err)
	}
	if err := holder.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() {
		_ = stdin.Close()
		_ = holder.Wait()
	}()
	deadline := time.Now().Add(30 * time.Second)
	for {
		if _, err := os.Stat(ready); err == nil {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("the holder process did not open the store")
		}
		time.Sleep(50 * time.Millisecond)
	}
	before, _ := compactFileSizes(path)
	if _, err := CompactStore(path, CompactOptions{FreeDiskBytes: roomyDisk}); !errors.Is(err, ErrCompactStoreInUse) {
		t.Fatalf("CompactStore beside another process = %v, want ErrCompactStoreInUse", err)
	}
	if size, _ := compactFileSizes(path); size != before {
		t.Fatalf("a refused compaction changed the store (size %d -> %d)", before, size)
	}
}

// TestCompactHolderProcess keeps a store open (a stand-in for the gateway)
// until its stdin closes.
func TestCompactHolderProcess(t *testing.T) {
	path := os.Getenv(compactHolderPathEnv)
	if path == "" {
		return
	}
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close() //nolint:errcheck
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".held", nil, 0o600); err != nil {
		t.Fatal(err)
	}
	buf := make([]byte, 1)
	_, _ = os.Stdin.Read(buf)
}

func TestCompactStoreClaimKeepsOtherConnectionsOut(t *testing.T) {
	path, _ := prunedStoreWithoutAutoVacuum(t)
	opened, err := openHardenedAuditSQLite(path, auditDBPathHooks{exclusive: true})
	if err != nil {
		t.Fatalf("open exclusive: %v", err)
	}
	defer opened.Close() //nolint:errcheck
	conn, err := opened.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	defer conn.Close() //nolint:errcheck
	if err := claimExclusive(context.Background(), conn); err != nil {
		t.Fatalf("claim: %v", err)
	}
	other, err := sql.Open("sqlite", path+"?_pragma=busy_timeout(100)")
	if err != nil {
		t.Fatal(err)
	}
	defer other.Close() //nolint:errcheck
	var rows int
	if err := other.QueryRow(`SELECT COUNT(*) FROM compact_filler`).Scan(&rows); !isSQLiteBusy(err) {
		t.Fatalf("a second connection during the claim = %v, want SQLITE_BUSY", err)
	}
	if _, err := CompactStore(path, CompactOptions{FreeDiskBytes: roomyDisk}); !errors.Is(err, ErrCompactStoreInUse) {
		t.Fatalf("a second compaction during the claim = %v, want ErrCompactStoreInUse", err)
	}
}

func TestCompactStoreRefusesWithoutDiskSpaceAndNamesTheNumbers(t *testing.T) {
	path, _ := prunedStoreWithoutAutoVacuum(t)
	before, _ := compactFileSizes(path)
	_, err := CompactStore(path, CompactOptions{FreeDiskBytes: func(string) (uint64, error) { return 1 << 20, nil }})
	var space *CompactSpaceError
	if !errors.As(err, &space) || space.Free != 1<<20 || space.Need <= compactSpaceMargin || space.Dir != filepath.Dir(path) {
		t.Fatalf("CompactStore on a full disk = %v", err)
	}
	if size, _ := compactFileSizes(path); size != before || compactPragma(t, path, "auto_vacuum") != 0 {
		t.Fatalf("a refused compaction changed the store (size %d -> %d)", before, size)
	}
	// An unreadable free-space figure does not block it.
	if _, err := CompactStore(path, CompactOptions{FreeDiskBytes: func(string) (uint64, error) { return 0, errors.New("no statfs") }}); err != nil {
		t.Fatalf("CompactStore with unknown free space: %v", err)
	}
}

func TestCompactStoreRefusesAMissingPathAndAFileThatIsNotAnAuditStore(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "absent.db")
	if _, err := CompactStore(missing, CompactOptions{}); !errors.Is(err, ErrCompactNoStore) {
		t.Fatalf("missing store = %v", err)
	}
	if _, err := os.Stat(missing); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("a refused compaction created %s", missing)
	}
	other := filepath.Join(dir, "other.db")
	db, err := sql.Open("sqlite", other)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`CREATE TABLE t (x)`); err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	if err := os.Chmod(other, 0o600); err != nil {
		t.Fatal(err)
	}
	for _, dryRun := range []bool{true, false} {
		if _, err := CompactStore(other, CompactOptions{DryRun: dryRun}); err == nil {
			t.Fatalf("CompactStore(dry run %v) compacted a database without schema_version", dryRun)
		}
	}
}
