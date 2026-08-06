//go:build aix || darwin || dragonfly || freebsd || linux || netbsd || openbsd || solaris

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

const auditDBLockHelperPathEnv = "DEFENSECLAW_AUDIT_DB_LOCK_HELPER_PATH"

const (
	sqlitePendingByte = int64(0x40000000)
	sqliteLockByteLen = int64(512)
)

func TestHardenedAuditSQLiteRetainsLocksUntilClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = store.Close()
		}
	})
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	assertSQLiteWALMode(t, store.db)
	assertAuditDBLockedByPeerProcess(t, path)
	assertAuditSidecarPinsReused(t, store)

	if _, err := store.db.Exec(`CREATE TABLE lock_probe (id INTEGER PRIMARY KEY, value TEXT)`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`INSERT INTO lock_probe(value) VALUES ('parent')`); err != nil {
		t.Fatal(err)
	}
	before := make(map[string]os.FileInfo, 2)
	for _, suffix := range []string{"-wal", "-shm"} {
		info, err := os.Stat(path + suffix)
		if err != nil {
			t.Fatalf("stat live SQLite sidecar %s: %v", suffix, err)
		}
		before[suffix] = info
	}

	runAuditDBHelperProcess(t, path, "TestAuditDBLockHelperProcess")

	for _, suffix := range []string{"-wal", "-shm"} {
		after, err := os.Stat(path + suffix)
		if err != nil {
			t.Fatalf("live SQLite sidecar %s disappeared after peer close: %v", suffix, err)
		}
		if !os.SameFile(before[suffix], after) {
			t.Fatalf("live SQLite sidecar %s was replaced after peer close", suffix)
		}
	}
	if _, err := store.db.Exec(`INSERT INTO lock_probe(value) VALUES ('parent-after-peer')`); err != nil {
		t.Fatalf("write after peer close: %v", err)
	}
	closeErr := store.Close()
	closed = true
	if closeErr != nil {
		t.Fatalf("close audit store: %v", closeErr)
	}
	assertAuditDBUnlockedByPeerProcess(t, path)
}

func TestJudgeBodySQLiteRetainsLocksUntilClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "judge_bodies.db")
	store, err := NewJudgeBodyStore(path)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = store.Close()
		}
	})
	assertSQLiteWALMode(t, store.db)
	assertAuditDBLockedByPeerProcess(t, path)

	const closeCalls = 8
	start := make(chan struct{})
	errs := make(chan error, closeCalls)
	for range closeCalls {
		go func() {
			<-start
			errs <- store.Close()
		}()
	}
	close(start)
	for range closeCalls {
		if err := <-errs; err != nil {
			t.Fatalf("concurrent judge-body close: %v", err)
		}
	}
	closed = true
	assertAuditDBUnlockedByPeerProcess(t, path)
}

func assertAuditDBLockedByPeerProcess(t *testing.T, path string) {
	t.Helper()
	runAuditDBHelperProcess(t, path, "TestAuditDBLockProbeHelperProcess")
}

func assertAuditDBUnlockedByPeerProcess(t *testing.T, path string) {
	t.Helper()
	runAuditDBHelperProcess(t, path, "TestAuditDBUnlockProbeHelperProcess")
}

func assertSQLiteWALMode(t *testing.T, db *sql.DB) {
	t.Helper()
	var mode string
	if err := db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil {
		t.Fatalf("read SQLite journal mode: %v", err)
	}
	if !strings.EqualFold(mode, "wal") {
		t.Fatalf("SQLite journal mode = %q, want WAL", mode)
	}
}

func assertAuditSidecarPinsReused(t *testing.T, store *Store) {
	t.Helper()
	before := make(map[string]*os.File, len(store.dbPathGuard.sidecars))
	for suffix, pinned := range store.dbPathGuard.sidecars {
		before[suffix] = pinned
	}
	if len(before) == 0 {
		t.Fatal("audit path guard retained no live SQLite sidecars")
	}
	for attempt := 0; attempt < 3; attempt++ {
		if err := revalidateHardenedAuditSQLite(store.dbPathGuard); err != nil {
			t.Fatalf("repeat audit path revalidation %d: %v", attempt+1, err)
		}
		if len(store.dbPathGuard.sidecars) != len(before) {
			t.Fatalf("repeat revalidation retained %d sidecars, want %d", len(store.dbPathGuard.sidecars), len(before))
		}
		for suffix, pinned := range before {
			if store.dbPathGuard.sidecars[suffix] != pinned {
				t.Fatalf("repeat revalidation replaced retained %s descriptor", suffix)
			}
		}
	}
}

func runAuditDBHelperProcess(t *testing.T, path, testName string) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, os.Args[0], "-test.run=^"+testName+"$")
	cmd.Env = append(os.Environ(), auditDBLockHelperPathEnv+"="+path)
	output, err := cmd.CombinedOutput()
	if ctx.Err() != nil {
		t.Fatalf("run %s: %v\n%s", testName, ctx.Err(), output)
	}
	if err != nil {
		t.Fatalf("run %s: %v\n%s", testName, err, output)
	}
}

func TestAuditDBLockProbeHelperProcess(t *testing.T) {
	probeAuditDBLockHelperProcess(t, true)
}

func TestAuditDBUnlockProbeHelperProcess(t *testing.T) {
	probeAuditDBLockHelperProcess(t, false)
}

func probeAuditDBLockHelperProcess(t *testing.T, wantLocked bool) {
	t.Helper()
	path := os.Getenv(auditDBLockHelperPathEnv)
	if path == "" {
		return
	}
	file, err := os.OpenFile(path, os.O_RDWR, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close() //nolint:errcheck
	lock := syscall.Flock_t{
		Type:   syscall.F_WRLCK,
		Whence: 0,
		Start:  sqlitePendingByte,
		Len:    sqliteLockByteLen,
	}
	if err := syscall.FcntlFlock(file.Fd(), syscall.F_GETLK, &lock); err != nil {
		t.Fatal(err)
	}
	if wantLocked && lock.Type == syscall.F_UNLCK {
		t.Fatal("live SQLite connection holds no kernel lock on the database")
	}
	if !wantLocked && lock.Type != syscall.F_UNLCK {
		t.Fatal("closed SQLite connection still holds a kernel lock on the database")
	}
}

func TestAuditDBLockHelperProcess(t *testing.T) {
	path := os.Getenv(auditDBLockHelperPathEnv)
	if path == "" {
		return
	}
	db, err := openSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := db.Ping(); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM lock_probe`).Scan(&count); err != nil {
		_ = db.Close()
		t.Fatal(err)
	}
	if count != 1 {
		_ = db.Close()
		t.Fatalf("lock probe rows = %d, want 1", count)
	}
	if err := db.Close(); err != nil {
		t.Fatal(err)
	}
}
