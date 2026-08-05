//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"os"
	"os/exec"
	"path/filepath"
	"syscall"
	"testing"
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
	defer store.Close() //nolint:errcheck
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	assertAuditDBLockedByPeerProcess(t, path)

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

	cmd := exec.Command(os.Args[0], "-test.run=^TestAuditDBLockHelperProcess$")
	cmd.Env = append(os.Environ(), auditDBLockHelperPathEnv+"="+path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("run second SQLite process: %v\n%s", err, output)
	}

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
}

func TestJudgeBodySQLiteRetainsLocksUntilClose(t *testing.T) {
	path := filepath.Join(t.TempDir(), "judge_bodies.db")
	store, err := NewJudgeBodyStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close() //nolint:errcheck
	assertAuditDBLockedByPeerProcess(t, path)
}

func assertAuditDBLockedByPeerProcess(t *testing.T, path string) {
	t.Helper()
	cmd := exec.Command(os.Args[0], "-test.run=^TestAuditDBLockProbeHelperProcess$")
	cmd.Env = append(os.Environ(), auditDBLockHelperPathEnv+"="+path)
	if output, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("probe SQLite lock from peer process: %v\n%s", err, output)
	}
}

func TestAuditDBLockProbeHelperProcess(t *testing.T) {
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
	if lock.Type == syscall.F_UNLCK {
		t.Fatal("live SQLite connection holds no kernel lock on the database")
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
