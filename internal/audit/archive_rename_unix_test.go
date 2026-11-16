// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package audit

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

// withoutHardLinks makes every hard link fail as on a file system that has
// none; before runs first, so a test can take the destination name in the
// window between the failed link and the move. Not parallel-safe: it swaps a
// package seam.
func withoutHardLinks(t *testing.T, before func(from, to string)) {
	t.Helper()
	original := linkAuditStoreFile
	t.Cleanup(func() { linkAuditStoreFile = original })
	linkAuditStoreFile = func(from, to string) error {
		if before != nil {
			before(from, to)
		}
		return &os.LinkError{Op: "link", Old: from, New: to, Err: syscall.EPERM}
	}
}

func withoutExclusiveRename(t *testing.T) {
	t.Helper()
	original := renameAuditStoreExclusive
	t.Cleanup(func() { renameAuditStoreExclusive = original })
	renameAuditStoreExclusive = func(_, _ string) error { return errNoReplaceMoveUnsupported }
}

func writeFiles(t *testing.T, files map[string]string) {
	t.Helper()
	for name, body := range files {
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
}

func requireFiles(t *testing.T, files map[string]string) {
	t.Helper()
	for name, body := range files {
		if got, err := os.ReadFile(name); err != nil || string(got) != body {
			t.Fatalf("%s = %q, %v; want %q", name, got, err, body)
		}
	}
}

// rel-1-0-2:GAP-0614: without hard links the move fell back to a check and
// then os.Rename, which replaced a file that took the name in between.
func TestRenameNoReplaceWithoutHardLinksNeverReplacesAFileThatTakesTheName(t *testing.T) {
	dir := t.TempDir()
	from, to := filepath.Join(dir, "from"), filepath.Join(dir, "to")
	writeFiles(t, map[string]string{from: "from"})
	withoutHardLinks(t, nil)
	// Another start takes the name after the link failed, right before the
	// kernel move: only a move that refuses an existing file keeps it.
	original := renameAuditStoreExclusive
	t.Cleanup(func() { renameAuditStoreExclusive = original })
	renameAuditStoreExclusive = func(from, to string) error {
		writeFiles(t, map[string]string{to: "another store's file"})
		return original(from, to)
	}

	err := renameNoReplace(from, to)

	if !errors.Is(err, fs.ErrExist) {
		t.Fatalf("renameNoReplace after the name was taken = %v, want fs.ErrExist", err)
	}
	requireFiles(t, map[string]string{from: "from", to: "another store's file"})
}

func TestRenameNoReplaceWithoutHardLinksMovesToAFreeName(t *testing.T) {
	dir := t.TempDir()
	from, to := filepath.Join(dir, "from"), filepath.Join(dir, "to")
	writeFiles(t, map[string]string{from: "from"})
	withoutHardLinks(t, nil)

	if err := renameNoReplace(from, to); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(from); !os.IsNotExist(err) {
		t.Fatalf("source still present after the move: %v", err)
	}
	requireFiles(t, map[string]string{to: "from"})
}

func TestRenameNoReplaceFailsClosedWithoutAnAtomicMove(t *testing.T) {
	dir := t.TempDir()
	from, to := filepath.Join(dir, "from"), filepath.Join(dir, "to")
	writeFiles(t, map[string]string{from: "from"})
	withoutHardLinks(t, nil)
	withoutExclusiveRename(t)

	err := renameNoReplace(from, to)

	if err == nil || !errors.Is(err, errNoReplaceMoveUnsupported) || errors.Is(err, fs.ErrExist) {
		t.Fatalf("renameNoReplace with no atomic move = %v, want the unsupported error", err)
	}
	requireFiles(t, map[string]string{from: "from"})
	if _, statErr := os.Lstat(to); !os.IsNotExist(statErr) {
		t.Fatalf("destination created: %v", statErr)
	}
}

// The quarantine retry also holds without hard links: the -shm name is taken
// after the check and the -wal already moved, so the set goes back and moves
// to a new name, and the other store's file stays.
func TestQuarantineCorruptAuditDBWithoutHardLinksNeverReplacesAFileThatTakesTheName(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "audit.db")
	set := map[string]string{db: "original", db + "-wal": "original-wal", db + "-shm": "original-shm"}
	writeFiles(t, set)
	pinQuarantineClock(t, time.Date(2026, 10, 17, 12, 0, 2, 0, time.UTC))
	base := db + ".corrupt-20261017T120002Z"
	raced := false
	withoutHardLinks(t, func(_, to string) {
		if !raced && to == base+"-shm" {
			raced = true
			writeFiles(t, map[string]string{to: "other store's SHM"})
		}
	})

	moved, err := quarantineCorruptAuditDB(db)

	if err != nil {
		t.Fatal(err)
	}
	if !raced || !strings.HasPrefix(moved, base+"-") {
		t.Fatalf("moved to %q (raced %v); want a new name after %s was taken", moved, raced, base)
	}
	requireFiles(t, map[string]string{base + "-shm": "other store's SHM"})
	if _, err := os.Lstat(base + "-wal"); !os.IsNotExist(err) {
		t.Fatalf("the WAL that moved first was not put back before the retry: %v", err)
	}
	requireFiles(t, map[string]string{moved: "original", moved + "-wal": "original-wal", moved + "-shm": "original-shm"})
}

func TestQuarantineCorruptAuditDBFailsClosedWithoutAnAtomicMove(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "audit.db")
	set := map[string]string{db: "original", db + "-wal": "original-wal"}
	writeFiles(t, set)
	withoutHardLinks(t, nil)
	withoutExclusiveRename(t)

	moved, err := quarantineCorruptAuditDB(db)

	if err == nil || moved != "" || !errors.Is(err, errNoReplaceMoveUnsupported) {
		t.Fatalf("quarantineCorruptAuditDB = %q, %v; want the unsupported error", moved, err)
	}
	requireFiles(t, set)
	if left, _ := filepath.Glob(db + ".corrupt-*"); len(left) != 0 {
		t.Fatalf("left aside: %v", left)
	}
}
