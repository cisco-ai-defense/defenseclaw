// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// rel-1-0-2:GAP-0491: the WAL moved aside before the database, and a database
// that then did not move stayed behind without it. Not parallel: it swaps the
// package's rename seam.
func TestQuarantineCorruptAuditDBPutsBackWhatMovedWhenAStepFails(t *testing.T) {
	for _, failing := range []string{"-wal", "-shm", "-journal", ""} {
		for _, backFails := range []bool{false, true} {
			if backFails && failing == "-wal" {
				continue // the first step: nothing moved yet
			}
			name := "audit.db" + failing
			if backFails {
				name += "/move-back-fails"
			}
			t.Run(name, func(t *testing.T) {
				dir := t.TempDir()
				db := filepath.Join(dir, "audit.db")
				files := map[string]string{"": "db", "-wal": "wal", "-shm": "shm", "-journal": "journal"}
				for suffix, body := range files {
					if err := os.WriteFile(db+suffix, []byte(body), 0o600); err != nil {
						t.Fatal(err)
					}
				}
				injected := errors.New("injected rename failure")
				t.Cleanup(func() { renameAuditStoreFile = os.Rename })
				renameAuditStoreFile = func(from, to string) error {
					if from == db+failing {
						return injected
					}
					if backFails && to == db+"-wal" {
						return errors.New("injected move-back failure")
					}
					return os.Rename(from, to)
				}

				moved, err := quarantineCorruptAuditDB(db)

				if !errors.Is(err, injected) || moved != "" {
					t.Fatalf("quarantineCorruptAuditDB = %q, %v; want the injected error", moved, err)
				}
				left, _ := filepath.Glob(db + ".corrupt-*")
				if backFails {
					if !strings.Contains(err.Error(), "-wal could not be moved back") || len(left) != 1 {
						t.Fatalf("error %v, left aside %v; want the stuck WAL named", err, left)
					}
					return
				}
				if len(left) != 0 {
					t.Fatalf("left aside: %v", left)
				}
				for suffix, body := range files {
					got, readErr := os.ReadFile(db + suffix)
					if readErr != nil || string(got) != body {
						t.Fatalf("audit.db%s = %q, %v; want %q at the original path", suffix, got, readErr, body)
					}
				}
			})
		}
	}
}

func TestQuarantineCorruptAuditDBMovesTheStoreWithItsSidecars(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "audit.db")
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if err := os.WriteFile(db+suffix, []byte("x"+suffix), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	moved, err := quarantineCorruptAuditDB(db)
	if err != nil {
		t.Fatalf("quarantineCorruptAuditDB: %v", err)
	}
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		if got, readErr := os.ReadFile(moved + suffix); readErr != nil || string(got) != "x"+suffix {
			t.Fatalf("%s%s = %q, %v", moved, suffix, got, readErr)
		}
		if _, statErr := os.Stat(db + suffix); !os.IsNotExist(statErr) {
			t.Fatalf("audit.db%s still at the original path (%v)", suffix, statErr)
		}
	}
}

func TestQuarantineCorruptAuditDBDoesNotReplaceAnOrphanArchiveSidecar(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "audit.db")
	for _, suffix := range []string{"", "-wal"} {
		if err := os.WriteFile(db+suffix, []byte("original"+suffix), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	base := db + ".corrupt-" + time.Now().UTC().Format("20060102T150405Z")
	if err := os.WriteFile(base+"-wal", []byte("other store's WAL"), 0o600); err != nil {
		t.Fatal(err)
	}
	moved, err := quarantineCorruptAuditDB(db)
	if err != nil {
		t.Fatal(err)
	}
	if moved == base {
		t.Fatal("quarantine reused a name with a pre-existing archive WAL")
	}
	if got, err := os.ReadFile(base + "-wal"); err != nil || string(got) != "other store's WAL" {
		t.Fatalf("pre-existing archive WAL = %q, %v", got, err)
	}
	for _, suffix := range []string{"", "-wal"} {
		if got, err := os.ReadFile(moved + suffix); err != nil || string(got) != "original"+suffix {
			t.Fatalf("new archive%s = %q, %v", suffix, got, err)
		}
	}
}
