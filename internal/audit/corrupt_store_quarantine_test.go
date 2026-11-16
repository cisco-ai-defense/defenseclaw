// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
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
				original := renameAuditStoreFile
				t.Cleanup(func() { renameAuditStoreFile = original })
				renameAuditStoreFile = func(from, to string) error {
					if from == db+failing {
						return injected
					}
					if backFails && to == db+"-wal" {
						return errors.New("injected move-back failure")
					}
					return original(from, to)
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
	// Pin the clock: a quarantine in the next second would pick another name
	// and never meet the orphan (rel-1-0-2:GAP-0614).
	pinQuarantineClock(t, time.Date(2026, 10, 17, 12, 0, 0, 0, time.UTC))
	base := db + ".corrupt-20261017T120000Z"
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

func pinQuarantineClock(t *testing.T, at time.Time) {
	t.Helper()
	original := quarantineNow
	quarantineNow = func() time.Time { return at }
	t.Cleanup(func() { quarantineNow = original })
}

// rel-1-0-2:GAP-0614: the archive name was checked free, then os.Rename
// replaced whatever took it in between, for example the WAL of a store a
// second start moved aside in the same second. Not parallel: it swaps the
// package's rename seam.
func TestQuarantineCorruptAuditDBNeverReplacesAFileThatTakesTheNameAfterTheCheck(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "audit.db")
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if err := os.WriteFile(db+suffix, []byte("original"+suffix), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	pinQuarantineClock(t, time.Date(2026, 10, 17, 12, 0, 1, 0, time.UTC))
	base := db + ".corrupt-20261017T120001Z"
	original := renameAuditStoreFile
	t.Cleanup(func() { renameAuditStoreFile = original })
	raced := false
	renameAuditStoreFile = func(from, to string) error {
		if !raced && to == base+"-shm" {
			raced = true
			// The -wal already moved; another start takes the -shm name now.
			if err := os.WriteFile(to, []byte("other store's SHM"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		return original(from, to)
	}

	moved, err := quarantineCorruptAuditDB(db)
	if err != nil {
		t.Fatal(err)
	}
	if !raced || moved == base || !strings.HasPrefix(moved, base+"-") {
		t.Fatalf("moved to %q (raced %v); want a new name after %s was taken", moved, raced, base)
	}
	if got, err := os.ReadFile(base + "-shm"); err != nil || string(got) != "other store's SHM" {
		t.Fatalf("the other store's SHM = %q, %v; want it untouched", got, err)
	}
	if _, err := os.Stat(base + "-wal"); !os.IsNotExist(err) {
		t.Fatalf("the WAL that moved first was not put back before the retry: %v", err)
	}
	for _, suffix := range []string{"", "-wal", "-shm"} {
		if got, err := os.ReadFile(moved + suffix); err != nil || string(got) != "original"+suffix {
			t.Fatalf("archive%s = %q, %v", suffix, got, err)
		}
	}
}

func TestRenameNoReplaceRefusesAnExistingDestination(t *testing.T) {
	dir := t.TempDir()
	from, to := filepath.Join(dir, "from"), filepath.Join(dir, "to")
	for name, body := range map[string]string{from: "from", to: "to"} {
		if err := os.WriteFile(name, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := renameNoReplace(from, to); !errors.Is(err, fs.ErrExist) {
		t.Fatalf("renameNoReplace over an existing file = %v, want fs.ErrExist", err)
	}
	for name, body := range map[string]string{from: "from", to: "to"} {
		if got, err := os.ReadFile(name); err != nil || string(got) != body {
			t.Fatalf("%s = %q, %v; want %q", name, got, err, body)
		}
	}
	if err := os.Remove(to); err != nil {
		t.Fatal(err)
	}
	if err := renameNoReplace(from, to); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(from); !os.IsNotExist(err) {
		t.Fatalf("source still present after the move: %v", err)
	}
	if got, err := os.ReadFile(to); err != nil || string(got) != "from" {
		t.Fatalf("destination = %q, %v", got, err)
	}
	if err := renameNoReplace(from, to); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("renameNoReplace of a missing file = %v, want fs.ErrNotExist", err)
	}
}

func TestArchiveRecoveryHintCopiesFirstAndRepairsTheHeaderOnTheCopy(t *testing.T) {
	archive := "/data/audit.db.corrupt-20261014T214026Z"
	for _, goos := range []string{"linux", "darwin", "windows"} {
		hint := archiveRecoveryHintFor(goos, archive)
		for _, want := range []string{
			"first copy " + archive + " together with its -wal, -shm and any -journal files to a new folder",
			"Then run sqlite3 <copy> .recover on the copy",
			"write the SQLite header back on the copy, never on the archive",
		} {
			if !strings.Contains(hint, want) {
				t.Fatalf("%s hint %q lacks %q", goos, hint, want)
			}
		}
		if strings.Contains(hint, "sqlite3 "+archive) {
			t.Fatalf("%s hint points SQLite at the archive: %q", goos, hint)
		}
		command := "dd of=<copy> bs=16 count=1 conv=notrunc"
		if goos == "windows" {
			command = "$f.Close()"
		}
		// The hint ends with the command, so a copied command has no trailing period.
		if !strings.HasSuffix(hint, command) {
			t.Fatalf("%s hint does not end with its header repair command %q: %q", goos, command, hint)
		}
	}
}

type codedProbeError int

func (e codedProbeError) Error() string { return "sqlite error" }
func (e codedProbeError) Code() int     { return int(e) }

// Contention, including extended codes, skips the probe; any other read
// failure with a populated WAL refuses the start (rel-1-0-2:GAP-0609).
func TestIsTransientSQLiteProbeError(t *testing.T) {
	for code, want := range map[int]bool{
		5:        true,  // SQLITE_BUSY
		5 | 1<<8: true,  // SQLITE_BUSY_RECOVERY
		6:        true,  // SQLITE_LOCKED
		15:       true,  // SQLITE_PROTOCOL
		1:        false, // SQLITE_ERROR, such as an unsupported file format
		10:       false, // SQLITE_IOERR
		14:       false, // SQLITE_CANTOPEN
		8 | 5<<8: false, // SQLITE_READONLY_CANTINIT: the writable open recovers it
	} {
		if got := isTransientSQLiteProbeError(codedProbeError(code)); got != want {
			t.Errorf("isTransientSQLiteProbeError(code %d) = %v, want %v", code, got, want)
		}
	}
}

// rel-1-0-3:GAP-0106: files that only had archive names, one for the second of
// the move and one later, made the start banner name the later file instead of
// the archive. The store moved to a new name, and its note says so.
func TestReportedMovedCorruptStoresNamesTheArchiveNotAFileWithAnArchiveName(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "audit.db")
	store, err := NewStore(dbPath)
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	if err := store.Close(); err != nil {
		t.Fatalf("Close: %v", err)
	}
	file, err := os.OpenFile(dbPath, os.O_WRONLY, 0)
	if err != nil {
		t.Fatalf("open for damage: %v", err)
	}
	if _, err := file.WriteAt(make([]byte, 192), 0); err != nil {
		t.Fatalf("damage header: %v", err)
	}
	_ = file.Close()
	pinQuarantineClock(t, time.Date(2026, 10, 18, 2, 13, 44, 0, time.UTC))
	others := []string{dbPath + ".corrupt-20261018T021344Z", dbPath + ".corrupt-20261018T021513Z"}
	for _, name := range others {
		if err := os.WriteFile(name, []byte("not an audit store"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	recovered, err := OpenDaemonStore(dbPath, &strings.Builder{})
	if err != nil {
		t.Fatalf("OpenDaemonStore: %v", err)
	}
	defer recovered.Close()

	listed := MovedCorruptStores(dbPath)
	if len(listed) != 3 {
		t.Fatalf("MovedCorruptStores = %+v; want the archive and the two other files", listed)
	}
	reported := ReportedMovedCorruptStores(listed)
	if len(reported) != 1 || !reported[0].CarryOverKnown || slices.Contains(others, reported[0].Path) ||
		!strings.HasPrefix(reported[0].Path, others[0]+"-") {
		t.Fatalf("ReportedMovedCorruptStores = %+v; want only the archive the start moved", reported)
	}
	for _, name := range others {
		if got, err := os.ReadFile(name); err != nil || string(got) != "not an audit store" {
			t.Fatalf("%s = %q, %v; want it unchanged", name, got, err)
		}
	}
}

// Stores an earlier version moved have no note; all of them stay reported.
func TestReportedMovedCorruptStoresKeepsStoresAnEarlierVersionMoved(t *testing.T) {
	db := filepath.Join(t.TempDir(), "audit.db")
	for _, stamp := range []string{"20261001T000000Z", "20261002T000000Z"} {
		if err := os.WriteFile(db+".corrupt-"+stamp, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	reported := ReportedMovedCorruptStores(MovedCorruptStores(db))
	if len(reported) != 2 || reported[1].Path != db+".corrupt-20261002T000000Z" {
		t.Fatalf("ReportedMovedCorruptStores = %+v; want both stores, newest last", reported)
	}
}
