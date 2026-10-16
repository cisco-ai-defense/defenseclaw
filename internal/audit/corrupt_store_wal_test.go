// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// corruptWALFixture copies a live SQLite store while a writer holds its WAL
// open. Closing the writer after the copy may checkpoint the source, but the
// fixture's marker and block entry exist only in its copied WAL.
func corruptWALFixture(t *testing.T, damage string) string {
	t.Helper()
	sourceDir := filepath.Join(t.TempDir(), "source")
	fixtureDir := filepath.Join(t.TempDir(), "fixture")
	for _, dir := range []string{sourceDir, fixtureDir} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	source := filepath.Join(sourceDir, "audit.db")
	store, err := NewStore(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	// Give audit_events several main-file leaf pages. The first leaf is not
	// rewritten by the later WAL-only insert at the right edge of the tree.
	tx, err := store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	for i := range 400 {
		if _, err := tx.Exec(`INSERT INTO audit_events (id, timestamp, action, target)
			VALUES (?, CURRENT_TIMESTAMP, 'fixture', ?)`, fmt.Sprintf("base-%04d", i), fmt.Sprintf("base-%04d", i)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}

	writer, err := openSQLite(source)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := writer.Ping(); err != nil {
		t.Fatal(err)
	}
	var autoCheckpoint, pageSize, leafPage int
	if err := writer.QueryRow(`PRAGMA wal_autocheckpoint`).Scan(&autoCheckpoint); err != nil || autoCheckpoint != 0 {
		t.Fatalf("wal_autocheckpoint = %d, %v", autoCheckpoint, err)
	}
	if err := writer.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		t.Fatal(err)
	}
	if err := writer.QueryRow(`SELECT pageno FROM dbstat WHERE name = 'audit_events' AND pagetype = 'leaf' ORDER BY pageno LIMIT 1`).Scan(&leafPage); err != nil {
		t.Fatal(err)
	}
	walTx, err := writer.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := walTx.Exec(`INSERT INTO audit_events (id, timestamp, action, target)
		VALUES ('wal-only-marker', CURRENT_TIMESTAMP, 'fixture', 'wal-only-marker')`); err != nil {
		t.Fatal(err)
	}
	if _, err := walTx.Exec(`INSERT INTO actions (id, target_type, target_name, actions_json, updated_at, connector)
		VALUES ('wal-only-block', 'tool', 'wal-only-block', '{"install":"block"}', CURRENT_TIMESTAMP, 'claudecode')`); err != nil {
		t.Fatal(err)
	}
	if err := walTx.Commit(); err != nil {
		t.Fatal(err)
	}
	fixture := filepath.Join(fixtureDir, "audit.db")
	for _, suffix := range []string{"", "-wal", "-shm"} {
		body, err := os.ReadFile(source + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(fixture+suffix, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	mainOnly := filepath.Join(t.TempDir(), "audit.db")
	mainBytes, err := os.ReadFile(fixture)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(mainOnly, mainBytes, 0o600); err != nil {
		t.Fatal(err)
	}
	mainDB, err := openAuditReadOnly(mainOnly)
	if err != nil {
		t.Fatal(err)
	}
	var count int
	if err := mainDB.QueryRow(`SELECT count(*) FROM audit_events WHERE id = 'wal-only-marker'`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("main-file-only marker count = %d, %v; want zero", count, err)
	}
	if err := mainDB.Close(); err != nil {
		t.Fatal(err)
	}
	file, err := os.OpenFile(fixture, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	switch damage {
	case "none":
	case "header":
		_, err = file.WriteAt(bytes.Repeat([]byte{0}, 16), 0)
	case "page":
		_, err = file.WriteAt(bytes.Repeat([]byte{0xff}, pageSize), int64(leafPage-1)*int64(pageSize))
	default:
		t.Fatalf("unknown damage %q", damage)
	}
	if err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return fixture
}

func TestOpenDaemonStorePreservesCorruptWAL(t *testing.T) {
	for _, damage := range []string{"header", "page"} {
		t.Run(damage, func(t *testing.T) {
			path := corruptWALFixture(t, damage)
			before := make(map[string][]byte)
			for _, suffix := range []string{"", "-wal", "-shm"} {
				var err error
				before[suffix], err = os.ReadFile(path + suffix)
				if err != nil {
					t.Fatal(err)
				}
			}
			if len(before["-wal"]) == 0 {
				t.Fatal("fixture WAL is empty")
			}
			var warning bytes.Buffer
			fresh, err := OpenDaemonStore(path, &warning)
			if err != nil {
				t.Fatalf("OpenDaemonStore: %v", err)
			}
			defer fresh.Close()
			moved := MovedCorruptStores(path)
			if len(moved) != 1 {
				t.Fatalf("MovedCorruptStores = %+v", moved)
			}
			archive := moved[0].Path
			for _, suffix := range []string{"", "-wal"} {
				got, err := os.ReadFile(archive + suffix)
				if err != nil || !bytes.Equal(got, before[suffix]) {
					t.Fatalf("archived %s: size=%d sha256=%x, err=%v; before size=%d sha256=%x",
						suffix, len(got), sha256.Sum256(got), err, len(before[suffix]), sha256.Sum256(before[suffix]))
				}
			}
			if _, err := os.Stat(archive + "-shm"); err != nil {
				t.Fatalf("archived SHM: %v", err)
			}
			if !strings.Contains(warning.String(), archive) ||
				!strings.Contains(warning.String(), "together with its -wal and -shm files") {
				t.Fatalf("start warning does not name the archived sidecars: %q", warning.String())
			}
			var count int
			if err := fresh.db.QueryRow(`SELECT count(*) FROM audit_events WHERE id = 'wal-only-marker'`).Scan(&count); err != nil || count != 0 {
				t.Fatalf("new store marker count = %d, %v", count, err)
			}
			var check string
			if err := fresh.db.QueryRow(`PRAGMA quick_check(1)`).Scan(&check); err != nil || check != "ok" {
				t.Fatalf("new store quick_check = %q, %v", check, err)
			}
			entry, err := fresh.GetActionForConnector("tool", "wal-only-block", "claudecode")
			if err != nil {
				t.Fatal(err)
			}
			if damage == "page" && (entry == nil || entry.Actions.Install != "block" || moved[0].CarriedOver != 1) {
				t.Fatalf("WAL-only block was not carried over: entry=%+v, note=%+v", entry, moved[0])
			}
			if damage == "header" && (entry != nil || moved[0].CarriedOver != 0) {
				t.Fatalf("unreadable header unexpectedly yielded an action: entry=%+v, note=%+v", entry, moved[0])
			}

			// Read only a separate copy. A damaged header cannot be opened by
			// SQLite at all, so restore its 16-byte magic in the copy first.
			// The archived bytes above remain untouched for forensic recovery.
			copyPath := filepath.Join(t.TempDir(), "audit.db")
			for _, suffix := range []string{"", "-wal", "-shm"} {
				body, err := os.ReadFile(archive + suffix)
				if err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(copyPath+suffix, body, 0o600); err != nil {
					t.Fatal(err)
				}
			}
			if damage == "header" {
				file, err := os.OpenFile(copyPath, os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				if _, err := file.WriteAt([]byte("SQLite format 3\x00"), 0); err != nil {
					t.Fatal(err)
				}
				if err := file.Close(); err != nil {
					t.Fatal(err)
				}
			}
			copyDB, err := openAuditReadOnly(copyPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := copyDB.QueryRow(`SELECT count(*) FROM audit_events WHERE id = 'wal-only-marker'`).Scan(&count); err != nil || count != 1 {
				_ = copyDB.Close()
				t.Fatalf("read-only archive copy marker count = %d, %v", count, err)
			}
			if err := copyDB.Close(); err != nil {
				t.Fatal(err)
			}
			gotWAL, err := os.ReadFile(archive + "-wal")
			if err != nil || !bytes.Equal(gotWAL, before["-wal"]) {
				t.Fatalf("archive WAL changed during recovery read: %v", err)
			}
		})
	}
}

func TestOpenDaemonStoreHealthyWALNoArchive(t *testing.T) {
	path := corruptWALFixture(t, "none")
	var warning bytes.Buffer
	store, err := OpenDaemonStore(path, &warning)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	var count int
	if err := store.db.QueryRow(`SELECT count(*) FROM audit_events WHERE id = 'wal-only-marker'`).Scan(&count); err != nil || count != 1 {
		t.Fatalf("healthy WAL marker count = %d, %v", count, err)
	}
	if entry, err := store.GetActionForConnector("tool", "wal-only-block", "claudecode"); err != nil || entry == nil || entry.Actions.Install != "block" {
		t.Fatalf("healthy WAL block = %+v, %v", entry, err)
	}
	if found := MovedCorruptStores(path); len(found) != 0 {
		t.Fatalf("healthy store was quarantined: %+v", found)
	}
	if leftovers, _ := filepath.Glob(path + ".recovering-*"); len(leftovers) != 0 {
		t.Fatalf("recovery temporary files: %v", leftovers)
	}
}

func assertOriginalAuditSetUnchanged(t *testing.T, path string, before map[string][]byte) {
	t.Helper()
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		want, existed := before[suffix]
		got, err := os.ReadFile(path + suffix)
		if !existed && errors.Is(err, os.ErrNotExist) {
			continue
		}
		if !existed {
			t.Fatalf("unexpected new audit.db%s after failed start: %v", suffix, err)
		}
		if err != nil || !bytes.Equal(got, want) {
			t.Fatalf("original audit.db%s changed: got size=%d sha256=%x, err=%v; want size=%d sha256=%x",
				suffix, len(got), sha256.Sum256(got), err, len(want), sha256.Sum256(want))
		}
	}
	if archives, _ := filepath.Glob(path + ".corrupt-*"); len(archives) != 0 {
		t.Fatalf("failed start left archive files: %v", archives)
	}
}

func auditSetBytes(t *testing.T, path string) map[string][]byte {
	t.Helper()
	before := make(map[string][]byte)
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		body, err := os.ReadFile(path + suffix)
		if errors.Is(err, os.ErrNotExist) && suffix != "" {
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		before[suffix] = body
	}
	return before
}

func TestOpenDaemonStoreProbeFailureKeepsWALSet(t *testing.T) {
	path := corruptWALFixture(t, "page")
	before := auditSetBytes(t, path)
	injected := errors.New("injected read-only probe failure")
	original := probeExistingAuditStore
	probeExistingAuditStore = func(string, io.Writer) ([]auditSidecarAtStart, error) { return nil, injected }
	t.Cleanup(func() { probeExistingAuditStore = original })
	store, err := OpenDaemonStore(path, &bytes.Buffer{})
	if store != nil || !errors.Is(err, injected) {
		t.Fatalf("OpenDaemonStore = %v, %v", store, err)
	}
	assertOriginalAuditSetUnchanged(t, path, before)
}

func TestOpenDaemonStoreQuarantineRenameFailureKeepsWALSet(t *testing.T) {
	for _, suffix := range []string{"-wal", "-shm", ""} {
		t.Run("audit.db"+suffix, func(t *testing.T) {
			path := corruptWALFixture(t, "page")
			before := auditSetBytes(t, path)
			injected := errors.New("injected quarantine rename failure")
			original := renameAuditStoreFile
			renameAuditStoreFile = func(from, to string) error {
				if from == path+suffix {
					return injected
				}
				return os.Rename(from, to)
			}
			t.Cleanup(func() { renameAuditStoreFile = original })
			store, err := OpenDaemonStore(path, &bytes.Buffer{})
			if store != nil || err == nil || !strings.Contains(err.Error(), injected.Error()) {
				t.Fatalf("OpenDaemonStore = %v, %v", store, err)
			}
			assertOriginalAuditSetUnchanged(t, path, before)
		})
	}
}

func TestOpenDaemonStoreFreshCreationFailureRestoresWALSet(t *testing.T) {
	path := corruptWALFixture(t, "page")
	before := auditSetBytes(t, path)
	injected := errors.New("injected fresh store failure")
	original := newCorruptRecoveryStore
	newCorruptRecoveryStore = func(path string, opts ...StoreOption) (*Store, error) {
		store, err := NewStore(path, opts...)
		if err != nil {
			return nil, err
		}
		if err := store.Close(); err != nil {
			return nil, err
		}
		return nil, injected
	}
	t.Cleanup(func() { newCorruptRecoveryStore = original })
	store, err := OpenDaemonStore(path, &bytes.Buffer{})
	if store != nil || !errors.Is(err, injected) {
		t.Fatalf("OpenDaemonStore = %v, %v", store, err)
	}
	assertOriginalAuditSetUnchanged(t, path, before)
}

func TestOpenDaemonStoreFreshInitFailureRestoresWALSet(t *testing.T) {
	path := corruptWALFixture(t, "page")
	before := auditSetBytes(t, path)
	injected := errors.New("injected fresh Init failure")
	original := initCorruptRecoveryStore
	initCorruptRecoveryStore = func(store *Store) error {
		if err := store.Init(); err != nil {
			return err
		}
		return injected
	}
	t.Cleanup(func() { initCorruptRecoveryStore = original })
	store, err := OpenDaemonStore(path, &bytes.Buffer{})
	if store != nil || !errors.Is(err, injected) {
		t.Fatalf("OpenDaemonStore = %v, %v", store, err)
	}
	assertOriginalAuditSetUnchanged(t, path, before)
}

func TestOpenDaemonStoreFreshCleanupRetriesTransientFailure(t *testing.T) {
	for _, suffix := range []string{"-wal", "-shm", "-journal", ""} {
		t.Run("audit.db"+suffix, func(t *testing.T) {
			path := corruptWALFixture(t, "page")
			before := auditSetBytes(t, path)
			injected := errors.New("injected fresh cleanup failure")
			originalNew, originalRemove := newCorruptRecoveryStore, removeCorruptRecoveryFile
			newCorruptRecoveryStore = func(path string, opts ...StoreOption) (*Store, error) {
				store, err := NewStore(path, opts...)
				if err != nil {
					return nil, err
				}
				if err := store.Close(); err != nil {
					return nil, err
				}
				for _, sidecar := range []string{"-wal", "-shm", "-journal"} {
					if err := os.WriteFile(path+sidecar, []byte("incomplete new store"), 0o600); err != nil {
						return nil, err
					}
				}
				return nil, injected
			}
			failedOnce := false
			removeCorruptRecoveryFile = func(name string) error {
				if name == path+suffix && !failedOnce {
					failedOnce = true
					return errors.New("transient removal refusal")
				}
				return os.Remove(name)
			}
			t.Cleanup(func() {
				newCorruptRecoveryStore, removeCorruptRecoveryFile = originalNew, originalRemove
			})
			store, err := OpenDaemonStore(path, &bytes.Buffer{})
			if store != nil || !errors.Is(err, injected) || !failedOnce {
				t.Fatalf("OpenDaemonStore = %v, %v; failedOnce=%t", store, err, failedOnce)
			}
			assertOriginalAuditSetUnchanged(t, path, before)
		})
	}
}

func TestOpenDaemonStoreFreshRestoreRetriesTransientRename(t *testing.T) {
	for _, suffix := range []string{"-wal", "-shm", "-journal", ""} {
		t.Run("audit.db"+suffix, func(t *testing.T) {
			var path string
			if suffix == "-journal" {
				path = corruptColdJournalFixture(t)
			} else {
				path = corruptWALFixture(t, "page")
			}
			before := auditSetBytes(t, path)
			injected := errors.New("injected fresh store failure")
			originalNew, originalRename := newCorruptRecoveryStore, renameAuditStoreFile
			newCorruptRecoveryStore = func(string, ...StoreOption) (*Store, error) { return nil, injected }
			failedOnce := false
			renameAuditStoreFile = func(from, to string) error {
				if to == path+suffix && strings.Contains(from, ".corrupt-") && !failedOnce {
					failedOnce = true
					return errors.New("transient restore rename refusal")
				}
				return os.Rename(from, to)
			}
			t.Cleanup(func() {
				newCorruptRecoveryStore, renameAuditStoreFile = originalNew, originalRename
			})
			store, err := OpenDaemonStore(path, &bytes.Buffer{})
			if store != nil || !errors.Is(err, injected) || !failedOnce {
				t.Fatalf("OpenDaemonStore = %v, %v; failedOnce=%t", store, err, failedOnce)
			}
			assertOriginalAuditSetUnchanged(t, path, before)
		})
	}
}

func TestOpenDaemonStoreUnwritableWALKeepsSet(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows ACL test is covered by audit_db_path_windows_test.go")
	}
	path := corruptWALFixture(t, "page")
	before := auditSetBytes(t, path)
	if err := os.Chmod(path+"-wal", 0o400); err != nil {
		t.Fatal(err)
	}
	store, err := OpenDaemonStore(path, &bytes.Buffer{})
	if store != nil || err == nil || !strings.Contains(err.Error(), "open SQLite sidecar -wal safely") {
		t.Fatalf("OpenDaemonStore = %v, %v; want WAL sidecar open refusal", store, err)
	}
	assertOriginalAuditSetUnchanged(t, path, before)
}

// A late corruption error can still surface after the preflight check, for
// example during a migration. If SQLite has already consumed a sidecar, the
// start warning must say that its pre-start size was not preserved.
func TestOpenDaemonStoreWarnsWhenALateOpenConsumesWAL(t *testing.T) {
	path := corruptWALFixture(t, "page")
	wal, err := os.Stat(path + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	original := probeExistingAuditStore
	probeExistingAuditStore = func(string, io.Writer) ([]auditSidecarAtStart, error) {
		return []auditSidecarAtStart{{suffix: "-wal", size: wal.Size()}}, nil
	}
	t.Cleanup(func() { probeExistingAuditStore = original })
	var warning bytes.Buffer
	store, err := OpenDaemonStore(path, &warning)
	if err != nil {
		t.Fatal(err)
	}
	defer store.Close()
	if !strings.Contains(warning.String(), "pre-existing -wal") ||
		!strings.Contains(warning.String(), "not preserved") && !strings.Contains(warning.String(), "could not be verified") {
		t.Fatalf("start silently lost the WAL after a late writable open: %q", warning.String())
	}
}

// corruptColdJournalFixture copies a rollback journal before SQLite writes its
// header magic. SQLite ignores the copy, so it remains beside a corrupt store.
func corruptColdJournalFixture(t *testing.T) string {
	t.Helper()
	source := filepath.Join(t.TempDir(), "audit.db")
	store, err := NewStore(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	var leafPage, pageSize int
	if err := store.db.QueryRow(`SELECT pageno FROM dbstat WHERE name = 'audit_events' AND pagetype = 'leaf' LIMIT 1`).Scan(&leafPage); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`PRAGMA page_size`).Scan(&pageSize); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	writer, err := openSQLiteWithPragmas(source, "?_pragma=journal_mode(DELETE)&_pragma=synchronous(FULL)")
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if err := writer.Ping(); err != nil {
		t.Fatal(err)
	}
	tx, err := writer.Begin()
	if err != nil {
		t.Fatal(err)
	}
	if _, err := tx.Exec(`INSERT INTO actions (id, target_type, target_name, actions_json, updated_at, connector)
		VALUES ('hot-journal-row', 'tool', 'hot-journal-row', '{"install":"block"}', CURRENT_TIMESTAMP, 'claudecode')`); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.db")
	for _, suffix := range []string{"", "-journal"} {
		body, err := os.ReadFile(source + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+suffix, body, 0o600); err != nil {
			t.Fatal(err)
		}
		if suffix == "-journal" {
			if len(body) == 0 {
				t.Fatal("cold journal is empty")
			}
			if body[0] != 0 {
				t.Fatalf("cold journal header: size=%d first byte=%d; want zero first byte", len(body), body[0])
			}
			t.Logf("cold journal: size=%d first byte=%d", len(body), body[0])
		}
	}
	_ = tx.Rollback()
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := file.WriteAt(bytes.Repeat([]byte{0xff}, pageSize), int64(leafPage-1)*int64(pageSize)); err != nil {
		t.Fatal(err)
	}
	if err := file.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

func TestOpenDaemonStoreArchivesColdJournal(t *testing.T) {
	path := corruptColdJournalFixture(t)
	logAuditStoreBytes(t, "cold journal before", path)
	before := map[string][]byte{}
	for _, suffix := range []string{"", "-journal"} {
		body, err := os.ReadFile(path + suffix)
		if err != nil {
			t.Fatal(err)
		}
		before[suffix] = body
	}
	_, probeErr := readOnlyAuditStoreProbe(path, &bytes.Buffer{})
	if !isSQLiteCorrupt(probeErr) {
		t.Fatalf("cold journal probe = %v; want corrupt page", probeErr)
	}
	logAuditStoreBytes(t, "cold journal after probe", path)
	var warning bytes.Buffer
	fresh, err := OpenDaemonStore(path, &warning)
	if err != nil {
		t.Fatal(err)
	}
	defer fresh.Close()
	moved := MovedCorruptStores(path)
	if len(moved) != 1 {
		t.Fatalf("MovedCorruptStores = %+v", moved)
	}
	archive := moved[0].Path
	for _, suffix := range []string{"", "-journal"} {
		got, err := os.ReadFile(archive + suffix)
		if err != nil || !bytes.Equal(got, before[suffix]) {
			t.Fatalf("archived %s changed: size=%d sha256=%x, err=%v; want size=%d sha256=%x",
				suffix, len(got), sha256.Sum256(got), err, len(before[suffix]), sha256.Sum256(before[suffix]))
		}
	}
	if !strings.Contains(warning.String(), "together with its -journal file") {
		t.Fatalf("start warning does not name journal: %q", warning.String())
	}
	logAuditStoreBytes(t, "cold journal after quarantine", archive)
}

func logAuditStoreBytes(t *testing.T, stage, dbPath string) {
	t.Helper()
	for _, suffix := range []string{"", "-wal", "-shm", "-journal"} {
		body, err := os.ReadFile(dbPath + suffix)
		if os.IsNotExist(err) {
			t.Logf("%s %s: absent", stage, filepath.Base(dbPath)+suffix)
			continue
		}
		if err != nil {
			t.Fatal(err)
		}
		t.Logf("%s %s: size=%d sha256=%x", stage, filepath.Base(dbPath)+suffix, len(body), sha256.Sum256(body))
	}
}

// This diagnostic names the precise step that changes a damaged store's
// sidecars. It exercises the same functions as OpenDaemonStore in their actual
// order, including the read-only carry-over open of the archive.
func TestCorruptStoreWALByteTrace(t *testing.T) {
	for _, damage := range []string{"header", "page"} {
		t.Run(damage, func(t *testing.T) {
			path := corruptWALFixture(t, damage)
			logAuditStoreBytes(t, "before start", path)
			prepared, err := prepareAuditDatabasePath(path, auditDBPathHooks{})
			if err != nil {
				t.Fatal(err)
			}
			prepared.close()
			logAuditStoreBytes(t, "after pre-open sidecar handling", path)
			_, probeErr := readOnlyAuditStoreProbe(path, &bytes.Buffer{})
			if !isSQLiteCorrupt(probeErr) {
				t.Fatalf("read-only probe error = %v, want corruption", probeErr)
			}
			logAuditStoreBytes(t, "after read-only probe", path)
			opened, err := openCheckedStore(path, &bytes.Buffer{}, nil)
			if opened != nil {
				_ = opened.Close()
			}
			if !isSQLiteCorrupt(err) {
				t.Fatalf("first writable open error = %v, want corruption", err)
			}
			logAuditStoreBytes(t, "after failed first open", path)
			if preCutoverAuditDB(path) {
				t.Fatal("fixture unexpectedly has a 0.x schema")
			}
			moved, err := quarantineCorruptAuditDB(path)
			if err != nil {
				t.Fatal(err)
			}
			logAuditStoreBytes(t, "after quarantine", moved)
			fresh, err := NewStore(path)
			if err != nil {
				t.Fatal(err)
			}
			defer fresh.Close()
			if err := fresh.Init(); err != nil {
				t.Fatal(err)
			}
			logAuditStoreBytes(t, "after new store creation", moved)
			if _, err := fresh.carryOverActions(moved); err != nil && !isSQLiteCorrupt(err) {
				t.Logf("carry-over: %v", err)
			}
			logAuditStoreBytes(t, "after carryOverActions", moved)

			// Repeat without the destructive writable open. This isolates H4:
			// a populated archive WAL must survive the read-only carry-over.
			preserved := corruptWALFixture(t, damage)
			walBefore, err := os.ReadFile(preserved + "-wal")
			if err != nil {
				t.Fatal(err)
			}
			preservedArchive, err := quarantineCorruptAuditDB(preserved)
			if err != nil {
				t.Fatal(err)
			}
			logAuditStoreBytes(t, "preserved path after quarantine", preservedArchive)
			preservedFresh, err := NewStore(preserved)
			if err != nil {
				t.Fatal(err)
			}
			if err := preservedFresh.Init(); err != nil {
				t.Fatal(err)
			}
			logAuditStoreBytes(t, "preserved path after new store creation", preservedArchive)
			_, _ = preservedFresh.carryOverActions(preservedArchive)
			if err := preservedFresh.Close(); err != nil {
				t.Fatal(err)
			}
			logAuditStoreBytes(t, "preserved path after carryOverActions", preservedArchive)
			walAfter, err := os.ReadFile(preservedArchive + "-wal")
			if err != nil || !bytes.Equal(walAfter, walBefore) {
				t.Fatalf("read-only carry-over changed preserved archive WAL: %v", err)
			}
		})
	}
}
