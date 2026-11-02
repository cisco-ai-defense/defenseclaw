// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"crypto/sha256"
	"encoding/binary"
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
			// rel-1-0-2:GAP-0647: copy first, repair the header on the copy.
			if !strings.Contains(warning.String(), ArchiveRecoveryHint(archive)) ||
				strings.Contains(warning.String(), "sqlite3 "+archive+" .recover") {
				t.Fatalf("start warning does not say to recover from a copy: %q", warning.String())
			}
			if got := strings.Join(moved[0].Sidecars, ","); got != "-wal,-shm" {
				t.Fatalf("MovedCorruptStores sidecars = %q, want -wal,-shm", got)
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
	probeExistingAuditStore = func(string, io.Writer) (auditStoreProbe, error) { return auditStoreProbe{}, injected }
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
				return original(from, to)
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
				return originalRename(from, to)
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
	if os.Geteuid() == 0 {
		t.Skip("root opens a 0400 file for writing, so the WAL is not unwritable (rel-1-0-2:GAP-0614)")
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
	probeExistingAuditStore = func(string, io.Writer) (auditStoreProbe, error) {
		return auditStoreProbe{sidecars: []auditSidecarAtStart{{suffix: "-wal", size: wal.Size()}}}, nil
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
}

// rel-1-0-2:GAP-0609: a read-only probe error that is neither corruption, a
// busy store nor a hot journal went on to the writable open. That open failed
// the same way and its last connection checkpointed the WAL into the main
// file and deleted it. The start must refuse with the set untouched.
func TestOpenDaemonStoreRefusesAnUnreadableStoreBeforeItsWALIsConsumed(t *testing.T) {
	path := schemaFormatDamagedWALFixture(t)
	before := auditSetBytes(t, path)
	if len(before["-wal"]) == 0 {
		t.Fatal("fixture WAL is empty")
	}
	var warning bytes.Buffer
	store, err := OpenDaemonStore(path, &warning)
	if store != nil {
		_ = store.Close()
	}
	if store != nil || err == nil || !strings.Contains(err.Error(), "did not open it for writing") ||
		isSQLiteCorrupt(err) {
		t.Fatalf("OpenDaemonStore = %v, %v; want a refusal before the writable open; warning %q", store != nil, err, warning.String())
	}
	assertOriginalAuditSetUnchanged(t, path, before)
	if moved := MovedCorruptStores(path); len(moved) != 0 {
		t.Fatalf("an unreadable store that is not corrupt was moved aside: %+v", moved)
	}
}

// schemaFormatDamagedWALFixture copies a store whose WAL holds a same-size
// update but not page 1, then sets an unsupported schema format number in the
// main file's header: SQLite reports SQLITE_ERROR, neither corruption nor a
// busy store. An insert would allocate a page and put page 1 in the WAL,
// where the main file's header is not read.
func schemaFormatDamagedWALFixture(t *testing.T) string {
	t.Helper()
	source := filepath.Join(t.TempDir(), "audit.db")
	store, err := NewStore(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`INSERT INTO audit_events (id, timestamp, action, target)
		VALUES ('same-size', CURRENT_TIMESTAMP, 'fixture', 'aaaaaaaa')`); err != nil {
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
	if _, err := writer.Exec(`UPDATE audit_events SET target = 'bbbbbbbb' WHERE id = 'same-size'`); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "audit.db")
	for _, suffix := range []string{"", "-wal", "-shm"} {
		body, err := os.ReadFile(source + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(path+suffix, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	wal, err := os.ReadFile(path + "-wal")
	if err != nil {
		t.Fatal(err)
	}
	const walHeader, frameHeader = 32, 24
	for offset := walHeader; offset+frameHeader <= len(wal); offset += frameHeader + 4096 {
		if page := binary.BigEndian.Uint32(wal[offset:]); page == 1 {
			t.Fatal("fixture WAL holds page 1, which hides the main file's header")
		}
	}
	file, err := os.OpenFile(path, os.O_WRONLY, 0)
	if err != nil {
		t.Fatal(err)
	}
	defer file.Close()
	// The schema format number is the big-endian integer at offset 44; SQLite
	// reads its low byte and supports formats 1 to 4.
	if _, err := file.WriteAt([]byte{0, 0, 0, 9}, 44); err != nil {
		t.Fatal(err)
	}
	return path
}
