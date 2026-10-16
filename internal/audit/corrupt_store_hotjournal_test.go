// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

type hotJournalFixture struct {
	path      string
	firstLeaf int
	pageSize  int
}

// realHotJournalFixture copies a DELETE-mode store during an uncommitted
// transaction. synchronous(OFF) makes SQLite write the journal header magic
// before the copy; cache_size(1) makes the modified main-file pages spill.
// The source transaction is then rolled back and closed. Damage to the first
// leaf is outside the journal: the uncommitted inserts reach the right edge.
func realHotJournalFixture(t *testing.T, damage string) hotJournalFixture {
	t.Helper()
	source := filepath.Join(t.TempDir(), "audit.db")
	store, err := NewStore(source)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
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
	var firstLeaf, rightLeaf, pageSize int
	for _, query := range []struct {
		sql  string
		dest *int
	}{
		{`SELECT pageno FROM dbstat WHERE name='audit_events' AND pagetype='leaf' ORDER BY pageno LIMIT 1`, &firstLeaf},
		{`SELECT pageno FROM dbstat WHERE name='audit_events' AND pagetype='leaf' ORDER BY pageno DESC LIMIT 1`, &rightLeaf},
		{`PRAGMA page_size`, &pageSize},
	} {
		if err := store.db.QueryRow(query.sql).Scan(query.dest); err != nil {
			t.Fatal(err)
		}
	}
	if firstLeaf == rightLeaf {
		t.Fatalf("fixture has only one audit_events leaf page: %d", firstLeaf)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	committed, err := os.ReadFile(source)
	if err != nil {
		t.Fatal(err)
	}

	writer, err := openSQLiteWithPragmas(source, "?_pragma=journal_mode(DELETE)&_pragma=synchronous(OFF)&_pragma=cache_size(1)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	if err := writer.Ping(); err != nil {
		t.Fatal(err)
	}
	var mode string
	if err := writer.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "delete" {
		t.Fatalf("fixture journal_mode = %q, %v; want delete", mode, err)
	}
	writeTx, err := writer.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer writeTx.Rollback()
	for i := range 50 {
		if _, err := writeTx.Exec(`INSERT INTO audit_events (id, timestamp, action, target)
			VALUES (?, CURRENT_TIMESTAMP, 'uncommitted', ?)`, fmt.Sprintf("hot-uncommitted-%03d", i), "right-edge"); err != nil {
			t.Fatal(err)
		}
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
	}
	if err := writeTx.Rollback(); err != nil {
		t.Fatal(err)
	}
	if err := writer.Close(); err != nil {
		t.Fatal(err)
	}
	main, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(main, committed) {
		t.Fatal("fixture did not spill uncommitted pages into the main file")
	}
	journal, err := os.ReadFile(path + "-journal")
	if err != nil {
		t.Fatal(err)
	}
	if len(journal) == 0 || journal[0] == 0 {
		t.Fatalf("fixture journal is not hot: size=%d first byte zero or absent", len(journal))
	}
	t.Logf("hot journal: size=%d first byte=%d; main file differs from committed state", len(journal), journal[0])
	pages := hotJournalPages(t, journal, pageSize, len(committed)/pageSize)
	if pages[firstLeaf] {
		t.Fatalf("first audit_events leaf page %d is in the journal", firstLeaf)
	}
	if !pages[rightLeaf] {
		t.Fatalf("right-edge audit_events leaf page %d is not in the journal", rightLeaf)
	}
	var damagedPage int
	switch damage {
	case "none":
	case "outside":
		damagedPage = firstLeaf
	case "inside":
		damagedPage = rightLeaf
	default:
		t.Fatalf("unknown damage %q", damage)
	}
	if damagedPage != 0 {
		file, err := os.OpenFile(path, os.O_WRONLY, 0)
		if err != nil {
			t.Fatal(err)
		}
		_, writeErr := file.WriteAt(bytes.Repeat([]byte{0xff}, pageSize), int64(damagedPage-1)*int64(pageSize))
		closeErr := file.Close()
		if writeErr != nil || closeErr != nil {
			t.Fatalf("damage page %d: %v, close: %v", damagedPage, writeErr, closeErr)
		}
	}
	return hotJournalFixture{path: path, firstLeaf: firstLeaf, pageSize: pageSize}
}

func hotJournalPages(t *testing.T, journal []byte, pageSize, originalPages int) map[int]bool {
	t.Helper()
	if len(journal) < 28 {
		t.Fatalf("short journal header: %d bytes", len(journal))
	}
	sectorSize := int(binary.BigEndian.Uint32(journal[20:24]))
	if sectorSize < 28 || sectorSize > len(journal) || int(binary.BigEndian.Uint32(journal[24:28])) != pageSize {
		t.Fatalf("journal sector/page sizes = %d/%d, want valid sector/%d", sectorSize, binary.BigEndian.Uint32(journal[24:28]), pageSize)
	}
	pages := make(map[int]bool)
	for offset := sectorSize; offset+pageSize+8 <= len(journal); offset += pageSize + 8 {
		page := int(binary.BigEndian.Uint32(journal[offset : offset+4]))
		if page > 0 && page <= originalPages {
			pages[page] = true
		}
	}
	if len(pages) == 0 {
		t.Fatal("hot journal contains no original pages")
	}
	return pages
}

func copyHotJournalSet(t *testing.T, source string) string {
	t.Helper()
	copyPath := filepath.Join(t.TempDir(), "audit.db")
	for _, suffix := range []string{"", "-journal"} {
		body, err := os.ReadFile(source + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(copyPath+suffix, body, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	return copyPath
}

func assertHotSetHashesUnchanged(t *testing.T, path string, before map[string][]byte) {
	t.Helper()
	for _, suffix := range []string{"", "-journal"} {
		body, err := os.ReadFile(path + suffix)
		if err != nil {
			t.Fatal(err)
		}
		if sha256.Sum256(body) != sha256.Sum256(before[suffix]) {
			t.Fatalf("read-only probe changed %s: before=%x after=%x", suffix, sha256.Sum256(before[suffix]), sha256.Sum256(body))
		}
	}
}

func assertHotRecoveredRows(t *testing.T, store *Store) {
	t.Helper()
	for _, tc := range []struct {
		query string
		want  int
	}{
		{`SELECT count(*) FROM audit_events WHERE id LIKE 'base-%'`, 400},
		{`SELECT count(*) FROM audit_events WHERE id LIKE 'hot-uncommitted-%'`, 0},
	} {
		var count int
		if err := store.db.QueryRow(tc.query).Scan(&count); err != nil || count != tc.want {
			t.Fatalf("%s = %d, %v; want %d", tc.query, count, err, tc.want)
		}
	}
	if err := quickCheckAuditDB(context.Background(), store.db); err != nil {
		t.Fatalf("recovered store quick_check: %v", err)
	}
}

func TestHotJournalHealthyProbeAndDaemonOpen(t *testing.T) {
	fixture := realHotJournalFixture(t, "none")
	before := auditSetBytes(t, fixture.path)
	raw, err := openAuditReadOnlyPreservingSHM(fixture.path, "")
	if err != nil {
		t.Fatal(err)
	}
	rawErr := quickCheckAuditDB(context.Background(), raw)
	if err := raw.Close(); err != nil {
		t.Fatal(err)
	}
	var coded sqliteCoded
	if rawErr == nil || isSQLiteCorrupt(rawErr) || !errors.As(rawErr, &coded) || coded.Code()&0xff != 8 {
		t.Fatalf("raw hot-journal quick_check = %v; want non-corrupt SQLITE_READONLY (primary code 8)", rawErr)
	}
	assertHotSetHashesUnchanged(t, fixture.path, before)
	var probeWarning bytes.Buffer
	if _, err := readOnlyAuditStoreProbe(fixture.path, &probeWarning); err != nil {
		t.Fatalf("hot-journal read-only probe: %v", err)
	}
	if !strings.Contains(probeWarning.String(), "read-only probe could not read") || !strings.Contains(probeWarning.String(), "normal open") {
		t.Fatalf("missing inconclusive probe warning: %q", probeWarning.String())
	}
	assertHotSetHashesUnchanged(t, fixture.path, before)

	path := copyHotJournalSet(t, fixture.path)
	var warning bytes.Buffer
	store, err := OpenDaemonStore(path, &warning)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	assertHotRecoveredRows(t, store)
	if archives := MovedCorruptStores(path); len(archives) != 0 {
		t.Fatalf("healthy hot journal was quarantined: %+v", archives)
	}
	if _, err := os.Stat(path + "-journal"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("hot journal still present after SQLite rollback: %v", err)
	}
	var mode string
	if err := store.db.QueryRow(`PRAGMA journal_mode`).Scan(&mode); err != nil || mode != "wal" {
		t.Fatalf("normal journal_mode = %q, %v; want wal", mode, err)
	}
	var autoCheckpoint int
	if err := store.db.QueryRow(`PRAGMA wal_autocheckpoint`).Scan(&autoCheckpoint); err != nil || autoCheckpoint != 0 {
		t.Fatalf("normal wal_autocheckpoint = %d, %v; want zero", autoCheckpoint, err)
	}
}

func TestHotJournalOutsideJournalDamageProbeAndQuarantine(t *testing.T) {
	fixture := realHotJournalFixture(t, "outside")
	before := auditSetBytes(t, fixture.path)
	var probeWarning bytes.Buffer
	if _, err := readOnlyAuditStoreProbe(fixture.path, &probeWarning); err != nil {
		t.Fatalf("damaged hot-journal read-only probe: %v", err)
	}
	if !strings.Contains(probeWarning.String(), "read-only probe could not read") {
		t.Fatalf("missing inconclusive probe warning: %q", probeWarning.String())
	}
	assertHotSetHashesUnchanged(t, fixture.path, before)

	path := copyHotJournalSet(t, fixture.path)
	var warning bytes.Buffer
	store, err := OpenDaemonStore(path, &warning)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	archives := MovedCorruptStores(path)
	if len(archives) != 1 {
		t.Fatalf("want one damaged-store archive, got %+v", archives)
	}
	archive := archives[0].Path
	if _, err := os.Stat(archive + "-journal"); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("consumed hot journal was archived: %v", err)
	}
	if !strings.Contains(warning.String(), "pre-existing -journal sidecar") || !strings.Contains(warning.String(), "not preserved") {
		t.Fatalf("missing consumed-journal start warning: %q", warning.String())
	}
	main, err := os.ReadFile(archive)
	if err != nil {
		t.Fatal(err)
	}
	if len(main) < fixture.firstLeaf*fixture.pageSize {
		t.Fatalf("short archived main file: %d bytes", len(main))
	}
	page := main[(fixture.firstLeaf-1)*fixture.pageSize : fixture.firstLeaf*fixture.pageSize]
	if !bytes.Equal(page, bytes.Repeat([]byte{0xff}, fixture.pageSize)) {
		t.Fatal("archive lost the damaged page outside the journal")
	}
	if bytes.Contains(main, []byte("hot-uncommitted-")) {
		t.Fatal("archive still has uncommitted rows after journal rollback")
	}
	var count int
	if err := store.db.QueryRow(`SELECT count(*) FROM audit_events`).Scan(&count); err != nil || count != 0 {
		t.Fatalf("new audit store has %d old rows, %v", count, err)
	}
	if err := quickCheckAuditDB(context.Background(), store.db); err != nil {
		t.Fatalf("new audit store quick_check: %v", err)
	}
}

func TestHotJournalInsideJournalDamageRecovered(t *testing.T) {
	fixture := realHotJournalFixture(t, "inside")
	var warning bytes.Buffer
	store, err := OpenDaemonStore(fixture.path, &warning)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	assertHotRecoveredRows(t, store)
	if archives := MovedCorruptStores(fixture.path); len(archives) != 0 {
		t.Fatalf("rollback-restored page was quarantined: %+v", archives)
	}
	if strings.Contains(warning.String(), "WARNING:") {
		t.Fatalf("rollback-restored page produced corruption warning: %q", warning.String())
	}
}

func TestHotJournalBusyProbeSkipped(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	writer, err := openSQLiteWithPragmas(path, "?_pragma=journal_mode(DELETE)&_pragma=busy_timeout(5000)")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = writer.Close() })
	conn, err := writer.Conn(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_, _ = conn.ExecContext(context.Background(), `ROLLBACK`)
		_ = conn.Close()
	})
	if _, err := conn.ExecContext(context.Background(), `BEGIN EXCLUSIVE`); err != nil {
		t.Fatal(err)
	}
	if _, err := conn.ExecContext(context.Background(), `INSERT INTO audit_events (id, timestamp, action, target)
		VALUES ('locked-row', CURRENT_TIMESTAMP, 'fixture', 'fixture')`); err != nil {
		t.Fatal(err)
	}
	before := auditSetBytes(t, path)
	var warning bytes.Buffer
	if _, err := readOnlyAuditStoreProbe(path, &warning); err != nil {
		t.Fatalf("busy read-only probe: %v", err)
	}
	if !strings.Contains(warning.String(), "startup integrity check skipped") || strings.Contains(warning.String(), "corrupt") {
		t.Fatalf("busy probe warning = %q", warning.String())
	}
	assertOriginalAuditSetUnchanged(t, path, before)
}
