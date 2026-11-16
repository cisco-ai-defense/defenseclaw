// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// rel-1-0-2:GAP-0647 and GAP-0614: status pointed sqlite3 .recover at the
// archive itself and did not say which sidecars were archived with it.
func TestPrintMovedCorruptAuditStoresRecoversFromACopyAndNamesTheSidecars(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "audit.db")
	moved := db + ".corrupt-20261014T214026Z"
	for _, name := range []string{moved, moved + "-wal", moved + "-shm"} {
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	out := captureStdout(t, func() { printMovedCorruptAuditStores(&config.Config{AuditDB: db}, time.Time{}) })
	for _, want := range []string{
		"moved to " + moved + " together with its -wal and -shm files on ",
		audit.ArchiveRecoveryHint(moved),
		"Delete the moved file and its -wal, -shm and -journal files",
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("status output lacks %q:\n%s", want, out)
		}
	}
	if strings.Contains(out, "sqlite3 "+moved+" .recover") {
		t.Fatalf("status points SQLite at the archive:\n%s", out)
	}
}

// rel-1-0-3:GAP-0106: the start banner named a file that only had an archive's
// name (the newest stamp) instead of the archive, which moved to a new name
// because the first one was taken. Only the archive has the gateway's note.
func TestPrintMovedCorruptAuditStoresNamesTheArchiveNotAFileWithAnArchiveName(t *testing.T) {
	dir := t.TempDir()
	db := filepath.Join(dir, "audit.db")
	archive := db + ".corrupt-20261018T021344Z-4bfc16b6-f3ca-490f-98a0-71b4f32de5ce"
	others := []string{db + ".corrupt-20261018T021344Z", db + ".corrupt-20261018T021513Z"}
	for _, name := range append([]string{archive, archive + "-wal", archive + "-shm"}, others...) {
		if err := os.WriteFile(name, []byte("x"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	note := `{"carried_over": 0, "error": "file is not a database"}`
	if err := os.WriteFile(archive+".carryover.json", []byte(note), 0o600); err != nil {
		t.Fatal(err)
	}
	since := time.Date(2026, 10, 18, 2, 13, 43, 0, time.UTC)
	out := captureStdout(t, func() { printMovedCorruptAuditStores(&config.Config{AuditDB: db}, since) })
	for _, want := range []string{
		"moved to " + archive + " together with its -wal and -shm files on ",
		"0 entries were carried over",
		audit.ArchiveRecoveryHint(archive),
	} {
		if !strings.Contains(out, want) {
			t.Fatalf("start output lacks %q:\n%s", want, out)
		}
	}
	for _, other := range others {
		if strings.Contains(out, other+" ") || strings.Contains(out, other+"\n") {
			t.Fatalf("start output names %s, which is no archive:\n%s", other, out)
		}
	}
}
