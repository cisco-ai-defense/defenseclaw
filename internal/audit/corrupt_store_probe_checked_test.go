// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"bytes"
	"context"
	"database/sql"
	"io"
	"os"
	"path/filepath"
	"testing"
)

// rel-1-0-6 GAP-0332: the start ran quick_check over the whole store twice,
// in the read-only probe and again on the writable connection. The probe now
// reports a check that read the store and found it intact, and only a start
// without one checks again.
func TestReadOnlyProbeReportsAnIntactStoreAsChecked(t *testing.T) {
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
	probe, err := readOnlyAuditStoreProbe(path, &bytes.Buffer{})
	if err != nil || probe.checked == nil {
		t.Fatalf("probe of an intact store = %+v, %v; want checked", probe, err)
	}
	missing, err := readOnlyAuditStoreProbe(filepath.Join(t.TempDir(), "absent.db"), &bytes.Buffer{})
	if err != nil || missing.checked != nil {
		t.Fatalf("probe of a missing store = %+v, %v; want not checked", missing, err)
	}
	reopened, err := OpenDaemonStore(path, &bytes.Buffer{})
	if err != nil {
		t.Fatal(err)
	}
	_ = reopened.Close()
}

func TestReadOnlyProbeOfACorruptStoreIsNotChecked(t *testing.T) {
	path := corruptColdJournalFixture(t)
	probe, err := readOnlyAuditStoreProbe(path, &bytes.Buffer{})
	if !isSQLiteCorrupt(err) || probe.checked != nil {
		t.Fatalf("probe of a corrupt store = %+v, %v; want corrupt, not checked", probe, err)
	}
}

// A start whose probe did not check the store (skipped, inconclusive, or a
// store rebuilt after it) still runs the writable connection's quick_check.
func TestAStartWithoutACheckedProbeChecksTheStore(t *testing.T) {
	original := probeExistingAuditStore
	t.Cleanup(func() { probeExistingAuditStore = original })
	probeExistingAuditStore = func(string, io.Writer) (auditStoreProbe, error) { return auditStoreProbe{}, nil }
	path := corruptColdJournalFixture(t)
	var warning bytes.Buffer
	store, err := OpenDaemonStore(path, &warning)
	if err != nil {
		t.Fatal(err)
	}
	_ = store.Close()
	if !bytes.Contains(warning.Bytes(), []byte("corrupt")) {
		t.Fatalf("a start without a checked probe did not find the corrupt store; warning %q", warning.String())
	}
}

// intactAuditStore creates an initialized store with a few rows and closes it.
func intactAuditStore(t *testing.T, dir string, rows int) string {
	t.Helper()
	path := filepath.Join(dir, "audit.db")
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	for i := range rows {
		if _, err := store.db.Exec(`INSERT INTO audit_events (id, timestamp, action, target) VALUES (?, CURRENT_TIMESTAMP, 'fixture', ?)`,
			filepath.Base(dir)+"-"+string(rune('a'+i%26))+string(rune('a'+i/26)), "t"); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	return path
}

// countWritableQuickChecks counts the writable open's quick_checks and runs
// change between the probe and the writable open.
func countWritableQuickChecks(t *testing.T, change func(path string)) *int {
	t.Helper()
	runs := new(int)
	originalCheck, originalAfter := writableStartupQuickCheck, afterAuditStoreProbe
	t.Cleanup(func() { writableStartupQuickCheck, afterAuditStoreProbe = originalCheck, originalAfter })
	writableStartupQuickCheck = func(ctx context.Context, db *sql.DB) error {
		*runs++
		return originalCheck(ctx, db)
	}
	afterAuditStoreProbe = change
	return runs
}

func openDaemonStoreForTest(t *testing.T, path string, opts ...StoreOption) {
	t.Helper()
	store, err := OpenDaemonStore(path, &bytes.Buffer{}, opts...)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
}

// rel-1-0-6 GAP-0332: the files the probe checked, unchanged, are not
// checked again.
func TestAStartChecksAnUnchangedStoreOnce(t *testing.T) {
	path := intactAuditStore(t, t.TempDir(), 40)
	runs := countWritableQuickChecks(t, func(string) {})
	openDaemonStoreForTest(t, path)
	if *runs != 0 {
		t.Fatalf("writable quick_check ran %d times on the store the probe checked; want 0", *runs)
	}
}

// Review of GAP-0332: a store renamed into place between the probe and the
// writable open is another file than the one checked, and is checked.
func TestAStoreSwappedAfterTheProbeIsCheckedAgain(t *testing.T) {
	dir := t.TempDir()
	path := intactAuditStore(t, dir, 40)
	other := intactAuditStore(t, filepath.Join(dir, "other"), 3)
	runs := countWritableQuickChecks(t, func(path string) {
		for _, suffix := range []string{"-wal", "-shm"} {
			_ = os.Remove(path + suffix)
		}
		if err := os.Rename(other, path); err != nil {
			t.Fatal(err)
		}
	})
	openDaemonStoreForTest(t, path)
	if *runs != 1 {
		t.Fatalf("writable quick_check ran %d times on a store swapped after the probe; want 1", *runs)
	}
}

// A -wal written between the probe and the writable open (an old gateway
// still flushing during a restart) holds pages the probe did not read.
func TestAStoreWrittenAfterTheProbeIsCheckedAgain(t *testing.T) {
	path := intactAuditStore(t, t.TempDir(), 40)
	runs := countWritableQuickChecks(t, func(path string) {
		writer, err := openSQLite(path)
		if err != nil {
			t.Fatal(err)
		}
		defer writer.Close()
		if _, err := writer.Exec(`INSERT INTO audit_events (id, timestamp, action, target) VALUES ('late', CURRENT_TIMESTAMP, 'fixture', 't')`); err != nil {
			t.Fatal(err)
		}
	})
	openDaemonStoreForTest(t, path)
	if *runs != 1 {
		t.Fatalf("writable quick_check ran %d times on a store written after the probe; want 1", *runs)
	}
}

// Secure Client keeps main's second check (#1092).
func TestASecureClientStartChecksTheStoreAgain(t *testing.T) {
	path := intactAuditStore(t, t.TempDir(), 40)
	runs := countWritableQuickChecks(t, func(string) {})
	openDaemonStoreForTest(t, path, WithSecureClientSchema())
	if *runs != 1 {
		t.Fatalf("writable quick_check ran %d times on a Secure Client start; want 1", *runs)
	}
}

// A -wal that holds frames and nobody writes between the probe and the open
// (the store of a gateway that stopped with its log not yet copied back) is
// part of the checked set: the writable open leaves it as it was.
func TestAStoreWithAnIdleWALIsCheckedOnce(t *testing.T) {
	path := intactAuditStore(t, t.TempDir(), 40)
	writer, err := openSQLite(path)
	if err != nil {
		t.Fatal(err)
	}
	defer writer.Close()
	if _, err := writer.Exec(`INSERT INTO audit_events (id, timestamp, action, target) VALUES ('in-wal', CURRENT_TIMESTAMP, 'fixture', 't')`); err != nil {
		t.Fatal(err)
	}
	if info, err := os.Stat(path + "-wal"); err != nil || info.Size() == 0 {
		t.Fatalf("fixture -wal = %v, %v; want frames", info, err)
	}
	runs := countWritableQuickChecks(t, func(string) {})
	openDaemonStoreForTest(t, path)
	if *runs != 0 {
		t.Fatalf("writable quick_check ran %d times on an unchanged store with a -wal; want 0", *runs)
	}
}

// Review round 2: frames a writer appends to the -wal while the probe's
// quick_check runs (after its read snapshot) are not in the checked set.
func TestAStoreWrittenDuringTheProbeCheckIsCheckedAgain(t *testing.T) {
	path := intactAuditStore(t, t.TempDir(), 40)
	runs := countWritableQuickChecks(t, func(string) {})
	original := duringAuditStoreProbeCheck
	t.Cleanup(func() { duringAuditStoreProbeCheck = original })
	duringAuditStoreProbeCheck = func(path string) {
		writer, err := openSQLite(path)
		if err != nil {
			t.Fatal(err)
		}
		defer writer.Close()
		if _, err := writer.Exec(`INSERT INTO audit_events (id, timestamp, action, target) VALUES ('during', CURRENT_TIMESTAMP, 'fixture', 't')`); err != nil {
			t.Fatal(err)
		}
	}
	openDaemonStoreForTest(t, path)
	if *runs != 1 {
		t.Fatalf("writable quick_check ran %d times on a store written during the probe check; want 1", *runs)
	}
}
