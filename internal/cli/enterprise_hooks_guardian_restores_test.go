// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// guardianRestoresForTest reads the restores of dataDir and fails the test
// on a read error.
func guardianRestoresForTest(t *testing.T, dataDir string) map[string]time.Time {
	t.Helper()
	restores, err := readEnterpriseHookGuardianRestores(dataDir)
	if err != nil {
		t.Fatalf("read restores: %v", err)
	}
	return restores
}

func shortenGuardianRestoreBackoff(t *testing.T) {
	t.Helper()
	previous := enterpriseHookGuardianRestoreReadBackoff
	t.Cleanup(func() { enterpriseHookGuardianRestoreReadBackoff = previous })
	enterpriseHookGuardianRestoreReadBackoff = []time.Duration{time.Millisecond, time.Millisecond, time.Millisecond}
}

func enableEnterpriseHookGuardianRestores(t *testing.T, enabled bool) {
	t.Helper()
	previous, previousOwnership := enterpriseHookGuardianRestoresEnabled, enterpriseHookAuthorizationOwnershipSetter
	t.Cleanup(func() {
		enterpriseHookGuardianRestoresEnabled, enterpriseHookAuthorizationOwnershipSetter = previous, previousOwnership
	})
	enterpriseHookGuardianRestoresEnabled = func() bool { return enabled }
	// The Windows protected-file writer hands the record to the gateway
	// service account, which a test host does not have.
	enterpriseHookAuthorizationOwnershipSetter = func(string) error { return nil }
}

func readGuardianRestoreRecordForTest(t *testing.T, dataDir string) enterpriseHookGuardianRestoreRecord {
	t.Helper()
	record, err := readEnterpriseHookGuardianRestoreRecord(filepath.Join(dataDir, hookGuardianRestoresFile))
	if err != nil {
		t.Fatalf("read restore record: %v", err)
	}
	return record
}

func resetGuardianRestorePendingForTest(t *testing.T, dataDir string) {
	t.Helper()
	path := filepath.Join(dataDir, hookGuardianRestoresFile)
	t.Cleanup(func() {
		enterpriseHookGuardianRestorePending.Lock()
		delete(enterpriseHookGuardianRestorePending.byPath, path)
		enterpriseHookGuardianRestorePending.Unlock()
	})
}

func guardianRestorePendingCountForTest(dataDir string) int {
	path := filepath.Join(dataDir, hookGuardianRestoresFile)
	enterpriseHookGuardianRestorePending.Lock()
	defer enterpriseHookGuardianRestorePending.Unlock()
	return len(enterpriseHookGuardianRestorePending.byPath[path])
}

// GAP-0440: the guardian dates each target it put back, keeps the entries of
// the other enrolled targets and drops those of targets that left the
// manifest; a pass that restored nothing writes nothing.
func TestEnterpriseHookGuardianRestoresRecordEachRestoredTarget(t *testing.T) {
	enableEnterpriseHookGuardianRestores(t, true)
	dataDir := t.TempDir()
	resetGuardianRestorePendingForTest(t, dataDir)
	const std1, std2 = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002"
	rows := []enterpriseHookReconcileRow{
		{SID: std1, Connector: "hermes", OK: true},
		{SID: std2, Connector: "hermes", OK: true},
		{SID: std2, Connector: "codex", OK: true},
	}
	first := time.Date(2026, 10, 13, 13, 24, 30, 0, time.UTC)
	var log bytes.Buffer
	if err := recordEnterpriseHookGuardianRestores(&log, dataDir, rows, []enterpriseHookGuardianRestore{
		{SID: strings.ToLower(std1), Connector: "Hermes", RestoredAt: first.Format(time.RFC3339Nano)},
	}); err != nil {
		t.Fatal(err)
	}
	restores := guardianRestoresForTest(t, dataDir)
	if len(restores) != 1 || !restores[enterpriseHookGuardianRestoreKey(std1, "hermes")].Equal(first) {
		t.Fatalf("restores after the first repair = %v, want hermes of %s at %s", restores, std1, first)
	}

	// A later pass restores another target; the first entry is kept.
	second := first.Add(10 * time.Minute)
	if err := recordEnterpriseHookGuardianRestores(&log, dataDir, rows, []enterpriseHookGuardianRestore{
		{SID: std2, Connector: "codex", RestoredAt: second.Format(time.RFC3339Nano)},
	}); err != nil {
		t.Fatal(err)
	}
	restores = guardianRestoresForTest(t, dataDir)
	if len(restores) != 2 || !restores[enterpriseHookGuardianRestoreKey(std1, "hermes")].Equal(first) ||
		!restores[enterpriseHookGuardianRestoreKey(std2, "codex")].Equal(second) {
		t.Fatalf("restores after the second repair = %v", restores)
	}

	// A pass that restored nothing leaves the record as it was.
	path := filepath.Join(dataDir, hookGuardianRestoresFile)
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	stale := time.Now().Add(-time.Hour)
	if err := os.Chtimes(path, stale, stale); err != nil {
		t.Fatal(err)
	}
	if err := recordEnterpriseHookGuardianRestores(&log, dataDir, rows, nil); err != nil {
		t.Fatal(err)
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(before, after) {
		t.Fatalf("a pass without restores rewrote the record: %q (%v)", after, err)
	}
	if info, err := os.Stat(path); err != nil || !info.ModTime().Equal(stale) {
		t.Fatalf("a pass without restores touched the record: %v %v", info, err)
	}

	// std1 left the manifest: its entry is dropped.
	if err := recordEnterpriseHookGuardianRestores(&log, dataDir, rows[1:], nil); err != nil {
		t.Fatal(err)
	}
	record := readGuardianRestoreRecordForTest(t, dataDir)
	if len(record.Targets) != 1 || record.Targets[0].SID != std2 || record.Targets[0].Connector != "codex" {
		t.Fatalf("record after std1 left = %+v, want only codex of %s", record.Targets, std2)
	}
	if log.Len() != 0 {
		t.Fatalf("unexpected log: %q", log.String())
	}
}

// Outside the standalone Windows guardian (Secure Client, Linux, macOS) no
// record is written.
func TestEnterpriseHookGuardianRestoresWriteNothingWhenDisabled(t *testing.T) {
	enableEnterpriseHookGuardianRestores(t, false)
	dataDir := t.TempDir()
	resetGuardianRestorePendingForTest(t, dataDir)
	if err := recordEnterpriseHookGuardianRestores(os.Stderr, dataDir,
		[]enterpriseHookReconcileRow{{SID: "S-1-5-21-1-2-3-1001", Connector: "hermes", OK: true}},
		[]enterpriseHookGuardianRestore{{SID: "S-1-5-21-1-2-3-1001", Connector: "hermes", RestoredAt: time.Now().UTC().Format(time.RFC3339Nano)}}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(dataDir, hookGuardianRestoresFile)); !os.IsNotExist(err) {
		t.Fatalf("disabled guardian wrote a restore record (err = %v)", err)
	}
}

// A record status cannot trust names no restore and is an error, so status
// reports the restart status unknown; the next restore replaces it. A
// missing record is no restore and no error.
func TestEnterpriseHookGuardianRestoresReadRejectsBadRecords(t *testing.T) {
	enableEnterpriseHookGuardianRestores(t, true)
	shortenGuardianRestoreBackoff(t)
	dataDir := t.TempDir()
	resetGuardianRestorePendingForTest(t, dataDir)
	if restores, err := readEnterpriseHookGuardianRestores(dataDir); restores != nil || err != nil {
		t.Fatalf("missing record = %v, %v; want none and no error", restores, err)
	}
	path := filepath.Join(dataDir, hookGuardianRestoresFile)
	for _, body := range []string{
		"not json",
		`{"version":2,"targets":[{"sid":"S-1-5-21-1-2-3-1001","connector":"hermes","restored_at":"2026-10-13T13:24:30Z"}]}`,
		strings.Repeat(" ", hookGuardianRestoresMaxBytes+1),
	} {
		if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
		if restores, err := readEnterpriseHookGuardianRestores(dataDir); len(restores) != 0 || err == nil {
			t.Fatalf("restores from %.40q = %v, %v; want none and an error", body, restores, err)
		}
	}
	at := time.Date(2026, 10, 13, 13, 24, 30, 0, time.UTC)
	if err := recordEnterpriseHookGuardianRestores(os.Stderr, dataDir,
		[]enterpriseHookReconcileRow{{SID: "S-1-5-21-1-2-3-1001", Connector: "hermes", OK: true}},
		[]enterpriseHookGuardianRestore{{SID: "S-1-5-21-1-2-3-1001", Connector: "hermes", RestoredAt: at.Format(time.RFC3339Nano)}}); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var record enterpriseHookGuardianRestoreRecord
	if err := json.Unmarshal(data, &record); err != nil || record.Version != 1 || len(record.Targets) != 1 {
		t.Fatalf("replaced record = %q (%v)", data, err)
	}
}

// Pass-6 review: a read that fails while the guardian replaces the record (a
// Windows sharing violation) is retried, and one that keeps failing is an
// error, never "no restore", so the restart warning cannot silently vanish.
func TestEnterpriseHookGuardianRestoresReadRetriesATransientError(t *testing.T) {
	shortenGuardianRestoreBackoff(t)
	dataDir := t.TempDir()
	const sid = "S-1-5-21-1-2-3-1001"
	at := time.Date(2026, 10, 13, 13, 24, 30, 0, time.UTC)
	previous := enterpriseHookGuardianRestoreRecordReader
	t.Cleanup(func() { enterpriseHookGuardianRestoreRecordReader = previous })
	sharing := errors.New("the process cannot access the file because it is being used by another process")
	failures, calls := 2, 0
	enterpriseHookGuardianRestoreRecordReader = func(string) (enterpriseHookGuardianRestoreRecord, error) {
		calls++
		if calls <= failures {
			return enterpriseHookGuardianRestoreRecord{}, sharing
		}
		return enterpriseHookGuardianRestoreRecord{Version: 1, Targets: []enterpriseHookGuardianRestore{
			{SID: sid, Connector: "hermes", RestoredAt: at.Format(time.RFC3339Nano)},
		}}, nil
	}
	restores, err := readEnterpriseHookGuardianRestores(dataDir)
	if err != nil || !restores[enterpriseHookGuardianRestoreKey(sid, "hermes")].Equal(at) || calls != 3 {
		t.Fatalf("transient error: restores %v err %v after %d reads, want the record on the third read", restores, err, calls)
	}
	failures, calls = 100, 0
	if restores, err := readEnterpriseHookGuardianRestores(dataDir); restores != nil || !errors.Is(err, sharing) ||
		calls != 1+len(enterpriseHookGuardianRestoreReadBackoff) {
		t.Fatalf("persistent error: restores %v err %v after %d reads, want the error", restores, err, calls)
	}
}

func TestEnterpriseHookGuardianRestoresPreservesRecordAfterReadFailure(t *testing.T) {
	enableEnterpriseHookGuardianRestores(t, true)
	shortenGuardianRestoreBackoff(t)
	dataDir := t.TempDir()
	resetGuardianRestorePendingForTest(t, dataDir)
	path := filepath.Join(dataDir, hookGuardianRestoresFile)
	const earlierSID, newSID, otherSID = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002", "S-1-5-21-1-2-3-1003"
	first := time.Date(2026, 10, 13, 13, 24, 30, 0, time.UTC)
	second := first.Add(10 * time.Minute)
	rows := []enterpriseHookReconcileRow{
		{SID: earlierSID, Connector: "hermes", OK: true},
		{SID: newSID, Connector: "codex", OK: true},
		{SID: otherSID, Connector: "hermes", OK: true},
	}
	if err := recordEnterpriseHookGuardianRestores(io.Discard, dataDir, rows, []enterpriseHookGuardianRestore{
		{SID: earlierSID, Connector: "hermes", RestoredAt: first.Format(time.RFC3339Nano)},
		{SID: otherSID, Connector: "hermes", RestoredAt: first.Format(time.RFC3339Nano)},
	}); err != nil {
		t.Fatal(err)
	}
	before, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	previous := enterpriseHookGuardianRestoreRecordReader
	t.Cleanup(func() { enterpriseHookGuardianRestoreRecordReader = previous })
	sharing := errors.New("sharing violation")
	calls := 0
	enterpriseHookGuardianRestoreRecordReader = func(string) (enterpriseHookGuardianRestoreRecord, error) {
		calls++
		return enterpriseHookGuardianRestoreRecord{}, sharing
	}
	var warning bytes.Buffer
	err = recordEnterpriseHookGuardianRestores(&warning, dataDir, rows, []enterpriseHookGuardianRestore{
		{SID: strings.ToLower(newSID), Connector: " CODEX ", RestoredAt: second.Format(time.RFC3339Nano)},
		{SID: earlierSID, Connector: "hermes", RestoredAt: second.Format(time.RFC3339Nano)},
	})
	if !errors.Is(err, sharing) || calls != 1+len(enterpriseHookGuardianRestoreReadBackoff) {
		t.Fatalf("recorder returned %v after %d reads; want the retried sharing error", err, calls)
	}
	if after, err := os.ReadFile(path); err != nil || !bytes.Equal(after, before) {
		t.Fatalf("unreadable record changed: %q (%v)", after, err)
	}
	enterpriseHookGuardianRestoreRecordReader = previous
	if err := recordEnterpriseHookGuardianRestores(&warning, dataDir, rows, nil); err != nil {
		t.Fatal(err)
	}
	restores := guardianRestoresForTest(t, dataDir)
	if len(restores) != 3 || !restores[enterpriseHookGuardianRestoreKey(earlierSID, "hermes")].Equal(second) ||
		!restores[enterpriseHookGuardianRestoreKey(newSID, "codex")].Equal(second) ||
		!restores[enterpriseHookGuardianRestoreKey(otherSID, "hermes")].Equal(first) {
		t.Fatalf("later readable record = %v, want all three restores including the newer re-restore", restores)
	}
	if got := warning.String(); !strings.Contains(got, path) || !strings.Contains(got, "left unchanged") ||
		!strings.Contains(got, "kept in memory") || !strings.Contains(got, "Windows status reports restart status unknown") ||
		strings.Count(got, "\n") != 1 {
		t.Fatalf("warning = %q, want one line naming the path, unchanged record, pending restores, and Windows status", got)
	}
	if count := guardianRestorePendingCountForTest(dataDir); count != 0 {
		t.Fatalf("pending entries after successful write = %d, want none", count)
	}
}

func TestEnterpriseHookGuardianRestoresDropsPendingTargetAfterItLeavesManifest(t *testing.T) {
	enableEnterpriseHookGuardianRestores(t, true)
	shortenGuardianRestoreBackoff(t)
	dataDir := t.TempDir()
	resetGuardianRestorePendingForTest(t, dataDir)
	const retainedSID, departedSID, survivorSID = "S-1-5-21-1-2-3-1001", "S-1-5-21-1-2-3-1002", "S-1-5-21-1-2-3-1003"
	first := time.Date(2026, 10, 13, 13, 24, 30, 0, time.UTC)
	second := first.Add(10 * time.Minute)
	rows := []enterpriseHookReconcileRow{
		{SID: retainedSID, Connector: "hermes", OK: true},
		{SID: departedSID, Connector: "codex", OK: true},
		{SID: survivorSID, Connector: "hermes", OK: true},
	}
	if err := recordEnterpriseHookGuardianRestores(io.Discard, dataDir, rows,
		[]enterpriseHookGuardianRestore{{SID: retainedSID, Connector: "hermes", RestoredAt: first.Format(time.RFC3339Nano)}}); err != nil {
		t.Fatal(err)
	}
	previous := enterpriseHookGuardianRestoreRecordReader
	t.Cleanup(func() { enterpriseHookGuardianRestoreRecordReader = previous })
	sharing := errors.New("sharing violation")
	enterpriseHookGuardianRestoreRecordReader = func(string) (enterpriseHookGuardianRestoreRecord, error) {
		return enterpriseHookGuardianRestoreRecord{}, sharing
	}
	if err := recordEnterpriseHookGuardianRestores(io.Discard, dataDir, rows, []enterpriseHookGuardianRestore{
		{SID: departedSID, Connector: "codex", RestoredAt: second.Format(time.RFC3339Nano)},
		{SID: survivorSID, Connector: "hermes", RestoredAt: second.Format(time.RFC3339Nano)},
	}); !errors.Is(err, sharing) {
		t.Fatalf("unreadable pass returned %v, want sharing error", err)
	}
	enterpriseHookGuardianRestoreRecordReader = previous
	if err := recordEnterpriseHookGuardianRestores(io.Discard, dataDir, []enterpriseHookReconcileRow{rows[0], rows[2]}, nil); err != nil {
		t.Fatal(err)
	}
	restores := guardianRestoresForTest(t, dataDir)
	if len(restores) != 2 || !restores[enterpriseHookGuardianRestoreKey(retainedSID, "hermes")].Equal(first) ||
		!restores[enterpriseHookGuardianRestoreKey(survivorSID, "hermes")].Equal(second) {
		t.Fatalf("later readable record = %v, want retained and surviving restores only", restores)
	}
	if count := guardianRestorePendingCountForTest(dataDir); count != 0 {
		t.Fatalf("pending entries after successful write = %d, want none", count)
	}
}

func TestEnterpriseHookGuardianRestoresRetriesPendingAfterWriteFailure(t *testing.T) {
	enableEnterpriseHookGuardianRestores(t, true)
	dataDir := filepath.Join(t.TempDir(), "record-dir")
	resetGuardianRestorePendingForTest(t, dataDir)
	if err := os.WriteFile(dataDir, []byte("regular file"), 0o600); err != nil {
		t.Fatal(err)
	}
	const sid = "S-1-5-21-1-2-3-1001"
	at := time.Date(2026, 10, 13, 13, 24, 30, 0, time.UTC)
	rows := []enterpriseHookReconcileRow{{SID: sid, Connector: "hermes", OK: true}}
	previous := enterpriseHookGuardianRestoreRecordReader
	t.Cleanup(func() { enterpriseHookGuardianRestoreRecordReader = previous })
	enterpriseHookGuardianRestoreRecordReader = func(string) (enterpriseHookGuardianRestoreRecord, error) {
		return enterpriseHookGuardianRestoreRecord{}, os.ErrNotExist
	}
	var warning bytes.Buffer
	if err := recordEnterpriseHookGuardianRestores(&warning, dataDir, rows,
		[]enterpriseHookGuardianRestore{{SID: sid, Connector: "hermes", RestoredAt: at.Format(time.RFC3339Nano)}}); err == nil {
		t.Fatal("write through a regular-file data directory succeeded")
	}
	if !strings.Contains(warning.String(), "could not record the restored targets") {
		t.Fatalf("write failure warning = %q", warning.String())
	}
	if err := os.Remove(dataDir); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(dataDir, 0o700); err != nil {
		t.Fatal(err)
	}
	enterpriseHookGuardianRestoreRecordReader = previous
	if err := recordEnterpriseHookGuardianRestores(io.Discard, dataDir, rows, nil); err != nil {
		t.Fatal(err)
	}
	restores := guardianRestoresForTest(t, dataDir)
	if len(restores) != 1 || !restores[enterpriseHookGuardianRestoreKey(sid, "hermes")].Equal(at) {
		t.Fatalf("later readable record = %v, want the restore from the failed write", restores)
	}
	if count := guardianRestorePendingCountForTest(dataDir); count != 0 {
		t.Fatalf("pending entries after successful write = %d, want none", count)
	}
}

func TestEnterpriseHookGuardianRestoresReplacesInvalidContentWithoutRetry(t *testing.T) {
	enableEnterpriseHookGuardianRestores(t, true)
	shortenGuardianRestoreBackoff(t)
	dataDir := t.TempDir()
	resetGuardianRestorePendingForTest(t, dataDir)
	path := filepath.Join(dataDir, hookGuardianRestoresFile)
	const sid = "S-1-5-21-1-2-3-1001"
	at := time.Date(2026, 10, 13, 13, 24, 30, 0, time.UTC)
	rows := []enterpriseHookReconcileRow{{SID: sid, Connector: "hermes", OK: true}}
	restored := []enterpriseHookGuardianRestore{{SID: sid, Connector: "hermes", RestoredAt: at.Format(time.RFC3339Nano)}}
	previous := enterpriseHookGuardianRestoreRecordReader
	t.Cleanup(func() { enterpriseHookGuardianRestoreRecordReader = previous })
	calls := 0
	enterpriseHookGuardianRestoreRecordReader = func(path string) (enterpriseHookGuardianRestoreRecord, error) {
		calls++
		return readEnterpriseHookGuardianRestoreRecord(path)
	}
	for name, body := range map[string]string{
		"json":     "not json",
		"version":  `{"version":2,"targets":[]}`,
		"oversize": strings.Repeat(" ", hookGuardianRestoresMaxBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
				t.Fatal(err)
			}
			calls = 0
			if restores, err := readEnterpriseHookGuardianRestores(dataDir); restores != nil || err == nil || calls != 1 {
				t.Fatalf("invalid content read = %v, %v after %d reads; want one read and an error", restores, err, calls)
			}
			calls = 0
			var warning bytes.Buffer
			if err := recordEnterpriseHookGuardianRestores(&warning, dataDir, rows, restored); err != nil {
				t.Fatalf("replace invalid content: %v", err)
			}
			if calls != 1 {
				t.Errorf("invalid content was read %d times, want once", calls)
			}
			if got := warning.String(); !strings.Contains(got, path) || !strings.Contains(got, "replaced") ||
				!strings.Contains(got, "could not be parsed") {
				t.Errorf("warning = %q, want the replaced invalid record named", got)
			}
			record := readGuardianRestoreRecordForTest(t, dataDir)
			if record.Version != 1 || len(record.Targets) != 1 || record.Targets[0].SID != sid {
				t.Errorf("replacement record = %+v, want the current restored target", record)
			}
		})
	}
}

func TestEnterpriseHookGuardianRestoresCreatesMissingRecordWithoutWarning(t *testing.T) {
	enableEnterpriseHookGuardianRestores(t, true)
	dataDir := t.TempDir()
	resetGuardianRestorePendingForTest(t, dataDir)
	const sid = "S-1-5-21-1-2-3-1001"
	var warning bytes.Buffer
	if err := recordEnterpriseHookGuardianRestores(&warning, dataDir,
		[]enterpriseHookReconcileRow{{SID: sid, Connector: "hermes", OK: true}},
		[]enterpriseHookGuardianRestore{{SID: sid, Connector: "hermes", RestoredAt: time.Now().UTC().Format(time.RFC3339Nano)}}); err != nil {
		t.Fatal(err)
	}
	if warning.Len() != 0 {
		t.Errorf("missing record warning = %q, want none", warning.String())
	}
	if record := readGuardianRestoreRecordForTest(t, dataDir); record.Version != 1 || len(record.Targets) != 1 {
		t.Errorf("created record = %+v, want one restored target", record)
	}
}

// Pass-6 review: the writer keeps the record within the 1 MiB both readers
// accept, dropping the oldest restores first; a record past it would be
// refused whole.
func TestEnterpriseHookGuardianRestoresWriterKeepsTheRecordWithinTheBound(t *testing.T) {
	enableEnterpriseHookGuardianRestores(t, true)
	dataDir := t.TempDir()
	resetGuardianRestorePendingForTest(t, dataDir)
	base := time.Date(2026, 10, 13, 0, 0, 0, 0, time.UTC)
	var rows []enterpriseHookReconcileRow
	var restored []enterpriseHookGuardianRestore
	const targets = 12000
	for i := 0; i < targets; i++ {
		sid := fmt.Sprintf("S-1-5-21-1111111111-2222222222-3333333333-%d", 100000+i)
		rows = append(rows, enterpriseHookReconcileRow{SID: sid, Connector: "hermes", OK: true})
		restored = append(restored, enterpriseHookGuardianRestore{SID: sid, Connector: "hermes", RestoredAt: base.Add(time.Duration(i) * time.Second).Format(time.RFC3339Nano)})
	}
	var log bytes.Buffer
	if err := recordEnterpriseHookGuardianRestores(&log, dataDir, rows, restored); err != nil {
		t.Fatal(err)
	}
	info, err := os.Stat(filepath.Join(dataDir, hookGuardianRestoresFile))
	if err != nil || info.Size() > hookGuardianRestoresMaxBytes {
		t.Fatalf("record size %v (%v), want at most %d bytes", info, err, hookGuardianRestoresMaxBytes)
	}
	restores := guardianRestoresForTest(t, dataDir)
	newest, oldest := restored[targets-1], restored[0]
	if len(restores) == 0 || len(restores) >= targets ||
		!restores[enterpriseHookGuardianRestoreKey(newest.SID, "hermes")].Equal(base.Add((targets-1)*time.Second)) {
		t.Fatalf("kept %d restores, want the newest within the bound", len(restores))
	}
	if _, kept := restores[enterpriseHookGuardianRestoreKey(oldest.SID, "hermes")]; kept {
		t.Fatalf("the oldest restore was kept over newer ones")
	}
	if !strings.Contains(log.String(), "dropped its") {
		t.Fatalf("log %q, want the dropped entries named", log.String())
	}
}
