// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func rejectedTestRow(at time.Time, marker string) RejectedRecordRow {
	return RejectedRecordRow{
		StoredAt: at, ObservedAt: at, Signal: "logs", Bucket: "security", EventName: "defenseclaw.hook.decision",
		Family: "compat_hook_decision", FamilySchemaVersion: 1, Source: "gateway", Connector: "claudecode",
		ReasonCode: "constraint_violation", Field: "defenseclaw.hook.result",
		ErrorText: "telemetry family build failed: constraint_violation; field defenseclaw.hook.result; " + marker,
		Payload:   json.RawMessage(`{"defenseclaw.hook.result":"success"}`),
	}
}

func TestRejectedRecordsTableIsMigratedAndRegisteredForRetention(t *testing.T) {
	store, _ := newRetentionStores(t)
	present, err := tableExists(store.db, "rejected_records")
	if err != nil || !present {
		t.Fatalf("rejected_records present=%v err=%v", present, err)
	}
	if retentionAuditMigrationCatalog["rejected_records"] != retentionOwnedHistory {
		t.Fatal("rejected_records is not declared as retention-owned history")
	}
	found := false
	for _, spec := range retentionAuditRegistry {
		found = found || (spec.class == RetentionRejectedRecords && spec.table == "rejected_records")
	}
	if !found {
		t.Fatal("rejected_records has no retention reaper")
	}
	if pending, err := PendingMigrations(store.DatabasePath()); err != nil || pending != 0 {
		t.Fatalf("pending migrations after Init = %d, %v", pending, err)
	}
}

func TestInsertRejectedRecordsKeepsTheNewestRowsUnderTheCap(t *testing.T) {
	store, _ := newRetentionStores(t)
	base := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	for batch := 0; batch < 10; batch++ {
		rows := make([]RejectedRecordRow, 0, RejectedRecordMaxBatch)
		for index := 0; index < 15; index++ {
			n := batch*15 + index
			rows = append(rows, rejectedTestRow(base.Add(time.Duration(n)*time.Second), fmt.Sprintf("row-%03d", n)))
		}
		if err := store.InsertRejectedRecords(t.Context(), rows, RejectedRecordsMinRows); err != nil {
			t.Fatal(err)
		}
	}
	count, err := store.CountRejectedRecords(t.Context())
	if err != nil || count != RejectedRecordsMinRows {
		t.Fatalf("rows=%d err=%v, want the cap %d", count, err, RejectedRecordsMinRows)
	}
	listed, err := store.ListRejectedRecords(t.Context(), RejectedRecordQuery{Limit: 1})
	if err != nil || len(listed) != 1 || !strings.HasSuffix(listed[0].ErrorText, "row-149") {
		t.Fatalf("newest=%+v err=%v", listed, err)
	}
	oldest, err := store.ListRejectedRecords(t.Context(), RejectedRecordQuery{Limit: RejectedRecordsMaxListLimit})
	if err != nil || len(oldest) != RejectedRecordsMinRows || !strings.HasSuffix(oldest[len(oldest)-1].ErrorText, "row-050") {
		t.Fatalf("kept %d rows, oldest %q", len(oldest), oldest[len(oldest)-1].ErrorText)
	}
}

func TestInsertRejectedRecordsRefusesOversizeBatchesAndBadCaps(t *testing.T) {
	store, _ := newRetentionStores(t)
	now := time.Now()
	rows := make([]RejectedRecordRow, RejectedRecordMaxBatch+1)
	for index := range rows {
		rows[index] = rejectedTestRow(now, "x")
	}
	if err := store.InsertRejectedRecords(t.Context(), rows, RejectedRecordsDefaultRows); err == nil {
		t.Fatal("a batch over RejectedRecordMaxBatch was accepted")
	}
	for _, cap := range []int{0, RejectedRecordsMinRows - 1, RejectedRecordsMaxRows + 1} {
		if err := store.InsertRejectedRecords(t.Context(), rows[:1], cap); err == nil {
			t.Fatalf("row cap %d was accepted", cap)
		}
	}
}

func TestInsertRejectedRecordsBoundsEachRow(t *testing.T) {
	store, _ := newRetentionStores(t)
	row := rejectedTestRow(time.Now(), "big")
	row.Payload = json.RawMessage(`{"defenseclaw.guardrail.reason":"` + strings.Repeat("a", RejectedRecordMaxPayloadBytes) + `"}`)
	row.ErrorText = strings.Repeat("é", 4096)
	row.OmittedFields = make([]string, 200)
	for index := range row.OmittedFields {
		row.OmittedFields[index] = fmt.Sprintf("field.%d", index)
	}
	if err := store.InsertRejectedRecords(t.Context(), []RejectedRecordRow{row}, RejectedRecordsDefaultRows); err != nil {
		t.Fatal(err)
	}
	listed, err := store.ListRejectedRecords(t.Context(), RejectedRecordQuery{Limit: 1})
	if err != nil || len(listed) != 1 {
		t.Fatalf("listed=%v err=%v", listed, err)
	}
	got := listed[0]
	if got.PayloadState != RejectedPayloadOmittedOversize || string(got.Payload) != "{}" {
		t.Fatalf("oversize payload kept: state=%s payload bytes=%d", got.PayloadState, len(got.Payload))
	}
	if len(got.ErrorText) > rejectedRecordTextBytes || !strings.HasPrefix(got.ErrorText, "é") {
		t.Fatalf("error text not bounded on a rune boundary: %d bytes", len(got.ErrorText))
	}
	if len(got.OmittedFields) != 64 {
		t.Fatalf("omitted fields=%d, want 64", len(got.OmittedFields))
	}
}

func TestListRejectedRecordsFiltersBySinceAndValidatesTheLimit(t *testing.T) {
	store, _ := newRetentionStores(t)
	base := time.Date(2026, 11, 12, 10, 0, 0, 0, time.UTC)
	rows := []RejectedRecordRow{
		rejectedTestRow(base, "old"), rejectedTestRow(base.Add(time.Hour), "new"),
	}
	if err := store.InsertRejectedRecords(t.Context(), rows, RejectedRecordsDefaultRows); err != nil {
		t.Fatal(err)
	}
	since := base.Add(30 * time.Minute)
	listed, err := store.ListRejectedRecords(t.Context(), RejectedRecordQuery{Since: &since, Limit: 10})
	if err != nil || len(listed) != 1 || !strings.HasSuffix(listed[0].ErrorText, "new") {
		t.Fatalf("since filter: %+v err=%v", listed, err)
	}
	if !listed[0].StoredAt.Equal(base.Add(time.Hour)) || listed[0].Field != "defenseclaw.hook.result" {
		t.Fatalf("row round trip: %+v", listed[0])
	}
	for _, limit := range []int{0, RejectedRecordsMaxListLimit + 1} {
		if _, err := store.ListRejectedRecords(t.Context(), RejectedRecordQuery{Limit: limit}); err == nil {
			t.Fatalf("limit %d accepted", limit)
		}
	}
}

func TestListRejectedRecordsOnAStoreWithoutTheTable(t *testing.T) {
	store, _ := newRetentionStores(t)
	if _, err := store.db.Exec(`DROP TABLE rejected_records`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.ListRejectedRecords(t.Context(), RejectedRecordQuery{Limit: 1}); !errors.Is(err, ErrRejectedRecordsUnavailable) {
		t.Fatalf("missing table error=%v", err)
	}
	if count, err := store.CountRejectedRecords(t.Context()); err != nil || count != 0 {
		t.Fatalf("count on a missing table = %d, %v", count, err)
	}
}

func TestReadOnlyStoreListsRejectedRecordsWithoutWriting(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	writer, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := writer.Init(); err != nil {
		t.Fatal(err)
	}
	if err := writer.InsertRejectedRecords(t.Context(), []RejectedRecordRow{rejectedTestRow(time.Now(), "ro")}, RejectedRecordsDefaultRows); err != nil {
		t.Fatal(err)
	}
	_ = writer.Close()
	reader, err := OpenReadOnlyStore(path)
	if err != nil {
		t.Fatal(err)
	}
	defer reader.Close() //nolint:errcheck
	listed, err := reader.ListRejectedRecords(t.Context(), RejectedRecordQuery{Limit: 5})
	if err != nil || len(listed) != 1 {
		t.Fatalf("read-only list=%v err=%v", listed, err)
	}
}

func TestRetentionDaysPruneRejectedRecordsWithTheOtherHistory(t *testing.T) {
	store, judge := newRetentionStores(t)
	now := time.Date(2026, 11, 12, 12, 0, 0, 0, time.UTC)
	old := now.Add(-48 * time.Hour)
	seedRejectedRecordRetentionBoundary(t, store, old.Add(-time.Second), old, now)
	reaper := newRetentionReaperAt(t, store, judge, 1, now, RetentionOptions{}, retentionHooks{})
	result, err := reaper.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if result.RowsDeleted[RetentionRejectedRecords] != 2 {
		t.Fatalf("rejected rows deleted=%d, want 2 (both older than one day)", result.RowsDeleted[RetentionRejectedRecords])
	}
	if count, _ := store.CountRejectedRecords(t.Context()); count != 1 {
		t.Fatalf("rows left=%d, want the newest", count)
	}
}

// seedRejectedRecordRetentionBoundary stores one row before, at and after
// the retention cutoff (TestRetentionReapsEveryHistoryClass...).
func seedRejectedRecordRetentionBoundary(t *testing.T, store *Store, before, equal, after time.Time) {
	t.Helper()
	rows := []RejectedRecordRow{
		rejectedTestRow(before, "rejected-before"),
		rejectedTestRow(equal, "rejected-equal"),
		rejectedTestRow(after, "rejected-after"),
	}
	if err := store.InsertRejectedRecords(t.Context(), rows, RejectedRecordsDefaultRows); err != nil {
		t.Fatal(err)
	}
}

func assertRejectedRecordRetentionBoundary(t *testing.T, store *Store) {
	t.Helper()
	count := func(marker string) int {
		var n int
		if err := store.db.QueryRow(`SELECT COUNT(*) FROM rejected_records WHERE error_text LIKE ?`,
			"%"+marker).Scan(&n); err != nil && !errors.Is(err, sql.ErrNoRows) {
			t.Fatal(err)
		}
		return n
	}
	if before, equal, after := count("rejected-before"), count("rejected-equal"), count("rejected-after"); before != 0 || equal != 1 || after != 1 {
		t.Errorf("rejected_records boundary before=%d equal=%d after=%d, want 0,1,1", before, equal, after)
	}
}
