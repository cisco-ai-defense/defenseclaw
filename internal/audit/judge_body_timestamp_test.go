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
	"database/sql"
	"fmt"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestJudgeTimestampMigrationsBackfillExactInstantsAndIndexedPlan(t *testing.T) {
	cutoff := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	var legacyTimestampMigration migration
	for _, candidate := range migrations {
		if candidate.description == "judge bodies: normalize timestamps for indexed retention" {
			legacyTimestampMigration = candidate
			break
		}
	}
	if legacyTimestampMigration.apply == nil {
		t.Fatal("legacy judge timestamp migration not found")
	}
	cases := []struct {
		name      string
		migration migration
		indexName string
	}{
		{
			name:      "legacy-audit",
			migration: legacyTimestampMigration,
			indexName: legacyJudgeTimestampUnixNanoIndex,
		},
		{
			name:      "authoritative",
			migration: judgeBodyMigrations[len(judgeBodyMigrations)-1],
			indexName: judgeBodyTimestampUnixNanoIndex,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "timestamps.db"))
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = db.Close() })
			if _, err := db.Exec(`CREATE TABLE judge_responses (
				id TEXT PRIMARY KEY,
				timestamp DATETIME NOT NULL
			)`); err != nil {
				t.Fatal(err)
			}
			encoded := map[string]string{
				"before": "2026-07-03T04:59:59.999999999-07:00",
				"equal":  "2026-07-03T17:30:00+05:30",
				"after":  "2026-07-03T12:00:00.000000001Z",
			}
			for id, timestamp := range encoded {
				if _, err := db.Exec(`INSERT INTO judge_responses(id, timestamp) VALUES (?, ?)`, id, timestamp); err != nil {
					t.Fatal(err)
				}
			}

			if err := tc.migration.apply(db); err != nil {
				t.Fatalf("apply appended timestamp migration: %v", err)
			}
			for id, timestamp := range encoded {
				parsed, err := time.Parse(time.RFC3339Nano, timestamp)
				if err != nil {
					t.Fatal(err)
				}
				var gotTimestamp string
				var gotUnixNano int64
				if err := db.QueryRow(`SELECT CAST(timestamp AS TEXT), timestamp_unix_nano
					FROM judge_responses WHERE id=?`, id).Scan(&gotTimestamp, &gotUnixNano); err != nil {
					t.Fatal(err)
				}
				if gotTimestamp != timestamp {
					t.Fatalf("%s original timestamp changed: got %q want %q", id, gotTimestamp, timestamp)
				}
				if gotUnixNano != parsed.UnixNano() {
					t.Fatalf("%s unix nanos=%d want %d", id, gotUnixNano, parsed.UnixNano())
				}
			}

			var indexSQL string
			if err := db.QueryRow(`SELECT sql FROM sqlite_master WHERE type='index' AND name=?`,
				tc.indexName).Scan(&indexSQL); err != nil {
				t.Fatalf("read timestamp index: %v", err)
			}
			if !strings.Contains(indexSQL, "timestamp_unix_nano, id") {
				t.Fatalf("timestamp index does not cover stable batch order: %s", indexSQL)
			}

			planRows, err := db.Query(`EXPLAIN QUERY PLAN
				SELECT id FROM judge_responses
				WHERE timestamp_unix_nano < ?
				ORDER BY timestamp_unix_nano ASC, id ASC
				LIMIT ?`, cutoff.UnixNano(), 2)
			if err != nil {
				t.Fatal(err)
			}
			var plan strings.Builder
			for planRows.Next() {
				var id, parent, notUsed int
				var detail string
				if err := planRows.Scan(&id, &parent, &notUsed, &detail); err != nil {
					_ = planRows.Close()
					t.Fatal(err)
				}
				plan.WriteString(detail)
			}
			if err := planRows.Close(); err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(plan.String(), tc.indexName) {
				t.Fatalf("retention query plan does not use %s: %s", tc.indexName, plan.String())
			}
		})
	}
}

func TestJudgeBodyInsertAndCutoverPathsPopulateUnixNano(t *testing.T) {
	legacy := newLegacyJudgeStore(t)
	base := time.Date(2026, 7, 3, 12, 0, 0, 123456789, time.UTC)
	west := time.FixedZone("west", -7*60*60)
	rows := []JudgeResponse{
		{ID: "legacy-single", Timestamp: base.In(west), Kind: "pii", Raw: "single"},
		{ID: "legacy-batch", Timestamp: base.Add(time.Nanosecond), Kind: "pii", Raw: "batch"},
	}
	if err := legacy.InsertJudgeResponse(rows[0]); err != nil {
		t.Fatal(err)
	}
	batch, err := legacy.BeginJudgeBatch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := batch.InsertJudgeResponse(rows[1]); err != nil {
		_ = batch.Rollback()
		t.Fatal(err)
	}
	if err := batch.Commit(); err != nil {
		t.Fatal(err)
	}

	target := newCutoverJudgeStore(t)
	if err := target.CutoverLegacyJudgeBodies(t.Context(), legacy); err != nil {
		t.Fatal(err)
	}
	if err := target.InsertJudgeResponse(JudgeResponse{
		ID: "target-single", Timestamp: base.Add(2 * time.Nanosecond), Kind: "pii", Raw: "target",
	}); err != nil {
		t.Fatal(err)
	}

	want := map[string]int64{
		"legacy-single": base.UnixNano(),
		"legacy-batch":  base.Add(time.Nanosecond).UnixNano(),
		"target-single": base.Add(2 * time.Nanosecond).UnixNano(),
	}
	for id, unixNano := range want {
		var got int64
		if err := target.db.QueryRow(`SELECT timestamp_unix_nano FROM judge_responses WHERE id=?`, id).Scan(&got); err != nil {
			t.Fatal(err)
		}
		if got != unixNano {
			t.Fatalf("target %s timestamp_unix_nano=%d want %d", id, got, unixNano)
		}
		if id != "target-single" {
			if err := legacy.db.QueryRow(`SELECT timestamp_unix_nano FROM judge_responses WHERE id=?`, id).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != unixNano {
				t.Fatalf("legacy %s timestamp_unix_nano=%d want %d", id, got, unixNano)
			}
		}
	}
}

func TestJudgeTimestampBackfillIsBoundedAndRetryable(t *testing.T) {
	db, err := sql.Open("sqlite", filepath.Join(t.TempDir(), "bounded.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = db.Close() })
	if _, err := db.Exec(`CREATE TABLE judge_responses (
		id TEXT PRIMARY KEY,
		timestamp DATETIME NOT NULL
	)`); err != nil {
		t.Fatal(err)
	}
	validTimestamp := "2026-07-03T12:00:00.123456789Z"
	for i := 0; i < judgeTimestampBackfillBatchSize; i++ {
		if _, err := db.Exec(`INSERT INTO judge_responses(id, timestamp) VALUES (?, ?)`,
			fmt.Sprintf("row-%04d", i), validTimestamp); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := db.Exec(`INSERT INTO judge_responses(id, timestamp) VALUES ('zz-invalid', 'not-a-timestamp')`); err != nil {
		t.Fatal(err)
	}

	if err := migrateJudgeBodyTimestampUnixNano(db, judgeBodyTimestampUnixNanoIndex); err == nil ||
		!strings.Contains(err.Error(), `row "zz-invalid"`) {
		t.Fatalf("first backfill error=%v want invalid row", err)
	}
	var populated int
	if err := db.QueryRow(`SELECT COUNT(*) FROM judge_responses
		WHERE timestamp_unix_nano IS NOT NULL`).Scan(&populated); err != nil {
		t.Fatal(err)
	}
	if populated != judgeTimestampBackfillBatchSize {
		t.Fatalf("rows committed before second-batch failure=%d want %d", populated, judgeTimestampBackfillBatchSize)
	}
	if _, err := db.Exec(`UPDATE judge_responses SET timestamp=? WHERE id='zz-invalid'`, validTimestamp); err != nil {
		t.Fatal(err)
	}
	if err := migrateJudgeBodyTimestampUnixNano(db, judgeBodyTimestampUnixNanoIndex); err != nil {
		t.Fatalf("idempotent retry: %v", err)
	}
	if err := verifyJudgeBodyTimestampUnixNanoReady(db); err != nil {
		t.Fatal(err)
	}
}

func TestJudgeTimestampStartupRepairsOlderBinaryNullInsert(t *testing.T) {
	encoded := "2026-07-03T17:30:00.123456789+05:30"
	want, err := time.Parse(time.RFC3339Nano, encoded)
	if err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name string
		open func(path string) (*sql.DB, func(), error)
	}{
		{
			name: "legacy-audit",
			open: func(path string) (*sql.DB, func(), error) {
				store, err := NewStore(path)
				if err != nil {
					return nil, nil, err
				}
				if err := store.Init(); err != nil {
					_ = store.Close()
					return nil, nil, err
				}
				return store.db, func() { _ = store.Close() }, nil
			},
		},
		{
			name: "authoritative",
			open: func(path string) (*sql.DB, func(), error) {
				store, err := NewJudgeBodyStore(path)
				if err != nil {
					return nil, nil, err
				}
				return store.db, func() { _ = store.Close() }, nil
			},
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "store.db")
			db, closeStore, err := tc.open(path)
			if err != nil {
				t.Fatal(err)
			}
			if _, err := db.Exec(`INSERT INTO judge_responses(id, timestamp, kind, raw_response)
				VALUES ('old-writer', ?, 'pii', 'body')`, encoded); err != nil {
				closeStore()
				t.Fatal(err)
			}
			if err := verifyJudgeBodyTimestampUnixNanoReady(db); err == nil {
				closeStore()
				t.Fatal("old-binary NULL timestamp was silently considered ready")
			}
			closeStore()

			db, closeStore, err = tc.open(path)
			if err != nil {
				t.Fatalf("reopen current store: %v", err)
			}
			defer closeStore()
			var got int64
			if err := db.QueryRow(`SELECT timestamp_unix_nano FROM judge_responses
				WHERE id='old-writer'`).Scan(&got); err != nil {
				t.Fatal(err)
			}
			if got != want.UnixNano() {
				t.Fatalf("startup repair nanos=%d want %d", got, want.UnixNano())
			}
		})
	}
}

func TestJudgeBodyListsOrderByNormalizedInstantAndStableID(t *testing.T) {
	legacy := newLegacyJudgeStore(t)
	target, err := NewJudgeBodyStore(filepath.Join(t.TempDir(), "judge_bodies.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Close() })

	base := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	east := time.FixedZone("IST", 5*60*60+30*60)
	west := time.FixedZone("PDT", -7*60*60)
	rows := []JudgeResponse{
		{ID: "old", Timestamp: base.Add(-time.Hour), Kind: "pii", Raw: "old", RequestID: "ordered"},
		{ID: "tie-a", Timestamp: base, Kind: "pii", Raw: "tie-a", RequestID: "ordered"},
		{ID: "tie-z", Timestamp: base.In(east), Kind: "pii", Raw: "tie-z", RequestID: "ordered"},
		{ID: "newest", Timestamp: base.Add(time.Hour).In(west), Kind: "pii", Raw: "new", RequestID: "ordered"},
	}
	for _, row := range rows {
		if err := legacy.InsertJudgeResponse(row); err != nil {
			t.Fatal(err)
		}
		if err := target.InsertJudgeResponse(row); err != nil {
			t.Fatal(err)
		}
	}
	// Exercise the pre-v8 Go time.String layout while retaining the numeric
	// instant. Readers must parse it through the shared compatibility parser.
	legacyLayout := rows[3].Timestamp.String()
	for _, db := range []*sql.DB{legacy.db, target.db} {
		if _, err := db.Exec(`UPDATE judge_responses SET timestamp=? WHERE id='newest'`, legacyLayout); err != nil {
			t.Fatal(err)
		}
	}
	want := []string{"newest", "tie-z"}
	legacyRows, err := legacy.ListJudgeResponses(2)
	if err != nil {
		t.Fatal(err)
	}
	targetRows, err := target.ListJudgeResponses(2)
	if err != nil {
		t.Fatal(err)
	}
	requestRows, err := legacy.GetJudgeResponsesByRequestID("ordered")
	if err != nil {
		t.Fatal(err)
	}
	if len(legacyRows) != 2 || len(targetRows) != 2 || len(requestRows) < 2 {
		t.Fatalf("unexpected list sizes legacy=%d target=%d request=%d",
			len(legacyRows), len(targetRows), len(requestRows))
	}
	for name, gotRows := range map[string][]JudgeResponse{
		"legacy-list":  legacyRows,
		"target-list":  targetRows,
		"request-list": requestRows[:2],
	} {
		got := []string{gotRows[0].ID, gotRows[1].ID}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("%s order=%v want %v", name, got, want)
		}
	}
}

func TestJudgeBodyCompatibilityListFetchesNewestLegacyAcrossOffsetAndLimit(t *testing.T) {
	legacy := newLegacyJudgeStore(t)
	base := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	east := time.FixedZone("east", 5*60*60+30*60)
	west := time.FixedZone("west", -7*60*60)
	for _, row := range []JudgeResponse{
		{ID: "legacy-old", Timestamp: base.Add(-30 * time.Minute), Kind: "pii", Raw: "old"},
		{ID: "duplicate-mid", Timestamp: base.In(east), Kind: "pii", Raw: "mid"},
		{ID: "legacy-new", Timestamp: base.Add(30 * time.Minute).In(west), Kind: "pii", Raw: "new"},
	} {
		if err := legacy.InsertJudgeResponse(row); err != nil {
			t.Fatal(err)
		}
	}
	target := newCutoverJudgeStore(t)
	if err := target.CutoverLegacyJudgeBodies(t.Context(), legacy); err != nil {
		t.Fatal(err)
	}
	if _, err := target.db.Exec(`DELETE FROM judge_responses WHERE id='legacy-new'`); err != nil {
		t.Fatal(err)
	}
	if err := target.InsertJudgeResponse(JudgeResponse{
		ID: "target-only", Timestamp: base.Add(time.Hour).In(west), Kind: "pii", Raw: "target",
	}); err != nil {
		t.Fatal(err)
	}

	rows, err := target.ListCompatibleJudgeResponsesCtx(t.Context(), legacy, 2)
	if err != nil {
		t.Fatal(err)
	}
	got := []string{rows[0].ID, rows[1].ID}
	want := []string{"target-only", "legacy-new"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("compatibility order=%v want %v", got, want)
	}
}

func TestJudgeBodyReadersFailClosedOnMalformedOrMismatchedTimestamp(t *testing.T) {
	legacy := newLegacyJudgeStore(t)
	target, err := NewJudgeBodyStore(filepath.Join(t.TempDir(), "judge_bodies.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = target.Close() })
	timestamp := time.Date(2026, 7, 3, 12, 0, 0, 123, time.UTC)
	row := JudgeResponse{
		ID: "corrupt", Timestamp: timestamp, Kind: "pii", Raw: "body", RequestID: "corrupt-request",
	}
	if err := legacy.InsertJudgeResponse(row); err != nil {
		t.Fatal(err)
	}
	if err := target.InsertJudgeResponse(row); err != nil {
		t.Fatal(err)
	}
	for name, fixture := range map[string]struct {
		db   *sql.DB
		list func() error
	}{
		"legacy": {
			db: legacy.db,
			list: func() error {
				_, err := legacy.ListJudgeResponses(10)
				return err
			},
		},
		"legacy-request": {
			db: legacy.db,
			list: func() error {
				_, err := legacy.GetJudgeResponsesByRequestID("corrupt-request")
				return err
			},
		},
		"authoritative": {
			db: target.db,
			list: func() error {
				_, err := target.ListJudgeResponses(10)
				return err
			},
		},
	} {
		t.Run(name, func(t *testing.T) {
			if _, err := fixture.db.Exec(`UPDATE judge_responses SET timestamp='invalid' WHERE id='corrupt'`); err != nil {
				t.Fatal(err)
			}
			if err := fixture.list(); err == nil || !strings.Contains(err.Error(), "parse timestamp") {
				t.Fatalf("malformed timestamp read error=%v", err)
			}
			if _, err := fixture.db.Exec(`UPDATE judge_responses
				SET timestamp=?, timestamp_unix_nano=? WHERE id='corrupt'`,
				timestamp.Format(time.RFC3339Nano), timestamp.UnixNano()+1); err != nil {
				t.Fatal(err)
			}
			if err := fixture.list(); err == nil || !strings.Contains(err.Error(), "timestamp index mismatch") {
				t.Fatalf("mismatched timestamp read error=%v", err)
			}
			if _, err := fixture.db.Exec(`UPDATE judge_responses
				SET timestamp_unix_nano=? WHERE id='corrupt'`, timestamp.UnixNano()); err != nil {
				t.Fatal(err)
			}
		})
	}
}
