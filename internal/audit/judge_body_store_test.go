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
	"context"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// TestJudgeBodyStore_RoundTrip exercises the full insert→list path
// against the standalone judge_bodies.db so we know the Phase 4
// extraction preserves every column we rely on downstream (kind,
// severity, action, raw body, request/trace/run IDs, v7 session +
// policy + tool columns). If a future refactor drops a column from
// either the schema or the INSERT statement, this test goes red.
func TestJudgeBodyStore_RoundTrip(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "judge_bodies.db")
	store, err := NewJudgeBodyStore(dbPath)
	if err != nil {
		t.Fatalf("NewJudgeBodyStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	row := JudgeResponse{
		Kind:              "llm-judge",
		Direction:         "outbound",
		Model:             "gpt-4o-mini",
		Action:            "warn",
		Severity:          "medium",
		LatencyMs:         42,
		Raw:               `{"verdict":"warn","reason":"contains api key"}`,
		RequestID:         "req-rt-1",
		TraceID:           "trace-rt-1",
		RunID:             "run-rt-1",
		SessionID:         "session-rt-1",
		InputHash:         "sha256:deadbeef",
		Confidence:        0.92,
		FailClosedApplied: true,
		InspectedModel:    "gpt-4o-mini",
		PromptTemplateID:  "tmpl-rt-1",
		SchemaVersion:     2,
		ContentHash:       "blake3:cafef00d",
		Generation:        7,
		BinaryVersion:     "v7.0.0",
		AgentID:           "agent-rt-1",
		AgentInstanceID:   "agent-instance-rt-1",
		SidecarInstanceID: "sidecar-instance-rt-1",
		PolicyID:          "policy-rt-1",
		DestinationApp:    "destination-app-rt-1",
		ToolName:          "Bash",
		ToolID:            "tool-rt-1",
	}
	if err := store.InsertJudgeResponse(row); err != nil {
		t.Fatalf("InsertJudgeResponse: %v", err)
	}

	rows, err := store.ListJudgeResponses(10)
	if err != nil {
		t.Fatalf("ListJudgeResponses: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("want 1 row, got %d", len(rows))
	}
	got := rows[0]

	// Spot-check the columns most likely to silently get dropped
	// by an INSERT/SELECT misalignment in a future refactor.
	cases := []struct {
		field string
		want  string
		got   string
	}{
		{"Kind", row.Kind, got.Kind},
		{"Direction", row.Direction, got.Direction},
		{"Model", row.Model, got.Model},
		{"Action", row.Action, got.Action},
		{"Severity", row.Severity, got.Severity},
		{"Raw", row.Raw, got.Raw},
		{"RequestID", row.RequestID, got.RequestID},
		{"TraceID", row.TraceID, got.TraceID},
		{"RunID", row.RunID, got.RunID},
		{"SessionID", row.SessionID, got.SessionID},
		{"InputHash", row.InputHash, got.InputHash},
		{"InspectedModel", row.InspectedModel, got.InspectedModel},
		{"PromptTemplateID", row.PromptTemplateID, got.PromptTemplateID},
		{"ContentHash", row.ContentHash, got.ContentHash},
		{"BinaryVersion", row.BinaryVersion, got.BinaryVersion},
		{"AgentID", row.AgentID, got.AgentID},
		{"AgentInstanceID", row.AgentInstanceID, got.AgentInstanceID},
		{"SidecarInstanceID", row.SidecarInstanceID, got.SidecarInstanceID},
		{"PolicyID", row.PolicyID, got.PolicyID},
		{"DestinationApp", row.DestinationApp, got.DestinationApp},
		{"ToolName", row.ToolName, got.ToolName},
		{"ToolID", row.ToolID, got.ToolID},
	}
	for _, c := range cases {
		if c.want != c.got {
			t.Errorf("column %s: want %q, got %q", c.field, c.want, c.got)
		}
	}
	if got.LatencyMs != row.LatencyMs {
		t.Errorf("LatencyMs: want %d, got %d", row.LatencyMs, got.LatencyMs)
	}
	if got.Confidence != row.Confidence {
		t.Errorf("Confidence: want %v, got %v", row.Confidence, got.Confidence)
	}
	if !got.FailClosedApplied {
		t.Errorf("FailClosedApplied: want true")
	}
	if got.Generation != row.Generation {
		t.Errorf("Generation: want %d, got %d", row.Generation, got.Generation)
	}
	if got.SchemaVersion != row.SchemaVersion {
		t.Errorf("SchemaVersion: want %d, got %d", row.SchemaVersion, got.SchemaVersion)
	}
}

// TestJudgeBodyStore_AppliesPragmasAndPoolCap asserts that the
// dedicated judge bodies DB inherits the same hardening as audit.db
// (WAL, busy_timeout=5000, synchronous=NORMAL, foreign_keys=ON,
// MaxOpenConns=1). We share the openSQLite helper, so a regression
// in that helper would silently widen the contention surface on both
// stores; this test is the cheapest tripwire for that.
func TestJudgeBodyStore_AppliesPragmasAndPoolCap(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "judge_bodies.db")
	store, err := NewJudgeBodyStore(dbPath)
	if err != nil {
		t.Fatalf("NewJudgeBodyStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	cases := []struct {
		pragma string
		want   int64
	}{
		{"busy_timeout", 5000},
		{"synchronous", 1},
		{"foreign_keys", 1},
	}
	for _, tc := range cases {
		var got int64
		if err := store.DB().QueryRow("PRAGMA " + tc.pragma).Scan(&got); err != nil {
			t.Fatalf("read pragma %s: %v", tc.pragma, err)
		}
		if got != tc.want {
			t.Fatalf("pragma %s: want %d, got %d", tc.pragma, tc.want, got)
		}
	}

	var jm string
	if err := store.DB().QueryRow("PRAGMA journal_mode").Scan(&jm); err != nil {
		t.Fatalf("read journal_mode: %v", err)
	}
	if !strings.EqualFold(jm, "wal") {
		t.Fatalf("journal_mode: want wal, got %q", jm)
	}

	// MaxOpenConns(1) is the single-most-important serialization
	// guarantee: it means Go's database/sql mutex (rather than
	// SQLite's write lock at the file level) is what queues writers,
	// which is far more cooperative under load.
	stats := store.DB().Stats()
	if stats.MaxOpenConnections != 1 {
		t.Fatalf("MaxOpenConnections: want 1, got %d", stats.MaxOpenConnections)
	}

	// Concurrent burst smoke: 25 writers should all land in the
	// dedicated DB without any returning SQLITE_BUSY.
	const writers = 25
	var wg sync.WaitGroup
	errs := make(chan error, writers)
	for i := 0; i < writers; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			err := store.InsertJudgeResponse(JudgeResponse{
				Timestamp: time.Now().UTC(),
				Kind:      "llm-judge",
				Raw:       `{"verdict":"allow"}`,
			})
			errs <- err
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent InsertJudgeResponse: %v", err)
		}
	}

	rows, err := store.ListJudgeResponses(writers + 5)
	if err != nil {
		t.Fatalf("ListJudgeResponses: %v", err)
	}
	if len(rows) != writers {
		t.Fatalf("want %d rows, got %d", writers, len(rows))
	}
}

// TestJudgeBodyStore_EmptyRawDropped mirrors audit.Store.InsertJudgeResponse:
// an empty Raw payload is a defensive no-op (nothing useful to retain),
// not an error. The async queue relies on this so that a buggy
// emit-site never adds an empty row.
func TestJudgeBodyStore_EmptyRawDropped(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "judge_bodies.db")
	store, err := NewJudgeBodyStore(dbPath)
	if err != nil {
		t.Fatalf("NewJudgeBodyStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	if err := store.InsertJudgeResponse(JudgeResponse{Kind: "llm-judge"}); err != nil {
		t.Fatalf("InsertJudgeResponse(empty raw): %v", err)
	}
	rows, err := store.ListJudgeResponses(10)
	if err != nil {
		t.Fatalf("ListJudgeResponses: %v", err)
	}
	if len(rows) != 0 {
		t.Fatalf("want 0 rows for empty raw, got %d", len(rows))
	}
}

// TestJudgeBodyStore_BatchCommitsAllRows verifies the BeginJudgeBatch
// path that the async gateway worker drives in production. A failure
// here would mean the worker's batched-transaction commit silently
// drops rows.
func TestJudgeBodyStore_BatchCommitsAllRows(t *testing.T) {
	dbPath := filepath.Join(t.TempDir(), "judge_bodies.db")
	store, err := NewJudgeBodyStore(dbPath)
	if err != nil {
		t.Fatalf("NewJudgeBodyStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	batch, err := store.BeginJudgeBatch(context.Background())
	if err != nil {
		t.Fatalf("BeginJudgeBatch: %v", err)
	}
	const n = 8
	for i := 0; i < n; i++ {
		if err := batch.InsertJudgeResponse(JudgeResponse{
			Kind: "llm-judge",
			Raw:  `{"verdict":"allow","i":` + intToString(i) + `}`,
		}); err != nil {
			t.Fatalf("batch insert %d: %v", i, err)
		}
	}
	if err := batch.Commit(); err != nil {
		t.Fatalf("Commit: %v", err)
	}
	rows, err := store.ListJudgeResponses(n + 5)
	if err != nil {
		t.Fatalf("ListJudgeResponses: %v", err)
	}
	if len(rows) != n {
		t.Fatalf("want %d rows after batch commit, got %d", n, len(rows))
	}
}

// intToString avoids pulling fmt into a tight test path so the
// import-graph for audit_test stays minimal. Two digits is plenty.
func intToString(i int) string {
	if i == 0 {
		return "0"
	}
	digits := ""
	for i > 0 {
		d := byte('0' + i%10)
		digits = string(d) + digits
		i /= 10
	}
	return digits
}
