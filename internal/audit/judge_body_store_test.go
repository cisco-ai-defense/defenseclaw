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
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
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

func TestJudgeBodyStore_BatchInsertHonorsTransactionCancellation(t *testing.T) {
	store, err := NewJudgeBodyStore(filepath.Join(t.TempDir(), "judge_bodies.db"))
	if err != nil {
		t.Fatalf("NewJudgeBodyStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	ctx, cancel := context.WithCancel(t.Context())
	batch, err := store.BeginJudgeBatch(ctx)
	if err != nil {
		t.Fatalf("BeginJudgeBatch: %v", err)
	}
	cancel()
	started := time.Now()
	if err := batch.InsertJudgeResponse(JudgeResponse{
		ID:   "cancelled-batch-row",
		Kind: "llm-judge",
		Raw:  `{}`,
	}); err == nil {
		t.Fatal("cancelled transaction accepted a batch insert")
	}
	if elapsed := time.Since(started); elapsed > time.Second {
		t.Fatalf("cancelled batch insert took %s", elapsed)
	}
	_ = batch.Rollback()

	var count int
	if err := store.DB().QueryRow(`SELECT COUNT(*) FROM judge_responses WHERE id=?`, "cancelled-batch-row").Scan(&count); err != nil {
		t.Fatal(err)
	}
	if count != 0 {
		t.Fatalf("cancelled batch persisted %d rows", count)
	}
}

// TestJudgeBodyStore_BatchConcurrentFinalizersReleaseRuntimeOnce pins the
// JudgeBatch lifecycle contract: concurrent Commit/Rollback retries are safe,
// and the runtime read lock held by a dedicated-store batch is released exactly
// once. A duplicate release panics in sync.RWMutex; a missed release prevents
// cutover from ever acquiring the writer lock.
func TestJudgeBodyStore_BatchConcurrentFinalizersReleaseRuntimeOnce(t *testing.T) {
	store, err := NewJudgeBodyStore(filepath.Join(t.TempDir(), "judge_bodies.db"))
	if err != nil {
		t.Fatalf("NewJudgeBodyStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	batch, err := store.BeginJudgeBatch(t.Context())
	if err != nil {
		t.Fatalf("BeginJudgeBatch: %v", err)
	}
	originalRelease := batch.release
	var releaseCalls atomic.Int32
	batch.release = func() {
		releaseCalls.Add(1)
		originalRelease()
	}

	const finalizers = 64
	start := make(chan struct{})
	errs := make(chan error, finalizers)
	var wg sync.WaitGroup
	for i := 0; i < finalizers; i++ {
		wg.Add(1)
		go func(commit bool) {
			defer wg.Done()
			<-start
			if commit {
				errs <- batch.Commit()
				return
			}
			errs <- batch.Rollback()
		}(i%2 == 0)
	}
	close(start)
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Errorf("concurrent finalizer: %v", err)
		}
	}
	if got := releaseCalls.Load(); got != 1 {
		t.Fatalf("runtime release calls = %d, want 1", got)
	}

	lockAcquired := make(chan struct{})
	go func() {
		store.cutoverMu.Lock()
		store.cutoverMu.Unlock()
		close(lockAcquired)
	}()
	select {
	case <-lockAcquired:
	case <-time.After(2 * time.Second):
		t.Fatal("cutover writer lock remained blocked after batch finalization")
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

// TestJudgeBodyStore_CreatesParentDirAndChmod pins the M6 fix:
// NewJudgeBodyStore is responsible for the full filesystem hygiene
// of the dedicated judge-bodies DB, including creating any missing
// parent directories with 0700 perms and tightening the SQLite file
// to 0600. Without this, the store either failed to open against a
// fresh data dir (production regression) OR left judge bodies
// world-readable on multi-user hosts (privacy regression).
//
// Skipped on Windows where Unix-style perm bits do not apply.
func TestJudgeBodyStore_CreatesParentDirAndChmod(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix permission bits not applicable on Windows")
	}
	base := t.TempDir()
	// Two missing levels of parent dir: forces MkdirAll to actually
	// do work. Mirrors the production case where ~/.defenseclaw/
	// already exists but a future subdir layout doesn't.
	dbPath := filepath.Join(base, "missing", "deeper", "judge_bodies.db")

	store, err := NewJudgeBodyStore(dbPath)
	if err != nil {
		t.Fatalf("NewJudgeBodyStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	parentInfo, err := os.Stat(filepath.Dir(dbPath))
	if err != nil {
		t.Fatalf("stat parent dir: %v", err)
	}
	if mode := parentInfo.Mode().Perm(); mode != 0o700 {
		t.Fatalf("parent dir mode = %o, want 0700 (regression: judge bodies dir would be world-readable)", mode)
	}

	fileInfo, err := os.Stat(dbPath)
	if err != nil {
		t.Fatalf("stat db file: %v", err)
	}
	if mode := fileInfo.Mode().Perm(); mode != 0o600 {
		t.Fatalf("db file mode = %o, want 0600 (regression: judge bodies file would be world-readable)", mode)
	}
}

// TestJudgeBodyStore_RejectsEmptyPath ensures NewJudgeBodyStore
// returns a deterministic error for the misconfiguration case
// instead of silently writing to "./judge_bodies.db" (which the
// old code path would have done after we added MkdirAll on an
// empty Dir()).
func TestJudgeBodyStore_RejectsEmptyPath(t *testing.T) {
	if _, err := NewJudgeBodyStore(""); err == nil {
		t.Fatal("NewJudgeBodyStore(\"\") = nil, expected error")
	}
	if _, err := NewJudgeBodyStore("   "); err == nil {
		t.Fatal("NewJudgeBodyStore(\"   \") = nil, expected error (whitespace)")
	}
}

// TestJudgeBodyStore_OpenErrorTier covers the L11 fix: the open-time
// error tier ("judge_body:") must NOT bleed through the shared
// openSQLite helper's "audit:" prefix. Operators triage by tier
// label; a wrong tier sends them to the wrong runbook.
func TestJudgeBodyStore_OpenErrorTier(t *testing.T) {
	// Create the parent dir as a file rather than a directory so
	// MkdirAll fails inside NewJudgeBodyStore. This exercises the
	// pre-open failure path; we don't need openSQLite to fail to
	// validate the error tier.
	parent := filepath.Join(t.TempDir(), "block")
	if err := os.WriteFile(parent, []byte("not a dir"), 0o600); err != nil {
		t.Fatalf("seed block file: %v", err)
	}
	dbPath := filepath.Join(parent, "judge_bodies.db")
	_, err := NewJudgeBodyStore(dbPath)
	if err == nil {
		t.Fatal("expected error opening into a file path, got nil")
	}
	if !strings.HasPrefix(err.Error(), "judge_body:") {
		t.Fatalf("error tier = %q, want prefix \"judge_body:\" (regression: L11)", err.Error())
	}
	if strings.Contains(err.Error(), "audit:") {
		t.Fatalf("error message leaks audit tier: %q (regression: L11)", err.Error())
	}
}

// TestJudgeBodyStore_InsertJudgeResponseCtx covers the L10 fix:
// the context-aware single-row variant must thread cancellation
// through to the underlying retryBusy loop. A pre-cancelled
// context returns the cancellation error promptly instead of
// proceeding to write.
func TestJudgeBodyStore_InsertJudgeResponseCtx(t *testing.T) {
	store, err := NewJudgeBodyStore(filepath.Join(t.TempDir(), "judge_bodies.db"))
	if err != nil {
		t.Fatalf("NewJudgeBodyStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })

	row := JudgeResponse{
		Kind: "llm-judge",
		Raw:  `{"verdict":"allow"}`,
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := store.InsertJudgeResponseCtx(ctx, row); err == nil {
		t.Fatal("InsertJudgeResponseCtx(cancelled) = nil, want error (regression: L10)")
	}

	// Sanity: the original (non-ctx) entry-point still works against
	// the same store after a cancellation attempt — we did not corrupt
	// state.
	if err := store.InsertJudgeResponse(row); err != nil {
		t.Fatalf("InsertJudgeResponse (post-cancel sanity): %v", err)
	}
}
