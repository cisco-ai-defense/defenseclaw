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
	"errors"
	"fmt"
	"path/filepath"
	"slices"
	"sort"
	"strings"
	"testing"
	"time"
)

func newLegacyJudgeStore(t *testing.T) *Store {
	t.Helper()
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}
	return store
}

func newCutoverJudgeStore(t *testing.T) *JudgeBodyStore {
	t.Helper()
	store, err := NewJudgeBodyStoreForCutover(filepath.Join(t.TempDir(), "judge_bodies.db"))
	if err != nil {
		t.Fatalf("NewJudgeBodyStoreForCutover: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	return store
}

func TestJudgeBodyCutover_BatchedIdempotentAndWriteGated(t *testing.T) {
	legacy := newLegacyJudgeStore(t)
	base := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	want := []JudgeResponse{
		{
			ID: "body-03", Timestamp: base.Add(3 * time.Minute), Kind: "injection",
			Raw: "exact body bytes \x00 with unicode: π", RequestID: "req-03",
			TraceID: "trace-03", RunID: "run-03", SessionID: "session-03",
			AgentID: "agent-03", PolicyID: "policy-03", ToolID: "tool-03",
		},
		{ID: "body-01", Timestamp: base.Add(time.Minute), Kind: "pii", Raw: "first", RequestID: "req-01"},
		{ID: "body-02", Timestamp: base.Add(2 * time.Minute), Kind: "secrets", Raw: "second", RequestID: "req-02"},
	}
	for _, row := range want {
		if err := legacy.InsertJudgeResponse(row); err != nil {
			t.Fatalf("seed legacy %s: %v", row.ID, err)
		}
	}

	authoritative := newCutoverJudgeStore(t)
	if authoritative.CutoverReady() {
		t.Fatal("cutover-gated store unexpectedly ready before migration")
	}
	if err := authoritative.InsertJudgeResponse(JudgeResponse{Raw: "must fail"}); err == nil {
		t.Fatal("write before cutover = nil, want fail-closed error")
	}
	if _, err := authoritative.ListJudgeResponses(10); err == nil {
		t.Fatal("read before cutover = nil, want fail-closed error")
	}

	// A two-row batch forces multiple commit+verify+mark cycles while source
	// IDs were intentionally inserted out of order.
	if err := authoritative.cutoverLegacyJudgeBodies(t.Context(), legacy, 2); err != nil {
		t.Fatalf("cutoverLegacyJudgeBodies: %v", err)
	}
	if !authoritative.CutoverReady() {
		t.Fatal("store not ready after successful cutover")
	}

	rows, err := authoritative.ListJudgeResponses(10)
	if err != nil {
		t.Fatalf("ListJudgeResponses: %v", err)
	}
	if len(rows) != len(want) {
		t.Fatalf("authoritative rows=%d want %d", len(rows), len(want))
	}
	byID := make(map[string]JudgeResponse, len(rows))
	for _, row := range rows {
		byID[row.ID] = row
	}
	for _, expected := range want {
		got := byID[expected.ID]
		if got.Raw != expected.Raw || got.RequestID != expected.RequestID ||
			got.TraceID != expected.TraceID || got.RunID != expected.RunID ||
			got.SessionID != expected.SessionID || got.PolicyID != expected.PolicyID ||
			got.ToolID != expected.ToolID {
			t.Errorf("migrated row %s lost body/correlation: got %+v", expected.ID, got)
		}
	}

	var verifiedRows int
	if err := authoritative.DB().QueryRow(`SELECT COUNT(*) FROM legacy_judge_cutover_rows`).Scan(&verifiedRows); err != nil {
		t.Fatalf("count verification markers: %v", err)
	}
	if verifiedRows != len(want) {
		t.Fatalf("verified markers=%d want %d", verifiedRows, len(want))
	}
	var completedRows int
	if err := authoritative.DB().QueryRow(`SELECT verified_rows FROM legacy_judge_cutover_state`).Scan(&completedRows); err != nil {
		t.Fatalf("read cutover completion: %v", err)
	}
	if completedRows != len(want) {
		t.Fatalf("completed verified_rows=%d want %d", completedRows, len(want))
	}

	// The source is permanently write-protected at cutover. There is no
	// post-cutover fallback path that can put a new raw body in audit.db.
	if err := legacy.InsertJudgeResponse(JudgeResponse{ID: "late", Kind: "pii", Raw: "late body"}); err == nil ||
		!strings.Contains(err.Error(), "read-only after v8 cutover") {
		t.Fatalf("legacy write after cutover error=%v, want read-only guard", err)
	}

	// Retry scans the same source rows, insert-ignores matching stable IDs,
	// re-verifies exact values, and does not duplicate either bodies or markers.
	if err := authoritative.cutoverLegacyJudgeBodies(t.Context(), legacy, 1); err != nil {
		t.Fatalf("idempotent cutover retry: %v", err)
	}
	if err := authoritative.DB().QueryRow(`SELECT COUNT(*) FROM judge_responses`).Scan(&verifiedRows); err != nil {
		t.Fatalf("count authoritative retry rows: %v", err)
	}
	if verifiedRows != len(want) {
		t.Fatalf("rows after retry=%d want %d", verifiedRows, len(want))
	}
	var replayedPhases int
	if err := authoritative.cutoverLegacyJudgeBodiesWithHooks(
		t.Context(), legacy, 1, judgeBodyCutoverHooks{afterPhase: func(judgeBodyCutoverPhase) error {
			replayedPhases++
			return nil
		}},
	); err != nil {
		t.Fatalf("completed cutover fast path: %v", err)
	}
	if replayedPhases != 0 {
		t.Fatalf("completed cutover replayed %d copy/commit phases", replayedPhases)
	}
}

func TestJudgeBodyCutover_ConflictFailsClosedBeforeMarkOrWriterSwitch(t *testing.T) {
	legacy := newLegacyJudgeStore(t)
	legacyRow := JudgeResponse{
		ID: "same-id", Timestamp: time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC),
		Kind: "pii", Raw: "legacy body", RequestID: "legacy-request",
	}
	if err := legacy.InsertJudgeResponse(legacyRow); err != nil {
		t.Fatalf("seed legacy: %v", err)
	}

	targetPath := filepath.Join(t.TempDir(), "judge_bodies.db")
	seedTarget, err := NewJudgeBodyStore(targetPath)
	if err != nil {
		t.Fatalf("NewJudgeBodyStore(seed): %v", err)
	}
	conflict := legacyRow
	conflict.Raw = "different authoritative body"
	if err := seedTarget.InsertJudgeResponse(conflict); err != nil {
		t.Fatalf("seed conflicting target: %v", err)
	}
	if err := seedTarget.Close(); err != nil {
		t.Fatalf("close seed target: %v", err)
	}

	authoritative, err := NewJudgeBodyStoreForCutover(targetPath)
	if err != nil {
		t.Fatalf("NewJudgeBodyStoreForCutover: %v", err)
	}
	t.Cleanup(func() { _ = authoritative.Close() })
	if err := authoritative.CutoverLegacyJudgeBodies(t.Context(), legacy); err == nil ||
		!strings.Contains(err.Error(), "conflicts with legacy source") {
		t.Fatalf("conflicting cutover error=%v, want verification conflict", err)
	}
	if authoritative.CutoverReady() {
		t.Fatal("failed cutover enabled runtime writer")
	}
	if err := authoritative.InsertJudgeResponse(JudgeResponse{Raw: "must fail"}); err == nil {
		t.Fatal("failed cutover accepted a runtime write")
	}
	var markers int
	if err := authoritative.DB().QueryRow(`SELECT COUNT(*) FROM legacy_judge_cutover_rows`).Scan(&markers); err != nil {
		t.Fatalf("count markers: %v", err)
	}
	if markers != 0 {
		t.Fatalf("conflicting committed row was marked verified: markers=%d", markers)
	}

	// The source transaction rolled back, including its read-only trigger, so
	// the pre-upgrade writer may remain active before a successful cutover.
	if err := legacy.InsertJudgeResponse(JudgeResponse{ID: "pre-cutover-still-active", Kind: "pii", Raw: "body"}); err != nil {
		t.Fatalf("legacy writer disabled by failed cutover: %v", err)
	}
}

func TestJudgeBodyCompatibilityRead_AuthoritativeFirstAndDeduplicated(t *testing.T) {
	legacy := newLegacyJudgeStore(t)
	base := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	for _, row := range []JudgeResponse{
		{ID: "duplicate", Timestamp: base.Add(time.Minute), Kind: "pii", Raw: "migrated"},
		{ID: "legacy-only", Timestamp: base.Add(2 * time.Minute), Kind: "pii", Raw: "legacy fallback"},
	} {
		if err := legacy.InsertJudgeResponse(row); err != nil {
			t.Fatalf("seed legacy %s: %v", row.ID, err)
		}
	}
	authoritative := newCutoverJudgeStore(t)
	if err := authoritative.CutoverLegacyJudgeBodies(t.Context(), legacy); err != nil {
		t.Fatalf("cutover: %v", err)
	}
	if _, err := authoritative.DB().Exec(`UPDATE judge_responses SET raw_response=? WHERE id=?`, "authoritative wins", "duplicate"); err != nil {
		t.Fatalf("update authoritative duplicate: %v", err)
	}
	if _, err := authoritative.DB().Exec(`DELETE FROM judge_responses WHERE id=?`, "legacy-only"); err != nil {
		t.Fatalf("make compatibility-only row: %v", err)
	}
	if err := authoritative.InsertJudgeResponse(JudgeResponse{
		ID: "authoritative-only", Timestamp: base.Add(3 * time.Minute), Kind: "pii", Raw: "new v8 body",
	}); err != nil {
		t.Fatalf("seed authoritative-only: %v", err)
	}

	rows, err := authoritative.ListCompatibleJudgeResponsesCtx(t.Context(), legacy, 10)
	if err != nil {
		t.Fatalf("ListCompatibleJudgeResponsesCtx: %v", err)
	}
	if len(rows) != 3 {
		t.Fatalf("compatibility rows=%d want 3: %+v", len(rows), rows)
	}
	counts := map[string]int{}
	byID := map[string]JudgeResponse{}
	for _, row := range rows {
		counts[row.ID]++
		byID[row.ID] = row
	}
	if counts["duplicate"] != 1 || counts["legacy-only"] != 1 || counts["authoritative-only"] != 1 {
		t.Fatalf("compatibility dedup counts=%v", counts)
	}
	if got := byID["duplicate"].Raw; got != "authoritative wins" {
		t.Fatalf("duplicate raw=%q want authoritative value", got)
	}
	if got := byID["legacy-only"].Raw; got != "legacy fallback" {
		t.Fatalf("legacy-only raw=%q", got)
	}
	if rows[0].ID != "authoritative-only" {
		t.Fatalf("newest row=%q want authoritative-only", rows[0].ID)
	}
}

func TestJudgeBodyPurge_LegacyFirstFailureResumesWithoutReappearance(t *testing.T) {
	legacy := newLegacyJudgeStore(t)
	base := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	for _, row := range []JudgeResponse{
		{ID: "old", Timestamp: base, Kind: "pii", Raw: "old body"},
		{ID: "new", Timestamp: base.Add(2 * time.Hour), Kind: "pii", Raw: "new body"},
	} {
		if err := legacy.InsertJudgeResponse(row); err != nil {
			t.Fatalf("seed %s: %v", row.ID, err)
		}
	}
	authoritative := newCutoverJudgeStore(t)
	if err := authoritative.CutoverLegacyJudgeBodies(t.Context(), legacy); err != nil {
		t.Fatalf("cutover: %v", err)
	}

	injected := errors.New("injected after legacy commit")
	legacyDeleted, targetDeleted, err := authoritative.purgeJudgeResponsesBeforeCtx(
		t.Context(), legacy, base.Add(time.Hour), 1000,
		func() error { return injected },
	)
	if !errors.Is(err, injected) {
		t.Fatalf("purge error=%v want injected", err)
	}
	if legacyDeleted != 1 || targetDeleted != 0 {
		t.Fatalf("first purge deleted legacy=%d target=%d want 1,0", legacyDeleted, targetDeleted)
	}
	rows, err := authoritative.ListCompatibleJudgeResponsesCtx(t.Context(), legacy, 10)
	if err != nil {
		t.Fatalf("compatibility read after failure: %v", err)
	}
	counts := map[string]int{}
	for _, row := range rows {
		counts[row.ID]++
	}
	if counts["old"] != 1 || counts["new"] != 1 {
		t.Fatalf("failed purge reappeared/duplicated rows: %v", counts)
	}

	legacyDeleted, targetDeleted, err = authoritative.PurgeJudgeResponsesBeforeCtx(
		t.Context(), legacy, base.Add(time.Hour), 1000,
	)
	if err != nil {
		t.Fatalf("resumed purge: %v", err)
	}
	if legacyDeleted != 0 || targetDeleted != 1 {
		t.Fatalf("resumed purge deleted legacy=%d target=%d want 0,1", legacyDeleted, targetDeleted)
	}
	rows, err = authoritative.ListCompatibleJudgeResponsesCtx(t.Context(), legacy, 10)
	if err != nil {
		t.Fatalf("compatibility read after resumed purge: %v", err)
	}
	if len(rows) != 1 || rows[0].ID != "new" {
		t.Fatalf("rows after resumed purge=%+v want new only", rows)
	}
}

func TestJudgeBodyPurge_UsesExactInstantsAcrossOffsetsAndFractions(t *testing.T) {
	legacy := newLegacyJudgeStore(t)
	cutoff := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	east := time.FixedZone("east", 5*60*60+30*60)
	west := time.FixedZone("west", -7*60*60)
	rows := []JudgeResponse{
		{ID: "one-second-before", Timestamp: cutoff.Add(-time.Second), Kind: "pii", Raw: "a"},
		{ID: "one-ns-before", Timestamp: cutoff.Add(-time.Nanosecond), Kind: "pii", Raw: "b"},
		{ID: "offset-one-ns-before", Timestamp: cutoff.Add(-time.Nanosecond).In(west), Kind: "pii", Raw: "c"},
		{ID: "exact-cutoff", Timestamp: cutoff, Kind: "pii", Raw: "d"},
		{ID: "offset-equivalent-cutoff", Timestamp: cutoff.In(east), Kind: "pii", Raw: "e"},
		{ID: "one-ns-after", Timestamp: cutoff.Add(time.Nanosecond), Kind: "pii", Raw: "f"},
		{ID: "fractional-after", Timestamp: cutoff.Add(100 * time.Millisecond), Kind: "pii", Raw: "g"},
	}
	for _, row := range rows {
		if err := legacy.InsertJudgeResponse(row); err != nil {
			t.Fatalf("seed %s: %v", row.ID, err)
		}
	}
	authoritative := newCutoverJudgeStore(t)
	if err := authoritative.CutoverLegacyJudgeBodies(t.Context(), legacy); err != nil {
		t.Fatalf("cutover: %v", err)
	}
	legacyDeleted, targetDeleted, err := authoritative.PurgeJudgeResponsesBeforeCtx(
		t.Context(), legacy, cutoff, 2,
	)
	if err != nil {
		t.Fatal(err)
	}
	if legacyDeleted != 3 || targetDeleted != 3 {
		t.Fatalf("deleted legacy=%d target=%d want 3,3", legacyDeleted, targetDeleted)
	}
	want := []string{"exact-cutoff", "fractional-after", "offset-equivalent-cutoff", "one-ns-after"}
	for name, db := range map[string]judgeBodyQueryer{
		"legacy": legacy.db, "authoritative": authoritative.db,
	} {
		got := judgeBodyIDs(t, db)
		if !slices.Equal(got, want) {
			t.Fatalf("%s remaining IDs=%v want %v", name, got, want)
		}
	}
}

func TestJudgeBodyCutover_OrdinaryStoreIsGatedForWholeTransition(t *testing.T) {
	dir := t.TempDir()
	legacy := openLegacyJudgeStoreAt(t, filepath.Join(dir, "audit.db"))
	defer legacy.Close()
	if err := legacy.InsertJudgeResponse(JudgeResponse{
		ID: "legacy", Timestamp: time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC), Kind: "pii", Raw: "body",
	}); err != nil {
		t.Fatal(err)
	}
	target, err := NewJudgeBodyStore(filepath.Join(dir, "judge_bodies.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer target.Close()
	if !target.CutoverReady() {
		t.Fatal("ordinary store fixture should begin ready")
	}

	entered := make(chan struct{})
	releaseFault := make(chan struct{})
	fault := errors.New("injected target-commit crash")
	cutoverDone := make(chan error, 1)
	go func() {
		cutoverDone <- target.cutoverLegacyJudgeBodiesWithHooks(
			t.Context(), legacy, 1, judgeBodyCutoverHooks{afterPhase: func(phase judgeBodyCutoverPhase) error {
				if phase == judgeBodyPhaseTargetCommitted {
					close(entered)
					<-releaseFault
					return fault
				}
				return nil
			}},
		)
	}()
	<-entered
	if target.CutoverReady() {
		t.Fatal("ordinary store remained ready during cutover")
	}
	writeDone := make(chan error, 1)
	go func() {
		writeDone <- target.InsertJudgeResponse(JudgeResponse{ID: "racing", Kind: "pii", Raw: "must not land"})
	}()
	readDone := make(chan error, 1)
	go func() {
		_, err := target.ListJudgeResponses(10)
		readDone <- err
	}()
	select {
	case err := <-writeDone:
		t.Fatalf("runtime write completed during cutover: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	select {
	case err := <-readDone:
		t.Fatalf("runtime read completed during cutover: %v", err)
	case <-time.After(50 * time.Millisecond):
	}
	close(releaseFault)
	if err := <-cutoverDone; !errors.Is(err, fault) {
		t.Fatalf("cutover error=%v want injected fault", err)
	}
	if err := <-writeDone; err == nil || !strings.Contains(err.Error(), "cutover is incomplete") {
		t.Fatalf("blocked runtime write error=%v", err)
	}
	if err := <-readDone; err == nil || !strings.Contains(err.Error(), "cutover is incomplete") {
		t.Fatalf("blocked runtime read error=%v", err)
	}
	if target.CutoverReady() {
		t.Fatal("failed cutover restored ordinary-store readiness")
	}
	var racing int
	if err := target.db.QueryRow(`SELECT COUNT(*) FROM judge_responses WHERE id='racing'`).Scan(&racing); err != nil || racing != 0 {
		t.Fatalf("racing rows=%d err=%v", racing, err)
	}
}

func TestJudgeBodyCutover_CrashPhasesResumeAfterReopen(t *testing.T) {
	tests := []struct {
		phase            judgeBodyCutoverPhase
		wantMarkers      int
		wantCompletion   int
		wantSourceGuards int
	}{
		{phase: judgeBodyPhaseTargetCommitted},
		{phase: judgeBodyPhaseMarkersCommitted, wantMarkers: 1},
		{phase: judgeBodyPhaseCompletionCommitted, wantMarkers: 1, wantCompletion: 1},
		{phase: judgeBodyPhaseSourceCommitted, wantMarkers: 1, wantCompletion: 1, wantSourceGuards: 2},
	}
	for _, test := range tests {
		t.Run(string(test.phase), func(t *testing.T) {
			dir := t.TempDir()
			legacyPath := filepath.Join(dir, "audit.db")
			targetPath := filepath.Join(dir, "judge_bodies.db")
			legacy := openLegacyJudgeStoreAt(t, legacyPath)
			if err := legacy.InsertJudgeResponse(JudgeResponse{
				ID: "stable", Timestamp: time.Date(2026, 7, 3, 12, 0, 0, 123, time.UTC),
				Kind: "pii", Raw: "exact body", RequestID: "request",
			}); err != nil {
				t.Fatal(err)
			}
			target, err := NewJudgeBodyStore(targetPath)
			if err != nil {
				t.Fatal(err)
			}
			fault := fmt.Errorf("injected crash after %s", test.phase)
			err = target.cutoverLegacyJudgeBodiesWithHooks(
				t.Context(), legacy, 1, judgeBodyCutoverHooks{afterPhase: func(phase judgeBodyCutoverPhase) error {
					if phase == test.phase {
						return fault
					}
					return nil
				}},
			)
			if !errors.Is(err, fault) {
				t.Fatalf("cutover error=%v want %v", err, fault)
			}
			if target.CutoverReady() {
				t.Fatal("faulted cutover enabled runtime access")
			}
			if got := countRows(t, target.db, `SELECT COUNT(*) FROM legacy_judge_cutover_rows`); got != test.wantMarkers {
				t.Fatalf("verification markers=%d want %d", got, test.wantMarkers)
			}
			if got := countRows(t, target.db, `SELECT COUNT(*) FROM legacy_judge_cutover_state`); got != test.wantCompletion {
				t.Fatalf("completion rows=%d want %d", got, test.wantCompletion)
			}
			if got := legacyJudgeGuardCount(t, legacy); got != test.wantSourceGuards {
				t.Fatalf("source guards=%d want %d", got, test.wantSourceGuards)
			}
			if err := target.Close(); err != nil {
				t.Fatal(err)
			}
			if err := legacy.Close(); err != nil {
				t.Fatal(err)
			}

			legacy = openLegacyJudgeStoreAt(t, legacyPath)
			target, err = NewJudgeBodyStoreForCutover(targetPath)
			if err != nil {
				t.Fatal(err)
			}
			if err := target.CutoverLegacyJudgeBodies(t.Context(), legacy); err != nil {
				t.Fatalf("resume cutover: %v", err)
			}
			if !target.CutoverReady() {
				t.Fatal("resumed store is not ready")
			}
			if got := countRows(t, target.db, `SELECT COUNT(*) FROM judge_responses WHERE id='stable'`); got != 1 {
				t.Fatalf("authoritative stable rows=%d", got)
			}
			assertPermanentLegacyJudgeGuards(t, legacy)
			_ = target.Close()
			_ = legacy.Close()
		})
	}
}

func TestJudgeBodyCutover_ReplacesForgedNamedTriggers(t *testing.T) {
	legacy := newLegacyJudgeStore(t)
	if err := legacy.InsertJudgeResponse(JudgeResponse{
		ID: "stable", Timestamp: time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC), Kind: "pii", Raw: "body",
	}); err != nil {
		t.Fatal(err)
	}
	for name, operation := range map[string]string{
		legacyJudgeNoInsertTriggerName: "INSERT",
		legacyJudgeNoUpdateTriggerName: "UPDATE",
	} {
		if _, err := legacy.db.Exec(fmt.Sprintf(`CREATE TRIGGER %s BEFORE %s ON judge_responses BEGIN SELECT 1; END`, name, operation)); err != nil {
			t.Fatal(err)
		}
	}
	target := newCutoverJudgeStore(t)
	if err := target.CutoverLegacyJudgeBodies(t.Context(), legacy); err != nil {
		t.Fatal(err)
	}
	assertPermanentLegacyJudgeGuards(t, legacy)
}

func openLegacyJudgeStoreAt(t *testing.T, path string) *Store {
	t.Helper()
	store, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	return store
}

func legacyJudgeGuardCount(t *testing.T, legacy *Store) int {
	t.Helper()
	return countRows(t, legacy.db, `SELECT COUNT(*) FROM sqlite_master WHERE type='trigger' AND name IN (?, ?)`,
		legacyJudgeNoInsertTriggerName, legacyJudgeNoUpdateTriggerName)
}

func assertPermanentLegacyJudgeGuards(t *testing.T, legacy *Store) {
	t.Helper()
	conn, err := legacy.db.Conn(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := verifyLegacyJudgeReadOnlyTriggers(t.Context(), conn); err != nil {
		_ = conn.Close()
		t.Fatal(err)
	}
	if err := conn.Close(); err != nil {
		t.Fatal(err)
	}
	if err := legacy.InsertJudgeResponse(JudgeResponse{ID: "late", Kind: "pii", Raw: "late"}); err == nil {
		t.Fatal("legacy INSERT succeeded after reopen")
	}
	if _, err := legacy.db.Exec(`UPDATE judge_responses SET kind='changed' WHERE id='stable'`); err == nil {
		t.Fatal("legacy UPDATE succeeded after reopen")
	}
	batch, err := legacy.BeginJudgeBatch(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if err := batch.InsertJudgeResponse(JudgeResponse{ID: "late-batch", Kind: "pii", Raw: "late"}); err == nil {
		_ = batch.Rollback()
		t.Fatal("legacy batched INSERT succeeded after reopen")
	}
	if err := batch.Rollback(); err != nil {
		t.Fatal(err)
	}
}

type judgeBodyQueryer interface {
	Query(string, ...any) (*sql.Rows, error)
}

func judgeBodyIDs(t *testing.T, db judgeBodyQueryer) []string {
	t.Helper()
	rows, err := db.Query(`SELECT id FROM judge_responses ORDER BY id`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var ids []string
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			t.Fatal(err)
		}
		ids = append(ids, id)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	sort.Strings(ids)
	return ids
}

func countRows(t *testing.T, db interface {
	QueryRow(string, ...any) *sql.Row
}, query string, args ...any) int {
	t.Helper()
	var count int
	if err := db.QueryRow(query, args...).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}
