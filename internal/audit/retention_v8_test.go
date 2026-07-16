// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"path/filepath"
	"reflect"
	"runtime"
	"sort"
	"strings"
	"sync"
	"testing"
	"time"
)

type retentionTestReporter struct {
	mu      sync.Mutex
	reports []RetentionRunReport
}

type retentionTestHealthReporter struct {
	store       *Store
	transitions []RetentionHealthTransition
	errors      []error
}

func (reporter *retentionTestHealthReporter) ReportRetentionHealth(transition RetentionHealthTransition) {
	reporter.transitions = append(reporter.transitions, transition)
	var count int
	reporter.errors = append(reporter.errors,
		reporter.store.db.QueryRow(`SELECT COUNT(*) FROM schema_version`).Scan(&count))
}

type retentionScriptScheduler struct {
	wait func(context.Context, time.Duration, <-chan struct{}) (RetentionScheduleWake, error)
}

func (scheduler retentionScriptScheduler) Wait(
	ctx context.Context,
	interval time.Duration,
	reload <-chan struct{},
) (RetentionScheduleWake, error) {
	return scheduler.wait(ctx, interval, reload)
}

func (reporter *retentionTestReporter) ReportRetentionRun(report RetentionRunReport) {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	reporter.reports = append(reporter.reports, report)
}

func (reporter *retentionTestReporter) snapshot() []RetentionRunReport {
	reporter.mu.Lock()
	defer reporter.mu.Unlock()
	return append([]RetentionRunReport(nil), reporter.reports...)
}

func newRetentionStores(t *testing.T) (*Store, *JudgeBodyStore) {
	t.Helper()
	directory := t.TempDir()
	store, err := NewStore(filepath.Join(directory, "audit.db"))
	if err != nil {
		t.Fatal(err)
	}
	if err := store.Init(); err != nil {
		_ = store.Close()
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	judge, err := NewJudgeBodyStore(filepath.Join(directory, "judge_bodies.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = judge.Close() })
	return store, judge
}

func newRetentionReaperAt(
	t *testing.T,
	store *Store,
	judge *JudgeBodyStore,
	days int64,
	now time.Time,
	options RetentionOptions,
	hooks retentionHooks,
) *RetentionReaper {
	t.Helper()
	hooks.now = func() time.Time { return now }
	reaper, err := newRetentionReaperWithHooks(store, judge, days, options, hooks)
	if err != nil {
		t.Fatal(err)
	}
	return reaper
}

func TestRetentionPolicyValidationAndZeroDisablesScheduleAndDeletion(t *testing.T) {
	store, judge := newRetentionStores(t)
	for _, days := range []int64{-1, math.MaxInt64/int64(24*time.Hour) + 1} {
		if _, err := NewRetentionReaper(store, judge, days, RetentionOptions{}); err == nil {
			t.Fatalf("retention_days=%d was accepted", days)
		}
	}

	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.FixedZone("offset", -7*60*60))
	old := now.Add(-10 * 365 * 24 * time.Hour).UTC().Format(time.RFC3339Nano)
	if _, err := store.db.Exec(`INSERT INTO activity_events
		(id, timestamp, actor, action, target_type, target_id)
		VALUES ('retained-forever', ?, 'operator', 'config-update', 'config', 'main')`, old); err != nil {
		t.Fatal(err)
	}
	reporter := &retentionTestReporter{}
	checkpointCalls := 0
	reaper := newRetentionReaperAt(t, store, judge, 0, now, RetentionOptions{
		Reporter: reporter, PassiveCheckpoint: true,
	}, retentionHooks{checkpoint: func(context.Context, *Store, *JudgeBodyStore) error {
		checkpointCalls++
		return nil
	}})
	if interval, enabled := reaper.ScheduleInterval(); enabled || interval != 0 {
		t.Fatalf("zero-day schedule=(%s,%t), want disabled", interval, enabled)
	}
	result, err := reaper.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Disabled || !result.Cutoff.IsZero() || result.BatchCount != 0 {
		t.Fatalf("disabled result = %#v", result)
	}
	if checkpointCalls != 0 {
		t.Fatalf("disabled retention ran %d checkpoints", checkpointCalls)
	}
	if got := countRetentionRows(t, store.db, "activity_events"); got != 1 {
		t.Fatalf("retention_days=0 rows=%d want 1", got)
	}
	reports := reporter.snapshot()
	if len(reports) != 1 || !reports[0].Success || !reports[0].Result.Disabled || reports[0].FailureClass != "" {
		t.Fatalf("disabled report = %#v", reports)
	}
}

func TestRetentionReapsEveryHistoryClassAtStrictUTCBoundaryAndPreservesState(t *testing.T) {
	store, judge := newRetentionStores(t)
	now := time.Date(2026, 7, 3, 16, 0, 0, 0, time.FixedZone("west", -4*60*60))
	cutoff := now.UTC().Add(-90 * 24 * time.Hour)
	before := cutoff.Add(-time.Nanosecond)
	after := cutoff.Add(time.Nanosecond)
	seedRetentionHistory(t, store, judge, before, cutoff, after)
	seedRetentionProtectedState(t, store, judge, before, cutoff)

	reporter := &retentionTestReporter{}
	reaper := newRetentionReaperAt(t, store, judge, 90, now, RetentionOptions{Reporter: reporter}, retentionHooks{})
	if interval, enabled := reaper.ScheduleInterval(); !enabled || interval != 6*time.Hour {
		t.Fatalf("schedule=(%s,%t)", interval, enabled)
	}
	result, err := reaper.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !result.Cutoff.Equal(cutoff) {
		t.Fatalf("cutoff=%s want %s", result.Cutoff, cutoff)
	}
	for _, class := range retentionTableClasses {
		if result.RowsDeleted[class] == 0 {
			t.Errorf("class %s deleted no rows", class)
		}
	}
	for _, class := range retentionProtectedClasses {
		if result.ProtectedRows[class] == 0 {
			t.Errorf("protected capacity class %s was not reported separately", class)
		}
	}
	assertRetentionBoundaryRows(t, store, judge)
	assertRetentionProtectedState(t, store, judge)

	// A completed run is idempotent and marker cleanup is stable.
	second, err := reaper.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, count := range second.RowsDeleted {
		if count != 0 {
			t.Fatalf("idempotent run deleted %d additional rows: %#v", count, second.RowsDeleted)
		}
	}
	reports := reporter.snapshot()
	if len(reports) != 2 || !reports[0].Success || !reports[1].Success {
		t.Fatalf("retention reports=%#v", reports)
	}
}

func TestRetentionUsesTwoBatchesFor1001RowsAndYieldsForInteractiveWrite(t *testing.T) {
	store, judge := newRetentionStores(t)
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	old := now.Add(-91 * 24 * time.Hour).Format(time.RFC3339Nano)
	tx, err := store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	statement, err := tx.Prepare(`INSERT INTO activity_events
		(id, timestamp, retention_timestamp_unix_nano, actor, action, target_type, target_id)
		VALUES (?, ?, ?, 'operator', 'config-update', 'config', 'main')`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1001; i++ {
		if _, err := statement.Exec(fmt.Sprintf("batch-%04d", i), old, now.Add(-91*24*time.Hour).UnixNano()); err != nil {
			t.Fatal(err)
		}
	}
	_ = statement.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	var missingRetentionInstants int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM activity_events
		WHERE retention_timestamp_unix_nano IS NULL`).Scan(&missingRetentionInstants); err != nil {
		t.Fatal(err)
	}
	if missingRetentionInstants != 0 {
		t.Fatalf("fixture left %d activity retention instants NULL", missingRetentionInstants)
	}

	yields := 0
	reaper := newRetentionReaperAt(t, store, judge, 90, now, RetentionOptions{}, retentionHooks{
		yield: func(ctx context.Context) error {
			yields++
			if yields == 1 {
				_, err := store.db.Exec(`INSERT INTO activity_events
					(id, timestamp, retention_timestamp_unix_nano, actor, action, target_type, target_id)
					VALUES ('interactive', ?, ?, 'operator', 'config-update', 'config', 'live')`,
					now.Format(time.RFC3339Nano), now.UnixNano())
				return err
			}
			return ctx.Err()
		},
	})
	result, err := reaper.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if got := result.RowsDeleted[RetentionActivityEvents]; got != 1001 {
		t.Fatalf("deleted activity rows=%d want 1001", got)
	}
	if result.BatchCount != 2 || yields != 2 {
		t.Fatalf("batches=%d yields=%d want 2,2", result.BatchCount, yields)
	}
	if got := countRetentionRows(t, store.db, "activity_events"); got != 1 {
		t.Fatalf("interactive row count=%d want 1", got)
	}
}

func TestRetentionACKMaterializationUsesTheSameBoundedCandidateBatch(t *testing.T) {
	store, judge := newRetentionStores(t)
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	old := now.Add(-91 * 24 * time.Hour).Format(time.RFC3339Nano)
	tx, err := store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	statement, err := tx.Prepare(`INSERT INTO audit_events
		(id, timestamp, action, actor, details, severity)
		VALUES (?, ?, ?, 'operator', 'ack', 'ACK')`)
	if err != nil {
		t.Fatal(err)
	}
	for index := 0; index < 1001; index++ {
		if _, err := statement.Exec(fmt.Sprintf("bounded-ack-%04d", index), old, string(ActionAlert)); err != nil {
			t.Fatal(err)
		}
	}
	_ = statement.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	yields := 0
	reaper := newRetentionReaperAt(t, store, judge, 90, now, RetentionOptions{}, retentionHooks{
		yield: func(ctx context.Context) error {
			yields++
			if yields == 1 {
				if got := countRetentionRows(t, store.db, "alert_acknowledgement_baselines"); got != 1000 {
					t.Fatalf("first ACK baseline batch=%d want 1000", got)
				}
				if got := countRetentionRows(t, store.db, "alert_acknowledgement_projection"); got != 1000 {
					t.Fatalf("first ACK projection batch=%d want 1000", got)
				}
				if got := countRetentionLike(t, store.db, "audit_events", "bounded-ack-%"); got != 1 {
					t.Fatalf("first ACK delete left %d candidates want 1", got)
				}
			}
			return ctx.Err()
		},
	})
	result, err := reaper.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if result.RowsDeleted[RetentionAuditEvents] != 1001 || result.BatchCount != 2 || yields != 2 {
		t.Fatalf("bounded ACK result=%#v batches=%d yields=%d",
			result.RowsDeleted, result.BatchCount, yields)
	}
	if countRetentionRows(t, store.db, "alert_acknowledgement_baselines") != 1001 ||
		countRetentionRows(t, store.db, "alert_acknowledgement_projection") != 1001 {
		t.Fatal("bounded ACK materialization did not preserve every candidate baseline/projection")
	}
}

func TestRetentionActiveDeleteTransactionAllowsReaderAndSerializesWriter(t *testing.T) {
	store, judge := newRetentionStores(t)
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	if _, err := store.db.Exec(`INSERT INTO activity_events
		(id, timestamp, actor, action, target_type, target_id)
		VALUES ('contention-old', ?, 'operator', 'config-update', 'config', 'old')`,
		now.Add(-91*24*time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	external, err := openSQLite(store.dbPath)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = external.Close() })
	if err := external.PingContext(t.Context()); err != nil {
		t.Fatal(err)
	}

	transactionActive := make(chan struct{})
	allowCommit := make(chan struct{})
	reaper := newRetentionReaperAt(t, store, judge, 90, now, RetentionOptions{}, retentionHooks{
		beforeAuditBatchCommit: func(class RetentionTableClass) error {
			if class == RetentionActivityEvents {
				close(transactionActive)
				<-allowCommit
			}
			return nil
		},
	})
	runDone := make(chan error, 1)
	go func() {
		_, err := reaper.Run(t.Context())
		runDone <- err
	}()
	select {
	case <-transactionActive:
	case <-time.After(5 * time.Second):
		close(allowCommit)
		t.Fatal("retention deletion transaction did not become active")
	}

	var visible int
	if err := external.QueryRowContext(t.Context(), `SELECT COUNT(*) FROM activity_events
		WHERE id='contention-old'`).Scan(&visible); err != nil {
		close(allowCommit)
		t.Fatal(err)
	}
	if visible != 1 {
		close(allowCommit)
		t.Fatalf("concurrent reader observed uncommitted deletion: %d", visible)
	}

	writerStarted := make(chan struct{})
	writerDone := make(chan error, 1)
	waitCountBefore := store.db.Stats().WaitCount
	go func() {
		close(writerStarted)
		_, err := store.db.ExecContext(t.Context(), `INSERT INTO activity_events
			(id, timestamp, actor, action, target_type, target_id)
			VALUES ('contention-current', ?, 'operator', 'config-update', 'config', 'current')`,
			now.Format(time.RFC3339Nano))
		writerDone <- err
	}()
	<-writerStarted
	waitDeadline := time.NewTimer(5 * time.Second)
	defer waitDeadline.Stop()
	for store.db.Stats().WaitCount <= waitCountBefore {
		select {
		case err := <-writerDone:
			close(allowCommit)
			t.Fatalf("concurrent writer completed before retention commit: %v", err)
		case <-waitDeadline.C:
			close(allowCommit)
			t.Fatal("concurrent writer did not enter the store connection wait queue")
		default:
			runtime.Gosched()
		}
	}
	select {
	case err := <-writerDone:
		close(allowCommit)
		t.Fatalf("queued writer completed before retention commit: %v", err)
	default:
	}
	close(allowCommit)
	select {
	case err := <-writerDone:
		if err != nil {
			t.Fatalf("serialized writer failed after retention commit: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("serialized writer did not resume after retention commit")
	}
	select {
	case err := <-runDone:
		if err != nil {
			t.Fatal(err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("retention did not finish after releasing active transaction")
	}
	if countRetentionLike(t, store.db, "activity_events", "contention-old") != 0 ||
		countRetentionLike(t, store.db, "activity_events", "contention-current") != 1 {
		t.Fatal("contention test lost the committed retention delete or concurrent writer")
	}
}

func TestRetentionCancellationStopsBetweenCommittedBatches(t *testing.T) {
	store, judge := newRetentionStores(t)
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	seedRetentionActivityRows(t, store, 1500, now.Add(-91*24*time.Hour))
	ctx, cancel := context.WithCancel(t.Context())
	reporter := &retentionTestReporter{}
	reaper := newRetentionReaperAt(t, store, judge, 90, now, RetentionOptions{Reporter: reporter}, retentionHooks{
		yield: func(context.Context) error {
			cancel()
			return context.Canceled
		},
	})
	result, err := reaper.Run(ctx)
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("cancellation error=%v", err)
	}
	if result.RowsDeleted[RetentionActivityEvents] != 1000 || result.BatchCount != 1 {
		t.Fatalf("partial result=%#v", result)
	}
	if got := countRetentionRows(t, store.db, "activity_events"); got != 500 {
		t.Fatalf("rows after cancellation=%d want 500", got)
	}
	reports := reporter.snapshot()
	if len(reports) != 1 || reports[0].Success || reports[0].FailureClass != RetentionFailureCancelled {
		t.Fatalf("cancellation report=%#v", reports)
	}
}

func TestRetentionJudgeDeletionIsLegacyFirstAndResumesAfterCrossDBFailure(t *testing.T) {
	store, judge := newRetentionStores(t)
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	old := now.Add(-91 * 24 * time.Hour)
	seedJudgePair(t, store, judge, "cross-db", old)
	if err := judge.CutoverLegacyJudgeBodies(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	fault := errors.New("injected after legacy commit")
	checkpointCalls := 0
	reporter := &retentionTestReporter{}
	reaper := newRetentionReaperAt(t, store, judge, 90, now, RetentionOptions{
		Reporter: reporter, PassiveCheckpoint: true,
	}, retentionHooks{
		afterLegacyJudgeCommit: func() error { return fault },
		checkpoint: func(context.Context, *Store, *JudgeBodyStore) error {
			checkpointCalls++
			return nil
		},
	})
	result, err := reaper.Run(t.Context())
	if !errors.Is(err, fault) {
		t.Fatalf("cross-database error=%v", err)
	}
	if result.RowsDeleted[RetentionLegacyJudgeResponses] != 1 ||
		result.RowsDeleted[RetentionAuthoritativeJudgeBodies] != 0 {
		t.Fatalf("partial judge result=%#v", result.RowsDeleted)
	}
	if countRetentionRows(t, store.db, "judge_responses") != 0 ||
		countRetentionRows(t, judge.db, "judge_responses") != 1 {
		t.Fatal("cross-database failure did not preserve the authoritative copy")
	}
	if checkpointCalls != 0 {
		t.Fatal("checkpoint ran after failed retention")
	}
	reports := reporter.snapshot()
	if len(reports) != 1 || reports[0].FailureClass != RetentionFailureCrossDatabase {
		t.Fatalf("failure report=%#v", reports)
	}

	resumeCheckpoint := 0
	resume := newRetentionReaperAt(t, store, judge, 90, now, RetentionOptions{PassiveCheckpoint: true}, retentionHooks{
		checkpoint: func(context.Context, *Store, *JudgeBodyStore) error {
			resumeCheckpoint++
			return nil
		},
	})
	resumed, err := resume.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if resumed.RowsDeleted[RetentionLegacyJudgeResponses] != 0 ||
		resumed.RowsDeleted[RetentionAuthoritativeJudgeBodies] != 1 {
		t.Fatalf("resumed judge result=%#v", resumed.RowsDeleted)
	}
	if countRetentionRows(t, judge.db, "judge_responses") != 0 ||
		countRetentionRows(t, judge.db, "legacy_judge_cutover_rows") != 0 {
		t.Fatal("resume left authoritative body or cutover-row evidence")
	}
	if resumeCheckpoint != 1 {
		t.Fatalf("successful resume checkpoints=%d want 1", resumeCheckpoint)
	}
}

func TestRetentionResumesAfterFailureFollowingAuthoritativeJudgeCommit(t *testing.T) {
	store, judge := newRetentionStores(t)
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	seedJudgePair(t, store, judge, "authoritative-commit", now.Add(-91*24*time.Hour))
	if err := judge.CutoverLegacyJudgeBodies(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	fault := errors.New("injected after authoritative commit")
	reaper := newRetentionReaperAt(t, store, judge, 90, now, RetentionOptions{}, retentionHooks{
		afterAuthoritativeJudgeCommit: func() error { return fault },
	})
	result, err := reaper.Run(t.Context())
	if !errors.Is(err, fault) || retentionFailureClass(err) != RetentionFailureCrossDatabase {
		t.Fatalf("authoritative post-commit error=%v", err)
	}
	if result.RowsDeleted[RetentionLegacyJudgeResponses] != 1 ||
		result.RowsDeleted[RetentionAuthoritativeJudgeBodies] != 1 {
		t.Fatalf("authoritative post-commit result=%#v", result.RowsDeleted)
	}
	if countRetentionRows(t, store.db, "judge_responses") != 0 ||
		countRetentionRows(t, judge.db, "judge_responses") != 0 ||
		countRetentionRows(t, judge.db, "legacy_judge_cutover_rows") != 0 {
		t.Fatal("authoritative commit did not atomically remove the body and its source marker")
	}

	resumed, err := newRetentionReaperAt(
		t, store, judge, 90, now, RetentionOptions{}, retentionHooks{},
	).Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if resumed.RowsDeleted[RetentionLegacyJudgeResponses] != 0 ||
		resumed.RowsDeleted[RetentionAuthoritativeJudgeBodies] != 0 {
		t.Fatalf("resume repeated committed deletion: %#v", resumed.RowsDeleted)
	}
}

func TestRetentionFailsClosedWhenLegacyJudgeCopyIsMissing(t *testing.T) {
	store, judge := newRetentionStores(t)
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	if err := store.InsertJudgeResponse(JudgeResponse{
		ID: "missing-copy", Timestamp: now.Add(-91 * 24 * time.Hour), Kind: "pii", Raw: "raw body",
	}); err != nil {
		t.Fatal(err)
	}
	if err := judge.CutoverLegacyJudgeBodies(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	if _, err := judge.db.Exec(`DELETE FROM judge_responses WHERE id='missing-copy'`); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`INSERT INTO activity_events
		(id, timestamp, actor, action, target_type, target_id)
		VALUES ('must-survive-preflight', ?, 'operator', 'config-update', 'config', 'main')`,
		now.Add(-91*24*time.Hour).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	reaper := newRetentionReaperAt(t, store, judge, 90, now, RetentionOptions{}, retentionHooks{})
	_, err := reaper.Run(t.Context())
	var runErr *retentionRunError
	if !errors.As(err, &runErr) || runErr.class != RetentionFailureJudgeCopyMissing {
		t.Fatalf("missing-copy error=%v", err)
	}
	if countRetentionRows(t, store.db, "judge_responses") != 1 {
		t.Fatal("missing authoritative copy deleted the legacy source")
	}
	if countRetentionLike(t, store.db, "activity_events", "must-survive-preflight") != 1 {
		t.Fatal("ordinary history was deleted before judge prerequisites passed")
	}
}

func TestRetentionTimestampTriggersAreExactIndexedAndCatchConcurrentInsert(t *testing.T) {
	store, judge := newRetentionStores(t)
	now := time.Date(2026, 7, 3, 12, 0, 0, 123456789, time.UTC)
	encoded := "2026-04-04T08:00:00.123456788-04:00"
	parsed, err := time.Parse(time.RFC3339Nano, encoded)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`INSERT INTO activity_events
		(id, timestamp, actor, action, target_type, target_id)
		VALUES ('trigger-exact', ?, 'operator', 'config-update', 'config', 'main')`, encoded); err != nil {
		t.Fatal(err)
	}
	var indexed int64
	if err := store.db.QueryRow(`SELECT retention_timestamp_unix_nano FROM activity_events
		WHERE id='trigger-exact'`).Scan(&indexed); err != nil {
		t.Fatal(err)
	}
	if indexed != parsed.UnixNano() {
		t.Fatalf("trigger instant=%d want %d", indexed, parsed.UnixNano())
	}
	for index, value := range []string{
		"2026-07-03T12:00:00Z",
		"2026-07-03T12:00:00.000000001Z",
		"2026-07-03T08:00:00-04:00",
		"2026-07-03T08:00:00.987654321-04:00",
		"2026-07-03 12:00:00",
		"2026-07-03 12:00:00.123456789",
		"2026-07-03 08:00:00-04:00",
		"2026-07-03 08:00:00.987654321-04:00",
		"2026-07-03 08:00:00 -0400 EDT",
		"2026-07-03 08:00:00.123456789 -0400 EDT",
	} {
		parsed, err := parseJudgeBodyTimestamp(value)
		if err != nil {
			t.Fatal(err)
		}
		id := fmt.Sprintf("trigger-form-%d", index)
		if _, err := store.db.Exec(`INSERT INTO activity_events
			(id, timestamp, actor, action, target_type, target_id)
			VALUES (?, ?, 'operator', 'config-update', 'config', 'main')`, id, value); err != nil {
			t.Fatal(err)
		}
		if err := store.db.QueryRow(`SELECT retention_timestamp_unix_nano
			FROM activity_events WHERE id=?`, id).Scan(&indexed); err != nil {
			t.Fatal(err)
		}
		if indexed != parsed.UnixNano() {
			t.Errorf("trigger form %q instant=%d want %d", value, indexed, parsed.UnixNano())
		}
	}
	boundTime := time.Date(2026, 7, 3, 8, 0, 0, 456789123, time.FixedZone("EDT", -4*60*60))
	if err := store.InsertScanResult(
		"trigger-bound-time", "scanner", "target", boundTime, 1, 0, "NONE", "{}",
	); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT retention_timestamp_unix_nano
		FROM scan_results WHERE id='trigger-bound-time'`).Scan(&indexed); err != nil {
		t.Fatal(err)
	}
	if indexed != boundTime.UnixNano() {
		t.Errorf("bound time instant=%d want %d", indexed, boundTime.UnixNano())
	}
	rows, err := store.db.Query(`EXPLAIN QUERY PLAN SELECT id FROM activity_events
		WHERE retention_timestamp_unix_nano < ?
		ORDER BY retention_timestamp_unix_nano, id LIMIT 1000`, now.UnixNano())
	if err != nil {
		t.Fatal(err)
	}
	plan := ""
	for rows.Next() {
		var id, parent, unused int
		var detail string
		if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
			t.Fatal(err)
		}
		plan += detail
	}
	_ = rows.Close()
	if !strings.Contains(plan, "idx_retention_activity_events_timestamp") {
		t.Fatalf("retention query does not use exact index: %s", plan)
	}
	assertRetentionDeletePlansUseIndexes(t, store, now.UnixNano())

	inserted := false
	reaper := newRetentionReaperAt(t, store, judge, 90, now, RetentionOptions{}, retentionHooks{
		afterTimestampRepairs: func() error {
			inserted = true
			_, err := store.db.Exec(`INSERT INTO activity_events
				(id, timestamp, actor, action, target_type, target_id)
				VALUES ('concurrent-old', ?, 'operator', 'config-update', 'config', 'main')`,
				now.Add(-91*24*time.Hour).Format(time.RFC3339Nano))
			return err
		},
	})
	result, err := reaper.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if !inserted || result.RowsDeleted[RetentionActivityEvents] != 2 {
		t.Fatalf("concurrent insert result=%#v inserted=%t", result.RowsDeleted, inserted)
	}
}

func TestRetentionStartupReinstallsForgedTimestampTrigger(t *testing.T) {
	store, _ := newRetentionStores(t)
	path := store.dbPath
	if _, err := store.db.Exec(`
		DROP TRIGGER retention_activity_events_timestamp_insert;
		CREATE TRIGGER retention_activity_events_timestamp_insert
		AFTER INSERT ON activity_events BEGIN SELECT 1; END;
	`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.Init(); err != nil {
		t.Fatalf("startup did not safely repair forged retention trigger: %v", err)
	}
	spec, found := retentionTimestampSpecForTable("activity_events")
	if !found {
		t.Fatal("activity retention timestamp spec is missing")
	}
	insertName, _, insertSQL, _ := retentionTimestampTriggerDDL(spec)
	var actual string
	if err := reopened.db.QueryRow(`SELECT sql FROM sqlite_master
		WHERE type='trigger' AND name=?`, insertName).Scan(&actual); err != nil {
		t.Fatal(err)
	}
	if normalizeSQLiteDDL(actual) != normalizeSQLiteDDL(insertSQL) {
		t.Fatalf("repaired trigger mismatch\nactual=%s\nwant=%s", actual, insertSQL)
	}
}

func TestRetentionStartupReinstallsForgedScanIntegrityTriggers(t *testing.T) {
	store, _ := newRetentionStores(t)
	path := store.dbPath
	for _, trigger := range retentionScanIntegrityTriggerDDL() {
		if _, err := store.db.Exec(`DROP TRIGGER ` + trigger.name); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.Exec(fmt.Sprintf(`CREATE TRIGGER %s
			BEFORE INSERT ON scan_findings BEGIN SELECT 1; END`, trigger.name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.Init(); err != nil {
		t.Fatalf("startup did not repair forged scan integrity triggers: %v", err)
	}
	for _, trigger := range retentionScanIntegrityTriggerDDL() {
		var actual string
		if err := reopened.db.QueryRow(`SELECT sql FROM sqlite_master
			WHERE type='trigger' AND name=?`, trigger.name).Scan(&actual); err != nil {
			t.Fatal(err)
		}
		if normalizeSQLiteDDL(actual) != normalizeSQLiteDDL(trigger.sql) {
			t.Fatalf("repaired scan trigger %s mismatch\nactual=%s\nwant=%s",
				trigger.name, actual, trigger.sql)
		}
	}
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC).Format(time.RFC3339Nano)
	if _, err := reopened.db.Exec(`INSERT INTO scan_results
		(id, scanner, target, timestamp) VALUES ('guard-parent', 'scanner', 'target', ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.db.Exec(`INSERT INTO scan_findings
		(id, scan_id, scanner, target, severity, timestamp)
		VALUES ('guard-child', 'guard-parent', 'scanner', 'target', 'LOW', ?)`, now); err != nil {
		t.Fatal(err)
	}
	if _, err := reopened.db.Exec(`UPDATE scan_findings SET scan_id='missing-parent'
		WHERE id='guard-child'`); err == nil {
		t.Fatal("repaired update guard accepted a missing parent")
	}
	if _, err := reopened.db.Exec(`DELETE FROM scan_results WHERE id='guard-parent'`); err == nil {
		t.Fatal("repaired parent-delete guard accepted a retained child")
	}
	if _, err := reopened.db.Exec(`INSERT INTO scan_findings
		(id, scan_id, scanner, target, severity, timestamp)
		VALUES ('missing-child', 'missing-parent', 'scanner', 'target', 'LOW', ?)`, now); err == nil {
		t.Fatal("repaired insert guard accepted a missing parent")
	}
}

func TestRetentionStartupRejectsForgedTimestampIndex(t *testing.T) {
	store, _ := newRetentionStores(t)
	path := store.dbPath
	if _, err := store.db.Exec(`
		DROP INDEX idx_retention_activity_events_timestamp;
		CREATE INDEX idx_retention_activity_events_timestamp
		ON activity_events(retention_timestamp_unix_nano DESC, id)
		WHERE retention_timestamp_unix_nano IS NOT NULL;
	`); err != nil {
		t.Fatal(err)
	}
	if err := store.Close(); err != nil {
		t.Fatal(err)
	}
	reopened, err := NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = reopened.Close() })
	if err := reopened.Init(); err == nil ||
		!strings.Contains(err.Error(), "retention timestamp index does not match required definition") {
		t.Fatalf("startup accepted forged retention index: %v", err)
	}
}

func TestRetentionScanFindingOwnAgePreservesBatchLimit(t *testing.T) {
	store, judge := newRetentionStores(t)
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	parentTime := now.Add(-100 * 24 * time.Hour)
	if _, err := store.db.Exec(`INSERT INTO scan_results
		(id, scanner, target, timestamp) VALUES ('dedupe-parent', 'scanner', 'target', ?)`,
		parentTime.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	tx, err := store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	statement, err := tx.Prepare(`INSERT INTO scan_findings
		(id, scan_id, scanner, target, severity, timestamp)
		VALUES (?, 'dedupe-parent', 'scanner', 'target', 'LOW', ?)`)
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 1001; i++ {
		childTime := now.Add(-time.Duration(91+i%5) * 24 * time.Hour)
		if _, err := statement.Exec(fmt.Sprintf("dedupe-%04d", i), childTime.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	_ = statement.Close()
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
	reaper := newRetentionReaperAt(t, store, judge, 90, now, RetentionOptions{}, retentionHooks{})
	result, err := reaper.Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if result.RowsDeleted[RetentionScanFindings] != 1001 {
		t.Fatalf("deduplicated scan finding deletes=%d want 1001", result.RowsDeleted[RetentionScanFindings])
	}
	if countRetentionLike(t, store.db, "scan_findings", "dedupe-%") != 0 {
		t.Fatal("duplicate candidate rows caused early batch termination")
	}
}

func TestRetentionOldScanParentDoesNotDeleteBoundaryOrNewerChildren(t *testing.T) {
	store, judge := newRetentionStores(t)
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	cutoff := now.Add(-90 * 24 * time.Hour)
	if _, err := store.db.Exec(`INSERT INTO scan_results
		(id, scanner, target, timestamp) VALUES ('mixed-age-parent', 'scanner', 'target', ?)`,
		cutoff.Add(-time.Nanosecond).Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	for _, fixture := range []struct {
		id string
		ts time.Time
	}{
		{id: "mixed-age-equal", ts: cutoff},
		{id: "mixed-age-after", ts: cutoff.Add(time.Nanosecond)},
	} {
		if _, err := store.db.Exec(`INSERT INTO scan_findings
			(id, scan_id, scanner, target, severity, timestamp)
			VALUES (?, 'mixed-age-parent', 'scanner', 'target', 'LOW', ?)`,
			fixture.id, fixture.ts.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	result, err := newRetentionReaperAt(
		t, store, judge, 90, now, RetentionOptions{}, retentionHooks{},
	).Run(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if result.RowsDeleted[RetentionScanFindings] != 0 ||
		result.RowsDeleted[RetentionScanResults] != 0 {
		t.Fatalf("mixed-age scan deletion result=%#v", result.RowsDeleted)
	}
	if countRetentionLike(t, store.db, "scan_findings", "mixed-age-%") != 2 ||
		countRetentionLike(t, store.db, "scan_results", "mixed-age-parent") != 1 {
		t.Fatal("old parent caused boundary/newer scan children to be deleted")
	}
}

func assertRetentionDeletePlansUseIndexes(t *testing.T, store *Store, cutoff int64) {
	t.Helper()
	wantIndexes := map[RetentionTableClass][]string{
		RetentionAuditEvents:         {"idx_retention_audit_events_timestamp"},
		RetentionActivityEvents:      {"idx_retention_activity_events_timestamp"},
		RetentionNetworkEgressEvents: {"idx_retention_network_egress_timestamp"},
		RetentionSinkHealth:          {"idx_retention_sink_health_timestamp"},
		RetentionScanFindings:        {"idx_retention_scan_findings_timestamp"},
		RetentionLegacyFindings: {
			"idx_retention_scan_results_timestamp",
			"idx_finding_scan",
		},
		RetentionScanResults: {"idx_retention_scan_results_timestamp"},
	}
	for class, indexes := range wantIndexes {
		statement := retentionAuditCandidateSelect
		if class != RetentionAuditEvents {
			var err error
			statement, err = retentionAuditDeleteStatement(class)
			if err != nil {
				t.Fatal(err)
			}
		}
		rows, err := store.db.Query(`EXPLAIN QUERY PLAN `+statement, cutoff, RetentionBatchSize)
		if err != nil {
			t.Fatalf("explain %s: %v", class, err)
		}
		plan := ""
		for rows.Next() {
			var id, parent, unused int
			var detail string
			if err := rows.Scan(&id, &parent, &unused, &detail); err != nil {
				_ = rows.Close()
				t.Fatal(err)
			}
			plan += " " + detail
		}
		_ = rows.Close()
		for _, index := range indexes {
			if !strings.Contains(plan, index) {
				t.Errorf("%s plan does not use %s: %s", class, index, plan)
			}
		}
	}
}

func TestRetentionScanParentGuardPreventsOrphansAcrossBatchInterleave(t *testing.T) {
	store, judge := newRetentionStores(t)
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	old := now.Add(-91 * 24 * time.Hour)
	if _, err := store.db.Exec(`INSERT INTO scan_results
		(id, scanner, target, timestamp) VALUES ('racing-scan', 'scanner', 'target', ?)`,
		old.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	reaper := newRetentionReaperAt(t, store, judge, 90, now, RetentionOptions{}, retentionHooks{
		beforeScanParentDrain: func() error {
			_, err := store.db.Exec(`INSERT INTO scan_findings
				(id, scan_id, scanner, target, severity, timestamp)
				VALUES ('racing-finding', 'racing-scan', 'scanner', 'target', 'LOW', ?)`,
				old.Format(time.RFC3339Nano))
			return err
		},
	})
	if _, err := reaper.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if countRetentionLike(t, store.db, "scan_results", "racing-scan") != 1 ||
		countRetentionLike(t, store.db, "scan_findings", "racing-finding") != 1 {
		t.Fatal("interleaved finding insert orphaned or lost its retained parent")
	}
	if _, err := store.db.Exec(`UPDATE scan_findings SET scan_id='missing-parent'
		WHERE id='racing-finding'`); err == nil {
		t.Fatal("scan finding update trigger accepted a missing parent")
	}
	var retainedParent string
	if err := store.db.QueryRow(`SELECT scan_id FROM scan_findings
		WHERE id='racing-finding'`).Scan(&retainedParent); err != nil {
		t.Fatal(err)
	}
	if retainedParent != "racing-scan" {
		t.Fatalf("rejected update changed finding parent to %q", retainedParent)
	}
	if _, err := store.db.Exec(`DELETE FROM scan_findings WHERE id='racing-finding'`); err != nil {
		t.Fatal(err)
	}
	clean := newRetentionReaperAt(t, store, judge, 90, now, RetentionOptions{}, retentionHooks{})
	if _, err := clean.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if countRetentionLike(t, store.db, "scan_results", "racing-scan") != 0 {
		t.Fatal("child-free old scan parent was not deleted")
	}
	if _, err := store.db.Exec(`INSERT INTO scan_findings
		(id, scan_id, scanner, target, severity, timestamp)
		VALUES ('orphan', 'racing-scan', 'scanner', 'target', 'LOW', ?)`,
		old.Format(time.RFC3339Nano)); err == nil {
		t.Fatal("scan finding trigger accepted a missing parent")
	}

	// Previous-binary parent deletion remains legal when the non-FK v7 detail
	// table has no child; the new guard does not broaden its scope.
	if _, err := store.db.Exec(`INSERT INTO scan_results
		(id, scanner, target, timestamp) VALUES ('legacy-delete', 'scanner', 'target', ?)`,
		old.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`DELETE FROM scan_results WHERE id='legacy-delete'`); err != nil {
		t.Fatalf("child-free previous-binary parent delete regressed: %v", err)
	}
}

func TestRetentionSchedulerReloadAndHealthTransitionCoalescing(t *testing.T) {
	store, judge := newRetentionStores(t)
	now := time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC)
	rowTime := now.Add(-60 * 24 * time.Hour)
	if _, err := store.db.Exec(`INSERT INTO activity_events
		(id, timestamp, actor, action, target_type, target_id)
		VALUES ('reload-row', ?, 'operator', 'config-update', 'config', 'main')`,
		rowTime.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	reaper := newRetentionReaperAt(t, store, judge, 90, now, RetentionOptions{}, retentionHooks{})
	stop := errors.New("script complete")
	waits := 0
	scheduler := retentionScriptScheduler{wait: func(
		_ context.Context, interval time.Duration, _ <-chan struct{},
	) (RetentionScheduleWake, error) {
		waits++
		if interval != 6*time.Hour {
			t.Fatalf("scheduler interval=%s", interval)
		}
		if waits == 1 {
			if err := reaper.UpdateRetentionDays(30); err != nil {
				t.Fatal(err)
			}
			return RetentionScheduleReload, nil
		}
		return 0, stop
	}}
	if err := reaper.RunScheduled(t.Context(), scheduler); !errors.Is(err, stop) {
		t.Fatalf("scheduler error=%v", err)
	}
	if countRetentionLike(t, store.db, "activity_events", "reload-row") != 0 {
		t.Fatal("90-to-30 reload did not trigger prompt run with new age")
	}
	if err := reaper.UpdateRetentionDays(-1); err == nil || reaper.RetentionDays() != 30 {
		t.Fatalf("invalid reload changed active days to %d, err=%v", reaper.RetentionDays(), err)
	}

	health := &retentionTestHealthReporter{store: store}
	failCheckpoint := true
	healthReaper := newRetentionReaperAt(t, store, judge, 30, now, RetentionOptions{
		PassiveCheckpoint: true, HealthReporter: health,
	}, retentionHooks{checkpoint: func(context.Context, *Store, *JudgeBodyStore) error {
		if failCheckpoint {
			return errors.New("checkpoint unavailable")
		}
		return nil
	}})
	for i := 0; i < 2; i++ {
		if _, err := healthReaper.Run(t.Context()); err == nil {
			t.Fatal("checkpoint failure was hidden")
		}
	}
	if len(health.transitions) != 1 || health.transitions[0].State != RetentionHealthDegraded ||
		health.transitions[0].FailureClass != RetentionFailureCheckpoint {
		t.Fatalf("coalesced degraded transitions=%#v", health.transitions)
	}
	failCheckpoint = false
	if _, err := healthReaper.Run(t.Context()); err != nil {
		t.Fatal(err)
	}
	if len(health.transitions) != 2 || health.transitions[1].State != RetentionHealthRecovered {
		t.Fatalf("recovery transitions=%#v", health.transitions)
	}
	for _, err := range health.errors {
		if err != nil {
			t.Fatalf("health callback ran with unavailable lifecycle/DB ownership: %v", err)
		}
	}
}

func TestRetentionMigrationCatalogCompletenessAndProtectedExclusions(t *testing.T) {
	store, judge := newRetentionStores(t)
	auditTables := listRetentionTables(t, store.db)
	judgeTables := listRetentionTables(t, judge.db)
	if !reflect.DeepEqual(auditTables, sortedRetentionCatalog(retentionAuditMigrationCatalog)) {
		t.Fatalf("audit migration ownership incomplete\nlive=%v\ncatalog=%v", auditTables, sortedRetentionCatalog(retentionAuditMigrationCatalog))
	}
	if !reflect.DeepEqual(judgeTables, sortedRetentionCatalog(retentionJudgeMigrationCatalog)) {
		t.Fatalf("judge migration ownership incomplete\nlive=%v\ncatalog=%v", judgeTables, sortedRetentionCatalog(retentionJudgeMigrationCatalog))
	}

	registered := map[string]bool{"judge_responses": true}
	for _, spec := range retentionAuditRegistry {
		registered[spec.table] = true
	}
	for table, ownership := range retentionAuditMigrationCatalog {
		if ownership == retentionOwnedHistory && !registered[table] {
			t.Errorf("history table %s is missing from retention registry", table)
		}
		if ownership == retentionOwnedProtected && registered[table] {
			t.Errorf("protected table %s is present in retention registry", table)
		}
		if ownership == retentionOwnedGraph && !retentionCorrelationGraphTables[table] {
			t.Errorf("graph-owned table %s is missing from the correlation retention registry", table)
		}
	}
	for table := range retentionCorrelationGraphTables {
		if retentionAuditMigrationCatalog[table] != retentionOwnedGraph {
			t.Errorf("correlation retention table %s is not declared graph-owned", table)
		}
	}
	for table, ownership := range retentionJudgeMigrationCatalog {
		if ownership == retentionOwnedHistory && table != "judge_responses" {
			t.Errorf("judge history table %s is missing from fixed authoritative reaper", table)
		}
	}
}

func seedRetentionHistory(
	t *testing.T,
	store *Store,
	judge *JudgeBodyStore,
	before time.Time,
	equal time.Time,
	after time.Time,
) {
	t.Helper()
	for _, fixture := range []struct {
		id string
		ts time.Time
	}{
		{id: "audit-before", ts: before}, {id: "audit-equal", ts: equal}, {id: "audit-after", ts: after},
	} {
		if _, err := store.db.Exec(`INSERT INTO audit_events
			(id, timestamp, action, actor, details, severity)
			VALUES (?, ?, 'scan', 'test', 'history', 'INFO')`, fixture.id, fixture.ts.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	if _, err := store.db.Exec(`INSERT INTO audit_events
		(id, timestamp, action, actor, details, severity)
		VALUES ('legacy-ack-before', ?, ?, 'operator', 'ack', 'ACK')`,
		before.Format(time.RFC3339Nano), string(ActionAlert)); err != nil {
		t.Fatal(err)
	}

	for _, table := range []string{"activity_events", "network_egress_events", "sink_health"} {
		seedSimpleRetentionBoundary(t, store, table, before, equal, after)
	}
	for _, fixture := range []struct {
		id string
		ts time.Time
	}{
		{id: "scan-before", ts: before}, {id: "scan-equal", ts: equal}, {id: "scan-after", ts: after},
	} {
		if _, err := store.db.Exec(`INSERT INTO scan_results
			(id, scanner, target, timestamp) VALUES (?, 'scanner', 'target', ?)`,
			fixture.id, fixture.ts.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.Exec(`INSERT INTO findings
			(id, scan_id, severity, title, scanner) VALUES (?, ?, 'LOW', 'legacy', 'scanner')`,
			"legacy-finding-"+fixture.id, fixture.id); err != nil {
			t.Fatal(err)
		}
		if _, err := store.db.Exec(`INSERT INTO scan_findings
			(id, scan_id, scanner, target, severity, timestamp)
			VALUES (?, ?, 'scanner', 'target', 'LOW', ?)`,
			"finding-"+fixture.id, fixture.id, fixture.ts.Format(time.RFC3339Nano)); err != nil {
			t.Fatal(err)
		}
	}
	for _, fixture := range []struct {
		id string
		ts time.Time
	}{
		{id: "judge-before", ts: before}, {id: "judge-equal", ts: equal}, {id: "judge-after", ts: after},
	} {
		seedJudgePair(t, store, judge, fixture.id, fixture.ts)
	}
	if err := judge.CutoverLegacyJudgeBodies(t.Context(), store); err != nil {
		t.Fatal(err)
	}
	seedRetentionCorrelationHistory(t, store, before)
}

func seedRetentionCorrelationHistory(t *testing.T, store *Store, old time.Time) {
	t.Helper()
	repo, err := store.CorrelationRepository()
	if err != nil {
		t.Fatal(err)
	}
	instance := mustCorrelationInstance(t, repo, "retention", ConnectorCustodyHookOnly)
	seedCorrelationEvent(t, repo, instance, correlationSeedOptions{
		receivedAt: old,
		receipt: &CorrelationReceiptClaim{
			SourceKeyDigest:   correlationDigest("retention-receipt"),
			FingerprintSHA256: correlationDigest("retention-payload"),
			ReceivedAt:        old, ExpiresAt: old.Add(time.Nanosecond),
		},
	})
	seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: old, mutate: func(tx *CorrelationTx, event CorrelationEvent) {
		if err := tx.PutCursor(t.Context(), CorrelationCursor{
			ConnectorInstanceID: instance.ConnectorInstanceID, SessionID: "old-session", AgentID: "old-agent",
			Phase: "completed", Sequence: 1, LastSemanticEventID: event.SemanticEventID,
			ProfileVersion: instance.ProfileVersion, Active: false, UpdatedAt: old,
		}); err != nil {
			t.Fatal(err)
		}
	}})
	seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: old, mutate: func(tx *CorrelationTx, event CorrelationEvent) {
		if err := tx.PutPendingOperation(t.Context(), CorrelationPendingOperation{
			ConnectorInstanceID: instance.ConnectorInstanceID, Namespace: "codex", Kind: CorrelationIdentifierTool,
			OperationID: "old-tool", Type: CorrelationOperationTool,
			ScopeKind: CorrelationOperationScopeConnectorInstance, ScopeID: string(instance.ConnectorInstanceID),
			StartSemanticEventID: event.SemanticEventID,
			StartedAt:            old, TerminalSemanticEventID: event.SemanticEventID,
			TerminalAt: old, Status: CorrelationOperationCompleted, UpdatedAt: old,
		}); err != nil {
			t.Fatal(err)
		}
	}})
	seedCorrelationEvent(t, repo, instance, correlationSeedOptions{receivedAt: old, mutate: func(tx *CorrelationTx, _ CorrelationEvent) {
		if _, err := tx.PutRelationship(t.Context(), CorrelationRelationshipInput{
			FromKind: CorrelationNodeSession, FromID: "old-session-node",
			ToKind: CorrelationNodeTurn, ToID: "old-turn-node", Type: CorrelationBelongsTo,
			Method: CorrelationMethodReported, RuleID: "retention-fixture", RuleVersion: "v1",
			Status: CorrelationRelationshipActive, ObservedAt: old,
		}); err != nil {
			t.Fatal(err)
		}
	}})
}

func seedSimpleRetentionBoundary(
	t *testing.T,
	store *Store,
	table string,
	before time.Time,
	equal time.Time,
	after time.Time,
) {
	t.Helper()
	for _, fixture := range []struct {
		suffix string
		ts     time.Time
	}{{"before", before}, {"equal", equal}, {"after", after}} {
		id := table + "-" + fixture.suffix
		var err error
		switch table {
		case "activity_events":
			_, err = store.db.Exec(`INSERT INTO activity_events
				(id, timestamp, actor, action, target_type, target_id)
				VALUES (?, ?, 'operator', 'config-update', 'config', 'main')`, id, fixture.ts.Format(time.RFC3339Nano))
		case "network_egress_events":
			_, err = store.db.Exec(`INSERT INTO network_egress_events
				(id, timestamp, hostname, policy_outcome) VALUES (?, ?, 'example.test', 'allowed')`,
				id, fixture.ts.Format(time.RFC3339Nano))
		case "sink_health":
			_, err = store.db.Exec(`INSERT INTO sink_health
				(id, timestamp, sink_name, sink_kind, outcome) VALUES (?, ?, 'sink', 'jsonl', 'ok')`,
				id, fixture.ts.Format(time.RFC3339Nano))
		default:
			t.Fatalf("unsupported seed table %s", table)
		}
		if err != nil {
			t.Fatal(err)
		}
	}
}

func seedRetentionProtectedState(
	t *testing.T,
	store *Store,
	judge *JudgeBodyStore,
	old time.Time,
	equal time.Time,
) {
	t.Helper()
	if _, err := store.db.Exec(`INSERT INTO actions
		(id, target_type, target_name, actions_json, updated_at)
		VALUES ('protected-action', 'skill', 'example', '{}', ?)`, old.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`INSERT INTO target_snapshots
		(id, target_type, target_path, content_hash, captured_at)
		VALUES ('protected-snapshot', 'skill', '/safe/path', 'hash', ?)`, old.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`INSERT INTO alert_acknowledgement_operations (
		operation_id, command_fingerprint, alert_id, requested_disposition, actor,
		expected_projection_version, outcome, observed_projection_version,
		projection_version_before, projection_version_after, event_id, created_at
	) VALUES ('protected-operation', 'hmac-sha256:v1:key:`+stringsOf("a", 64)+`',
		'protected-alert', 'acknowledged', 'operator', 0, 'applied', 0, 0, 1,
		'protected-event', ?)`, old.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	if _, err := store.db.Exec(`INSERT INTO alert_acknowledgement_health
		(alert_id, code, health_event_id, detected_at)
		VALUES ('health-alert', 'gap', 'health-event', ?)`, old.Format(time.RFC3339Nano)); err != nil {
		t.Fatal(err)
	}
	_ = judge
	_ = equal
}

func assertRetentionBoundaryRows(t *testing.T, store *Store, judge *JudgeBodyStore) {
	t.Helper()
	for _, table := range []string{
		"audit_events", "activity_events", "network_egress_events", "sink_health",
		"scan_findings", "findings", "scan_results", "judge_responses",
	} {
		assertRetentionSuffixes(t, store.db, table)
	}
	assertRetentionSuffixes(t, judge.db, "judge_responses")
	var baseline, projection int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM alert_acknowledgement_baselines
		WHERE alert_id='legacy-ack-before'`).Scan(&baseline); err != nil {
		t.Fatal(err)
	}
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM alert_acknowledgement_projection
		WHERE alert_id='legacy-ack-before'`).Scan(&projection); err != nil {
		t.Fatal(err)
	}
	if baseline != 1 || projection != 1 {
		t.Fatalf("legacy ACK baseline=%d projection=%d want 1,1", baseline, projection)
	}
	for _, table := range []string{"correlation_receipts", "correlation_cursors",
		"correlation_pending_operations", "correlation_relationships", "correlation_events"} {
		if countRetentionRows(t, store.db, table) != 0 {
			t.Errorf("old correlation table %s was not fully reaped", table)
		}
	}
}

func assertRetentionSuffixes(t *testing.T, db interface {
	QueryRow(string, ...any) *sql.Row
}, table string) {
	t.Helper()
	var before, equal, after int
	if table == "findings" {
		before = countRetentionLike(t, db, table, "%scan-before")
		equal = countRetentionLike(t, db, table, "%scan-equal")
		after = countRetentionLike(t, db, table, "%scan-after")
	} else if table == "scan_findings" {
		before = countRetentionLike(t, db, table, "%scan-before")
		equal = countRetentionLike(t, db, table, "%scan-equal")
		after = countRetentionLike(t, db, table, "%scan-after")
	} else if table == "scan_results" {
		before = countRetentionLike(t, db, table, "scan-before")
		equal = countRetentionLike(t, db, table, "scan-equal")
		after = countRetentionLike(t, db, table, "scan-after")
	} else if table == "audit_events" {
		before = countRetentionLike(t, db, table, "audit-before")
		equal = countRetentionLike(t, db, table, "audit-equal")
		after = countRetentionLike(t, db, table, "audit-after")
	} else if table == "judge_responses" {
		before = countRetentionLike(t, db, table, "judge-before")
		equal = countRetentionLike(t, db, table, "judge-equal")
		after = countRetentionLike(t, db, table, "judge-after")
	} else {
		before = countRetentionLike(t, db, table, table+"-before")
		equal = countRetentionLike(t, db, table, table+"-equal")
		after = countRetentionLike(t, db, table, table+"-after")
	}
	if before != 0 || equal != 1 || after != 1 {
		t.Fatalf("%s boundary rows before/equal/after=%d/%d/%d", table, before, equal, after)
	}
}

func assertRetentionProtectedState(t *testing.T, store *Store, judge *JudgeBodyStore) {
	t.Helper()
	for _, table := range []string{
		"actions", "target_snapshots", "schema_version", "observability_store_readiness",
		"alert_acknowledgement_projection", "alert_acknowledgement_operations",
		"alert_acknowledgement_baselines", "alert_acknowledgement_health",
	} {
		if countRetentionRows(t, store.db, table) == 0 {
			t.Errorf("protected audit table %s was emptied", table)
		}
	}
	if countRetentionRows(t, judge.db, "schema_version") == 0 ||
		countRetentionRows(t, judge.db, "legacy_judge_cutover_state") != 1 {
		t.Fatal("protected judge schema/cutover state was reaped")
	}
	var oldMarker, equalMarker int
	if err := judge.db.QueryRow(`SELECT COUNT(*) FROM legacy_judge_cutover_rows
		WHERE legacy_id='judge-before'`).Scan(&oldMarker); err != nil {
		t.Fatal(err)
	}
	if err := judge.db.QueryRow(`SELECT COUNT(*) FROM legacy_judge_cutover_rows
		WHERE legacy_id='judge-equal'`).Scan(&equalMarker); err != nil {
		t.Fatal(err)
	}
	if oldMarker != 0 || equalMarker != 1 {
		t.Fatalf("cutover markers old/equal=%d/%d want 0/1", oldMarker, equalMarker)
	}
}

func seedRetentionActivityRows(t *testing.T, store *Store, count int, timestamp time.Time) {
	t.Helper()
	tx, err := store.db.Begin()
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck
	statement, err := tx.Prepare(`INSERT INTO activity_events
		(id, timestamp, retention_timestamp_unix_nano, actor, action, target_type, target_id)
		VALUES (?, ?, ?, 'operator', 'config-update', 'config', 'main')`)
	if err != nil {
		t.Fatal(err)
	}
	defer statement.Close() //nolint:errcheck
	for i := 0; i < count; i++ {
		if _, err := statement.Exec(
			fmt.Sprintf("cancel-%04d", i), timestamp.Format(time.RFC3339Nano), timestamp.UnixNano(),
		); err != nil {
			t.Fatal(err)
		}
	}
	if err := tx.Commit(); err != nil {
		t.Fatal(err)
	}
}

func seedJudgePair(t *testing.T, store *Store, _ *JudgeBodyStore, id string, timestamp time.Time) {
	t.Helper()
	response := JudgeResponse{
		ID: id, Timestamp: timestamp, Kind: "pii", Raw: "raw-" + id,
		RequestID: "request-" + id, TraceID: "trace-" + id,
	}
	if err := store.InsertJudgeResponse(response); err != nil {
		t.Fatal(err)
	}
}

func countRetentionRows(t *testing.T, db *sql.DB, table string) int {
	t.Helper()
	allowed := retentionAuditMigrationCatalog[table] != "" || retentionJudgeMigrationCatalog[table] != ""
	if !allowed {
		t.Fatalf("test attempted dynamic count for unknown table %s", table)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM ` + table).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func countRetentionLike(t *testing.T, db interface {
	QueryRow(string, ...any) *sql.Row
}, table, pattern string) int {
	t.Helper()
	if retentionAuditMigrationCatalog[table] == "" && retentionJudgeMigrationCatalog[table] == "" {
		t.Fatalf("test attempted dynamic query for unknown table %s", table)
	}
	var count int
	if err := db.QueryRow(`SELECT COUNT(*) FROM `+table+` WHERE id LIKE ?`, pattern).Scan(&count); err != nil {
		t.Fatal(err)
	}
	return count
}

func listRetentionTables(t *testing.T, db *sql.DB) []string {
	t.Helper()
	rows, err := db.Query(`SELECT name FROM sqlite_master
		WHERE type='table' AND name NOT LIKE 'sqlite_%' ORDER BY name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var tables []string
	for rows.Next() {
		var table string
		if err := rows.Scan(&table); err != nil {
			t.Fatal(err)
		}
		tables = append(tables, table)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return tables
}

func sortedRetentionCatalog(catalog map[string]retentionOwnership) []string {
	tables := make([]string, 0, len(catalog))
	for table := range catalog {
		tables = append(tables, table)
	}
	sort.Strings(tables)
	return tables
}

func stringsOf(value string, count int) string {
	result := ""
	for i := 0; i < count; i++ {
		result += value
	}
	return result
}
