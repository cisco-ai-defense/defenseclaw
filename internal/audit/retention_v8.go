// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"math"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"time"
)

const (
	RetentionBatchSize        = 1000
	RetentionScheduleInterval = 6 * time.Hour
)

// RetentionTableClass is a fixed metric/reporting label. Values can only come
// from the private retention registry; callers never supply a table name.
type RetentionTableClass string

const (
	RetentionAuditEvents              RetentionTableClass = "audit_events"
	RetentionActivityEvents           RetentionTableClass = "activity_events"
	RetentionNetworkEgressEvents      RetentionTableClass = "network_egress_events"
	RetentionSinkHealth               RetentionTableClass = "sink_health"
	RetentionScanFindings             RetentionTableClass = "scan_findings"
	RetentionLegacyFindings           RetentionTableClass = "legacy_findings"
	RetentionScanResults              RetentionTableClass = "scan_results"
	RetentionLegacyJudgeResponses     RetentionTableClass = "legacy_judge_responses"
	RetentionAuthoritativeJudgeBodies RetentionTableClass = "authoritative_judge_bodies"
	RetentionCorrelationReceipts      RetentionTableClass = "correlation_receipts"
	RetentionCorrelationCursors       RetentionTableClass = "correlation_cursors"
	RetentionCorrelationPending       RetentionTableClass = "correlation_pending_operations"
	RetentionCorrelationRelationships RetentionTableClass = "correlation_relationships"
	RetentionCorrelationEvents        RetentionTableClass = "correlation_events"
)

var retentionTableClasses = [...]RetentionTableClass{
	RetentionAuditEvents,
	RetentionActivityEvents,
	RetentionNetworkEgressEvents,
	RetentionSinkHealth,
	RetentionScanFindings,
	RetentionLegacyFindings,
	RetentionScanResults,
	RetentionLegacyJudgeResponses,
	RetentionAuthoritativeJudgeBodies,
	RetentionCorrelationReceipts,
	RetentionCorrelationCursors,
	RetentionCorrelationPending,
	RetentionCorrelationRelationships,
	RetentionCorrelationEvents,
}

// RetentionFailureClass is deliberately bounded and contains no driver error,
// row content, path, table name supplied by a caller, or SQL text.
type RetentionFailureClass string

const (
	RetentionFailureCancelled               RetentionFailureClass = "cancelled"
	RetentionFailureConcurrentRun           RetentionFailureClass = "concurrent_run"
	RetentionFailureAuditStore              RetentionFailureClass = "audit_store"
	RetentionFailureLegacyJudgeStore        RetentionFailureClass = "legacy_judge_store"
	RetentionFailureAuthoritativeJudgeStore RetentionFailureClass = "authoritative_judge_store"
	RetentionFailureJudgeCopyMissing        RetentionFailureClass = "judge_copy_missing"
	RetentionFailureCrossDatabase           RetentionFailureClass = "cross_database_transition"
	RetentionFailureCheckpoint              RetentionFailureClass = "checkpoint"
)

// RetentionRunResult is bounded by the fixed class registry. RowsDeleted always
// has exactly the registry's keys and contains counts only.
type RetentionRunResult struct {
	Disabled      bool
	Cutoff        time.Time
	CompletedAt   time.Time
	Duration      time.Duration
	BatchCount    int64
	RowsDeleted   map[RetentionTableClass]int64
	ProtectedRows map[RetentionProtectedClass]int64
}

type RetentionProtectedClass string

const (
	RetentionProtectedAlertProjection RetentionProtectedClass = "alert_projection"
	RetentionProtectedAlertOperations RetentionProtectedClass = "alert_operations"
	RetentionProtectedAlertBaselines  RetentionProtectedClass = "alert_baselines"
	RetentionProtectedAlertHealth     RetentionProtectedClass = "alert_health"
)

var retentionProtectedClasses = [...]RetentionProtectedClass{
	RetentionProtectedAlertProjection,
	RetentionProtectedAlertOperations,
	RetentionProtectedAlertBaselines,
	RetentionProtectedAlertHealth,
}

// RetentionRunReport is the health/metrics integration boundary. A reporter can
// derive duration, last success, per-class row counts, batch count, and bounded
// failure counters without receiving database diagnostics or stored content.
type RetentionRunReport struct {
	Success      bool
	FailureClass RetentionFailureClass
	Result       RetentionRunResult
}

type RetentionReporter interface {
	ReportRetentionRun(RetentionRunReport)
}

type RetentionHealthState string

const (
	RetentionHealthDegraded  RetentionHealthState = "degraded"
	RetentionHealthRecovered RetentionHealthState = "recovered"
)

type RetentionHealthTransition struct {
	State        RetentionHealthState
	FailureClass RetentionFailureClass
}

type RetentionHealthReporter interface {
	ReportRetentionHealth(RetentionHealthTransition)
}

type RetentionOptions struct {
	Reporter          RetentionReporter
	HealthReporter    RetentionHealthReporter
	PassiveCheckpoint bool
}

type retentionHooks struct {
	now                           func() time.Time
	yield                         func(context.Context) error
	afterTimestampRepairs         func() error
	beforeAuditBatchCommit        func(RetentionTableClass) error
	beforeScanParentDrain         func() error
	afterLegacyJudgeCommit        func() error
	afterAuthoritativeJudgeCommit func() error
	checkpoint                    func(context.Context, *Store, *JudgeBodyStore) error
}

func (hooks retentionHooks) withDefaults() retentionHooks {
	if hooks.now == nil {
		hooks.now = time.Now
	}
	if hooks.yield == nil {
		hooks.yield = func(ctx context.Context) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			runtime.Gosched()
			return ctx.Err()
		}
	}
	if hooks.checkpoint == nil {
		hooks.checkpoint = passiveRetentionCheckpoint
	}
	return hooks
}

type RetentionReaper struct {
	store             *Store
	judgeBodies       *JudgeBodyStore
	retentionDays     atomic.Int64
	reporter          RetentionReporter
	healthReporter    RetentionHealthReporter
	passiveCheckpoint bool
	hooks             retentionHooks
	running           atomic.Bool
	reload            chan struct{}
	promptRun         atomic.Bool
	healthMu          sync.Mutex
	lastHealthFailure RetentionFailureClass
}

// NewRetentionReaper validates and snapshots the one global retention age. It
// may be constructed before Store readiness so startup can initialize the
// reaper before publishing readiness; Run still fails closed until the Store is
// ready. A nil judge store is allowed only when no authoritative database is in
// scope and no eligible legacy judge rows require ordered deletion.
func NewRetentionReaper(
	store *Store,
	judgeBodies *JudgeBodyStore,
	retentionDays int64,
	options RetentionOptions,
) (*RetentionReaper, error) {
	return newRetentionReaperWithHooks(store, judgeBodies, retentionDays, options, retentionHooks{})
}

func newRetentionReaperWithHooks(
	store *Store,
	judgeBodies *JudgeBodyStore,
	retentionDays int64,
	options RetentionOptions,
	hooks retentionHooks,
) (*RetentionReaper, error) {
	if store == nil || store.db == nil {
		return nil, errors.New("audit: retention requires an initialized audit store")
	}
	if err := validateRetentionDays(retentionDays); err != nil {
		return nil, errors.New("audit: retention_days is outside the supported range")
	}
	reaper := &RetentionReaper{
		store: store, judgeBodies: judgeBodies,
		reporter: options.Reporter, healthReporter: options.HealthReporter,
		passiveCheckpoint: options.PassiveCheckpoint,
		hooks:             hooks.withDefaults(), reload: make(chan struct{}, 1),
	}
	reaper.retentionDays.Store(retentionDays)
	return reaper, nil
}

func (reaper *RetentionReaper) RetentionDays() int64 {
	if reaper == nil {
		return 0
	}
	return reaper.retentionDays.Load()
}

func validateRetentionDays(days int64) error {
	const day = int64(24 * time.Hour)
	if days < 0 || days > math.MaxInt64/day {
		return errors.New("retention_days is outside the supported range")
	}
	return nil
}

// UpdateRetentionDays atomically changes the next run's single age after full
// validation. A shorter policy requests one prompt asynchronous run; invalid
// reloads leave the previously active policy untouched.
func (reaper *RetentionReaper) UpdateRetentionDays(days int64) error {
	if reaper == nil {
		return errors.New("audit: retention is not initialized")
	}
	if err := validateRetentionDays(days); err != nil {
		return fmt.Errorf("audit: %w", err)
	}
	previous := reaper.retentionDays.Swap(days)
	if days > 0 && (previous == 0 || days < previous) {
		reaper.promptRun.Store(true)
	}
	select {
	case reaper.reload <- struct{}{}:
	default:
	}
	return nil
}

// ScheduleInterval returns false for retention_days=0, which is the explicit
// no-deletion/no-schedule policy.
func (reaper *RetentionReaper) ScheduleInterval() (time.Duration, bool) {
	if reaper == nil || reaper.retentionDays.Load() == 0 {
		return 0, false
	}
	return RetentionScheduleInterval, true
}

type RetentionScheduleWake uint8

const (
	RetentionScheduleTick RetentionScheduleWake = iota + 1
	RetentionScheduleReload
)

// RetentionScheduler is injectable so scheduling tests never wait for wall
// time. An interval of zero means no deletion timer: wait only for reload or
// cancellation.
type RetentionScheduler interface {
	Wait(context.Context, time.Duration, <-chan struct{}) (RetentionScheduleWake, error)
}

type TimerRetentionScheduler struct{}

func (TimerRetentionScheduler) Wait(
	ctx context.Context,
	interval time.Duration,
	reload <-chan struct{},
) (RetentionScheduleWake, error) {
	if interval == 0 {
		select {
		case <-ctx.Done():
			return 0, ctx.Err()
		case <-reload:
			return RetentionScheduleReload, nil
		}
	}
	timer := time.NewTimer(interval)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return 0, ctx.Err()
	case <-reload:
		return RetentionScheduleReload, nil
	case <-timer.C:
		return RetentionScheduleTick, nil
	}
}

// RunScheduled performs the startup run and six-hour cadence. Retention errors
// are reported by Run and do not terminate the scheduler; cancellation and a
// scheduler implementation error do.
func (reaper *RetentionReaper) RunScheduled(ctx context.Context, scheduler RetentionScheduler) error {
	if reaper == nil || scheduler == nil {
		return errors.New("audit: retention scheduler is not initialized")
	}
	if ctx == nil {
		return errors.New("audit: retention scheduler context is required")
	}
	if reaper.retentionDays.Load() > 0 {
		_, _ = reaper.Run(ctx)
	}
	for {
		interval, enabled := reaper.ScheduleInterval()
		if !enabled {
			interval = 0
		}
		wake, err := scheduler.Wait(ctx, interval, reaper.reload)
		if err != nil {
			return err
		}
		switch wake {
		case RetentionScheduleTick:
			if reaper.retentionDays.Load() > 0 {
				_, _ = reaper.Run(ctx)
			}
		case RetentionScheduleReload:
			if reaper.promptRun.Swap(false) && reaper.retentionDays.Load() > 0 {
				_, _ = reaper.Run(ctx)
			}
		default:
			return errors.New("audit: retention scheduler returned an invalid wake reason")
		}
	}
}

type retentionAuditTable struct {
	class RetentionTableClass
	table string
}

// Order is normative. Scan children precede their parent, while independent
// history tables use one fixed deterministic order.
var retentionAuditRegistry = [...]retentionAuditTable{
	{class: RetentionAuditEvents, table: "audit_events"},
	{class: RetentionActivityEvents, table: "activity_events"},
	{class: RetentionNetworkEgressEvents, table: "network_egress_events"},
	{class: RetentionSinkHealth, table: "sink_health"},
	{class: RetentionScanFindings, table: "scan_findings"},
	{class: RetentionLegacyFindings, table: "findings"},
	{class: RetentionScanResults, table: "scan_results"},
}

type retentionTimestampSpec struct {
	table string
	index string
}

var retentionTimestampRegistry = [...]retentionTimestampSpec{
	{table: "audit_events", index: "idx_retention_audit_events_timestamp"},
	{table: "activity_events", index: "idx_retention_activity_events_timestamp"},
	{table: "network_egress_events", index: "idx_retention_network_egress_timestamp"},
	{table: "sink_health", index: "idx_retention_sink_health_timestamp"},
	{table: "scan_findings", index: "idx_retention_scan_findings_timestamp"},
	{table: "scan_results", index: "idx_retention_scan_results_timestamp"},
}

type retentionOwnership string

const (
	retentionOwnedHistory   retentionOwnership = "history"
	retentionOwnedProtected retentionOwnership = "protected"
	retentionOwnedGraph     retentionOwnership = "graph"
)

// Correlation state has a fixed graph-aware lifecycle. Direct stages are
// counted; identifiers, observations, and relationship evidence are removed by
// declared foreign-key cascades from their owning event/relationship.
var retentionCorrelationGraphTables = map[string]bool{
	"correlation_events": true, "correlation_identifiers": true,
	"correlation_identity_claims": true,
	"correlation_observations":    true, "correlation_relationships": true,
	"correlation_relationship_evidence": true, "correlation_cursors": true,
	"correlation_pending_operations": true, "correlation_receipts": true,
}

// These catalogs deliberately cover every application table created by the
// two migration lists. The completeness test compares the live migrated schema
// to these declarations and then verifies every history table has a reaper.
var retentionAuditMigrationCatalog = map[string]retentionOwnership{
	"audit_events": retentionOwnedHistory, "activity_events": retentionOwnedHistory,
	"network_egress_events": retentionOwnedHistory, "sink_health": retentionOwnedHistory,
	"scan_findings": retentionOwnedHistory, "findings": retentionOwnedHistory,
	"scan_results": retentionOwnedHistory, "judge_responses": retentionOwnedHistory,
	"actions": retentionOwnedProtected, "target_snapshots": retentionOwnedProtected,
	"schema_version": retentionOwnedProtected, "observability_store_readiness": retentionOwnedProtected,
	"alert_acknowledgement_projection": retentionOwnedProtected,
	"alert_acknowledgement_operations": retentionOwnedProtected,
	"alert_acknowledgement_baselines":  retentionOwnedProtected,
	"alert_acknowledgement_health":     retentionOwnedProtected,
	"quarantine_records":               retentionOwnedProtected,
	"quarantine_record_connectors":     retentionOwnedProtected,
	// Correlation state is graph-owned rather than independent row history.
	// Its bounded graph reaper is added alongside the ledger so the generic
	// table reaper can never delete a parent before its cursor, receipt, or
	// relationship evidence has been resolved.
	"correlation_connector_instances":   retentionOwnedProtected,
	"correlation_events":                retentionOwnedGraph,
	"correlation_identifiers":           retentionOwnedGraph,
	"correlation_identity_claims":       retentionOwnedGraph,
	"correlation_observations":          retentionOwnedGraph,
	"correlation_relationships":         retentionOwnedGraph,
	"correlation_relationship_evidence": retentionOwnedGraph,
	"correlation_cursors":               retentionOwnedGraph,
	"correlation_pending_operations":    retentionOwnedGraph,
	"correlation_receipts":              retentionOwnedGraph,
}

var retentionJudgeMigrationCatalog = map[string]retentionOwnership{
	"judge_responses":            retentionOwnedHistory,
	"schema_version":             retentionOwnedProtected,
	"legacy_judge_cutover_rows":  retentionOwnedProtected,
	"legacy_judge_cutover_state": retentionOwnedProtected,
}

type retentionRunError struct {
	class RetentionFailureClass
	cause error
}

func (err *retentionRunError) Error() string {
	if err == nil {
		return "audit: retention run failed"
	}
	return "audit: retention run failed: " + string(err.class)
}

func (err *retentionRunError) Unwrap() error {
	if err == nil {
		return nil
	}
	return err.cause
}

func retentionRunFailure(class RetentionFailureClass, cause error) error {
	return &retentionRunError{class: class, cause: cause}
}

func retentionFailureClass(err error) RetentionFailureClass {
	if err == nil {
		return ""
	}
	if errors.Is(err, context.Canceled) || errors.Is(err, context.DeadlineExceeded) {
		return RetentionFailureCancelled
	}
	var runErr *retentionRunError
	if errors.As(err, &runErr) {
		return runErr.class
	}
	return RetentionFailureAuditStore
}

// Run computes one UTC cutoff and drains every registered class in bounded
// transactions. It is safe to call again after any partial failure; committed
// batches are idempotently absent and the next run resumes in registry order.
func (reaper *RetentionReaper) Run(ctx context.Context) (RetentionRunResult, error) {
	result := RetentionRunResult{
		RowsDeleted: newRetentionCounts(), ProtectedRows: newRetentionProtectedCounts(),
	}
	if reaper == nil || reaper.store == nil || reaper.store.db == nil {
		return result, retentionRunFailure(RetentionFailureAuditStore, errors.New("retention is not initialized"))
	}
	if ctx == nil {
		return result, retentionRunFailure(RetentionFailureCancelled, errors.New("retention context is required"))
	}
	if !reaper.running.CompareAndSwap(false, true) {
		err := retentionRunFailure(RetentionFailureConcurrentRun, errors.New("retention run already active"))
		reaper.report(result, err)
		return result, err
	}
	defer reaper.running.Store(false)

	started := reaper.hooks.now().UTC()
	days := reaper.retentionDays.Load()
	if days == 0 {
		result.Disabled = true
		result.CompletedAt = started
		reaper.finishTiming(&result, started)
		reaper.report(result, nil)
		return result, nil
	}
	cutoff := started.Add(-time.Duration(days) * 24 * time.Hour)
	result.Cutoff = cutoff

	var runErr error
	judgeSourceKey := ""
	if err := ctx.Err(); err != nil {
		runErr = err
	} else {
		judgeSourceKey, runErr = reaper.preflightJudgeRetention(ctx, cutoff)
	}
	if runErr == nil {
		for _, spec := range retentionAuditRegistry {
			if err := reaper.repairRetentionTimestamps(ctx, spec); err != nil {
				runErr = retentionRunFailure(RetentionFailureAuditStore, err)
				break
			}
		}
	}
	if runErr == nil && reaper.hooks.afterTimestampRepairs != nil {
		if err := reaper.hooks.afterTimestampRepairs(); err != nil {
			runErr = retentionRunFailure(RetentionFailureAuditStore, err)
		}
	}
	if runErr == nil {
		if err := reaper.drainCorrelationState(ctx, cutoff, started, &result); err != nil {
			runErr = retentionRunFailure(RetentionFailureAuditStore, err)
		}
	}
	if runErr == nil {
		for _, spec := range retentionAuditRegistry {
			if err := reaper.drainAuditTable(ctx, spec, cutoff, started, &result); err != nil {
				runErr = retentionRunFailure(RetentionFailureAuditStore, err)
				break
			}
			if spec.class == RetentionLegacyFindings && reaper.hooks.beforeScanParentDrain != nil {
				if err := reaper.hooks.beforeScanParentDrain(); err != nil {
					runErr = retentionRunFailure(RetentionFailureAuditStore, err)
					break
				}
			}
		}
	}
	if runErr == nil {
		runErr = reaper.drainJudgeBodies(ctx, cutoff, judgeSourceKey, &result)
	}
	if runErr == nil {
		result.ProtectedRows, runErr = reaper.readProtectedCapacity(ctx)
		if runErr != nil {
			runErr = retentionRunFailure(RetentionFailureAuditStore, runErr)
		}
	}
	if runErr == nil && reaper.passiveCheckpoint {
		if err := reaper.hooks.checkpoint(ctx, reaper.store, reaper.judgeBodies); err != nil {
			runErr = retentionRunFailure(RetentionFailureCheckpoint, err)
		}
	}
	if runErr == nil {
		result.CompletedAt = reaper.hooks.now().UTC()
	}
	reaper.finishTiming(&result, started)
	reaper.report(result, runErr)
	return result, runErr
}

func newRetentionCounts() map[RetentionTableClass]int64 {
	counts := make(map[RetentionTableClass]int64, len(retentionTableClasses))
	for _, class := range retentionTableClasses {
		counts[class] = 0
	}
	return counts
}

func newRetentionProtectedCounts() map[RetentionProtectedClass]int64 {
	counts := make(map[RetentionProtectedClass]int64, len(retentionProtectedClasses))
	for _, class := range retentionProtectedClasses {
		counts[class] = 0
	}
	return counts
}

func (reaper *RetentionReaper) finishTiming(result *RetentionRunResult, started time.Time) {
	ended := reaper.hooks.now().UTC()
	if ended.Before(started) {
		ended = started
	}
	result.Duration = ended.Sub(started)
}

func (reaper *RetentionReaper) report(result RetentionRunResult, err error) {
	if reaper == nil {
		return
	}
	if reaper.reporter != nil {
		copyResult := result
		copyResult.RowsDeleted = newRetentionCounts()
		for class, count := range result.RowsDeleted {
			copyResult.RowsDeleted[class] = count
		}
		copyResult.ProtectedRows = newRetentionProtectedCounts()
		for class, count := range result.ProtectedRows {
			copyResult.ProtectedRows[class] = count
		}
		reaper.reporter.ReportRetentionRun(RetentionRunReport{
			Success: err == nil, FailureClass: retentionFailureClass(err), Result: copyResult,
		})
	}
	reaper.reportHealthTransition(err)
}

func (reaper *RetentionReaper) reportHealthTransition(err error) {
	if reaper == nil || reaper.healthReporter == nil {
		return
	}
	class := retentionFailureClass(err)
	reaper.healthMu.Lock()
	var transition *RetentionHealthTransition
	if err == nil {
		if reaper.lastHealthFailure == "" {
			reaper.healthMu.Unlock()
			return
		}
		reaper.lastHealthFailure = ""
		value := RetentionHealthTransition{
			State: RetentionHealthRecovered,
		}
		transition = &value
	} else {
		if reaper.lastHealthFailure == class {
			reaper.healthMu.Unlock()
			return
		}
		reaper.lastHealthFailure = class
		value := RetentionHealthTransition{
			State: RetentionHealthDegraded, FailureClass: class,
		}
		transition = &value
	}
	reaper.healthMu.Unlock()
	reaper.healthReporter.ReportRetentionHealth(*transition)
}

func (reaper *RetentionReaper) readProtectedCapacity(
	ctx context.Context,
) (map[RetentionProtectedClass]int64, error) {
	counts := newRetentionProtectedCounts()
	release, err := reaper.store.acquireReady()
	if err != nil {
		return counts, err
	}
	defer release()
	queries := [...]struct {
		class RetentionProtectedClass
		sql   string
	}{
		{RetentionProtectedAlertProjection, `SELECT COUNT(*) FROM alert_acknowledgement_projection`},
		{RetentionProtectedAlertOperations, `SELECT COUNT(*) FROM alert_acknowledgement_operations`},
		{RetentionProtectedAlertBaselines, `SELECT COUNT(*) FROM alert_acknowledgement_baselines`},
		{RetentionProtectedAlertHealth, `SELECT COUNT(*) FROM alert_acknowledgement_health`},
	}
	for _, query := range queries {
		var count int64
		if err := reaper.store.db.QueryRowContext(ctx, query.sql).Scan(&count); err != nil {
			return counts, err
		}
		counts[query.class] = count
	}
	return counts, nil
}

func (reaper *RetentionReaper) drainAuditTable(
	ctx context.Context,
	spec retentionAuditTable,
	cutoff time.Time,
	baselineAt time.Time,
	result *RetentionRunResult,
) error {
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		deleted, err := reaper.deleteAuditBatch(ctx, spec, cutoff, baselineAt)
		if err != nil {
			return err
		}
		if deleted == 0 {
			return nil
		}
		result.RowsDeleted[spec.class] += deleted
		result.BatchCount++
		if err := reaper.hooks.yield(ctx); err != nil {
			return err
		}
		if deleted < RetentionBatchSize {
			return nil
		}
	}
}

// drainCorrelationState follows dependency order. Receipts and inactive state
// release event references first; relationships release their evidence; only
// then may an old, wholly unreferenced event cascade to identifiers and
// observations. Connector instances and active state are never candidates.
func (reaper *RetentionReaper) drainCorrelationState(
	ctx context.Context,
	cutoff time.Time,
	now time.Time,
	result *RetentionRunResult,
) error {
	stages := [...]struct {
		class RetentionTableClass
		args  []any
	}{
		{RetentionCorrelationReceipts, []any{unixNano(now)}},
		{RetentionCorrelationCursors, []any{unixNano(cutoff)}},
		{RetentionCorrelationPending, []any{unixNano(cutoff)}},
		{RetentionCorrelationRelationships, []any{unixNano(now), unixNano(now), unixNano(cutoff)}},
		{RetentionCorrelationEvents, []any{unixNano(cutoff)}},
	}
	for _, stage := range stages {
		for {
			if err := ctx.Err(); err != nil {
				return err
			}
			deleted, err := reaper.deleteCorrelationBatch(ctx, stage.class, stage.args...)
			if err != nil {
				return err
			}
			if deleted == 0 {
				break
			}
			result.RowsDeleted[stage.class] += deleted
			result.BatchCount++
			if err := reaper.hooks.yield(ctx); err != nil {
				return err
			}
			if deleted < RetentionBatchSize {
				break
			}
		}
	}
	return nil
}

func (reaper *RetentionReaper) deleteCorrelationBatch(
	ctx context.Context,
	class RetentionTableClass,
	args ...any,
) (int64, error) {
	statement, err := correlationRetentionDeleteStatement(class)
	if err != nil {
		return 0, err
	}
	args = append(args, RetentionBatchSize)
	release, err := reaper.store.acquireReady()
	if err != nil {
		return 0, err
	}
	defer release()
	var deleted int64
	err = retryBusy(ctx, "observability_v8_retention_"+string(class), func() error {
		tx, beginErr := reaper.store.db.BeginTx(ctx, nil)
		if beginErr != nil {
			return beginErr
		}
		defer tx.Rollback() //nolint:errcheck
		res, execErr := tx.ExecContext(ctx, statement, args...)
		if execErr != nil {
			return execErr
		}
		rows, rowsErr := res.RowsAffected()
		if rowsErr != nil {
			return rowsErr
		}
		if rows > RetentionBatchSize {
			return errors.New("correlation retention batch exceeded fixed limit")
		}
		if rows > 0 && reaper.hooks.beforeAuditBatchCommit != nil {
			if hookErr := reaper.hooks.beforeAuditBatchCommit(class); hookErr != nil {
				return hookErr
			}
		}
		if commitErr := tx.Commit(); commitErr != nil {
			return commitErr
		}
		deleted = rows
		return nil
	})
	return deleted, err
}

func correlationRetentionDeleteStatement(class RetentionTableClass) (string, error) {
	switch class {
	case RetentionCorrelationReceipts:
		return `DELETE FROM correlation_receipts WHERE rowid IN (
			SELECT rowid FROM correlation_receipts
			WHERE expires_time_unix_nano < ?
			ORDER BY expires_time_unix_nano, connector_instance_id, source_key_digest,
				fingerprint_sha256 LIMIT ?
		)`, nil
	case RetentionCorrelationCursors:
		return `DELETE FROM correlation_cursors WHERE rowid IN (
			SELECT rowid FROM correlation_cursors
			WHERE active=0 AND updated_time_unix_nano < ?
			ORDER BY updated_time_unix_nano, connector_instance_id, session_id, agent_id LIMIT ?
		)`, nil
	case RetentionCorrelationPending:
		return `DELETE FROM correlation_pending_operations WHERE rowid IN (
			SELECT rowid FROM correlation_pending_operations
			WHERE status<>'active' AND updated_time_unix_nano < ?
			ORDER BY updated_time_unix_nano, connector_instance_id, operation_id, operation_type LIMIT ?
		)`, nil
	case RetentionCorrelationRelationships:
		return `DELETE FROM correlation_relationships WHERE rowid IN (
			WITH protected_nodes(kind, id) AS (
				SELECT 'semantic_event', semantic_event_id FROM correlation_receipts
					WHERE expires_time_unix_nano >= ?
				UNION SELECT 'semantic_event', conflicts_with_semantic_event_id FROM correlation_receipts
					WHERE expires_time_unix_nano >= ? AND conflicts_with_semantic_event_id IS NOT NULL
				UNION SELECT 'semantic_event', last_semantic_event_id FROM correlation_cursors
					WHERE active=1 AND last_semantic_event_id IS NOT NULL
				UNION SELECT 'session', session_id FROM correlation_cursors WHERE active=1
				UNION SELECT 'agent', agent_id FROM correlation_cursors WHERE active=1
				UNION SELECT 'lifecycle', lifecycle_id FROM correlation_cursors
					WHERE active=1 AND lifecycle_id IS NOT NULL
				UNION SELECT 'execution', execution_id FROM correlation_cursors
					WHERE active=1 AND execution_id IS NOT NULL
				UNION SELECT 'turn', active_turn_id FROM correlation_cursors
					WHERE active=1 AND active_turn_id IS NOT NULL
				UNION SELECT 'semantic_event', start_semantic_event_id FROM correlation_pending_operations
					WHERE status='active'
				UNION SELECT 'session', session_id FROM correlation_pending_operations
					WHERE status='active' AND session_id IS NOT NULL
				UNION SELECT 'turn', turn_id FROM correlation_pending_operations
					WHERE status='active' AND turn_id IS NOT NULL
				UNION SELECT 'agent', agent_id FROM correlation_pending_operations
					WHERE status='active' AND agent_id IS NOT NULL
				UNION SELECT 'execution', execution_id FROM correlation_pending_operations
					WHERE status='active' AND execution_id IS NOT NULL
				UNION SELECT CASE operation_type WHEN 'model' THEN 'model_request'
					ELSE 'tool_invocation' END, operation_id FROM correlation_pending_operations
					WHERE status='active'
			)
			SELECT relationship.rowid FROM correlation_relationships AS relationship
			WHERE relationship.last_seen_time_unix_nano < ?
			AND NOT EXISTS (SELECT 1 FROM protected_nodes AS node WHERE
				(node.kind=relationship.from_kind AND node.id=relationship.from_id) OR
				(node.kind=relationship.to_kind AND node.id=relationship.to_id))
			AND NOT EXISTS (
				SELECT 1 FROM correlation_relationship_evidence AS evidence
				JOIN protected_nodes AS node ON node.kind='semantic_event'
					AND node.id=evidence.semantic_event_id
				WHERE evidence.relationship_id=relationship.relationship_id
			)
			ORDER BY relationship.last_seen_time_unix_nano, relationship.relationship_id LIMIT ?
		)`, nil
	case RetentionCorrelationEvents:
		return `DELETE FROM correlation_events WHERE rowid IN (
			SELECT event.rowid FROM correlation_events AS event
			WHERE event.received_time_unix_nano < ?
			AND NOT EXISTS (SELECT 1 FROM correlation_receipts AS receipt WHERE
				receipt.semantic_event_id=event.semantic_event_id OR
				receipt.conflicts_with_semantic_event_id=event.semantic_event_id)
			AND NOT EXISTS (SELECT 1 FROM correlation_cursors AS cursor
				WHERE cursor.last_semantic_event_id=event.semantic_event_id)
			AND NOT EXISTS (SELECT 1 FROM correlation_pending_operations AS operation WHERE
				operation.start_semantic_event_id=event.semantic_event_id OR
				operation.terminal_semantic_event_id=event.semantic_event_id)
			AND NOT EXISTS (SELECT 1 FROM correlation_relationship_evidence AS evidence
				WHERE evidence.semantic_event_id=event.semantic_event_id)
			AND NOT EXISTS (
				SELECT 1 FROM correlation_relationship_evidence AS evidence
				JOIN correlation_observations AS observation
					ON observation.record_id=evidence.evidence_record_id
				WHERE observation.semantic_event_id=event.semantic_event_id
			)
			AND NOT EXISTS (SELECT 1 FROM correlation_relationships AS relationship WHERE
				(relationship.from_kind='semantic_event' AND relationship.from_id=event.semantic_event_id) OR
				(relationship.to_kind='semantic_event' AND relationship.to_id=event.semantic_event_id) OR
				(relationship.from_kind='logical_event' AND relationship.from_id=event.logical_group_id) OR
				(relationship.to_kind='logical_event' AND relationship.to_id=event.logical_group_id))
			ORDER BY event.received_time_unix_nano, event.semantic_event_id LIMIT ?
		)`, nil
	default:
		return "", errors.New("retention registry contains an unsupported correlation class")
	}
}

func (reaper *RetentionReaper) deleteAuditBatch(
	ctx context.Context,
	spec retentionAuditTable,
	cutoff time.Time,
	baselineAt time.Time,
) (int64, error) {
	cutoffUnixNano, err := judgeBodyUnixNano(cutoff)
	if err != nil {
		return 0, err
	}
	release, err := reaper.store.acquireReady()
	if err != nil {
		return 0, err
	}
	defer release()
	var deleted int64
	err = retryBusy(ctx, "observability_v8_retention_"+string(spec.class), func() error {
		tx, beginErr := reaper.store.db.BeginTx(ctx, nil)
		if beginErr != nil {
			return beginErr
		}
		defer tx.Rollback() //nolint:errcheck
		var candidateCount int64
		if spec.class == RetentionAuditEvents {
			var candidateErr error
			candidateCount, candidateErr = materializeRetentionAuditCandidates(ctx, tx, cutoffUnixNano)
			if candidateErr != nil {
				return candidateErr
			}
			if baselineErr := materializeRetentionACKBaselines(ctx, tx, baselineAt); baselineErr != nil {
				return baselineErr
			}
		}
		statement, statementErr := retentionAuditDeleteStatement(spec.class)
		if statementErr != nil {
			return statementErr
		}
		var res sql.Result
		var execErr error
		if spec.class == RetentionAuditEvents {
			res, execErr = tx.ExecContext(ctx, statement)
		} else {
			res, execErr = tx.ExecContext(ctx, statement, cutoffUnixNano, RetentionBatchSize)
		}
		if execErr != nil {
			return execErr
		}
		rows, rowsErr := res.RowsAffected()
		if rowsErr != nil {
			return rowsErr
		}
		if rows > RetentionBatchSize {
			return errors.New("retention batch exceeded fixed limit")
		}
		if spec.class == RetentionAuditEvents && rows != candidateCount {
			return errors.New("retention audit candidate batch changed within transaction")
		}
		if rows > 0 && reaper.hooks.beforeAuditBatchCommit != nil {
			if hookErr := reaper.hooks.beforeAuditBatchCommit(spec.class); hookErr != nil {
				return hookErr
			}
		}
		if commitErr := tx.Commit(); commitErr != nil {
			return commitErr
		}
		deleted = rows
		return nil
	})
	return deleted, err
}

func retentionAuditDeleteStatement(class RetentionTableClass) (string, error) {
	switch class {
	case RetentionAuditEvents:
		return `DELETE FROM audit_events WHERE id IN (
			SELECT id FROM retention_v8_audit_candidates
		)`, nil
	case RetentionActivityEvents:
		return `DELETE FROM activity_events WHERE id IN (
			SELECT id FROM activity_events
			WHERE retention_timestamp_unix_nano < ?
			ORDER BY retention_timestamp_unix_nano ASC, id ASC LIMIT ?
		)`, nil
	case RetentionNetworkEgressEvents:
		return `DELETE FROM network_egress_events WHERE id IN (
			SELECT id FROM network_egress_events
			WHERE retention_timestamp_unix_nano < ?
			ORDER BY retention_timestamp_unix_nano ASC, id ASC LIMIT ?
		)`, nil
	case RetentionSinkHealth:
		return `DELETE FROM sink_health WHERE id IN (
			SELECT id FROM sink_health
			WHERE retention_timestamp_unix_nano < ?
			ORDER BY retention_timestamp_unix_nano ASC, id ASC LIMIT ?
		)`, nil
	case RetentionScanFindings:
		return `DELETE FROM scan_findings WHERE id IN (
			SELECT id FROM scan_findings INDEXED BY idx_retention_scan_findings_timestamp
			WHERE retention_timestamp_unix_nano < ?
			ORDER BY retention_timestamp_unix_nano ASC, id ASC LIMIT ?
		)`, nil
	case RetentionLegacyFindings:
		return `DELETE FROM findings WHERE id IN (
			SELECT finding.id FROM scan_results AS scan
			     INDEXED BY idx_retention_scan_results_timestamp
			JOIN findings AS finding INDEXED BY idx_finding_scan
			  ON finding.scan_id = scan.id
			WHERE scan.retention_timestamp_unix_nano < ?
			ORDER BY scan.retention_timestamp_unix_nano ASC, finding.id ASC LIMIT ?
		)`, nil
	case RetentionScanResults:
		return `DELETE FROM scan_results WHERE id IN (
			SELECT id FROM scan_results
			WHERE retention_timestamp_unix_nano < ?
			  AND NOT EXISTS (SELECT 1 FROM scan_findings WHERE scan_id = scan_results.id)
			  AND NOT EXISTS (SELECT 1 FROM findings WHERE scan_id = scan_results.id)
			ORDER BY retention_timestamp_unix_nano ASC, id ASC LIMIT ?
		)`, nil
	default:
		return "", errors.New("retention registry contains an unsupported audit class")
	}
}

const retentionAuditCandidateSelect = `SELECT id FROM audit_events
	WHERE retention_timestamp_unix_nano < ?
	ORDER BY retention_timestamp_unix_nano ASC, id ASC LIMIT ?`

func materializeRetentionAuditCandidates(
	ctx context.Context,
	tx *sql.Tx,
	cutoffUnixNano int64,
) (int64, error) {
	if _, err := tx.ExecContext(ctx, `CREATE TEMP TABLE IF NOT EXISTS
		retention_v8_audit_candidates (id TEXT PRIMARY KEY) WITHOUT ROWID`); err != nil {
		return 0, fmt.Errorf("retention create bounded audit candidate set: %w", err)
	}
	if _, err := tx.ExecContext(ctx, `DELETE FROM retention_v8_audit_candidates`); err != nil {
		return 0, fmt.Errorf("retention clear bounded audit candidate set: %w", err)
	}
	result, err := tx.ExecContext(ctx,
		`INSERT INTO retention_v8_audit_candidates (id) `+retentionAuditCandidateSelect,
		cutoffUnixNano, RetentionBatchSize)
	if err != nil {
		return 0, fmt.Errorf("retention materialize bounded audit candidate set: %w", err)
	}
	count, err := result.RowsAffected()
	if err != nil {
		return 0, fmt.Errorf("retention count bounded audit candidate set: %w", err)
	}
	if count > RetentionBatchSize {
		return 0, errors.New("retention audit candidate set exceeded fixed batch size")
	}
	return count, nil
}

func materializeRetentionACKBaselines(
	ctx context.Context,
	tx *sql.Tx,
	createdAt time.Time,
) error {
	actions := legacyAlertEligibleActions()
	if len(actions) == 0 {
		return errors.New("retention legacy ACK action registry is empty")
	}
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(actions)), ",")
	args := []any{createdAt.Format(time.RFC3339Nano)}
	for _, action := range actions {
		args = append(args, action)
	}
	_, err := tx.ExecContext(ctx, fmt.Sprintf(`
		INSERT OR IGNORE INTO alert_acknowledgement_baselines (
			alert_id, baseline_version, disposition, actor, disposition_at,
			legacy_event_id, raw_legacy_severity, legacy_original_severity,
			timestamp_provenance, created_at
		)
		SELECT event.id, 1, 'acknowledged', COALESCE(NULLIF(event.actor,''), 'unknown'), event.timestamp,
			event.id, 'ACK', 'unknown', 'legacy_occurrence_timestamp_unreliable', ?
		FROM audit_events AS event
		JOIN retention_v8_audit_candidates AS candidate ON candidate.id = event.id
		WHERE event.bucket IS NULL AND UPPER(COALESCE(event.severity,'')) = 'ACK'
		AND event.action IN (%s)`, placeholders), args...)
	if err != nil {
		return fmt.Errorf("retention materialize legacy ACK baseline: %w", err)
	}
	_, err = tx.ExecContext(ctx, `
		INSERT OR IGNORE INTO alert_acknowledgement_projection (
			alert_id, disposition, actor, disposition_at, projection_version,
			source, source_event_id, updated_at
		)
		SELECT baseline.alert_id, baseline.disposition, baseline.actor,
			baseline.disposition_at, baseline.baseline_version,
			'legacy_ack', baseline.legacy_event_id, ?
		FROM alert_acknowledgement_baselines AS baseline
		JOIN audit_events AS event ON event.id = baseline.alert_id
		JOIN retention_v8_audit_candidates AS candidate ON candidate.id = event.id`,
		createdAt.Format(time.RFC3339Nano))
	if err != nil {
		return fmt.Errorf("retention materialize legacy ACK projection: %w", err)
	}
	return nil
}

func migrateRetentionTimestampUnixNano(ex dbExecer) error {
	for _, spec := range retentionTimestampRegistry {
		present, err := tableExists(ex, spec.table)
		if err != nil {
			return err
		}
		if !present {
			continue
		}
		exists, err := hasColumnDB(ex, spec.table, "retention_timestamp_unix_nano")
		if err != nil {
			return err
		}
		if !exists {
			if _, err := ex.Exec(fmt.Sprintf(
				`ALTER TABLE %s ADD COLUMN retention_timestamp_unix_nano INTEGER`, spec.table,
			)); err != nil {
				return fmt.Errorf("add exact retention timestamp: %w", err)
			}
		}
		if _, err := ex.Exec(fmt.Sprintf(
			`CREATE INDEX IF NOT EXISTS %s ON %s(retention_timestamp_unix_nano, id)`,
			spec.index, spec.table,
		)); err != nil {
			return fmt.Errorf("create exact retention timestamp index: %w", err)
		}
		if err := installRetentionTimestampTriggers(ex, spec); err != nil {
			return err
		}
	}
	return nil
}

func installRetentionTimestampTriggers(ex dbExecer, spec retentionTimestampSpec) error {
	insertTrigger, updateTrigger, insertSQL, updateSQL := retentionTimestampTriggerDDL(spec)
	if _, err := ex.Exec(fmt.Sprintf(`DROP TRIGGER IF EXISTS %s; DROP TRIGGER IF EXISTS %s`,
		insertTrigger, updateTrigger)); err != nil {
		return fmt.Errorf("replace exact retention timestamp triggers: %w", err)
	}
	for _, statement := range []string{insertSQL, updateSQL} {
		if _, err := ex.Exec(statement); err != nil {
			return fmt.Errorf("create exact retention timestamp triggers: %w", err)
		}
	}
	for _, trigger := range []struct {
		name string
		sql  string
	}{{insertTrigger, insertSQL}, {updateTrigger, updateSQL}} {
		var actual string
		if err := ex.QueryRow(`SELECT sql FROM sqlite_master
			WHERE type='trigger' AND name=?`, trigger.name).Scan(&actual); err != nil {
			return fmt.Errorf("verify exact retention timestamp trigger: %w", err)
		}
		if normalizeSQLiteDDL(actual) != normalizeSQLiteDDL(trigger.sql) {
			return errors.New("audit: retention timestamp trigger does not match required definition")
		}
	}
	return nil
}

func retentionTimestampTriggerDDL(spec retentionTimestampSpec) (string, string, string, string) {
	expression := `CASE
		WHEN timestamp GLOB '????-??-??T??:??:??*' THEN
			CAST(strftime('%s', substr(timestamp, 1, 19) ||
				CASE WHEN substr(timestamp, -1) = 'Z' THEN 'Z' ELSE substr(timestamp, -6) END
			) AS INTEGER) * 1000000000 +
			CASE WHEN substr(timestamp, 20, 1) = '.' THEN CAST(substr(
				substr(timestamp, 21, length(timestamp) - 20 -
					CASE WHEN substr(timestamp, -1) = 'Z' THEN 1 ELSE 6 END) || '000000000',
				1, 9) AS INTEGER) ELSE 0 END
		WHEN timestamp GLOB '????-??-?? ??:??:??*'
			AND (instr(timestamp, ' +') > 0 OR instr(timestamp, ' -') > 0) THEN
			CAST(strftime('%s', substr(timestamp, 1, 19) ||
				CASE WHEN instr(timestamp, ' +') > 0 THEN
					substr(timestamp, instr(timestamp, ' +') + 1, 3) || ':' ||
					substr(timestamp, instr(timestamp, ' +') + 4, 2)
				ELSE
					substr(timestamp, instr(timestamp, ' -') + 1, 3) || ':' ||
					substr(timestamp, instr(timestamp, ' -') + 4, 2)
				END
			) AS INTEGER) * 1000000000 +
			CASE WHEN substr(timestamp, 20, 1) = '.' THEN CAST(substr(
				substr(timestamp, 21,
					CASE WHEN instr(timestamp, ' +') > 0 THEN instr(timestamp, ' +')
					ELSE instr(timestamp, ' -') END - 21) || '000000000',
				1, 9) AS INTEGER) ELSE 0 END
		WHEN timestamp GLOB '????-??-?? ??:??:??*'
			AND substr(timestamp, -6, 1) IN ('+', '-') THEN
			CAST(strftime('%s', substr(timestamp, 1, 19) || substr(timestamp, -6)) AS INTEGER) *
				1000000000 +
			CASE WHEN substr(timestamp, 20, 1) = '.' THEN CAST(substr(
				substr(timestamp, 21, length(timestamp) - 26) || '000000000', 1, 9
			) AS INTEGER) ELSE 0 END
		WHEN timestamp GLOB '????-??-?? ??:??:??*' THEN
			CAST(strftime('%s', substr(timestamp, 1, 19)) AS INTEGER) * 1000000000 +
			CASE WHEN substr(timestamp, 20, 1) = '.' THEN CAST(substr(
				substr(timestamp, 21) || '000000000', 1, 9
			) AS INTEGER) ELSE 0 END
		ELSE NULL END`
	insertTrigger := "retention_" + spec.table + "_timestamp_insert"
	updateTrigger := "retention_" + spec.table + "_timestamp_update"
	insertSQL := fmt.Sprintf(`CREATE TRIGGER %s
		AFTER INSERT ON %s
		BEGIN
			UPDATE %s SET retention_timestamp_unix_nano = %s WHERE id = NEW.id;
		END`, insertTrigger, spec.table, spec.table, expression)
	updateSQL := fmt.Sprintf(`CREATE TRIGGER %s
		AFTER UPDATE OF timestamp ON %s
		BEGIN
			UPDATE %s SET retention_timestamp_unix_nano = %s WHERE id = NEW.id;
		END`, updateTrigger, spec.table, spec.table, expression)
	return insertTrigger, updateTrigger, insertSQL, updateSQL
}

type retentionScanIntegrityTrigger struct {
	name string
	sql  string
}

func retentionScanIntegrityTriggerDDL() [3]retentionScanIntegrityTrigger {
	return [3]retentionScanIntegrityTrigger{
		{
			name: "scan_findings_require_parent",
			sql: `CREATE TRIGGER scan_findings_require_parent
				BEFORE INSERT ON scan_findings
				WHEN NOT EXISTS (SELECT 1 FROM scan_results WHERE id = NEW.scan_id)
				BEGIN
					SELECT RAISE(ABORT, 'scan finding requires an existing scan result');
				END`,
		},
		{
			name: "scan_findings_update_require_parent",
			sql: `CREATE TRIGGER scan_findings_update_require_parent
				BEFORE UPDATE OF scan_id ON scan_findings
				WHEN NOT EXISTS (SELECT 1 FROM scan_results WHERE id = NEW.scan_id)
				BEGIN
					SELECT RAISE(ABORT, 'scan finding requires an existing scan result');
				END`,
		},
		{
			name: "scan_results_preserve_children",
			sql: `CREATE TRIGGER scan_results_preserve_children
				BEFORE DELETE ON scan_results
				WHEN EXISTS (SELECT 1 FROM scan_findings WHERE scan_id = OLD.id)
				BEGIN
					SELECT RAISE(ABORT, 'scan result still has findings');
				END`,
		},
	}
}

func installRetentionScanIntegrityTriggers(ex dbExecer) error {
	for _, table := range []string{"scan_findings", "scan_results"} {
		present, err := tableExists(ex, table)
		if err != nil {
			return fmt.Errorf("check scan integrity table: %w", err)
		}
		if !present {
			// Supported partial legacy fixtures may predate one of the scan
			// tables. A complete Store.Init verifies the mandatory local anchor,
			// while scan guards become applicable only when both tables exist.
			return nil
		}
	}
	triggers := retentionScanIntegrityTriggerDDL()
	for _, trigger := range triggers {
		if _, err := ex.Exec(`DROP TRIGGER IF EXISTS ` + trigger.name); err != nil {
			return fmt.Errorf("replace scan integrity trigger: %w", err)
		}
	}
	for _, trigger := range triggers {
		if _, err := ex.Exec(trigger.sql); err != nil {
			return fmt.Errorf("create scan integrity trigger: %w", err)
		}
		var actual string
		if err := ex.QueryRow(`SELECT sql FROM sqlite_master
			WHERE type='trigger' AND name=?`, trigger.name).Scan(&actual); err != nil {
			return fmt.Errorf("verify scan integrity trigger: %w", err)
		}
		if normalizeSQLiteDDL(actual) != normalizeSQLiteDDL(trigger.sql) {
			return errors.New("audit: scan integrity trigger does not match required definition")
		}
	}
	return nil
}

func ensureRetentionTimestampInfrastructure(db *sql.DB) error {
	return retryBusy(context.Background(), "ensure-retention-timestamp-infrastructure", func() error {
		return ensureRetentionTimestampInfrastructureOnce(db)
	})
}

func ensureRetentionTimestampInfrastructureOnce(db *sql.DB) error {
	tx, err := db.Begin()
	if err != nil {
		return fmt.Errorf("begin retention timestamp infrastructure verification: %w", err)
	}
	defer tx.Rollback() //nolint:errcheck
	for _, spec := range retentionTimestampRegistry {
		present, err := tableExists(tx, spec.table)
		if err != nil {
			return fmt.Errorf("check retention timestamp table: %w", err)
		}
		if !present {
			// Some supported legacy databases predate optional event-history
			// tables. Their migrations intentionally remain additive rather
			// than synthesizing unrelated historical tables.
			continue
		}
		if err := installRetentionTimestampTriggers(tx, spec); err != nil {
			return err
		}
		if err := verifyRetentionTimestampIndex(tx, spec); err != nil {
			return err
		}
	}
	if err := installRetentionScanIntegrityTriggers(tx); err != nil {
		return err
	}
	if err := tx.Commit(); err != nil {
		return fmt.Errorf("commit retention timestamp infrastructure verification: %w", err)
	}
	return nil
}

func verifyRetentionTimestampIndex(tx *sql.Tx, spec retentionTimestampSpec) error {
	rows, err := tx.Query(fmt.Sprintf(`PRAGMA index_list(%s)`, spec.table))
	if err != nil {
		return fmt.Errorf("inspect exact retention timestamp index registration: %w", err)
	}
	found := false
	for rows.Next() {
		var sequence, unique, partial int
		var name, origin string
		if err := rows.Scan(&sequence, &name, &unique, &origin, &partial); err != nil {
			_ = rows.Close()
			return fmt.Errorf("read exact retention timestamp index registration: %w", err)
		}
		if name == spec.index {
			found = true
			if unique != 0 || partial != 0 || origin != "c" {
				_ = rows.Close()
				return errors.New("audit: retention timestamp index does not match required definition")
			}
		}
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate exact retention timestamp index registration: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close exact retention timestamp index registration: %w", err)
	}
	if !found {
		return errors.New("audit: required retention timestamp index is missing")
	}

	rows, err = tx.Query(fmt.Sprintf(`PRAGMA index_xinfo(%s)`, spec.index))
	if err != nil {
		return fmt.Errorf("inspect exact retention timestamp index: %w", err)
	}
	columns := make([]string, 0, 2)
	for rows.Next() {
		var sequence, columnID, descending, key int
		var column sql.NullString
		var collation string
		if err := rows.Scan(&sequence, &columnID, &column, &descending, &collation, &key); err != nil {
			_ = rows.Close()
			return fmt.Errorf("read exact retention timestamp index: %w", err)
		}
		if key == 0 {
			continue
		}
		if !column.Valid || descending != 0 || collation != "BINARY" {
			_ = rows.Close()
			return errors.New("audit: retention timestamp index does not match required definition")
		}
		columns = append(columns, column.String)
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate exact retention timestamp index: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close exact retention timestamp index inspection: %w", err)
	}
	if len(columns) != 2 || columns[0] != "retention_timestamp_unix_nano" || columns[1] != "id" {
		return errors.New("audit: retention timestamp index does not match required definition")
	}
	return nil
}

func backfillRetentionTimestamp(ex dbExecer, spec retentionTimestampSpec, limit int) error {
	query := fmt.Sprintf(`SELECT id, CAST(timestamp AS TEXT) FROM %s
		WHERE retention_timestamp_unix_nano IS NULL ORDER BY id ASC`, spec.table)
	args := []any{}
	if limit > 0 {
		query += ` LIMIT ?`
		args = append(args, limit)
	}
	rows, err := ex.Query(query, args...)
	if err != nil {
		return fmt.Errorf("read retention timestamp repair: %w", err)
	}
	type repairRow struct {
		id       string
		unixNano int64
	}
	repairs := make([]repairRow, 0, RetentionBatchSize)
	for rows.Next() {
		var id, encoded string
		if err := rows.Scan(&id, &encoded); err != nil {
			_ = rows.Close()
			return fmt.Errorf("scan retention timestamp repair: %w", err)
		}
		parsed, err := parseJudgeBodyTimestamp(encoded)
		if err != nil {
			_ = rows.Close()
			return errors.New("audit: stored retention timestamp is invalid")
		}
		unixNano, err := judgeBodyUnixNano(parsed)
		if err != nil {
			_ = rows.Close()
			return errors.New("audit: stored retention timestamp is outside the supported range")
		}
		repairs = append(repairs, repairRow{id: id, unixNano: unixNano})
	}
	if err := rows.Err(); err != nil {
		_ = rows.Close()
		return fmt.Errorf("iterate retention timestamp repair: %w", err)
	}
	if err := rows.Close(); err != nil {
		return fmt.Errorf("close retention timestamp repair: %w", err)
	}
	for _, row := range repairs {
		if _, err := ex.Exec(fmt.Sprintf(`UPDATE %s
			SET retention_timestamp_unix_nano = ?
			WHERE id = ? AND retention_timestamp_unix_nano IS NULL`, spec.table),
			row.unixNano, row.id); err != nil {
			return fmt.Errorf("write retention timestamp repair: %w", err)
		}
	}
	return nil
}

func retentionTimestampSpecForTable(table string) (retentionTimestampSpec, bool) {
	for _, spec := range retentionTimestampRegistry {
		if spec.table == table {
			return spec, true
		}
	}
	return retentionTimestampSpec{}, false
}

func (reaper *RetentionReaper) repairRetentionTimestamps(
	ctx context.Context,
	table retentionAuditTable,
) error {
	spec, found := retentionTimestampSpecForTable(table.table)
	if !found {
		return nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		release, err := reaper.store.acquireReady()
		if err != nil {
			return err
		}
		var repaired int
		err = retryBusy(ctx, "observability_v8_retention_timestamp_repair", func() error {
			tx, beginErr := reaper.store.db.BeginTx(ctx, nil)
			if beginErr != nil {
				return beginErr
			}
			defer tx.Rollback() //nolint:errcheck
			var before int
			if err := tx.QueryRowContext(ctx, fmt.Sprintf(
				`SELECT COUNT(*) FROM (SELECT id FROM %s
				 WHERE retention_timestamp_unix_nano IS NULL LIMIT ?)`, spec.table,
			), RetentionBatchSize).Scan(&before); err != nil {
				return err
			}
			if before > 0 {
				if err := backfillRetentionTimestamp(tx, spec, RetentionBatchSize); err != nil {
					return err
				}
			}
			if err := tx.Commit(); err != nil {
				return err
			}
			repaired = before
			return nil
		})
		release()
		if err != nil {
			return err
		}
		if repaired == 0 {
			return nil
		}
		if repaired > RetentionBatchSize {
			return errors.New("retention timestamp repair exceeded fixed batch size")
		}
		if err := reaper.hooks.yield(ctx); err != nil {
			return err
		}
	}
}

func (reaper *RetentionReaper) preflightJudgeRetention(ctx context.Context, cutoff time.Time) (string, error) {
	release, err := reaper.store.acquireReady()
	if err != nil {
		return "", retentionRunFailure(RetentionFailureLegacyJudgeStore, err)
	}
	defer release()
	if err := verifyJudgeBodyTimestampUnixNanoReady(reaper.store.db); err != nil {
		return "", retentionRunFailure(RetentionFailureLegacyJudgeStore, err)
	}
	cutoffUnixNano, err := judgeBodyUnixNano(cutoff)
	if err != nil {
		return "", retentionRunFailure(RetentionFailureLegacyJudgeStore, err)
	}
	var eligible int
	if err := reaper.store.db.QueryRowContext(ctx, `SELECT EXISTS(
		SELECT 1 FROM judge_responses WHERE timestamp_unix_nano < ?
	)`, cutoffUnixNano).Scan(&eligible); err != nil {
		return "", retentionRunFailure(RetentionFailureLegacyJudgeStore, err)
	}
	if reaper.judgeBodies == nil {
		if eligible != 0 {
			return "", retentionRunFailure(
				RetentionFailureAuthoritativeJudgeStore,
				errors.New("authoritative judge store is required"),
			)
		}
		return "", nil
	}
	judgeRelease, err := reaper.judgeBodies.acquireRuntime()
	if err != nil {
		return "", retentionRunFailure(RetentionFailureAuthoritativeJudgeStore, err)
	}
	defer judgeRelease()

	conn, err := reaper.store.db.Conn(ctx)
	if err != nil {
		return "", retentionRunFailure(RetentionFailureLegacyJudgeStore, err)
	}
	defer conn.Close()
	sourceKey, sourcePath, err := legacyJudgeSourceKey(ctx, conn)
	if err != nil {
		return "", retentionRunFailure(RetentionFailureLegacyJudgeStore, err)
	}
	if sameSQLitePath(sourcePath, reaper.judgeBodies.path) {
		return "", retentionRunFailure(
			RetentionFailureAuthoritativeJudgeStore,
			errors.New("legacy and authoritative judge stores must differ"),
		)
	}
	completed, err := reaper.judgeBodies.legacyJudgeCutoverCompleted(ctx, sourceKey)
	if err != nil {
		return "", retentionRunFailure(RetentionFailureAuthoritativeJudgeStore, err)
	}
	if eligible == 0 && !completed {
		return sourceKey, nil
	}
	if !completed {
		return "", retentionRunFailure(
			RetentionFailureJudgeCopyMissing,
			errors.New("legacy judge cutover completion is missing"),
		)
	}
	if err := verifyLegacyJudgeReadOnlyTriggers(ctx, conn); err != nil {
		return "", retentionRunFailure(RetentionFailureJudgeCopyMissing, err)
	}

	lastID := ""
	for {
		rows, err := conn.QueryContext(ctx, `SELECT `+judgeBodySelectColumns+`
			FROM judge_responses
			WHERE timestamp_unix_nano < ? AND id > ?
			ORDER BY id ASC LIMIT ?`, cutoffUnixNano, lastID, RetentionBatchSize)
		if err != nil {
			return "", retentionRunFailure(RetentionFailureLegacyJudgeStore, err)
		}
		batch := make([]legacyJudgeBodyRow, 0, RetentionBatchSize)
		for rows.Next() {
			row, scanErr := scanLegacyJudgeBody(rows)
			if scanErr != nil {
				_ = rows.Close()
				return "", retentionRunFailure(RetentionFailureLegacyJudgeStore, scanErr)
			}
			batch = append(batch, row)
		}
		if err := rows.Err(); err != nil {
			_ = rows.Close()
			return "", retentionRunFailure(RetentionFailureLegacyJudgeStore, err)
		}
		_ = rows.Close()
		if len(batch) == 0 {
			break
		}
		for _, want := range batch {
			got, err := reaper.judgeBodies.readLegacyShapeByID(ctx, want.id)
			if err != nil || !want.equal(got) {
				return "", retentionRunFailure(
					RetentionFailureJudgeCopyMissing,
					errors.New("authoritative judge copy does not match verified legacy source"),
				)
			}
			var marked int
			if err := reaper.judgeBodies.db.QueryRowContext(ctx, `SELECT EXISTS(
				SELECT 1 FROM legacy_judge_cutover_rows WHERE source_key=? AND legacy_id=?
			)`, sourceKey, want.id).Scan(&marked); err != nil || marked == 0 {
				return "", retentionRunFailure(
					RetentionFailureJudgeCopyMissing,
					errors.New("verified judge cutover marker is missing"),
				)
			}
		}
		lastID = batch[len(batch)-1].id
	}
	return sourceKey, nil
}

func (reaper *RetentionReaper) drainJudgeBodies(
	ctx context.Context,
	cutoff time.Time,
	sourceKey string,
	result *RetentionRunResult,
) error {
	for {
		ids, err := reaper.legacyJudgeBatchIDs(ctx, cutoff)
		if err != nil {
			return retentionRunFailure(RetentionFailureLegacyJudgeStore, err)
		}
		if len(ids) == 0 {
			break
		}
		if reaper.judgeBodies == nil {
			return retentionRunFailure(
				RetentionFailureAuthoritativeJudgeStore,
				errors.New("authoritative judge store is required"),
			)
		}
		if err := reaper.verifyAuthoritativeJudgeCopies(ctx, ids); err != nil {
			return retentionRunFailure(RetentionFailureJudgeCopyMissing, err)
		}
		deleted, err := reaper.deleteLegacyJudgeIDs(ctx, ids)
		if err != nil {
			return retentionRunFailure(RetentionFailureLegacyJudgeStore, err)
		}
		result.RowsDeleted[RetentionLegacyJudgeResponses] += deleted
		if deleted > 0 {
			result.BatchCount++
			if reaper.hooks.afterLegacyJudgeCommit != nil {
				if err := reaper.hooks.afterLegacyJudgeCommit(); err != nil {
					return retentionRunFailure(RetentionFailureCrossDatabase, err)
				}
			}
			if err := reaper.hooks.yield(ctx); err != nil {
				return err
			}
		}
	}

	if reaper.judgeBodies == nil {
		return nil
	}
	for {
		if err := ctx.Err(); err != nil {
			return err
		}
		deleted, err := reaper.deleteAuthoritativeJudgeBatch(ctx, cutoff, sourceKey)
		if err != nil {
			return retentionRunFailure(RetentionFailureAuthoritativeJudgeStore, err)
		}
		if deleted == 0 {
			return nil
		}
		result.RowsDeleted[RetentionAuthoritativeJudgeBodies] += deleted
		result.BatchCount++
		if reaper.hooks.afterAuthoritativeJudgeCommit != nil {
			if err := reaper.hooks.afterAuthoritativeJudgeCommit(); err != nil {
				return retentionRunFailure(RetentionFailureCrossDatabase, err)
			}
		}
		if err := reaper.hooks.yield(ctx); err != nil {
			return err
		}
		if deleted < RetentionBatchSize {
			return nil
		}
	}
}

func (reaper *RetentionReaper) legacyJudgeBatchIDs(ctx context.Context, cutoff time.Time) ([]string, error) {
	release, err := reaper.store.acquireReady()
	if err != nil {
		return nil, err
	}
	defer release()
	if err := verifyJudgeBodyTimestampUnixNanoReady(reaper.store.db); err != nil {
		return nil, err
	}
	cutoffUnixNano, err := judgeBodyUnixNano(cutoff)
	if err != nil {
		return nil, err
	}
	rows, err := reaper.store.db.QueryContext(ctx, `
		SELECT id FROM judge_responses
		WHERE timestamp_unix_nano < ?
		ORDER BY timestamp_unix_nano ASC, id ASC LIMIT ?`, cutoffUnixNano, RetentionBatchSize)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	ids := make([]string, 0, RetentionBatchSize)
	for rows.Next() {
		var id string
		if err := rows.Scan(&id); err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, rows.Err()
}

func (reaper *RetentionReaper) verifyAuthoritativeJudgeCopies(ctx context.Context, ids []string) error {
	release, err := reaper.judgeBodies.acquireRuntime()
	if err != nil {
		return err
	}
	defer release()
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, len(ids))
	for index, id := range ids {
		args[index] = id
	}
	var count int
	if err := reaper.judgeBodies.db.QueryRowContext(ctx,
		`SELECT COUNT(*) FROM judge_responses WHERE id IN (`+placeholders+`)`, args...).Scan(&count); err != nil {
		return err
	}
	if count != len(ids) {
		return errors.New("authoritative judge copy verification failed")
	}
	return nil
}

func (reaper *RetentionReaper) deleteLegacyJudgeIDs(ctx context.Context, ids []string) (int64, error) {
	release, err := reaper.store.acquireReady()
	if err != nil {
		return 0, err
	}
	defer release()
	placeholders := strings.TrimSuffix(strings.Repeat("?,", len(ids)), ",")
	args := make([]any, len(ids))
	for index, id := range ids {
		args[index] = id
	}
	var deleted int64
	err = retryBusy(ctx, "observability_v8_retention_legacy_judge", func() error {
		tx, beginErr := reaper.store.db.BeginTx(ctx, nil)
		if beginErr != nil {
			return beginErr
		}
		defer tx.Rollback() //nolint:errcheck
		res, execErr := tx.ExecContext(ctx,
			`DELETE FROM judge_responses WHERE id IN (`+placeholders+`)`, args...)
		if execErr != nil {
			return execErr
		}
		rows, rowsErr := res.RowsAffected()
		if rowsErr != nil {
			return rowsErr
		}
		if rows > RetentionBatchSize {
			return errors.New("legacy judge retention batch exceeded fixed limit")
		}
		if commitErr := tx.Commit(); commitErr != nil {
			return commitErr
		}
		deleted = rows
		return nil
	})
	return deleted, err
}

func (reaper *RetentionReaper) deleteAuthoritativeJudgeBatch(
	ctx context.Context,
	cutoff time.Time,
	sourceKey string,
) (int64, error) {
	release, err := reaper.judgeBodies.acquireRuntime()
	if err != nil {
		return 0, err
	}
	defer release()
	if err := verifyJudgeBodyTimestampUnixNanoReady(reaper.judgeBodies.db); err != nil {
		return 0, err
	}
	cutoffUnixNano, err := judgeBodyUnixNano(cutoff)
	if err != nil {
		return 0, err
	}
	var deleted int64
	err = retryBusy(ctx, "observability_v8_retention_authoritative_judge", func() error {
		tx, beginErr := reaper.judgeBodies.db.BeginTx(ctx, nil)
		if beginErr != nil {
			return beginErr
		}
		defer tx.Rollback() //nolint:errcheck
		// Marker cleanup is in the same commit as authoritative deletion.
		// This phase starts only after every eligible legacy source row is gone.
		if _, execErr := tx.ExecContext(ctx, `
			DELETE FROM legacy_judge_cutover_rows WHERE source_key = ? AND legacy_id IN (
				SELECT id FROM judge_responses WHERE timestamp_unix_nano < ?
				ORDER BY timestamp_unix_nano ASC, id ASC LIMIT ?
			)`, sourceKey, cutoffUnixNano, RetentionBatchSize); execErr != nil {
			return execErr
		}
		res, execErr := tx.ExecContext(ctx, `
			DELETE FROM judge_responses WHERE id IN (
				SELECT id FROM judge_responses WHERE timestamp_unix_nano < ?
				ORDER BY timestamp_unix_nano ASC, id ASC LIMIT ?
			)`, cutoffUnixNano, RetentionBatchSize)
		if execErr != nil {
			return execErr
		}
		rows, rowsErr := res.RowsAffected()
		if rowsErr != nil {
			return rowsErr
		}
		if rows > RetentionBatchSize {
			return errors.New("authoritative judge retention batch exceeded fixed limit")
		}
		if commitErr := tx.Commit(); commitErr != nil {
			return commitErr
		}
		deleted = rows
		return nil
	})
	return deleted, err
}

func passiveRetentionCheckpoint(ctx context.Context, store *Store, judge *JudgeBodyStore) error {
	if store == nil {
		return errors.New("audit retention checkpoint store is unavailable")
	}
	release, err := store.acquireReady()
	if err != nil {
		return err
	}
	var busy, logFrames, checkpointed int
	err = store.db.QueryRowContext(ctx, `PRAGMA wal_checkpoint(PASSIVE)`).Scan(
		&busy, &logFrames, &checkpointed,
	)
	release()
	if err != nil {
		return err
	}
	if judge == nil {
		return nil
	}
	judgeRelease, err := judge.acquireRuntime()
	if err != nil {
		return err
	}
	err = judge.db.QueryRowContext(ctx, `PRAGMA wal_checkpoint(PASSIVE)`).Scan(
		&busy, &logFrames, &checkpointed,
	)
	judgeRelease()
	return err
}
