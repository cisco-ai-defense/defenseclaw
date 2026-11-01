// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
	"sync/atomic"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// CallWriteBatch collects the event-history appends and correlation
// observations of one hook call so they commit in one transaction
// (GAP-1303, GAP-1791, GAP-0614).
//
// A benign Claude Code PreToolUse made 15 commits, and ten of them were
// these writes: the lifecycle, tool, scan, audit-envelope and hook_decision
// rows and the observations of their metrics, each committed on its own
// while the next waited for it. Every commit wrote the same audit_events and
// correlation_observations index pages to the WAL again (about 250 frames a
// call), so a 10 Hz flood grew the WAL faster than a checkpoint on a slow
// disk could drain it, and the writer queue made concurrent calls miss their
// answer budget (GAP-1790, GAP-1822).
//
// While a batch is open on a call's context, such a write is queued instead
// of committed, and work that must follow its commit (the export of the
// record, DeferAfterCallWrites) is queued behind it. FlushCallWrites commits
// the queue in one transaction, each write in its own savepoint, then runs
// the queued work: commit before export holds. Concurrent calls' flushes
// share one transaction (write group). A write the shared transaction did
// not commit is written again on its own through its ordinary path, which
// reports its failure exactly as before. A caller that needs the outcome of
// its own write (the audit row of the verdict) reads it with
// WithCallWriteOutcome after the flush.
type CallWriteBatch struct {
	store  *Store
	mu     sync.Mutex
	closed bool
	writes []*deferredCallWrite
	after  []func()
}

// deferredCallWrite is one queued write.
type deferredCallWrite struct {
	ctx context.Context
	run func(ctx context.Context, tx *sql.Tx) error
	// committed runs after the shared transaction committed this write.
	committed func()
	// alone writes it through its ordinary path, when the shared
	// transaction did not commit it.
	alone   func(ctx context.Context) error
	outcome *CallWriteOutcome
	// report hears the final outcome of the producer's write
	// (WithCallWriteReport).
	report *CallWriteReport
	ran    bool
	done   bool
}

// CallWriteReport hands a producer the final outcome of the one
// event-history write it made with its context while that write waited in a
// hook call's open batch. The append returned nil at once, so the producer
// (the local-sqlite accounting of the observability runtime) counts the
// write delivered or lost only when settle runs: nil once the shared
// transaction or the retry on its own committed it, the retry's error when
// neither did (disk full, read-only store). Without it a deferred write that
// failed was counted delivered and never reached the local write loss
// journal (RV-ha1-1791, GAP-1129).
type CallWriteReport struct {
	settle   func(err error)
	deferred atomic.Bool
}

// Deferred reports whether a write made with the report's context waits in
// a batch; settle runs for it later, exactly once.
func (report *CallWriteReport) Deferred() bool {
	return report != nil && report.deferred.Load()
}

// claim takes the report for one deferred write; a second write with the
// same context does not take it.
func (report *CallWriteReport) claim() bool {
	return report != nil && report.settle != nil && report.deferred.CompareAndSwap(false, true)
}

func (report *CallWriteReport) unclaim() {
	if report != nil {
		report.deferred.Store(false)
	}
}

func (report *CallWriteReport) done(err error) {
	if report != nil && report.settle != nil {
		report.settle(err)
	}
}

type callWriteReportKey struct{}

// WithCallWriteReport returns a context whose next event-history write, if
// it joins ctx's open batch, reports its final outcome to settle. With no
// open batch for store it returns ctx and a nil report.
func WithCallWriteReport(
	ctx context.Context,
	store *Store,
	settle func(err error),
) (context.Context, *CallWriteReport) {
	if settle == nil || !CallWritesOpen(ctx, store) {
		return ctx, nil
	}
	report := &CallWriteReport{settle: settle}
	return context.WithValue(ctx, callWriteReportKey{}, report), report
}

// CallWriteOutcome is the final outcome of the event-history writes made
// with its context (WithCallWriteOutcome), known after FlushCallWrites.
type CallWriteOutcome struct {
	mu  sync.Mutex
	err error
}

// Err is the first error of the writes it tracks; nil when all were
// committed.
func (outcome *CallWriteOutcome) Err() error {
	if outcome == nil {
		return nil
	}
	outcome.mu.Lock()
	defer outcome.mu.Unlock()
	return outcome.err
}

func (outcome *CallWriteOutcome) record(err error) {
	if outcome == nil || err == nil {
		return
	}
	outcome.mu.Lock()
	if outcome.err == nil {
		outcome.err = err
	}
	outcome.mu.Unlock()
}

type callWriteBatchKey struct{}

type callWriteOutcomeKey struct{}

// WithCallWriteBatch opens a write batch for the call that ctx carries.
func WithCallWriteBatch(ctx context.Context, store *Store) context.Context {
	if ctx == nil || store == nil {
		return ctx
	}
	return context.WithValue(ctx, callWriteBatchKey{}, &CallWriteBatch{store: store})
}

// WithCallWriteOutcome tracks the event-history writes made with the
// returned context.
func WithCallWriteOutcome(ctx context.Context) (context.Context, *CallWriteOutcome) {
	outcome := new(CallWriteOutcome)
	if ctx == nil {
		return ctx, outcome
	}
	return context.WithValue(ctx, callWriteOutcomeKey{}, outcome), outcome
}

func callWriteBatchFrom(ctx context.Context, store *Store) *CallWriteBatch {
	if ctx == nil || store == nil {
		return nil
	}
	batch, _ := ctx.Value(callWriteBatchKey{}).(*CallWriteBatch)
	if batch == nil || batch.store != store {
		return nil
	}
	return batch
}

// deferringBatch is the open batch a write with ctx joins. A record whose
// producer tracks its remote delivery or exports only after its own local
// write keeps the ordinary path: those producers read the commit at once.
func deferringBatch(ctx context.Context, store *Store) *CallWriteBatch {
	batch := callWriteBatchFrom(ctx, store)
	if batch == nil || observability.RemoteDeliveryFrom(ctx) != nil ||
		observability.RemoteExportFrom(ctx) != observability.RemoteExportDefault {
		return nil
	}
	return batch
}

func (batch *CallWriteBatch) add(write *deferredCallWrite) bool {
	batch.mu.Lock()
	defer batch.mu.Unlock()
	if batch.closed {
		return false
	}
	batch.writes = append(batch.writes, write)
	return true
}

// CallWritesOpen reports whether a write with ctx would join an open batch.
func CallWritesOpen(ctx context.Context, store *Store) bool {
	batch := deferringBatch(ctx, store)
	if batch == nil {
		return false
	}
	batch.mu.Lock()
	defer batch.mu.Unlock()
	return !batch.closed
}

// DeferAfterCallWrites queues fn to run after the next flush of the open
// batch on ctx, behind every write queued before it. It returns false, and
// does not run fn, when no batch is open: the caller runs fn itself.
func DeferAfterCallWrites(ctx context.Context, store *Store, fn func()) bool {
	batch := deferringBatch(ctx, store)
	if batch == nil || fn == nil {
		return false
	}
	batch.mu.Lock()
	defer batch.mu.Unlock()
	if batch.closed {
		return false
	}
	batch.after = append(batch.after, fn)
	return true
}

// FlushCallWrites commits the writes queued on ctx's batch and runs the work
// queued behind them. The batch stays open.
func FlushCallWrites(ctx context.Context) {
	flushCallWrites(ctx, false)
}

// CloseCallWrites flushes ctx's batch and closes it: later writes of the
// call commit on their own, as without a batch.
func CloseCallWrites(ctx context.Context) {
	flushCallWrites(ctx, true)
}

func flushCallWrites(ctx context.Context, closeBatch bool) {
	if ctx == nil {
		return
	}
	batch, _ := ctx.Value(callWriteBatchKey{}).(*CallWriteBatch)
	if batch == nil {
		return
	}
	for {
		batch.mu.Lock()
		writes, after := batch.writes, batch.after
		batch.writes, batch.after = nil, nil
		if closeBatch {
			batch.closed = true
		}
		batch.mu.Unlock()
		if len(writes) == 0 && len(after) == 0 {
			return
		}
		if len(writes) > 0 {
			batch.store.writeCallBatch(ctx, writes)
		}
		for _, fn := range after {
			runCallWriteFollowUp(fn)
		}
		if !closeBatch {
			return
		}
		// Work run after the commit may queue more before the batch closed.
	}
}

func runCallWriteFollowUp(fn func()) {
	defer func() { _ = recover() }()
	fn()
}

// writeCallBatch commits one call's queued writes in one transaction shared
// with the flushes of concurrent calls, then writes again on its own every
// write that transaction did not commit.
func (s *Store) writeCallBatch(ctx context.Context, writes []*deferredCallWrite) {
	call := &groupedWrite{ctx: context.WithoutCancel(ctx), run: func(ctx context.Context, tx *sql.Tx) error {
		for _, write := range writes {
			write.ran = false
			if _, err := tx.ExecContext(ctx, `SAVEPOINT call_write`); err != nil {
				return groupedTxLost(err)
			}
			if err := write.run(groupedWriteCtx{Context: ctx, values: write.ctx}, tx); err != nil {
				if _, rollbackErr := tx.ExecContext(ctx, `ROLLBACK TO call_write`); rollbackErr != nil {
					return groupedTxLost(errors.Join(err, rollbackErr))
				}
				if _, releaseErr := tx.ExecContext(ctx, `RELEASE call_write`); releaseErr != nil {
					return groupedTxLost(errors.Join(err, releaseErr))
				}
				continue
			}
			if _, err := tx.ExecContext(ctx, `RELEASE call_write`); err != nil {
				return groupedTxLost(err)
			}
			write.ran = true
		}
		return nil
	}, data: writes}
	_ = s.callGroup.do(call, func(batch []*groupedWrite) {
		release, err := s.acquireReady()
		if err != nil {
			for _, item := range batch {
				item.err = err
			}
			return
		}
		defer release()
		_ = s.runGroupedTx(batch, groupedTxHooks{
			op: "hook_call_transaction",
			begin: func(err error) error {
				return fmt.Errorf("audit: begin hook call transaction: %w", err)
			},
			commit: func(_ context.Context, tx *sql.Tx, ran []*groupedWrite) error {
				if err := tx.Commit(); err != nil {
					return fmt.Errorf("audit: commit hook call transaction: %w", err)
				}
				for _, item := range ran {
					for _, write := range item.data.([]*deferredCallWrite) {
						write.done = write.ran
					}
				}
				return nil
			},
		})
	})
	for _, write := range writes {
		if write.done {
			if write.committed != nil {
				write.committed()
			}
			write.report.done(nil)
			continue
		}
		err := write.alone(groupedWriteCtx{Context: context.WithoutCancel(ctx), values: write.ctx})
		write.outcome.record(err)
		write.report.done(err)
	}
}

// deferAppend queues one event-history append on ctx's open batch.
func (writer *EventHistoryWriter) deferAppend(
	ctx context.Context,
	records []observability.Record,
	projections []observabilityredaction.Projection,
) bool {
	batch := deferringBatch(ctx, writer.store)
	if batch == nil {
		return false
	}
	outcomes := make([]eventHistoryAppendOutcome, len(records))
	outcome, _ := ctx.Value(callWriteOutcomeKey{}).(*CallWriteOutcome)
	report, _ := ctx.Value(callWriteReportKey{}).(*CallWriteReport)
	if !report.claim() {
		report = nil
	}
	added := batch.add(&deferredCallWrite{
		ctx: ctx, outcome: outcome, report: report,
		run: func(ctx context.Context, tx *sql.Tx) error {
			for index := range records {
				appended, err := writer.appendContextTx(ctx, tx, records[index], projections[index])
				if err != nil {
					return err
				}
				outcomes[index] = appended
			}
			return nil
		},
		committed: func() {
			writer.appendCommitMu.Lock()
			for _, appended := range outcomes {
				writer.stageAppendOutcome(appended, writer.nextHealthSequence())
			}
			writer.appendCommitMu.Unlock()
			writer.flushHealth()
		},
		alone: func(ctx context.Context) error {
			if len(records) == 1 {
				return writer.appendGrouped(ctx, records[0], projections[0])
			}
			return writer.appendBatchDirect(ctx, records, projections)
		},
	})
	if !added {
		report.unclaim()
	}
	return added
}

// deferObservations queues correlation observations on ctx's open batch.
func (repo *CorrelationRepository) deferObservations(
	ctx context.Context,
	observations []CorrelationObservation,
) bool {
	batch := deferringBatch(ctx, repo.store)
	if batch == nil {
		return false
	}
	return batch.add(&deferredCallWrite{
		ctx: ctx,
		run: func(ctx context.Context, tx *sql.Tx) error {
			for _, observation := range observations {
				if err := putCorrelationObservationTx(ctx, tx, repo.store, observation); err != nil {
					return err
				}
			}
			return nil
		},
		alone: func(ctx context.Context) error {
			return repo.recordObservationsDirect(ctx, observations)
		},
	})
}
