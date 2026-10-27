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

// writeGroupMax bounds the writes one transaction carries, so one commit
// holds the writer connection for a few milliseconds of inserts.
const writeGroupMax = 64

// writeGroupBatchObserved is a test seam: it sees the size of every grouped
// transaction.
var writeGroupBatchObserved func(op string, size int)

// writeGroup lets concurrent writers of one kind share one transaction
// (group commit). The store has one writer connection: under concurrent hook
// calls each event-history append and each correlation observation batch
// waited for the connection, began, wrote and committed alone, so a hook
// queued behind the commits of every other call in flight and its answer
// missed the answer budget under CPU load (GAP-1790, GAP-1822), and every
// commit wrote the same index pages to the WAL again (GAP-1791). A write that
// arrives while a transaction runs joins the next one, so no write waits
// longer than the transaction before it; a lone write runs exactly as before.
// Every caller returns only after its own rows are committed, or with its
// own error.
type writeGroup struct {
	mu      sync.Mutex
	pending []*groupedWrite
	active  bool
}

// groupedWrite is one caller's write. run performs it inside the shared
// transaction; data is the caller's state for the commit callback.
type groupedWrite struct {
	ctx  context.Context
	run  func(ctx context.Context, tx *sql.Tx) error
	data any
	// result receives exactly one message: the outcome of the write, or lead
	// when the write heads the queue and runs the next transaction.
	result  chan groupedWriteResult
	err     error
	ran     bool
	skipped bool
}

type groupedWriteResult struct {
	err  error
	lead bool
}

// removeLocked drops a write no transaction has taken. It reports false when
// the write is in a running transaction or was told to lead the next.
func (group *writeGroup) removeLocked(write *groupedWrite) bool {
	if len(write.result) > 0 {
		return false
	}
	for index, pending := range group.pending {
		if pending == write {
			group.pending = append(group.pending[:index], group.pending[index+1:]...)
			return true
		}
	}
	return false
}

// do queues write and returns its outcome. execute runs one batch; it is
// called by the caller whose write heads the queue.
func (group *writeGroup) do(write *groupedWrite, execute func([]*groupedWrite)) error {
	write.result = make(chan groupedWriteResult, 1)
	group.mu.Lock()
	group.pending = append(group.pending, write)
	lead := !group.active
	group.active = true
	group.mu.Unlock()
	if !lead {
		var outcome groupedWriteResult
		select {
		case outcome = <-write.result:
		case <-write.ctx.Done():
			group.mu.Lock()
			removed := group.removeLocked(write)
			group.mu.Unlock()
			if removed {
				return write.ctx.Err()
			}
			outcome = <-write.result
		}
		if !outcome.lead {
			return outcome.err
		}
	}
	group.mu.Lock()
	count := min(len(group.pending), writeGroupMax)
	batch := append([]*groupedWrite(nil), group.pending[:count]...)
	group.pending = append(group.pending[:0], group.pending[count:]...)
	group.mu.Unlock()

	execute(batch)

	group.mu.Lock()
	if len(group.pending) > 0 {
		group.pending[0].result <- groupedWriteResult{lead: true}
	} else {
		group.active = false
	}
	group.mu.Unlock()
	for _, item := range batch[1:] {
		item.result <- groupedWriteResult{err: item.err}
	}
	return batch[0].err
}

// groupedTxHooks are the per-kind parts of a grouped transaction.
type groupedTxHooks struct {
	op string
	// begin wraps a failed BeginTx.
	begin func(error) error
	// commit commits tx; ran are the writes that succeeded in it.
	commit func(ctx context.Context, tx *sql.Tx, ran []*groupedWrite) error
}

// runGroupedTx writes the batch in one transaction. With more than one write,
// each runs in its own savepoint, so a write that fails is rolled back alone
// and the others commit. The transaction is cancelled only when every caller
// in it has given up; a write whose caller gave up before its turn is not
// attempted (skipped). A failed begin or commit fails every write in it.
func (s *Store) runGroupedTx(batch []*groupedWrite, hooks groupedTxHooks) error {
	if writeGroupBatchObserved != nil {
		writeGroupBatchObserved(hooks.op, len(batch))
	}
	for _, item := range batch {
		item.err, item.ran, item.skipped = nil, false, false
		if err := item.ctx.Err(); err != nil {
			item.err, item.skipped = err, true
		}
	}
	batchCtx, cancel := context.WithCancel(context.WithoutCancel(batch[0].ctx))
	defer cancel()
	var remaining atomic.Int64
	remaining.Store(int64(len(batch)))
	for _, item := range batch {
		stop := context.AfterFunc(item.ctx, func() {
			if remaining.Add(-1) == 0 {
				cancel()
			}
		})
		defer stop()
	}
	single := len(batch) == 1
	err := retryBusyObserved(batchCtx, hooks.op, s.sqliteBusyObservabilityV8(), func() error {
		tx, beginErr := s.db.BeginTx(batchCtx, nil)
		if beginErr != nil {
			return hooks.begin(beginErr)
		}
		ran := make([]*groupedWrite, 0, len(batch))
		for _, item := range batch {
			item.ran = false
			if item.skipped {
				continue
			}
			if !single {
				if ctxErr := item.ctx.Err(); ctxErr != nil {
					item.err, item.skipped = ctxErr, true
					continue
				}
			}
			item.err = nil
			if runErr := s.runGroupedWrite(batchCtx, tx, item, single); runErr != nil {
				if single || isSQLiteBusy(runErr) || errors.Is(runErr, errGroupedTxLost) {
					_ = tx.Rollback()
					return runErr
				}
				item.err = runErr
				continue
			}
			item.ran = true
			ran = append(ran, item)
		}
		commitCtx := batchCtx
		if single {
			commitCtx = batch[0].ctx
		}
		if commitErr := hooks.commit(commitCtx, tx, ran); commitErr != nil {
			_ = tx.Rollback()
			return commitErr
		}
		return nil
	})
	for _, item := range batch {
		if err != nil && !item.skipped {
			item.err, item.ran = err, false
		}
	}
	return err
}

// runGroupedWrite runs one write. In a shared transaction it runs in a
// savepoint, so its failure rolls back only its own statements, and with a
// context that keeps the caller's values but ends with the transaction: an
// interrupted statement inside an explicit transaction would roll back the
// other callers' rows with it.
func (s *Store) runGroupedWrite(batchCtx context.Context, tx *sql.Tx, item *groupedWrite, single bool) error {
	if single {
		return item.run(item.ctx, tx)
	}
	if _, err := tx.ExecContext(batchCtx, `SAVEPOINT grouped_write`); err != nil {
		return err
	}
	if err := item.run(groupedWriteCtx{Context: batchCtx, values: item.ctx}, tx); err != nil {
		if _, rollbackErr := tx.ExecContext(batchCtx, `ROLLBACK TO grouped_write`); rollbackErr != nil {
			return groupedTxLost(errors.Join(err, rollbackErr))
		}
		if _, releaseErr := tx.ExecContext(batchCtx, `RELEASE grouped_write`); releaseErr != nil {
			return groupedTxLost(errors.Join(err, releaseErr))
		}
		return err
	}
	if _, err := tx.ExecContext(batchCtx, `RELEASE grouped_write`); err != nil {
		return groupedTxLost(err)
	}
	return nil
}

// errGroupedTxLost marks a shared transaction whose savepoint could not be
// rolled back to or released. SQLite rolls back the whole transaction on some
// errors of a statement (SQLITE_FULL, SQLITE_IOERR, SQLITE_NOMEM), and the
// savepoint goes with it: the next write's SAVEPOINT would then start a
// transaction of its own and its RELEASE commit it, so the batch's commit
// failed while those rows were stored, and their callers saw an error for
// rows on disk (a false local-write gap and a duplicate on replay, GAP-1980).
// The batch stops and every write in it fails, with nothing committed.
var errGroupedTxLost = errors.New("audit: the shared transaction was rolled back under its writes")

func groupedTxLost(cause error) error {
	return fmt.Errorf("%w: %w", errGroupedTxLost, cause)
}

// groupedWriteCtx carries one caller's context values (its sink policy and
// provenance) with the shared transaction's lifetime.
type groupedWriteCtx struct {
	context.Context
	values context.Context
}

func (ctx groupedWriteCtx) Value(key any) any { return ctx.values.Value(key) }

// appendGrouped is AppendContext's write: one event-history row, committed
// with the appends queued beside it.
func (writer *EventHistoryWriter) appendGrouped(
	ctx context.Context,
	record observability.Record,
	projection observabilityredaction.Projection,
) error {
	outcome := new(eventHistoryAppendOutcome)
	write := &groupedWrite{ctx: ctx, data: outcome, run: func(ctx context.Context, tx *sql.Tx) error {
		appended, err := writer.appendContextTx(ctx, tx, record, projection)
		*outcome = appended
		return err
	}}
	err := writer.group.do(write, writer.runAppendBatch)
	writer.flushHealth()
	return err
}

func (writer *EventHistoryWriter) runAppendBatch(batch []*groupedWrite) {
	release, err := writer.store.acquireReady()
	if err != nil {
		writer.reportHealthFailure(EventHistoryHealthWriteFailed, err, EventHistorySQLiteUnavailable)
		for _, item := range batch {
			if item.ctx.Err() == nil {
				item.err = err
			} else {
				item.err = item.ctx.Err()
			}
		}
		return
	}
	_ = writer.store.runGroupedTx(batch, groupedTxHooks{
		op: "v8_event_history_transaction",
		begin: func(err error) error {
			return eventHistoryFailure(EventHistoryHealthWriteFailed, &eventHistoryWriteError{cause: err})
		},
		commit: func(ctx context.Context, tx *sql.Tx, ran []*groupedWrite) error {
			outcomes := make([]eventHistoryAppendOutcome, 0, len(ran))
			for _, item := range ran {
				outcomes = append(outcomes, *item.data.(*eventHistoryAppendOutcome))
			}
			if err := writer.commitAppendTransactionContext(ctx, tx, outcomes...); err != nil {
				return eventHistoryFailure(EventHistoryHealthWriteFailed, &eventHistoryWriteError{cause: err})
			}
			return nil
		},
	})
	release()
	for _, item := range batch {
		// A caller that gave up before its turn had nothing attempted, as
		// when AppendContext saw a done context before it began.
		if item.err != nil && !item.skipped {
			writer.stageAppendErrorClass(item.err, eventHistoryCallerGaveUpClass(item.ctx, item.err))
		}
	}
}
