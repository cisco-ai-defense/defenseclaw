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
	"time"

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
	ctx      context.Context
	queuedAt time.Time
	run      func(ctx context.Context, tx *sql.Tx) error
	data     any
	// committed, when set, runs once the shared transaction that ran this
	// write has committed (runCallGroupBatch).
	committed func()
	// durable asks for a commit that survives a power loss: the batch that
	// carries it commits with synchronous=FULL (and fullfsync where the
	// platform has it), which also makes every earlier commit durable.
	// dirSync asks for the database folder to be flushed once that commit
	// landed (syncDurableDir). Both are set only by durableGrouped.
	durable, dirSync bool
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
	write.queuedAt = time.Now()
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
	batch := group.takeBatchLocked()
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

// writeGroupAging is how long a write may wait before it goes ahead of
// newer writes in takeBatchLocked, so durable writes never starve the rest.
const writeGroupAging = 50 * time.Millisecond

// takeBatchLocked removes the next batch from the queue: at most
// writeGroupMax writes: the head of the queue, then durable ones (and any
// write queued longer than writeGroupAging), then the rest. A durable write is the hook
// journal row or the commit confirmation an answer waits on (durableGrouped);
// the other writes of the group are those of calls already answered, so a
// full queue never makes an answer wait behind them. The rest keep their
// order.
func (group *writeGroup) takeBatchLocked() []*groupedWrite {
	pending := group.pending
	if len(pending) <= writeGroupMax {
		batch := append([]*groupedWrite(nil), pending...)
		group.pending = pending[:0]
		return batch
	}
	// The head of the queue leads the batch and stays its first write: do
	// returns the result of batch[0] to the leader and sends every other
	// write its own.
	batch := make([]*groupedWrite, 0, writeGroupMax)
	batch = append(batch, pending[0])
	kept := make([]*groupedWrite, 0, len(pending)-writeGroupMax)
	now := time.Now()
	urgent := func(write *groupedWrite) bool {
		return write.durable || now.Sub(write.queuedAt) > writeGroupAging
	}
	for _, first := range []bool{true, false} {
		for _, write := range pending[1:] {
			if urgent(write) != first {
				continue
			}
			if len(batch) < writeGroupMax {
				batch = append(batch, write)
			} else {
				kept = append(kept, write)
			}
		}
	}
	group.pending = append(pending[:0], kept...)
	return batch
}

// WriteQueueSnapshot is the number of writes waiting for the next grouped
// transaction and the age of the oldest one. A transaction in progress is
// excluded because its writes have left the queue.
type WriteQueueSnapshot struct {
	Depth     int64
	OldestAge time.Duration
}

func (group *writeGroup) snapshot(now time.Time) WriteQueueSnapshot {
	group.mu.Lock()
	defer group.mu.Unlock()
	if len(group.pending) == 0 {
		return WriteQueueSnapshot{}
	}
	return WriteQueueSnapshot{
		Depth:     int64(len(group.pending)),
		OldestAge: max(now.Sub(group.pending[0].queuedAt), 0),
	}
}

// CallWriteQueueSnapshot reports the foreground hook-call write queue.
func (s *Store) CallWriteQueueSnapshot() WriteQueueSnapshot {
	if s == nil {
		return WriteQueueSnapshot{}
	}
	return s.callGroup.snapshot(time.Now())
}

// ObservationWriteQueueSnapshot reports the correlation-observation queue.
func (s *Store) ObservationWriteQueueSnapshot() WriteQueueSnapshot {
	if s == nil {
		return WriteQueueSnapshot{}
	}
	return s.observationGroup.snapshot(time.Now())
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
//
// The first attempt runs the writes without savepoints (groupedWriteDirect).
// A savepoint copies every page a write changes into SQLite's in-memory
// sub-journal before it changes it, so a batch of hook calls, each with a
// savepoint per write and per call, copied the same index pages again and
// again while it held the one writer connection: a third of the writer's time
// at 100 hook calls/s (r108 SWEEP-100). When a write fails in that attempt,
// the whole attempt is rolled back and the batch runs again with a savepoint
// per write, so the writes that commit, and the errors each caller sees, are
// those of the savepoint form.
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
	isolate := false
	attempt := func() error {
		for {
			err, fallBack := s.attemptGroupedTx(batchCtx, batch, hooks, single, isolate)
			if !fallBack {
				return err
			}
			isolate = true
		}
	}
	var err error
	if groupedBatchDurable(batch) {
		// A durable write is one an answer waits on (the hook journal row):
		// it keeps the bounded busy wait of the journal
		// (hookDeliveryJournalBusyWait), not the longer retry of the others.
		err = s.retryDurableBusy(batchCtx, hooks.op, s.groupedTxBusyObservabilityV8(), attempt)
	} else {
		err = retryBusyObserved(batchCtx, hooks.op, s.groupedTxBusyObservabilityV8(), attempt)
	}
	for _, item := range batch {
		if err != nil && !item.skipped {
			item.err, item.ran = err, false
		}
	}
	return err
}

// attemptGroupedTx makes one attempt at the batch's transaction. Without
// isolate, a write that fails other than on a busy store rolls the attempt
// back and reports fallBack: the caller runs the batch again with isolate.
func (s *Store) attemptGroupedTx(
	batchCtx context.Context,
	batch []*groupedWrite,
	hooks groupedTxHooks,
	single, isolate bool,
) (err error, fallBack bool) {
	acquire := s.writeBaton.acquire
	if groupedBatchDurable(batch) {
		acquire = s.writeBaton.acquireUrgent
	}
	release, turnErr := acquire(batchCtx)
	if turnErr != nil {
		return hooks.begin(turnErr), false
	}
	defer release()
	begin := s.db.BeginTx
	if groupedBatchDurable(batch) {
		conn, connErr := s.durableBatchConn(batchCtx)
		if connErr != nil {
			return hooks.begin(connErr), false
		}
		defer conn.restore()
		begin = conn.BeginTx
	}
	tx, beginErr := begin(batchCtx, nil)
	if beginErr != nil {
		return hooks.begin(beginErr), false
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
		if !isolate {
			if runErr := runGroupedWriteDirect(batchCtx, tx, item, single); runErr != nil {
				_ = tx.Rollback()
				if isSQLiteBusy(runErr) || batchCtx.Err() != nil || (single && item.ctx.Err() != nil) {
					return runErr, false
				}
				return nil, true
			}
		} else if runErr := s.runGroupedWrite(batchCtx, tx, item, single); runErr != nil {
			if single || isSQLiteBusy(runErr) || errors.Is(runErr, errGroupedTxLost) {
				_ = tx.Rollback()
				return runErr, false
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
		return commitErr, false
	}
	return nil, false
}

// groupedWriteDirectKey marks the context of a write that runs in the first,
// savepoint-free attempt of its shared transaction (runGroupedTx).
type groupedWriteDirectKey struct{}

// groupedWriteDirect reports whether a write with ctx runs without
// savepoints: a write made of several writes (writeCallBatch) then runs them
// without a savepoint each and returns the first error.
func groupedWriteDirect(ctx context.Context) bool {
	direct, _ := ctx.Value(groupedWriteDirectKey{}).(bool)
	return direct
}

// runGroupedWriteDirect runs one write of the savepoint-free attempt, with
// the same contexts as runGroupedWrite.
func runGroupedWriteDirect(batchCtx context.Context, tx *sql.Tx, item *groupedWrite, single bool) error {
	values := context.WithValue(item.ctx, groupedWriteDirectKey{}, true)
	if single {
		return item.run(values, tx)
	}
	return item.run(groupedWriteCtx{Context: batchCtx, values: values}, tx)
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
	// The reprojection, validation and envelope of the row need no store: do
	// them before the write queues, so the shared transaction holds the one
	// writer connection only for its statements (#1384), as the deferred
	// appends of a hook call already do (deferAppend).
	prepared := writer.prepareAppend(ctx, record, projection)
	write := &groupedWrite{ctx: ctx, data: outcome, run: func(ctx context.Context, tx *sql.Tx) error {
		appended, err := writer.appendPreparedTx(ctx, tx, record, projection, prepared)
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
		// Staged, not reported: this caller leads the group, and every caller
		// flushes the health state after its write returns (appendGrouped).
		writer.stageHealthFailure(EventHistoryHealthWriteFailed, err, EventHistorySQLiteUnavailable)
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
