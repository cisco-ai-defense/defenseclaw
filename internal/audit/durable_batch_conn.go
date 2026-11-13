// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"database/sql/driver"
	"errors"
	"fmt"
	"os"
	"sync/atomic"
	"time"
)

// groupedBatchDurable reports whether a batch carries a write that is to
// survive a power loss (durableGrouped) and was not given up before its turn.
func groupedBatchDurable(batch []*groupedWrite) bool {
	for _, item := range batch {
		if item.durable && !item.skipped {
			return true
		}
	}
	return false
}

// durableBatchConn is the store writer connection held for one batch that
// commits with synchronous=FULL. The hook journal row, its updates and the
// commit confirmation used to commit on a second synchronous=FULL connection
// that took turns with the writer (writeBaton): every hook call waited for
// about seven commits, two of them flushed to disk, one after the other, so
// the store answered about 25 to 30 calls a second (rel-1-0-6 GAP-0558 to
// GAP-0560, GAP-0770, #1384). On the one writer connection a durable write
// joins the grouped transaction of the hook-call writes queued beside it,
// and the batch makes one flush for all of them. In WAL mode a FULL commit
// flushes the log up to and including that commit, so every commit before it
// is durable too, as on the second connection.
type durableBatchConn struct {
	*sql.Conn
}

// auditDurableBatchPragmas are set on the writer connection before a
// durable batch begins; auditNormalBatchPragmas put back the store pragmas
// (auditPragmas: synchronous NORMAL, no fullfsync) after it ends.
var (
	auditDurableBatchPragmas = []string{"PRAGMA synchronous = FULL", "PRAGMA fullfsync = 1"}
	auditNormalBatchPragmas  = []string{"PRAGMA fullfsync = 0", "PRAGMA synchronous = NORMAL"}
)

// durableRestoreFault is a test seam: an error it returns for a pragma fails
// putting that pragma back after a durable batch.
var durableRestoreFault func(pragma string) error

// durableRestoreFailures counts the writer connections dropped because the
// NORMAL pragmas could not be put back after a durable batch.
var durableRestoreFailures atomic.Int64

// durableBatchFault is a test seam: an error it returns fails the durable
// batch before it begins, as a writer connection that cannot flush would.
var durableBatchFault func() error

func (s *Store) durableBatchConn(ctx context.Context) (*durableBatchConn, error) {
	if durableBatchFault != nil {
		if err := durableBatchFault(); err != nil {
			return nil, err
		}
	}
	conn, err := s.db.Conn(ctx)
	if err != nil {
		return nil, fmt.Errorf("hold the writer connection: %w", err)
	}
	held := &durableBatchConn{Conn: conn}
	for _, pragma := range auditDurableBatchPragmas {
		if _, err := conn.ExecContext(ctx, pragma); err != nil {
			held.restore()
			return nil, fmt.Errorf("%s: %w", pragma, err)
		}
	}
	return held, nil
}

// restore puts the NORMAL pragmas back and returns the connection to the
// pool. When that fails the connection is discarded instead.
func (c *durableBatchConn) restore() {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	for _, pragma := range auditNormalBatchPragmas {
		var err error
		if durableRestoreFault != nil {
			err = durableRestoreFault(pragma)
		}
		if err == nil {
			_, err = c.ExecContext(ctx, pragma)
		}
		if err != nil {
			if errors.Is(err, sql.ErrConnDone) {
				// The store closed under the batch: nothing to keep or drop.
				break
			}
			if durableRestoreFailures.Add(1) == 1 {
				fmt.Fprintf(os.Stderr, "[audit] dropping the writer connection after a durable batch: %s: %v\n", pragma, err)
			}
			// The pool opens a new connection with the store pragmas, which
			// the mandatory pragma check expects (synchronous NORMAL).
			_ = c.Raw(func(any) error { return driver.ErrBadConn })
			break
		}
	}
	_ = c.Close()
}

func countDurable(batch []*groupedWrite) int {
	count := 0
	for _, item := range batch {
		if item.durable {
			count++
		}
	}
	return count
}

// syncDurableDirFor flushes the database folder once after a batch in which
// a committed durable write asked for it (dirSync); the writes that asked
// see a failure of that flush as their error.
func (s *Store) syncDurableDirFor(batch []*groupedWrite) {
	flush := false
	for _, item := range batch {
		flush = flush || item.dirSync && item.ran && item.err == nil
	}
	if !flush {
		return
	}
	if dirErr := s.syncDurableDir(); dirErr != nil {
		for _, item := range batch {
			if item.dirSync && item.ran && item.err == nil {
				item.err = &durableDirSyncError{err: dirErr}
			}
		}
	}
}

// releaseUnlessGrouped returns a release to defer around a durable write: a
// store whose durable writes join the hook-call write group gives the
// lifecycle read lock back at once, because the group batch runner takes its
// own (runCallGroupBatch), and a second read lock under a waiting Close
// would block both; a Secure Client store keeps it for the call.
func (s *Store) releaseUnlessGrouped(release func()) func() {
	if s.secureClientSchema {
		return release
	}
	release()
	return func() {}
}

// retryDurableBusy runs attempt again while the store answers SQLITE_BUSY,
// for at most hookDeliveryJournalBusyWait, as the durable connection did
// (commitDurableBatch); the last error is returned as it is. Each attempt is
// recorded and counted as retryBusyObserved does. Unlike the other writers
// it keeps waiting while another process holds the write lock: the journal
// row of a managed answer waits out a lock for its whole bound
// (TestHookDeliveryJournalWaitsOutABusyStore, rel-1-0-4 GAP-1790).
func (s *Store) retryDurableBusy(ctx context.Context, op string, observer SQLiteBusyObservabilityV8, attempt func() error) error {
	deadline := time.Now().Add(hookDeliveryJournalBusyWait)
	pause := 10 * time.Millisecond
	for {
		started := time.Now()
		err := attempt()
		s.noteWriteAttempt(started, err, false)
		if err == nil || !isSQLiteBusy(err) || ctx.Err() != nil {
			return err
		}
		if observer != nil {
			_ = observer.RecordSQLiteBusyMetric(ctx, op)
		}
		if !time.Now().Add(pause).Before(deadline) {
			return err
		}
		timer := time.NewTimer(pause)
		select {
		case <-ctx.Done():
			timer.Stop()
			return err
		case <-timer.C:
		}
		pause = min(2*pause, hookDeliveryJournalBusyPause)
	}
}
