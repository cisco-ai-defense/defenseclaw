// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"database/sql"
	"errors"
	"fmt"
	"sync"
)

// Correlation occurrences of concurrent hook calls share a transaction
// (occurrence group). Each hook call opened its own transaction on the store's
// one writer connection, held it while the gateway placed the call in its
// session, and committed alone. At 100 hook calls/s those commits were a
// third of the writer's time, and a freed connection went to a random one of
// the queued occurrences and grouped audit writes: after a stall, a few dozen
// queued occurrences kept the grouped audit rows of every answered call
// waiting for seconds (r108 SWEEP-100).
//
// A grouped occurrence keeps the CorrelationTx a caller drives statement by
// statement: the group's leader begins one transaction and hands it to each
// queued occurrence in turn inside its own savepoint. The occurrence's Commit
// releases its savepoint and returns once the shared transaction committed;
// its Rollback rolls back only its savepoint. Statements run with the shared
// transaction's lifetime and the caller's values (groupedWriteCtx), so one
// caller's cancellation cannot interrupt the others' statements; the caller's
// own context still ends its occurrence at the next statement (usable) and
// while it waits for its turn. Secure Client keeps its own transactions.

// errOccurrenceGroupLost fails every occurrence of a shared transaction that
// SQLite rolled back under one of them (see errGroupedTxLost).
var errOccurrenceGroupLost = errors.New("audit: the shared correlation transaction was rolled back")

type occurrenceLeaseState int

const (
	occurrenceLeaseWaiting occurrenceLeaseState = iota
	occurrenceLeaseGranted
	occurrenceLeaseAbandoned
)

// occurrenceLease is one queued occurrence of the occurrence group.
type occurrenceLease struct {
	mu    sync.Mutex
	state occurrenceLeaseState
	// granted receives the shared transaction and its statement context when
	// the occurrence's turn comes.
	granted chan occurrenceGrant
	// finished receives the caller's decision: true to keep its statements.
	finished chan bool
	// done receives the outcome of the shared transaction for this
	// occurrence (nil once committed).
	done chan error
}

type occurrenceGrant struct {
	tx  *sql.Tx
	ctx context.Context
}

// grant hands the occurrence its turn; false when the caller gave up first.
func (lease *occurrenceLease) grant(tx *sql.Tx, ctx context.Context) bool {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.state != occurrenceLeaseWaiting {
		return false
	}
	lease.state = occurrenceLeaseGranted
	lease.granted <- occurrenceGrant{tx: tx, ctx: ctx}
	return true
}

// abandon reports whether the caller left before its turn; false when the turn
// was already granted (the caller must then finish it).
func (lease *occurrenceLease) abandon() bool {
	lease.mu.Lock()
	defer lease.mu.Unlock()
	if lease.state == occurrenceLeaseWaiting {
		lease.state = occurrenceLeaseAbandoned
		return true
	}
	return false
}

// beginGroupedCorrelationTx queues an occurrence on the occurrence group and
// returns its CorrelationTx once its turn comes, or ctx's error when ctx ends
// first.
func (s *Store) beginGroupedCorrelationTx(ctx context.Context, repo *CorrelationRepository) (*CorrelationTx, error) {
	lease := &occurrenceLease{
		granted:  make(chan occurrenceGrant, 1),
		finished: make(chan bool, 1),
		done:     make(chan error, 1),
	}
	write := &groupedWrite{ctx: ctx, data: lease}
	go func() { lease.done <- s.occurrenceGroup.do(write, s.runOccurrenceBatch) }()
	select {
	case grant := <-lease.granted:
		return &CorrelationTx{repo: repo, tx: grant.tx, lease: lease, stmtCtx: grant.ctx}, nil
	case err := <-lease.done:
		if err == nil {
			err = errors.New("audit: correlation occurrence ended before its turn")
		}
		return nil, err
	case <-ctx.Done():
	}
	if lease.abandon() {
		return nil, ctx.Err()
	}
	// The turn came as ctx ended: give it back unused.
	<-lease.granted
	lease.finished <- false
	return nil, ctx.Err()
}

// runOccurrenceBatch runs one shared transaction of the occurrence group.
func (s *Store) runOccurrenceBatch(batch []*groupedWrite) {
	fail := func(err error) {
		for _, item := range batch {
			item.err = err
		}
	}
	release, err := s.acquireReady()
	if err != nil {
		fail(err)
		return
	}
	defer release()
	batchCtx := context.WithoutCancel(batch[0].ctx)
	tx, err := s.db.BeginTx(batchCtx, nil)
	if err != nil {
		fail(err)
		return
	}
	var lost error
	kept := make([]*groupedWrite, 0, len(batch))
	for _, item := range batch {
		item.err = nil
		lease := item.data.(*occurrenceLease)
		if lost != nil {
			item.err = lost
			continue
		}
		if err := item.ctx.Err(); err != nil {
			item.err = err
			continue
		}
		if _, err := tx.ExecContext(batchCtx, `SAVEPOINT correlation_occurrence`); err != nil {
			lost = fmt.Errorf("%w: %w", errOccurrenceGroupLost, err)
			item.err = lost
			continue
		}
		if !lease.grant(tx, batchCtx) {
			item.err = item.ctx.Err()
			if _, err := tx.ExecContext(batchCtx, `RELEASE correlation_occurrence`); err != nil {
				lost = fmt.Errorf("%w: %w", errOccurrenceGroupLost, err)
			}
			continue
		}
		keep := <-lease.finished
		if !keep {
			if _, err := tx.ExecContext(batchCtx, `ROLLBACK TO correlation_occurrence`); err != nil {
				lost = fmt.Errorf("%w: %w", errOccurrenceGroupLost, err)
				continue
			}
		}
		if _, err := tx.ExecContext(batchCtx, `RELEASE correlation_occurrence`); err != nil {
			lost = fmt.Errorf("%w: %w", errOccurrenceGroupLost, err)
			continue
		}
		if keep {
			kept = append(kept, item)
		}
	}
	if lost != nil {
		_ = tx.Rollback()
		for _, item := range kept {
			item.err = lost
		}
		return
	}
	if err := tx.Commit(); err != nil {
		_ = tx.Rollback()
		err = fmt.Errorf("audit: commit correlation transaction: %w", err)
		for _, item := range kept {
			item.err = err
		}
	}
}
