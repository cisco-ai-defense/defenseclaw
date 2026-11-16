// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"fmt"
	"sync"
	"time"
)

// writeLockWait tracks a write lock that another connection or process holds
// on audit.db for longer than a whole busy timeout (a CLI or backup tool in a
// long transaction, sqlite3 after BEGIN IMMEDIATE). Each audit write used to
// wait the full busy timeout, up to five times, and a hook call makes about
// two dozen writes before its answer: with the lock held, a benign call was
// answered long after its hook had given up, so the agent was told "the
// gateway is running but did not answer" and the call was refused in every
// fail mode (GAP-1021). A failed audit write already has its own answer (the
// verdict with an audit-degraded alert, closed only where policy says so); the
// wait must not turn it into a missing answer.
//
// Once the store has met only busy results for writeLockHeldAfter (one
// statement that waited that long, or busy attempts with no write committed
// in between), the lock counts as held: the store's connection stops waiting
// (busy timeout 0), busy writes are not retried, and their errors are no
// longer transient to callers that retry a whole transaction
// (IsSQLiteBusy), so they fail at once and the hook answers. The first write
// statement that succeeds ends the hold and restores the busy timeout.
type writeLockWait struct {
	mu   sync.Mutex
	held bool
	// firstBusy is when the current run of busy results began; zero after
	// a write succeeded.
	firstBusy time.Time
	// applied is the busy timeout last set on the store's connection, -1
	// when unknown (a whole wait showed that a new connection has the
	// DSN value again).
	applied  int
	applying bool
	// applyMu serializes the statements that set the busy timeout.
	applyMu sync.Mutex
}

// writeLockHeldAfter is how long the store must meet only busy results for
// the write lock to count as held by someone else. A busy timeout is longer,
// so one whole wait is enough; a transaction that reads first and then finds
// the lock taken fails without waiting, so its retries count too.
const writeLockHeldAfter = 250 * time.Millisecond

// errAuditWriteLockHeld marks a busy error met while another process holds
// the write lock (writeLockWait): it is not transient contention.
var errAuditWriteLockHeld = errors.New("audit: another process holds the audit.db write lock")

// markHeldLockError marks err when it is a busy error of a held lock.
func (s *Store) markHeldLockError(err error) error {
	if err == nil || errors.Is(err, errAuditWriteLockHeld) || !isSQLiteBusy(err) || !s.writeLockHeld() {
		return err
	}
	return fmt.Errorf("%w: %w", errAuditWriteLockHeld, err)
}

// writeLockPragmaWait bounds one statement that changes the busy timeout in
// the background, and writeLockApplyWait one that a failed write runs before
// it returns.
const (
	writeLockPragmaWait = 2 * time.Second
	writeLockApplyWait  = 100 * time.Millisecond
)

// storeBusyObserver is the busy observer the store hands its statements: it
// reports to the bound observer and lets the busy paths find the store.
type storeBusyObserver struct {
	store *Store
	inner SQLiteBusyObservabilityV8
	// detached reports in the background (reportSQLiteBusyDetached): the
	// caller leads a grouped write (writeGroup), and the report itself writes
	// through those groups.
	detached bool
}

func (o storeBusyObserver) RecordSQLiteBusyMetric(ctx context.Context, op string) error {
	if o.detached {
		reportSQLiteBusyDetached(ctx, o.inner, op)
		return nil
	}
	return o.inner.RecordSQLiteBusyMetric(ctx, op)
}

func busyObserverStore(observer SQLiteBusyObservabilityV8) *Store {
	if wrapped, ok := observer.(storeBusyObserver); ok {
		return wrapped.store
	}
	return nil
}

func (s *Store) writeLockHeld() bool {
	if s == nil {
		return false
	}
	s.lockWait.mu.Lock()
	defer s.lockWait.mu.Unlock()
	return s.lockWait.held
}

// noteWriteAttempt updates the hold from one statement or transaction attempt
// that started at started: a busy error after a whole busy wait starts it, a
// write that succeeded ends it. Reads report only their busy errors.
func (s *Store) noteWriteAttempt(started time.Time, err error, write bool) {
	if s == nil {
		return
	}
	switch {
	case err == nil && write:
		s.setWriteLockHeld(false)
	case err != nil && isSQLiteBusy(err):
		s.lockWait.mu.Lock()
		if s.lockWait.firstBusy.IsZero() {
			s.lockWait.firstBusy = started
		}
		since, held := time.Since(s.lockWait.firstBusy), s.lockWait.held
		s.lockWait.mu.Unlock()
		// A whole wait also shows that the connection has its busy timeout
		// again (a new pool connection): set it once more.
		if time.Since(started) >= writeLockHeldAfter || (!held && since >= writeLockHeldAfter) {
			s.setWriteLockHeld(true)
		}
	}
}

// setWriteLockHeld records a held lock or its end. The busy timeout of the
// store's connection follows in the background, because the caller may hold
// that connection in a transaction; a caller that does not hold it applies
// it at once (applyWriteLockWait). A pool connection opened later starts with
// the full busy timeout, and its first whole wait sets it again.
func (s *Store) setWriteLockHeld(held bool) {
	s.lockWait.mu.Lock()
	defer s.lockWait.mu.Unlock()
	if !held {
		s.lockWait.firstBusy = time.Time{}
		if !s.lockWait.held {
			return
		}
	}
	s.lockWait.held = held
	if held {
		s.lockWait.applied = -1
	}
	if s.lockWait.applying {
		return
	}
	s.lockWait.applying = true
	go func() {
		s.applyWriteLockWait(writeLockPragmaWait)
		s.lockWait.mu.Lock()
		s.lockWait.applying = false
		pending := s.lockWait.applied != s.wantBusyTimeoutLocked()
		s.lockWait.mu.Unlock()
		if pending {
			s.applyWriteLockWait(writeLockPragmaWait)
		}
	}()
}

func (s *Store) wantBusyTimeoutLocked() int {
	if s.lockWait.held {
		return 0
	}
	return auditBusyTimeoutMillis
}

// applyWriteLockWait sets the busy timeout the hold wants on the store's
// connection, waiting at most wait for the connection. The caller must not
// hold that connection.
func (s *Store) applyWriteLockWait(wait time.Duration) {
	if s == nil {
		return
	}
	s.lockWait.applyMu.Lock()
	defer s.lockWait.applyMu.Unlock()
	for range 3 {
		s.lockWait.mu.Lock()
		want := s.wantBusyTimeoutLocked()
		done := s.lockWait.applied == want
		s.lockWait.mu.Unlock()
		if done {
			return
		}
		ctx, cancel := context.WithTimeout(context.Background(), wait)
		_, err := s.db.ExecContext(ctx, fmt.Sprintf("PRAGMA busy_timeout = %d", want))
		cancel()
		if err != nil {
			// The store is closing or its connection is busy; the next
			// whole wait tries again.
			return
		}
		s.lockWait.mu.Lock()
		s.lockWait.applied = want
		s.lockWait.mu.Unlock()
	}
}
