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
)

// CorrelationGroupLimits bounds one shared correlation transaction of the
// store's correlation group (JoinCorrelationGroup).
type CorrelationGroupLimits struct {
	// Occurrences is the most occurrences one transaction carries; 1 gives
	// every occurrence its own transaction and COMMIT.
	Occurrences int
	// Hold is how long after its BEGIN a transaction still takes the next
	// queued occurrence; 0 does not bound it.
	Hold time.Duration
	// Boundary makes the occurrence that joins with it end its transaction:
	// the transaction commits when the occurrence ends, and the next one
	// starts a new one. For an occurrence whose answer other calls of its
	// session wait for (a session start), so its COMMIT does not wait for
	// the occurrences queued behind it.
	Boundary bool
}

// correlationGroup orders the hook occurrences of the store and lets those
// that write one after the other share one write transaction (S8 design
// section 13).
//
// The correlation ledger is written by one connection, one transaction at a
// time. A hook occurrence read its session cursor, waited for the write baton
// behind the grouped audit rows of the calls already answered, then began,
// wrote and committed alone, so at 100 calls a second the store spent a baton
// turn, a BEGIN and a COMMIT on every hook and the calls of every session
// queued past the hook window (rel-1-0-6 GAP-0558 to GAP-0560, issue #1384).
//
// Two turns order an occurrence:
//   - its session's turn (FIFO per session key), from its first correlation
//     read to the end of its savepoint: the occurrences of one session read
//     what the one before them wrote, in arrival order;
//   - the store's write turn (FIFO), from the BEGIN of its savepoint to its
//     end. When an occurrence ends, the next one waiting for the write turn,
//     of any session, continues in the same transaction until it is full
//     (Occurrences) or old (Hold); then one COMMIT, and the next one starts a
//     new transaction.
//
// An occurrence whose session predecessor is still uncommitted in the open
// transaction takes the write turn before its first read, and reads inside
// that transaction, so it sees the predecessor as the serial path saw its
// commit; every other occurrence reads on the read pool, without either the
// writer or another session waiting for it. Each occurrence has its own
// savepoint: one that fails rolls back alone. An occurrence that released its
// savepoint returns from Commit only after the shared COMMIT, with its own
// result.
type correlationGroup struct {
	mu       sync.Mutex
	held     bool
	waiters  []*correlationWriteWaiter
	members  int
	sessions map[string]*correlationSessionTurn
	// sessionWaiting counts the occurrences waiting for a session turn.
	sessionWaiting int
	oldestSession  map[*correlationSessionWaiter]time.Time
}

type correlationWriteWaiter struct {
	queuedAt time.Time
	limits   CorrelationGroupLimits
	ready    chan *correlationBatch
	handed   bool
}

type correlationSessionTurn struct {
	held    bool
	waiters []*correlationSessionWaiter
	refs    int
	// dirty is the transaction that holds the last occurrence of the session
	// that released its savepoint; it may not have committed yet.
	dirty *correlationBatch
}

type correlationSessionWaiter struct {
	queuedAt time.Time
	ready    chan struct{}
	handed   bool
	// batch is the write turn handed on with the session turn
	// (correlationBatchMember.leave), or nil.
	batch *correlationBatch
}

// correlationBatch is one shared transaction of the group.
type correlationBatch struct {
	store  *Store
	limits CorrelationGroupLimits

	mu         sync.Mutex
	tx         *sql.Tx
	release    func()
	openedAt   time.Time
	savepoints int
	// sessions are the session keys whose last occurrence released its
	// savepoint here: their turns are forgotten once the batch ended.
	sessions []string
	poison   error
	closing  bool
	finished bool

	// done is closed once the batch ended; err is its outcome for the
	// occurrences that released their savepoints.
	done chan struct{}
	err  error
}

// correlationBatchMember is the turn of one occurrence: the repository
// JoinCorrelationGroup returned carries it. Only the goroutine of the
// occurrence uses it.
type correlationBatchMember struct {
	store  *Store
	key    string
	limits CorrelationGroupLimits
	// wait is the caller's context: the waits for the write turn and for the
	// write baton at the BEGIN end with it.
	wait context.Context
	// dirty is the transaction that held the session predecessor when this
	// occurrence got the session turn.
	dirty *correlationBatch
	// batch is the transaction of the write turn this occurrence holds; nil
	// while it holds none.
	batch *correlationBatch
	// writing is set while member holds the write turn; the statement
	// context (CorrelationTurnContext) reads it from other goroutines.
	writing    atomic.Bool
	wrote      bool
	writeLeft  bool
	sessionOut bool
}

// correlationGroupFinished is a test seam: it sees the savepoints every shared
// correlation transaction carried and its outcome.
var correlationGroupFinished func(savepoints int, err error)

// JoinCorrelationGroup waits for the session turn of key, or for ctx, and
// returns the repository the occurrence correlates through and the release
// that ends its turns. Release may be called any number of times and must be
// called at least once; Commit and Rollback of the occurrence call it.
//
// BeginOccurrence of the returned repository opens a savepoint in the
// group's shared transaction. The statements of the occurrence must use a
// context without cancellation (context.WithoutCancel of the caller's): an
// interrupted statement inside an explicit transaction makes SQLite roll back
// all of it, the other occurrences too. ctx itself bounds only the waits.
func (s *Store) JoinCorrelationGroup(ctx context.Context, key string, limits CorrelationGroupLimits) (*CorrelationRepository, func(), error) {
	repo, err := s.CorrelationRepository()
	if err != nil {
		return nil, nil, err
	}
	if ctx == nil {
		return nil, nil, errors.New("audit: correlation context is required")
	}
	limits.Occurrences = max(limits.Occurrences, 1)
	if s.secureClientSchema {
		// Secure Client keeps its own transaction and COMMIT per occurrence.
		limits.Occurrences = 1
	}
	member := &correlationBatchMember{store: s, key: key, limits: limits, wait: ctx}
	if err := s.correlationGroup.joinSession(ctx, member); err != nil {
		return nil, nil, err
	}
	repo.batch = member
	return repo, member.leave, nil
}

// CorrelationTurnQueueSnapshot is the number of occurrences waiting for a
// session turn or the write turn of the store's correlation group, and the
// age of the oldest one.
func (s *Store) CorrelationTurnQueueSnapshot() WriteQueueSnapshot {
	if s == nil {
		return WriteQueueSnapshot{}
	}
	group := &s.correlationGroup
	group.mu.Lock()
	defer group.mu.Unlock()
	depth := len(group.waiters) + group.sessionWaiting
	if depth == 0 {
		return WriteQueueSnapshot{}
	}
	oldest := time.Now()
	if len(group.waiters) > 0 {
		oldest = group.waiters[0].queuedAt
	}
	for _, queuedAt := range group.oldestSession {
		if queuedAt.Before(oldest) {
			oldest = queuedAt
		}
	}
	return WriteQueueSnapshot{Depth: int64(depth), OldestAge: max(time.Since(oldest), 0)}
}

// joinSession waits for the session turn of member, or for ctx, and sets
// what member continues: the transaction of its session predecessor and, when
// the predecessor handed it on, the write turn.
func (group *correlationGroup) joinSession(ctx context.Context, member *correlationBatchMember) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	key := member.key
	group.mu.Lock()
	if group.sessions == nil {
		group.sessions = make(map[string]*correlationSessionTurn)
		group.oldestSession = make(map[*correlationSessionWaiter]time.Time)
	}
	turn := group.sessions[key]
	if turn == nil {
		turn = &correlationSessionTurn{}
		group.sessions[key] = turn
	}
	turn.refs++
	if !turn.held {
		turn.held = true
		member.dirty = turn.dirty
		group.mu.Unlock()
		return nil
	}
	waiter := &correlationSessionWaiter{queuedAt: time.Now(), ready: make(chan struct{}, 1)}
	turn.waiters = append(turn.waiters, waiter)
	group.sessionWaiting++
	group.oldestSession[waiter] = waiter.queuedAt
	group.mu.Unlock()
	select {
	case <-waiter.ready:
		group.mu.Lock()
		member.dirty, member.batch = turn.dirty, waiter.batch
		member.writing.Store(member.batch != nil)
		group.mu.Unlock()
		return nil
	case <-ctx.Done():
	}
	group.mu.Lock()
	if !waiter.handed {
		for index, queued := range turn.waiters {
			if queued == waiter {
				turn.waiters = append(turn.waiters[:index], turn.waiters[index+1:]...)
				break
			}
		}
		group.sessionWaiting--
		delete(group.oldestSession, waiter)
		group.leaveSessionLocked(key, turn)
		group.mu.Unlock()
		return ctx.Err()
	}
	group.mu.Unlock()
	// The turn reached this caller as it left: hand it on at once.
	<-waiter.ready
	group.mu.Lock()
	member.dirty, member.batch = turn.dirty, waiter.batch
	group.mu.Unlock()
	member.leave()
	return ctx.Err()
}

// passSession ends the session turn of key; wrote is the transaction that
// holds the occurrence that ends it, when it released its savepoint.
func (group *correlationGroup) passSession(key string, wrote *correlationBatch) {
	group.mu.Lock()
	defer group.mu.Unlock()
	turn := group.sessions[key]
	if wrote != nil {
		turn.dirty = wrote
		wrote.sessions = append(wrote.sessions, key)
	}
	if len(turn.waiters) > 0 {
		next := turn.waiters[0]
		turn.waiters[0] = nil
		turn.waiters = turn.waiters[1:]
		next.handed = true
		group.sessionWaiting--
		delete(group.oldestSession, next)
		turn.refs--
		next.ready <- struct{}{}
		return
	}
	turn.held = false
	group.leaveSessionLocked(key, turn)
}

func (group *correlationGroup) leaveSessionLocked(key string, turn *correlationSessionTurn) {
	turn.refs--
	if turn.refs == 0 && (turn.dirty == nil || turn.dirty.isFinished()) {
		delete(group.sessions, key)
	}
}

// joinWrite waits for the write turn, or for ctx, and returns the
// transaction this occurrence continues: the open one, or a new one.
func (group *correlationGroup) joinWrite(ctx context.Context, s *Store, limits CorrelationGroupLimits) (*correlationBatch, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	group.mu.Lock()
	if !group.held {
		group.held = true
		group.members = 1
		group.mu.Unlock()
		return newCorrelationBatch(s, limits), nil
	}
	waiter := &correlationWriteWaiter{queuedAt: time.Now(), limits: limits, ready: make(chan *correlationBatch, 1)}
	group.waiters = append(group.waiters, waiter)
	group.mu.Unlock()
	select {
	case batch := <-waiter.ready:
		return batch, nil
	case <-ctx.Done():
	}
	group.mu.Lock()
	if !waiter.handed {
		for index, queued := range group.waiters {
			if queued == waiter {
				group.waiters = append(group.waiters[:index], group.waiters[index+1:]...)
				break
			}
		}
		group.mu.Unlock()
		return nil, ctx.Err()
	}
	group.mu.Unlock()
	group.passWrite(s, <-waiter.ready)
	return nil, ctx.Err()
}

// passWrite ends the write turn of an occurrence of batch: the next queued
// occurrence continues in the same transaction while the batch takes more,
// otherwise the batch commits and the next one starts a new batch.
func (group *correlationGroup) passWrite(s *Store, batch *correlationBatch) {
	group.mu.Lock()
	if len(group.waiters) > 0 && group.members < batch.limits.Occurrences && batch.takesMore() {
		next := group.popWriteLocked()
		group.members++
		group.mu.Unlock()
		next.ready <- batch
		return
	}
	group.mu.Unlock()
	batch.finish()
	group.mu.Lock()
	for _, key := range batch.sessions {
		if turn := group.sessions[key]; turn != nil && turn.refs == 0 && turn.dirty == batch {
			delete(group.sessions, key)
		}
	}
	if len(group.waiters) == 0 {
		group.held = false
		group.members = 0
		group.mu.Unlock()
		return
	}
	next := group.popWriteLocked()
	group.members = 1
	group.mu.Unlock()
	next.ready <- newCorrelationBatch(s, next.limits)
}

func (group *correlationGroup) popWriteLocked() *correlationWriteWaiter {
	next := group.waiters[0]
	group.waiters[0] = nil
	group.waiters = group.waiters[1:]
	next.handed = true
	return next
}

func newCorrelationBatch(s *Store, limits CorrelationGroupLimits) *correlationBatch {
	return &correlationBatch{store: s, limits: limits, done: make(chan struct{})}
}

// takesMore reports whether the next queued occurrence may join the batch.
func (batch *correlationBatch) takesMore() bool {
	batch.mu.Lock()
	defer batch.mu.Unlock()
	if batch.closing || batch.poison != nil || batch.finished {
		return false
	}
	return batch.tx == nil || batch.limits.Hold <= 0 || time.Since(batch.openedAt) < batch.limits.Hold
}

func (batch *correlationBatch) isFinished() bool {
	batch.mu.Lock()
	defer batch.mu.Unlock()
	return batch.finished
}

// fail marks the shared transaction as rolled back by SQLite or otherwise
// unusable: it takes no more occurrences and rolls back when it ends.
func (batch *correlationBatch) fail(cause error) {
	batch.mu.Lock()
	defer batch.mu.Unlock()
	if batch.poison == nil {
		batch.poison = cause
	}
}

// finish commits the shared transaction (or rolls it back when it failed)
// and releases the occurrences waiting for it.
func (batch *correlationBatch) finish() {
	batch.mu.Lock()
	if batch.finished {
		batch.mu.Unlock()
		return
	}
	tx, release, poison, savepoints := batch.tx, batch.release, batch.poison, batch.savepoints
	batch.mu.Unlock()
	var err error
	if tx != nil {
		if poison != nil {
			_ = tx.Rollback()
			err = fmt.Errorf("%w: the shared correlation transaction was rolled back: %v", ErrCorrelationStale, poison)
		} else if err = tx.Commit(); err != nil {
			_ = tx.Rollback()
		}
		release()
	}
	batch.mu.Lock()
	batch.finished = true
	batch.err = err
	batch.mu.Unlock()
	close(batch.done)
	if observe := correlationGroupFinished; observe != nil {
		observe(savepoints, err)
	}
}

// enterWrite takes the store's write turn for member, once.
func (member *correlationBatchMember) enterWrite() error {
	if member.batch != nil {
		return nil
	}
	if member.writeLeft || member.sessionOut {
		return errors.New("audit: the correlation turn of this occurrence has ended")
	}
	batch, err := member.store.correlationGroup.joinWrite(member.wait, member.store, member.limits)
	if err != nil {
		return err
	}
	member.batch = batch
	member.writing.Store(true)
	return nil
}

// leaveWrite ends the write turn of member, if it holds one.
func (member *correlationBatchMember) leaveWrite() {
	if member.batch == nil || member.writeLeft {
		return
	}
	member.writeLeft = true
	member.writing.Store(false)
	member.store.correlationGroup.passWrite(member.store, member.batch)
}

// leave ends both turns of member. When member holds the write turn and its
// session has the next occurrence waiting, that occurrence gets the session turn and the
// write turn together and continues in the same transaction while it takes
// more: it reads what member wrote there, and one session at 100 calls a
// second shares one COMMIT instead of one each.
func (member *correlationBatchMember) leave() {
	if member.sessionOut {
		member.leaveWrite()
		return
	}
	if member.limits.Boundary && member.inWrite() {
		member.batch.mu.Lock()
		member.batch.closing = true
		member.batch.mu.Unlock()
	}
	if member.inWrite() && member.store.correlationGroup.handOnSession(member) {
		return
	}
	member.leaveWrite()
	if member.sessionOut {
		return
	}
	member.sessionOut = true
	var wrote *correlationBatch
	if member.wrote {
		wrote = member.batch
	}
	member.store.correlationGroup.passSession(member.key, wrote)
}

// handOnSession hands the session turn and the write turn of member to the
// next occurrence of its session, when one waits and the transaction takes
// more. It reports whether it did.
func (group *correlationGroup) handOnSession(member *correlationBatchMember) bool {
	batch := member.batch
	group.mu.Lock()
	defer group.mu.Unlock()
	turn := group.sessions[member.key]
	if len(turn.waiters) == 0 || group.members >= batch.limits.Occurrences || !batch.takesMore() {
		return false
	}
	member.writeLeft, member.sessionOut = true, true
	member.writing.Store(false)
	turn.dirty = batch
	batch.sessions = append(batch.sessions, member.key)
	next := turn.waiters[0]
	turn.waiters[0] = nil
	turn.waiters = turn.waiters[1:]
	next.handed = true
	next.batch = batch
	group.sessionWaiting--
	delete(group.oldestSession, next)
	turn.refs--
	group.members++
	next.ready <- struct{}{}
	return true
}

// CorrelationTurnContext is the context for the statements of an occurrence
// of repo (JoinCorrelationGroup). While the occurrence holds the write turn
// it has no cancellation and no deadline: its statements run inside the
// transaction other occurrences share, and an interrupted statement would
// make SQLite roll all of it back. Outside the write turn (its reads on the
// read pool, a connector instance resolution) it is ctx, cancellation and
// deadline included. Values are always those of ctx.
func CorrelationTurnContext(ctx context.Context, repo *CorrelationRepository) context.Context {
	if repo == nil || repo.batch == nil {
		return ctx
	}
	return correlationTurnContext{Context: ctx, member: repo.batch}
}

type correlationTurnContext struct {
	context.Context
	member *correlationBatchMember
}

func (c correlationTurnContext) Deadline() (time.Time, bool) {
	if c.member.writing.Load() {
		return time.Time{}, false
	}
	return c.Context.Deadline()
}

func (c correlationTurnContext) Done() <-chan struct{} {
	if c.member.writing.Load() {
		return nil
	}
	return c.Context.Done()
}

func (c correlationTurnContext) Err() error {
	if c.member.writing.Load() {
		return nil
	}
	return c.Context.Err()
}

// inWrite reports whether member holds an unfinished write turn.
func (member *correlationBatchMember) inWrite() bool {
	return member.batch != nil && !member.writeLeft && !member.sessionOut
}

// sharedTx is the open shared transaction while repo holds the write turn,
// and nil otherwise.
func (repo *CorrelationRepository) sharedTx() *sql.Tx {
	if repo == nil || repo.batch == nil || !repo.batch.inWrite() {
		return nil
	}
	batch := repo.batch.batch
	batch.mu.Lock()
	defer batch.mu.Unlock()
	if batch.finished || batch.poison != nil {
		return nil
	}
	return batch.tx
}

// correlationQueryer is a read connection: the read pool, or the shared
// transaction of a correlation turn.
type correlationQueryer interface {
	QueryContext(ctx context.Context, query string, args ...any) (*sql.Rows, error)
	QueryRowContext(ctx context.Context, query string, args ...any) *sql.Row
}

// queryPool is where the correlation reads of repo run: inside the shared
// transaction while it holds the write turn of an open one, and on the
// store's read pool otherwise. Call acquireReady first.
func (repo *CorrelationRepository) queryPool() correlationQueryer {
	if tx := repo.sharedTx(); tx != nil {
		return tx
	}
	return repo.store.queryPool()
}

// acquireReady is Store.acquireReady for a correlation read of repo. An
// occurrence whose session predecessor may still be uncommitted in the open
// shared transaction first takes the write turn, so its reads see the
// predecessor (inside that transaction, or on the pool after its COMMIT).
// Inside an open shared transaction, which holds the read lock of the store
// already, it takes no second one: a nested read lock would wait behind a
// Close that waits for the transaction.
func (repo *CorrelationRepository) acquireReady() (func(), error) {
	if member := repo.batch; member != nil && !member.inWrite() && member.dirty != nil && !member.dirty.isFinished() {
		if err := member.enterWrite(); err != nil {
			return nil, err
		}
	}
	if repo.sharedTx() != nil {
		return func() {}, nil
	}
	return repo.store.acquireReady()
}

// ownTransactionAllowed reports ErrCorrelationStale when repo holds the write
// turn of an open shared transaction: a write that opens its own transaction
// on the store's one writer connection (connector instance resolution and
// upsert) would wait for the shared one, which waits for this occurrence. The
// shared transaction then takes no more occurrences, so the stale retry runs
// after its COMMIT.
func (repo *CorrelationRepository) ownTransactionAllowed() error {
	if repo.sharedTx() == nil {
		return nil
	}
	batch := repo.batch.batch
	batch.mu.Lock()
	batch.closing = true
	batch.mu.Unlock()
	return fmt.Errorf("%w: a connector instance write waits for the shared correlation transaction", ErrCorrelationStale)
}

// beginOccurrenceTx opens the transaction of one occurrence: its own, or for
// a repository of the correlation group (JoinCorrelationGroup), a savepoint
// in the group's shared transaction.
func (repo *CorrelationRepository) beginOccurrenceTx(ctx context.Context) (*CorrelationTx, error) {
	if repo.batch != nil {
		return repo.batch.beginOccurrence(ctx, repo)
	}
	release, err := repo.store.acquireReady()
	if err != nil {
		return nil, err
	}
	turn, err := repo.store.acquireCorrelationWriteTurn(ctx)
	if err != nil {
		release()
		return nil, fmt.Errorf("audit: begin correlation occurrence: %w", err)
	}
	tx, err := repo.store.db.BeginTx(ctx, nil)
	if err != nil {
		turn()
		release()
		return nil, fmt.Errorf("audit: begin correlation occurrence: %w", err)
	}
	return &CorrelationTx{repo: repo, tx: tx, release: func() { turn(); release() }}, nil
}

// acquireCorrelationWriteTurn takes the write baton for a correlation
// transaction. The occurrence reads before it writes. Another writer of this
// process that commits in between makes the upgrade fail at once with
// SQLITE_BUSY_SNAPSHOT and the hook starts its correlation over, so the
// transaction takes the write baton first (writeBaton), ahead of the records
// of calls already answered: the answer waits on it. Secure Client keeps the
// arrival order of the baton.
func (s *Store) acquireCorrelationWriteTurn(ctx context.Context) (func(), error) {
	if s.secureClientSchema {
		return s.writeBaton.acquire(ctx)
	}
	return s.writeBaton.acquireUrgent(ctx)
}

func (member *correlationBatchMember) beginOccurrence(ctx context.Context, repo *CorrelationRepository) (*CorrelationTx, error) {
	if err := member.enterWrite(); err != nil {
		return nil, fmt.Errorf("audit: begin correlation occurrence: %w", err)
	}
	if ctx.Done() != nil {
		// Checked in the write turn, where CorrelationTurnContext has none.
		return nil, errors.New("audit: a correlation group occurrence needs a context without cancellation in its write turn")
	}
	if !member.inWrite() {
		return nil, errors.New("audit: the correlation turn of this occurrence has ended")
	}
	batch := member.batch
	batch.mu.Lock()
	tx, poison, finished := batch.tx, batch.poison, batch.finished
	batch.mu.Unlock()
	if finished {
		return nil, errors.New("audit: the shared correlation transaction has ended")
	}
	if poison != nil {
		return nil, fmt.Errorf("%w: the shared correlation transaction failed: %v", ErrCorrelationStale, poison)
	}
	if tx == nil {
		release, err := member.store.acquireReady()
		if err != nil {
			return nil, err
		}
		turn, err := member.store.acquireCorrelationWriteTurn(member.wait)
		if err != nil {
			release()
			return nil, fmt.Errorf("audit: begin correlation occurrence: %w", err)
		}
		// The wait for the writer connection ends with the caller; the
		// transaction outlives it and ends with the batch.
		conn, err := member.store.db.Conn(member.wait)
		if err != nil {
			turn()
			release()
			return nil, fmt.Errorf("audit: begin correlation occurrence: %w", err)
		}
		tx, err = conn.BeginTx(context.WithoutCancel(member.wait), nil)
		if err != nil {
			_ = conn.Close()
			turn()
			release()
			return nil, fmt.Errorf("audit: begin correlation occurrence: %w", err)
		}
		batch.mu.Lock()
		batch.tx, batch.openedAt = tx, time.Now()
		batch.release = func() { _ = conn.Close(); turn(); release() }
		batch.mu.Unlock()
	}
	batch.mu.Lock()
	batch.savepoints++
	savepoint := fmt.Sprintf("dc_correlation_%d", batch.savepoints)
	batch.mu.Unlock()
	if _, err := tx.ExecContext(ctx, "SAVEPOINT "+savepoint); err != nil {
		batch.fail(err)
		return nil, fmt.Errorf("audit: begin correlation occurrence: %w", err)
	}
	return &CorrelationTx{repo: repo, tx: tx, savepoint: savepoint}, nil
}

// commitSavepoint ends an occurrence of a shared transaction: it releases
// its savepoint, passes both turns on and returns once the shared
// transaction committed, with that outcome.
func (tx *CorrelationTx) commitSavepoint() error {
	member := tx.repo.batch
	batch := member.batch
	tx.closed = true
	if _, err := tx.tx.ExecContext(context.Background(), "RELEASE "+tx.savepoint); err != nil {
		batch.fail(err)
		member.leave()
		return fmt.Errorf("audit: commit correlation transaction: %w", err)
	}
	member.wrote = true
	member.leave()
	<-batch.done
	if err := batch.err; err != nil {
		return fmt.Errorf("audit: commit correlation transaction: %w", err)
	}
	return nil
}

// rollbackSavepoint undoes one occurrence of a shared transaction and passes
// both turns on; the occurrences before it stay. A savepoint that cannot be
// rolled back means SQLite rolled back the whole transaction: the batch then
// fails, and the occurrences that already released theirs start over.
func (tx *CorrelationTx) rollbackSavepoint() error {
	member := tx.repo.batch
	tx.closed = true
	_, err := tx.tx.ExecContext(context.Background(), "ROLLBACK TO "+tx.savepoint)
	if err == nil {
		_, err = tx.tx.ExecContext(context.Background(), "RELEASE "+tx.savepoint)
	}
	if err != nil {
		member.batch.fail(err)
	}
	member.leave()
	if err != nil {
		return fmt.Errorf("audit: rollback correlation transaction: %w", err)
	}
	return nil
}
