// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"fmt"
	"math/rand/v2"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

var groupTestLimits = CorrelationGroupLimits{Occurrences: 64, Hold: time.Minute}

// groupOccurrence is one occurrence the way a hook writes it: it reads its
// session cursor, begins, stores its event and moves the cursor.
func groupOccurrence(t *testing.T, ctx context.Context, repo *CorrelationRepository, instance ConnectorInstance, session string) (*CorrelationTx, SemanticEventID, error) {
	t.Helper()
	semantic, err := NewSemanticEventID()
	if err != nil {
		t.Fatal(err)
	}
	sequence := uint64(1)
	cursor, err := repo.GetCursor(ctx, instance.ConnectorInstanceID, session, "agent")
	switch {
	case err == nil:
		sequence = cursor.Sequence + 1
	case !errors.Is(err, ErrCorrelationNotFound):
		return nil, semantic, err
	}
	tx, _, err := repo.BeginOccurrence(ctx, CorrelationOccurrenceInput{Event: CorrelationEvent{
		SemanticEventID: semantic, LogicalEventID: LogicalEventID(semantic),
		Connector: instance.Connector, ConnectorInstanceID: instance.ConnectorInstanceID,
		Rail: CorrelationRailHook, EventName: "tool.started", ReceivedTime: time.Now().UTC(),
		ProfileVersion: instance.ProfileVersion, Completeness: CorrelationComplete,
	}})
	if err != nil {
		return nil, semantic, err
	}
	if err := tx.PutCursor(ctx, CorrelationCursor{
		ConnectorInstanceID: instance.ConnectorInstanceID, SessionID: session, AgentID: "agent",
		Phase: "active", Sequence: sequence, LastSemanticEventID: semantic,
		ProfileVersion: instance.ProfileVersion, Active: true, UpdatedAt: time.Now().UTC(),
	}); err != nil {
		_ = tx.Rollback()
		return nil, semantic, err
	}
	return tx, semantic, nil
}

func groupEventExists(t *testing.T, store *Store, semantic SemanticEventID) bool {
	t.Helper()
	var n int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM correlation_events WHERE semantic_event_id=?`, string(semantic)).Scan(&n); err != nil {
		t.Fatal(err)
	}
	return n == 1
}

// waitForCorrelationQueue waits until depth occurrences wait for a turn.
func waitForCorrelationQueue(t *testing.T, store *Store, depth int64) {
	t.Helper()
	deadline := time.Now().Add(10 * time.Second)
	for store.CorrelationTurnQueueSnapshot().Depth != depth {
		if time.Now().After(deadline) {
			t.Fatalf("correlation turn queue depth %d, want %d", store.CorrelationTurnQueueSnapshot().Depth, depth)
		}
		time.Sleep(time.Millisecond)
	}
}

func observeCorrelationGroups(t *testing.T) func() []int {
	t.Helper()
	var mu sync.Mutex
	var sizes []int
	correlationGroupFinished = func(savepoints int, err error) {
		mu.Lock()
		defer mu.Unlock()
		sizes = append(sizes, savepoints)
	}
	t.Cleanup(func() { correlationGroupFinished = nil })
	return func() []int {
		mu.Lock()
		defer mu.Unlock()
		return append([]int(nil), sizes...)
	}
}

func groupIdle(t *testing.T, store *Store) {
	t.Helper()
	group := &store.correlationGroup
	group.mu.Lock()
	defer group.mu.Unlock()
	if group.held || len(group.waiters) != 0 || group.sessionWaiting != 0 || len(group.sessions) != 0 {
		t.Fatalf("correlation group left held=%v with %d write waiters, %d session waiters, %d sessions",
			group.held, len(group.waiters), group.sessionWaiting, len(group.sessions))
	}
}

// holdCorrelationWriteTurn takes the store's write turn with an occurrence
// of its own and returns the function that commits it.
func holdCorrelationWriteTurn(t *testing.T, store *Store, instance ConnectorInstance, limits CorrelationGroupLimits) func() <-chan error {
	t.Helper()
	repo, release, err := store.JoinCorrelationGroup(t.Context(), "holder", limits)
	if err != nil {
		t.Fatal(err)
	}
	tx, _, err := groupOccurrence(t, context.WithoutCancel(t.Context()), repo, instance, "holder")
	if err != nil {
		t.Fatal(err)
	}
	return func() <-chan error {
		done := make(chan error, 1)
		go func() {
			defer release()
			done <- tx.Commit()
		}()
		return done
	}
}

// queuedOccurrence is the outcome of one occurrence run through the group.
type queuedOccurrence struct {
	semantic SemanticEventID
	err      error
}

func runGroupOccurrence(t *testing.T, store *Store, instance ConnectorInstance, session string, limits CorrelationGroupLimits, fail bool, out chan<- queuedOccurrence) {
	repo, release, err := store.JoinCorrelationGroup(t.Context(), session, limits)
	if err != nil {
		out <- queuedOccurrence{err: err}
		return
	}
	defer release()
	ctx := context.WithoutCancel(t.Context())
	tx, semantic, err := groupOccurrence(t, ctx, repo, instance, session)
	if err != nil {
		out <- queuedOccurrence{semantic: semantic, err: err}
		return
	}
	if fail {
		// A write the occurrence cannot make: it rolls back its savepoint.
		err = tx.PutCursor(ctx, CorrelationCursor{})
		_ = tx.Rollback()
		out <- queuedOccurrence{semantic: semantic, err: err}
		return
	}
	out <- queuedOccurrence{semantic: semantic, err: tx.Commit()}
}

// Occurrences of several sessions queued behind the write turn share one
// transaction and one COMMIT, each in its own savepoint, and every one
// returns only after that COMMIT. An occurrence whose session predecessor is
// still uncommitted in the shared transaction reads its cursor there.
func TestCorrelationGroupSharesOneTransaction(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "group", ConnectorCustodyHookOnly)
	groups := observeCorrelationGroups(t)
	commit := holdCorrelationWriteTurn(t, store, instance, groupTestLimits)
	out := make(chan queuedOccurrence, 6)
	for i := 0; i < 6; i++ {
		go runGroupOccurrence(t, store, instance, fmt.Sprintf("s%d", i%2), groupTestLimits, false, out)
		waitForCorrelationQueue(t, store, int64(i+1))
	}
	holder := commit()
	for i := 0; i < 6; i++ {
		got := <-out
		if got.err != nil {
			t.Fatalf("occurrence %d: %v", i, got.err)
		}
		if !groupEventExists(t, store, got.semantic) {
			t.Fatalf("occurrence %s not committed", got.semantic)
		}
	}
	if err := <-holder; err != nil {
		t.Fatal(err)
	}
	if sizes := groups(); len(sizes) != 1 || sizes[0] != 7 {
		t.Fatalf("shared transactions %v, want one of 7 savepoints", sizes)
	}
	for _, session := range []string{"s0", "s1"} {
		cursor, err := repo.GetCursor(t.Context(), instance.ConnectorInstanceID, session, "agent")
		if err != nil || cursor.Sequence != 3 {
			t.Fatalf("session %s cursor %+v %v, want sequence 3", session, cursor, err)
		}
	}
	groupIdle(t, store)
}

// Groups of one are the serial path: one transaction and COMMIT each, and an
// occurrence reads its predecessor on the read pool after that COMMIT.
func TestCorrelationGroupOfOneCommitsEachOccurrence(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "group", ConnectorCustodyHookOnly)
	groups := observeCorrelationGroups(t)
	one := CorrelationGroupLimits{Occurrences: 1}
	commit := holdCorrelationWriteTurn(t, store, instance, one)
	out := make(chan queuedOccurrence, 3)
	for i := 0; i < 3; i++ {
		go runGroupOccurrence(t, store, instance, "s", one, false, out)
		waitForCorrelationQueue(t, store, int64(i+1))
	}
	holder := commit()
	for i := 0; i < 3; i++ {
		if got := <-out; got.err != nil {
			t.Fatal(got.err)
		}
	}
	if err := <-holder; err != nil {
		t.Fatal(err)
	}
	if sizes := groups(); len(sizes) != 4 || sizes[0] != 1 || sizes[3] != 1 {
		t.Fatalf("transactions %v, want four of one savepoint", sizes)
	}
	cursor, err := repo.GetCursor(t.Context(), instance.ConnectorInstanceID, "s", "agent")
	if err != nil || cursor.Sequence != 3 {
		t.Fatalf("cursor %+v %v, want sequence 3", cursor, err)
	}
	groupIdle(t, store)
}

// A boundary occurrence (a session start) commits its transaction when it
// ends: the occurrences queued behind it start a new one, so its answer does
// not wait for them.
func TestCorrelationGroupBoundaryEndsItsTransaction(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "group", ConnectorCustodyHookOnly)
	groups := observeCorrelationGroups(t)
	commit := holdCorrelationWriteTurn(t, store, instance, groupTestLimits)
	boundary := groupTestLimits
	boundary.Boundary = true
	outs := make([]chan queuedOccurrence, 3)
	for i := range outs {
		outs[i] = make(chan queuedOccurrence, 1)
		limits := groupTestLimits
		if i == 0 {
			limits = boundary
		}
		go runGroupOccurrence(t, store, instance, "s", limits, false, outs[i])
		waitForCorrelationQueue(t, store, int64(i+1))
	}
	holder := commit()
	for _, out := range outs {
		if got := <-out; got.err != nil {
			t.Fatal(got.err)
		}
	}
	if err := <-holder; err != nil {
		t.Fatal(err)
	}
	if sizes := groups(); len(sizes) != 2 || sizes[0] != 2 || sizes[1] != 2 {
		t.Fatalf("transactions %v, want the holder with the boundary, then the two after it", sizes)
	}
	groupIdle(t, store)
}

// One occurrence that fails rolls back its savepoint alone: the occurrences
// before and after it in the shared transaction commit.
func TestCorrelationGroupOneFailingOccurrenceRollsBackAlone(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "group", ConnectorCustodyHookOnly)
	groups := observeCorrelationGroups(t)
	commit := holdCorrelationWriteTurn(t, store, instance, groupTestLimits)
	outs := make([]chan queuedOccurrence, 3)
	for i := range outs {
		outs[i] = make(chan queuedOccurrence, 1)
		go runGroupOccurrence(t, store, instance, "s", groupTestLimits, i == 1, outs[i])
		waitForCorrelationQueue(t, store, int64(i+1))
	}
	holder := commit()
	first, bad, last := <-outs[0], <-outs[1], <-outs[2]
	if first.err != nil || last.err != nil {
		t.Fatalf("the good occurrences failed: %v, %v", first.err, last.err)
	}
	if bad.err == nil {
		t.Fatal("the invalid cursor was accepted")
	}
	if err := <-holder; err != nil {
		t.Fatal(err)
	}
	if !groupEventExists(t, store, first.semantic) || !groupEventExists(t, store, last.semantic) {
		t.Fatal("a good occurrence was not committed")
	}
	if groupEventExists(t, store, bad.semantic) {
		t.Fatal("the failed occurrence was committed")
	}
	cursor, err := repo.GetCursor(t.Context(), instance.ConnectorInstanceID, "s", "agent")
	if err != nil || cursor.Sequence != 2 || cursor.LastSemanticEventID != last.semantic {
		t.Fatalf("cursor %+v %v: want sequence 2 at the last good occurrence", cursor, err)
	}
	if sizes := groups(); len(sizes) != 1 || sizes[0] != 4 {
		t.Fatalf("shared transactions %v, want one of 4 savepoints", sizes)
	}
	groupIdle(t, store)
}

// When SQLite rolled back the whole shared transaction, the occurrences that
// already released their savepoints get ErrCorrelationStale (they start over)
// and the next occurrence gets a new transaction.
func TestCorrelationGroupRolledBackTransactionRestartsTheOthers(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "group", ConnectorCustodyHookOnly)
	commit := holdCorrelationWriteTurn(t, store, instance, groupTestLimits)
	first := make(chan queuedOccurrence, 1)
	go runGroupOccurrence(t, store, instance, "a", groupTestLimits, false, first)
	waitForCorrelationQueue(t, store, 1)
	breaker := make(chan error, 1)
	go func() {
		repo, release, err := store.JoinCorrelationGroup(t.Context(), "b", groupTestLimits)
		if err != nil {
			breaker <- err
			return
		}
		defer release()
		ctx := context.WithoutCancel(t.Context())
		tx, _, err := groupOccurrence(t, ctx, repo, instance, "b")
		if err != nil {
			breaker <- err
			return
		}
		// What SQLite does on SQLITE_FULL, IOERR or an interrupt.
		if _, err := tx.tx.ExecContext(ctx, "ROLLBACK"); err != nil {
			breaker <- err
			return
		}
		breaker <- tx.Rollback()
	}()
	waitForCorrelationQueue(t, store, 2)
	last := make(chan queuedOccurrence, 1)
	go runGroupOccurrence(t, store, instance, "c", groupTestLimits, false, last)
	waitForCorrelationQueue(t, store, 3)
	holder := commit()
	if got := <-first; !errors.Is(got.err, ErrCorrelationStale) {
		t.Fatalf("an occurrence of the rolled-back transaction got %v, want ErrCorrelationStale", got.err)
	}
	if err := <-holder; !errors.Is(err, ErrCorrelationStale) {
		t.Fatalf("the holder of the rolled-back transaction got %v, want ErrCorrelationStale", err)
	}
	if err := <-breaker; err == nil {
		t.Fatal("the broken savepoint rolled back cleanly")
	}
	got := <-last
	if got.err != nil || !groupEventExists(t, store, got.semantic) {
		t.Fatalf("the occurrence after the rolled-back transaction: %v", got.err)
	}
	groupIdle(t, store)
}

// A caller leaves the session turn and the write turn with its context and
// takes nothing; the turns go on.
func TestCorrelationGroupWaiterLeavesWithItsContext(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "group", ConnectorCustodyHookOnly)
	_, release, err := store.JoinCorrelationGroup(t.Context(), "k", groupTestLimits)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancel()
	if _, _, err := store.JoinCorrelationGroup(ctx, "k", groupTestLimits); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a session waiter got %v while the turn was held", err)
	}
	release()
	release()
	commit := holdCorrelationWriteTurn(t, store, instance, groupTestLimits)
	short, cancelShort := context.WithTimeout(t.Context(), 20*time.Millisecond)
	defer cancelShort()
	member, leave, err := store.JoinCorrelationGroup(short, "other", groupTestLimits)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := groupOccurrence(t, context.WithoutCancel(short), member, instance, "other"); !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("a write-turn waiter got %v while the turn was held", err)
	}
	leave()
	if err := <-commit(); err != nil {
		t.Fatal(err)
	}
	_, next, err := store.JoinCorrelationGroup(t.Context(), "k", groupTestLimits)
	if err != nil {
		t.Fatal(err)
	}
	next()
	groupIdle(t, store)
}

// The statements of a group occurrence must not be cancellable.
func TestCorrelationGroupRefusesACancellableContext(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "group", ConnectorCustodyHookOnly)
	member, release, err := store.JoinCorrelationGroup(t.Context(), "s", groupTestLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	if _, _, err := groupOccurrence(t, t.Context(), member, instance, "s"); err == nil {
		t.Fatal("a cancellable context opened a savepoint in the shared transaction")
	}
}

// The statement context of an occurrence follows the caller outside its
// write turn and has no cancellation inside it.
func TestCorrelationTurnContextHasNoCancellationInTheWriteTurn(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "group", ConnectorCustodyHookOnly)
	ctx, cancel := context.WithCancel(t.Context())
	defer cancel()
	member, release, err := store.JoinCorrelationGroup(ctx, "s", groupTestLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	turn := CorrelationTurnContext(ctx, member)
	if turn.Done() == nil {
		t.Fatal("outside the write turn the statement context lost its cancellation")
	}
	tx, _, err := groupOccurrence(t, turn, member, instance, "s")
	if err != nil {
		t.Fatal(err)
	}
	cancel()
	if turn.Done() != nil || turn.Err() != nil {
		t.Fatal("inside the write turn the statement context can be cancelled")
	}
	if err := tx.Commit(); err != nil {
		t.Fatalf("an occurrence whose caller left inside its write turn: %v", err)
	}
	if !errors.Is(turn.Err(), context.Canceled) {
		t.Fatalf("after the write turn the statement context error is %v, want the caller's", turn.Err())
	}
}

// Inside an open shared transaction, a connector-instance write that needs
// its own transaction is stale (and closes the transaction) instead of
// waiting for the writer connection the shared transaction holds.
func TestCorrelationGroupOwnTransactionIsStaleInsideTheGroup(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "group", ConnectorCustodyHookOnly)
	member, release, err := store.JoinCorrelationGroup(t.Context(), "s", groupTestLimits)
	if err != nil {
		t.Fatal(err)
	}
	defer release()
	ctx := context.WithoutCancel(t.Context())
	tx, _, err := groupOccurrence(t, ctx, member, instance, "s")
	if err != nil {
		t.Fatal(err)
	}
	defer tx.Rollback() //nolint:errcheck
	done := make(chan error, 1)
	go func() {
		_, err := member.ResolveConnectorInstance(ctx, "group-other", "group-other-profile-v1", ConnectorCustodyHookOnly)
		done <- err
	}()
	select {
	case err := <-done:
		if !errors.Is(err, ErrCorrelationStale) {
			t.Fatalf("resolution inside the group got %v, want ErrCorrelationStale", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("resolution inside the group waited for the shared transaction")
	}
	if member.batch.batch.takesMore() {
		t.Fatal("the shared transaction still takes occurrences after a stale resolution")
	}
	// A cached instance needs no transaction and resolves.
	if _, err := member.ResolveConnectorInstance(ctx, instance.Connector, instance.ProfileVersion, ConnectorCustodyHookOnly); err != nil {
		t.Fatal(err)
	}
}

// Occurrences of many sessions, some with contexts that end while they wait,
// run one at a time per session, every committed one is stored, every
// session's cursor counts its committed occurrences, and the group ends
// idle. Run with -race.
func TestCorrelationGroupConcurrentOccurrences(t *testing.T) {
	store, repo := newCorrelationTestStore(t)
	instance := mustCorrelationInstance(t, repo, "group", ConnectorCustodyHookOnly)
	groups := observeCorrelationGroups(t)
	const sessions, perSession = 6, 25
	var inside [sessions]atomic.Int32
	var overlapped atomic.Bool
	var committed [sessions]atomic.Int32
	var wg sync.WaitGroup
	limits := CorrelationGroupLimits{Occurrences: 8, Hold: 5 * time.Millisecond}
	for s := 0; s < sessions; s++ {
		session := fmt.Sprintf("race-%d", s)
		for i := 0; i < perSession; i++ {
			wg.Add(1)
			go func() {
				defer wg.Done()
				ctx, cancel := context.WithTimeout(t.Context(), time.Duration(rand.IntN(60)+1)*time.Millisecond)
				defer cancel()
				member, release, err := store.JoinCorrelationGroup(ctx, session, limits)
				if err != nil {
					return
				}
				if inside[s].Add(1) > 1 {
					overlapped.Store(true)
				}
				tx, _, err := groupOccurrence(t, context.WithoutCancel(ctx), member, instance, session)
				inside[s].Add(-1)
				if err == nil {
					// The turns end in Commit, before its COMMIT returns.
					if err = tx.Commit(); err == nil {
						committed[s].Add(1)
					}
				}
				release()
				if err != nil && !errors.Is(err, context.DeadlineExceeded) {
					t.Error(err)
				}
			}()
		}
	}
	wg.Wait()
	if overlapped.Load() {
		t.Fatal("two occurrences of one session held its turn together")
	}
	for s := 0; s < sessions; s++ {
		want := uint64(committed[s].Load())
		if want == 0 {
			continue
		}
		cursor, err := repo.GetCursor(t.Context(), instance.ConnectorInstanceID, fmt.Sprintf("race-%d", s), "agent")
		if err != nil || cursor.Sequence != want {
			t.Fatalf("session %d cursor %+v %v, want sequence %d", s, cursor, err, want)
		}
	}
	shared := 0
	for _, size := range groups() {
		if size > 1 {
			shared++
		}
	}
	t.Logf("%d shared transactions of more than one occurrence out of %d", shared, len(groups()))
	groupIdle(t, store)
}
