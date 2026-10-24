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
	"time"
)

// walFrameBytes is the size of one WAL frame at the default 4096-byte page:
// the page plus the 24-byte frame header.
const walFrameBytes = 4096 + 24

// auditWALJournalSizeLimitBytes is the journal_size_limit of every audit
// connection. When a writer restarts the log from its start, SQLite cuts the
// WAL file back to this size at that commit, so a burst's disk space comes
// back without waiting for the next WAL guard pass (rel-1-0-2:GAP-0709).
const auditWALJournalSizeLimitBytes = 64 << 20

// auditBusyTimeoutMillis is the busy_timeout of every audit connection.
const auditBusyTimeoutMillis = 5000

// walIdleTrimBytes is the WAL file size at which a fully copied log is cut
// to zero bytes even though it is below the caller's limit: a log that stops
// growing is never restarted by a writer, so its file kept its peak size
// while the gateway was idle. A variable so tests can use a small file.
var walIdleTrimBytes int64 = auditWALJournalSizeLimitBytes

// walCopyPasses bounds the copy passes on the dedicated connection. Each pass
// copies what was written during the one before, so the backlog shrinks pass
// by pass while the disk copies faster than the hooks write. The passes stop
// once the backlog is at most walCopyTargetFrames (about 1 MiB).
const (
	walCopyPasses       = 6
	walCopyTargetFrames = 256
)

// walTrickleFrames is the longest log in use (about 8 MiB) that still counts
// as a trickle of background writes after a flood: such a log was restarted
// recently, so a file at least walIdleTrimBytes is left from the flood and is
// trimmed in an idle gap. A variable so tests can use a short log.
var walTrickleFrames = 2048

// walCatchUpFraction: the pass starts to bring the log to its end once the
// log passes limit/walCatchUpFraction, so a pass or two that finds no idle
// gap still leaves it under the limit.
const walCatchUpFraction = 2

// walSettleRounds bounds the extra copy-and-sync rounds before a catch-up,
// and walSettledSync is the sync time that ends them: a sync that fast left
// only a few pages for the copy under the writer. Variables so tests can
// change them.
var (
	walSettleRounds = 3
	walSettledSync  = 20 * time.Millisecond
)

// The writer phase of a pass. walIdleWindow is how long the store must go
// without a commit before a pass takes the writer connection; walIdleWait
// bounds how long a pass looks for such a gap; walWriterAcquireWait is how
// long it waits for the connection itself (a hook that holds it is not
// idle); walCatchUpCap is the hard cap on how long a catch-up holds it.
// Variables so tests can shorten them.
var (
	walIdleWindow        = 20 * time.Millisecond
	walIdleWait          = 500 * time.Millisecond
	walWriterAcquireWait = 5 * time.Millisecond
	walCatchUpCap        = 100 * time.Millisecond
)

// The bounding catch-up of a log over the limit. A hook flood on a disk with
// slow scattered writes (a cloud VM's network disk on Windows) leaves no idle
// gap, and the copy under the writer needs longer than walCatchUpCap there: a
// hook call dirties pages of about 80 indexes of audit.db, and a sync on that
// disk writes them one at a time (about 2 ms each), so the copy and sync of
// one settle round's pages took 360-530 ms. No catch-up completed and the WAL
// grew to about 9.5 GB in ten minutes at 10 calls/s, until the audit volume
// could fill (rel-1-0-3 GAP-0320, GAP-0136). Past the limit the catch-up waits
// up to walBoundedAcquireWait for the writer connection whatever the hooks
// do, and holds it until its copy reaches the end of the log, at most
// walBoundedCatchUpCap: the hooks wait that long for their audit records, and
// the log restarts.
//
// A bounded catch-up can still give the writer back before the log restarted:
// no free writer within its wait, or a copy longer than its cap. The log then
// kept growing, pass after pass, on a disk too slow for the 2 s cap. So each
// such miss doubles the next bounded catch-up's wait and cap, up to
// walBoundedAcquireMax and walBoundedCatchUpMax, until one restarts the log:
// the hooks wait longer (one that waits past its own budget is denied, fail
// closed), and the log cannot outgrow the disk. A restart, or a log back
// under the limit, resets them. Variables so tests can shorten them.
var (
	walBoundedAcquireWait = time.Second
	walBoundedCatchUpCap  = 2 * time.Second
	walBoundedAcquireMax  = 10 * time.Second
	walBoundedCatchUpMax  = 30 * time.Second
)

// walBoundedMissesMax bounds the miss count; the doubled wait and cap reach
// their ceilings long before it.
const walBoundedMissesMax = 16

// Test seams: walCopyPhaseHook runs inside each copy pass on the dedicated
// connection, after the pass read the commit counter, walSyncPhaseHook before
// each sync of the database file off the writer, and walWriterPhaseHook while
// the writer connection is held (in a catch-up, inside its copy after it read
// the commit counter), so tests can write during a copy, slow a sync or hold
// the writer phase open.
var (
	walCopyPhaseHook   func(context.Context)
	walSyncPhaseHook   func(context.Context)
	walWriterPhaseHook func(context.Context)
)

// WALCheckpoint reports one CheckpointWALIfLarge pass.
type WALCheckpoint struct {
	// LogBytes is the length of the log in use when the pass started.
	LogBytes int64
	// FileBytes is the size of the WAL file on disk when the pass ended.
	FileBytes int64
	// Restarted is true when the pass left the whole log copied into the
	// database and synced, so the next write starts the log again from its
	// start (and its commit cuts the file back to journal_size_limit).
	Restarted bool
	// Truncated is true when the pass also cut the WAL file to zero bytes,
	// which it does only in an idle gap after the hooks stopped.
	Truncated bool
	// WriterHeld is how long the pass held the writer connection, from getting
	// it until giving it back; zero when it did not take it.
	WriterHeld time.Duration
	// WriterDeferred is true when the log needed the writer phase but the pass
	// found no idle gap for it, or the catch-up reached its cap and gave the
	// writer back before the copy reached the end of the log.
	WriterDeferred bool
	// Bounded is true when the log was over the limit, so the catch-up held
	// the writer until its copy reached the end of the log (up to HoldCap)
	// instead of waiting for an idle gap and giving it back at walCatchUpCap.
	Bounded bool
	// HoldCap is how long a bounded catch-up could hold the writer:
	// walBoundedCatchUpCap, doubled for each bounded catch-up before it that
	// gave the writer back before the log restarted, up to
	// walBoundedCatchUpMax.
	HoldCap time.Duration
	// Syncs is how many times the pass synced the database file off the
	// writer before a catch-up, and SyncLongest the longest of those syncs.
	Syncs       int
	SyncLongest time.Duration
}

// CheckpointWALIfLarge keeps the write-ahead log bounded under sustained hook
// traffic. The store runs with wal_autocheckpoint=0, so nothing else copies
// the log while hooks keep writing.
//
// All copying runs on the dedicated checkpoint connection with PASSIVE
// checkpoints, which never hold off the writer. A copy is bounded only by
// ctx: SQLite records a checkpoint's progress when it finishes, so a copy cut
// short by a deadline starts over at the next pass (rel-1-0-2:GAP-0709).
//
// The log is restarted by SQLite itself: once a checkpoint has copied the
// whole log and synced the database, the next write transaction starts the
// log again from its start. Under a flood a PASSIVE copy rarely reaches the
// end, because the hooks commit while it runs. Each copy that stops short of
// the end also leaves its pages unsynced, and the one that reaches it syncs
// them all.
//
// The pass used to finish that last copy with a RESTART checkpoint on the
// store's single writer connection, which every hook needs for its
// correlation and verdict records. That held the hooks for the copy and the
// sync of every page the earlier copies had left; under a 10 calls/s flood
// the hold grew with the database to 1.1-1.7 s, the 200 ms budget could not
// interrupt it, and the WAL passed its bound because the restart then failed
// (rel-1-0-3 GAP-0186, GAP-0247, GAP-0136). Now:
//
//   - Once the log passes limit/walCatchUpFraction (and is still under the
//     limit) and the copy cannot reach its end, the pass syncs the database
//     file from its own pinned handle, off the writer. While that sync takes
//     longer than walSettledSync it copies what the hooks wrote meanwhile and
//     syncs again (at most walSettleRounds more times), so the copy under the
//     writer has only the pages of the last round to write and sync. Then it
//     waits for an idle
//     gap (no commit for walIdleWindow and the writer free) and holds the
//     writer only while one more PASSIVE copy on the checkpoint connection
//     reaches the end. It gives the writer back at walCatchUpCap whether or
//     not that copy finished; an unfinished copy goes on without the writer
//     and the next pass tries again.
//   - A log over the limit is bounded: right after the copy that finds it
//     over, with no settle syncs, the catch-up takes the writer whatever the
//     hooks do, and SQLite's write lock so that no other store or process
//     commits either (lockWALWriter), and holds them until the copy reaches
//     the end, at most walBoundedCatchUpCap, so a flood on a slow disk delays
//     hooks by up to that long now and then instead of growing the WAL until
//     the disk is full (rel-1-0-3 GAP-0320, GAP-0136). Each bounded catch-up
//     that still gives the writer back first, and each pass that fails or
//     runs out of time while the log is over, doubles the next one's wait and
//     cap, up to walBoundedAcquireMax and walBoundedCatchUpMax.
//   - A fully copied log whose file is at least walIdleTrimBytes (or whose
//     log is over the limit) is cut to zero bytes with a TRUNCATE checkpoint
//     on the writer when the hooks are not flooding the store: nothing was
//     committed since the previous pass (PRAGMA data_version on the
//     checkpoint connection), or the log in use is at most walTrickleFrames
//     long. It runs only in an idle gap and only when nothing was committed
//     since the copy, so it copies and syncs nothing and only resets the log;
//     writerBudget bounds it.
//
// After each pass, however it ended, the store records whether the log is over
// the limit; while it is, background writers (retention, planner statistics)
// wait for it (awaitWALHeadroom). Hook writes are never held back by this.
func (s *Store) CheckpointWALIfLarge(ctx context.Context, limitBytes int64, writerBudget time.Duration) (result WALCheckpoint, err error) {
	if ctx == nil {
		return result, fmt.Errorf("audit: WAL checkpoint context is required")
	}
	if writerBudget <= 0 {
		return result, fmt.Errorf("audit: WAL checkpoint writer budget is required")
	}
	release, err := s.acquireReady()
	if err != nil {
		return result, err
	}
	defer release()
	defer func() { result.FileBytes = s.walFileBytes() }()
	db, err := s.checkpointConn()
	if err != nil {
		return result, fmt.Errorf("audit: open SQLite checkpoint connection: %w", err)
	}
	quiet := s.walGuardQuiet(ctx, db)
	// logBytes is the log in use as of the latest copy, -1 until a copy
	// measured it. The pass's outcome is recorded however the pass ends, at
	// its deadline too (noteWALGuardPass).
	logBytes := int64(-1)
	defer func() { s.noteWALGuardPass(result, err, logBytes, limitBytes) }()
	var ckpt walCopy
	for pass := 0; pass < walCopyPasses; pass++ {
		ckpt, err = s.copyWAL(ctx, db, walCopyPhaseHook)
		if err != nil {
			return result, err
		}
		if ckpt.busy != 0 {
			// Another checkpoint holds the log; the next pass tries again.
			return result, nil
		}
		logBytes = int64(ckpt.frames) * walFrameBytes
		if pass == 0 {
			result.LogBytes = logBytes
		}
		// A log over the limit goes to the bounded catch-up after this copy:
		// on a slow disk more copies, and the syncs below, could use up the
		// pass before it held the writer.
		if ckpt.complete || ckpt.frames-ckpt.copied <= walCopyTargetFrames || logBytes > limitBytes {
			break
		}
	}
	if ckpt.complete {
		result.Restarted = ckpt.frames > 0
		oversized := s.walFileBytes() >= walIdleTrimBytes || logBytes > limitBytes
		if !oversized || (!quiet && ckpt.frames > walTrickleFrames) {
			return result, nil
		}
		var truncated bool
		truncated, result.WriterHeld, result.WriterDeferred, err = s.trimWALOnIdleWriter(ctx, db, ckpt.version, writerBudget)
		result.Truncated = truncated
		return result, err
	}
	if logBytes <= limitBytes/walCatchUpFraction {
		return result, nil
	}
	// Under the limit, sync the pages the copies left, off the writer, and
	// copy and sync again while the hooks write more during a sync than the
	// copy under the writer can write and sync within walCatchUpCap (rel-1-0-3
	// GAP-0247, GAP-0136). A log over the limit, from the start or after a
	// copy here, goes to the bounded catch-up instead: on a slow disk these
	// syncs took 8-26 s each, so the pass could run out of time before it
	// held the writer while the hooks kept writing (G-flood-wal round 3). Its
	// copy syncs under the writer, and a copy that outruns the hold goes on
	// and syncs without it.
	for round := 0; logBytes <= limitBytes; round++ {
		began := time.Now()
		if walSyncPhaseHook != nil {
			walSyncPhaseHook(ctx)
		}
		if err := s.syncDatabaseFile(); err != nil {
			return result, fmt.Errorf("audit: sync the database file before the WAL catch-up: %w", err)
		}
		took := time.Since(began)
		result.Syncs++
		result.SyncLongest = max(result.SyncLongest, took)
		if took <= walSettledSync || round == walSettleRounds {
			break
		}
		ckpt, err = s.copyWAL(ctx, db, walCopyPhaseHook)
		if err != nil {
			return result, err
		}
		if ckpt.busy != 0 {
			return result, nil
		}
		logBytes = int64(ckpt.frames) * walFrameBytes
		if ckpt.complete {
			// The hooks paused: this copy brought the log to its end.
			result.Restarted = ckpt.frames > 0
			return result, nil
		}
	}
	policy := walCatchUpPolicy{window: walIdleWindow, acquire: walWriterAcquireWait, hold: walCatchUpCap}
	if logBytes > limitBytes {
		policy = s.boundedCatchUpPolicy()
		result.Bounded, result.HoldCap = true, policy.hold
	}
	result.Restarted, result.WriterHeld, result.WriterDeferred, err = s.catchUpWAL(ctx, db, policy)
	return result, err
}

// walCatchUpPolicy is how a catch-up takes and holds the writer connection:
// in an idle gap of window (no commit for that long, see takeIdleWriter) with
// the connection free within acquire, or, when bounded, as soon as the
// connection is free within acquire; and for at most hold.
type walCatchUpPolicy struct {
	window, acquire, hold time.Duration
	bounded               bool
}

// boundedCatchUpPolicy is the policy of a bounded catch-up: the free writer
// within walBoundedAcquireWait, held for at most walBoundedCatchUpCap, both
// doubled for each bounded catch-up in a row that gave the writer back before
// the log restarted, up to walBoundedAcquireMax and walBoundedCatchUpMax.
func (s *Store) boundedCatchUpPolicy() walCatchUpPolicy {
	s.walGuardMu.Lock()
	misses := s.walBoundedMisses
	s.walGuardMu.Unlock()
	return walCatchUpPolicy{
		acquire: walEscalated(walBoundedAcquireWait, walBoundedAcquireMax, misses),
		hold:    walEscalated(walBoundedCatchUpCap, walBoundedCatchUpMax, misses),
		bounded: true,
	}
}

// noteWALGuardPass records how a pass left the log, however it ended. The log
// is over when the pass did not restart it and its last copy found it over
// limitBytes; a pass that never measured it (logBytes < 0) keeps the last
// pass's record. Over marks the store for background writers
// (awaitWALHeadroom). For boundedCatchUpPolicy a log that is not over resets
// the misses, and over adds one after a bounded catch-up that gave the writer
// back first or a pass that failed or ran out of time. Such a pass used to
// clear the mark and leave the misses as they were, so background writers
// went on and the next bounded catch-up waited and held no longer
// (G-flood-wal round 3).
func (s *Store) noteWALGuardPass(result WALCheckpoint, err error, logBytes, limitBytes int64) {
	over := !result.Restarted && logBytes > limitBytes
	if logBytes < 0 {
		over = s.walPressure.Load()
	}
	s.walPressure.Store(over)
	s.walGuardMu.Lock()
	defer s.walGuardMu.Unlock()
	switch {
	case !over:
		s.walBoundedMisses = 0
	case err != nil || (result.Bounded && result.WriterDeferred):
		s.walBoundedMisses = min(s.walBoundedMisses+1, walBoundedMissesMax)
	}
}

// walEscalated is base doubled misses times, at most ceiling.
func walEscalated(base, ceiling time.Duration, misses int) time.Duration {
	escalated := base
	for range misses {
		if escalated >= ceiling {
			break
		}
		escalated *= 2
	}
	return min(escalated, ceiling)
}

// walCopy is one PASSIVE checkpoint on the dedicated connection: SQLite's
// busy, log and checkpointed columns, the commit counter as of its start, and
// whether it left the whole log copied and synced. The columns describe the
// log as of the checkpoint's start, so a copy is complete only when it copied
// every frame and no connection committed while it ran.
type walCopy struct {
	busy, frames, copied int
	version              int64
	complete             bool
}

func (s *Store) copyWAL(ctx context.Context, db *sql.DB, hook func(context.Context)) (walCopy, error) {
	var ckpt walCopy
	before, versionErr := walDataVersion(ctx, db)
	if hook != nil {
		hook(ctx)
	}
	if err := db.QueryRowContext(ctx, "PRAGMA wal_checkpoint(PASSIVE)").Scan(&ckpt.busy, &ckpt.frames, &ckpt.copied); err != nil {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ckpt, fmt.Errorf("audit: copy SQLite WAL: %w", ctxErr)
		}
		return ckpt, fmt.Errorf("audit: copy SQLite WAL: %w", err)
	}
	after, afterErr := walDataVersion(ctx, db)
	ckpt.version = after
	ckpt.complete = versionErr == nil && afterErr == nil && before == after && ckpt.busy == 0 && ckpt.frames == ckpt.copied
	return ckpt, nil
}

// walDataVersion reads PRAGMA data_version on the dedicated checkpoint
// connection. It changes when another connection commits; checkpoints do not
// change it.
func walDataVersion(ctx context.Context, db *sql.DB) (int64, error) {
	var version int64
	err := db.QueryRowContext(ctx, "PRAGMA data_version").Scan(&version)
	return version, err
}

// walGuardQuiet reports whether no connection committed since the previous
// pass. The first pass, and a pass after a failed read, is never quiet.
func (s *Store) walGuardQuiet(ctx context.Context, db *sql.DB) bool {
	version, err := walDataVersion(ctx, db)
	s.walGuardMu.Lock()
	defer s.walGuardMu.Unlock()
	quiet := err == nil && s.walGuardSeen && version == s.walGuardVersion
	s.walGuardVersion, s.walGuardSeen = version, err == nil
	return quiet
}

// takeIdleWriter waits up to walIdleWait for an idle gap and takes the writer
// connection in it: no commit for window (zero: none since since, the
// counter the caller read), the connection free within acquire, and still no
// commit once it is held. It returns nil and no error when it found no gap. A
// hook that waits for the connection meanwhile gets it when the caller closes
// it.
func (s *Store) takeIdleWriter(ctx context.Context, db *sql.DB, since int64, window, acquire time.Duration) (*sql.Conn, error) {
	deadline := time.Now().Add(walIdleWait)
	version := since
	for {
		if window > 0 {
			before, err := walDataVersion(ctx, db)
			if err != nil {
				return nil, fmt.Errorf("audit: read the SQLite commit counter: %w", err)
			}
			if err := sleepContext(ctx, window); err != nil {
				return nil, err
			}
			version = before
		}
		current, err := walDataVersion(ctx, db)
		if err != nil {
			return nil, fmt.Errorf("audit: read the SQLite commit counter: %w", err)
		}
		if current == version {
			acquireCtx, cancel := context.WithTimeout(ctx, acquire)
			conn, err := s.db.Conn(acquireCtx)
			cancel()
			if err == nil {
				held, versionErr := walDataVersion(ctx, db)
				if versionErr == nil && held == version {
					return conn, nil
				}
				_ = conn.Close()
			} else if ctx.Err() != nil {
				return nil, ctx.Err()
			}
		}
		if window == 0 || time.Now().After(deadline) {
			return nil, nil
		}
	}
}

// catchUpWAL takes the writer connection as policy says, and SQLite's write
// lock on it (lockWALWriter), and holds them while one PASSIVE copy on the
// checkpoint connection reaches the end of the log, and gives them back when
// the copy finishes or at policy.hold, whichever comes first. It reports
// whether the copy left the whole log copied and synced, how long it held the
// writer, and whether it deferred (no gap, no free connection or lock, or the
// cap).
func (s *Store) catchUpWAL(ctx context.Context, db *sql.DB, policy walCatchUpPolicy) (complete bool, held time.Duration, deferred bool, err error) {
	conn, err := s.takeCatchUpWriter(ctx, db, policy)
	if err != nil || conn == nil {
		return false, 0, err == nil, err
	}
	acquired := time.Now()
	locked, err := lockWALWriter(ctx, conn, policy.acquire)
	if err != nil || !locked {
		if err != nil {
			dropWriterConn(conn)
		}
		_ = conn.Close()
		return false, heldSince(acquired), err == nil, err
	}
	holdCtx, cancelHold := context.WithTimeout(ctx, policy.hold)
	defer cancelHold()
	done := make(chan walCopyResult, 1)
	go func() {
		ckpt, err := s.copyWAL(ctx, db, func(context.Context) {
			if walWriterPhaseHook != nil {
				walWriterPhaseHook(holdCtx)
			}
		})
		done <- walCopyResult{ckpt: ckpt, err: err}
	}()
	timer := time.NewTimer(policy.hold)
	defer timer.Stop()
	var outcome walCopyResult
	capped := false
	select {
	case outcome = <-done:
	case <-timer.C:
		capped = true
	}
	// The writer goes back before the pass waits for an unfinished copy.
	unlockWALWriter(ctx, conn)
	_ = conn.Close()
	held = heldSince(acquired)
	if capped {
		outcome = <-done
	}
	if outcome.err != nil {
		return false, held, false, outcome.err
	}
	complete = !capped && outcome.ckpt.complete
	return complete, held, !complete, nil
}

// takeCatchUpWriter takes the writer connection for a catch-up: in an idle
// gap (takeIdleWriter), or, for a bounded catch-up, as soon as it is free
// within policy.acquire. It returns nil and no error when it did not get it.
func (s *Store) takeCatchUpWriter(ctx context.Context, db *sql.DB, policy walCatchUpPolicy) (*sql.Conn, error) {
	if !policy.bounded {
		since, err := walDataVersion(ctx, db)
		if err != nil {
			return nil, fmt.Errorf("audit: read the SQLite commit counter: %w", err)
		}
		return s.takeIdleWriter(ctx, db, since, policy.window, policy.acquire)
	}
	acquireCtx, cancel := context.WithTimeout(ctx, policy.acquire)
	defer cancel()
	conn, err := s.db.Conn(acquireCtx)
	if err != nil {
		if ctx.Err() != nil {
			return nil, ctx.Err()
		}
		return nil, nil
	}
	return conn, nil
}

// lockWALWriter takes SQLite's write lock on the held writer connection (BEGIN
// IMMEDIATE), waiting at most wait for it, so that no connection commits
// while the copy under the writer runs. Holding the store's writer connection
// holds off this store's hooks only: another store or process with audit.db
// open (a CLI command, a scan) could commit during every copy, which then
// never reached the end of the log, so the log need not restart and could
// grow without bound (G-flood-wal round 3). Their writes wait in SQLite's
// busy handler meanwhile, up to their busy timeout (auditBusyTimeoutMillis for
// every audit connection). It reports false and no error when another
// connection held the lock throughout; on an error the caller drops the
// connection, whose close rolls back the transaction.
func lockWALWriter(ctx context.Context, conn *sql.Conn, wait time.Duration) (bool, error) {
	if _, err := conn.ExecContext(ctx, fmt.Sprintf("PRAGMA busy_timeout = %d", max(wait.Milliseconds(), 1))); err != nil {
		return false, fmt.Errorf("audit: set the WAL catch-up lock wait: %w", err)
	}
	_, beginErr := conn.ExecContext(ctx, "BEGIN IMMEDIATE")
	restoreCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	if _, err := conn.ExecContext(restoreCtx, fmt.Sprintf("PRAGMA busy_timeout = %d", auditBusyTimeoutMillis)); err != nil {
		return false, fmt.Errorf("audit: restore the writer busy timeout: %w", err)
	}
	switch {
	case beginErr == nil:
		return true, nil
	case isSQLiteBusy(beginErr):
		return false, nil
	default:
		return false, fmt.Errorf("audit: take the SQLite write lock for the WAL catch-up: %w", beginErr)
	}
}

// unlockWALWriter ends lockWALWriter's transaction, which wrote nothing, before
// the writer connection goes back to the hooks. A connection it cannot roll
// back is dropped from the pool, whose close rolls it back.
func unlockWALWriter(ctx context.Context, conn *sql.Conn) {
	rollbackCtx, cancel := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
	defer cancel()
	if _, err := conn.ExecContext(rollbackCtx, "ROLLBACK"); err != nil {
		dropWriterConn(conn)
	}
}

// dropWriterConn makes the pool discard conn when it is closed, instead of
// handing it to a hook in an unknown state.
func dropWriterConn(conn *sql.Conn) {
	_ = conn.Raw(func(any) error { return driver.ErrBadConn })
}

// heldSince is how long the pass has held the writer connection since it got
// it at acquired, never zero: the Windows clock moves in steps of up to a
// millisecond, so a short hold could read as zero there, which WALCheckpoint
// reserves for a pass that did not take the writer.
func heldSince(acquired time.Time) time.Duration {
	return max(time.Since(acquired), time.Nanosecond)
}

type walCopyResult struct {
	ckpt walCopy
	err  error
}

// trimWALOnIdleWriter cuts a fully copied WAL file to zero bytes with a
// TRUNCATE checkpoint on the writer connection, in an idle gap and only when
// nothing was committed since the copy that left the log complete (version):
// the checkpoint then has nothing to copy or sync and only resets the log.
func (s *Store) trimWALOnIdleWriter(ctx context.Context, db *sql.DB, version int64, budget time.Duration) (truncated bool, held time.Duration, deferred bool, err error) {
	conn, err := s.takeIdleWriter(ctx, db, version, 0, walWriterAcquireWait)
	if err != nil || conn == nil {
		return false, 0, err == nil, err
	}
	busy, held, err := s.checkpointWALOnWriter(ctx, conn, budget, walCheckpointTruncate)
	if err != nil {
		return false, held, false, err
	}
	return busy == 0, held, busy != 0, nil
}

// walCheckpointTruncate is the writer-phase checkpoint statement.
const walCheckpointTruncate = "PRAGMA wal_checkpoint(TRUNCATE)"

// checkpointWALOnWriter runs statement on the held writer connection within
// budget, closes the connection, and returns the busy column and how long it
// held the connection, from the caller getting it until giving it back. A
// checkpoint waits in SQLite's busy handler for readers on older snapshots,
// and a deadline does not interrupt that wait, so the connection's busy
// timeout is zero for the statement and restored afterwards. A connection
// whose busy timeout cannot be restored is dropped from the pool.
func (s *Store) checkpointWALOnWriter(ctx context.Context, conn *sql.Conn, budget time.Duration, statement string) (busy int, held time.Duration, err error) {
	acquired := time.Now()
	writerCtx, cancel := context.WithTimeout(ctx, budget)
	defer cancel()
	defer func() {
		_ = conn.Close()
		held = heldSince(acquired)
	}()
	yielded := func(err error) error {
		if errors.Is(writerCtx.Err(), context.DeadlineExceeded) && ctx.Err() == nil {
			return fmt.Errorf("audit: WAL checkpoint yielded the writer after %s: %w", budget, context.DeadlineExceeded)
		}
		return fmt.Errorf("audit: checkpoint SQLite WAL on the writer: %w", err)
	}
	if _, err := conn.ExecContext(writerCtx, "PRAGMA busy_timeout = 0"); err != nil {
		dropWriterConn(conn)
		return 0, 0, yielded(err)
	}
	defer func() {
		restoreCtx, cancelRestore := context.WithTimeout(context.WithoutCancel(ctx), time.Second)
		defer cancelRestore()
		if _, err := conn.ExecContext(restoreCtx, fmt.Sprintf("PRAGMA busy_timeout = %d", auditBusyTimeoutMillis)); err != nil {
			// Hook writes on a connection without its busy timeout would fail
			// under contention. The pool opens a new one with the DSN pragmas.
			dropWriterConn(conn)
		}
	}()
	if walWriterPhaseHook != nil {
		walWriterPhaseHook(writerCtx)
	}
	var frames, copied int
	if err := conn.QueryRowContext(writerCtx, statement).Scan(&busy, &frames, &copied); err != nil {
		return 0, 0, yielded(err)
	}
	return busy, 0, nil
}

// syncDatabaseFile flushes the database file through the store's pinned
// handle (read-write on every platform), so a later checkpoint's sync has
// only its own pages left.
func (s *Store) syncDatabaseFile() error {
	if s.dbPathGuard == nil || s.dbPathGuard.inMemory || s.dbPathGuard.pinned == nil {
		return nil
	}
	return syncDatabaseFileData(s.dbPathGuard.pinned)
}

// walBackgroundWait bounds how long a background writer waits for the WAL
// to come back under its limit; walBackgroundPoll is how often it looks.
// Variables so tests can shorten them.
var (
	walBackgroundWait = 2 * time.Second
	walBackgroundPoll = 50 * time.Millisecond
)

// awaitWALHeadroom slows a background writer (never a hook) while the last
// WAL guard pass left the log over its limit: it waits until a pass brings
// the log back or walBackgroundWait passes, then lets the write go on, so
// background work is delayed but never lost. Fewer background commits give
// the copies the gaps they need to reach the end of the log.
func (s *Store) awaitWALHeadroom(ctx context.Context) error {
	if !s.walPressure.Load() {
		return nil
	}
	deadline := time.Now().Add(walBackgroundWait)
	for s.walPressure.Load() && time.Now().Before(deadline) {
		if err := sleepContext(ctx, walBackgroundPoll); err != nil {
			return err
		}
	}
	return nil
}

// WALOverLimit reports whether the last WAL guard pass left the log over its
// limit, so background writers are being slowed.
func (s *Store) WALOverLimit() bool { return s.walPressure.Load() }

func sleepContext(ctx context.Context, d time.Duration) error {
	timer := time.NewTimer(d)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func (s *Store) walFileBytes() int64 {
	if s.dbPath == "" || s.dbPath == ":memory:" {
		return 0
	}
	info, err := os.Stat(s.dbPath + "-wal")
	if err != nil {
		return 0
	}
	return info.Size()
}
