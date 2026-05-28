// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"errors"
	"fmt"
	"path/filepath"
	"testing"
)

// fakeBusyErr is a sentinel that the production isSQLiteBusy detector
// recognizes — matches against the string "database is locked".
var fakeBusyErr = errors.New("database is locked (synthetic)")
var fakeOtherErr = errors.New("constraint failed: NOT NULL")

// TestRetryBusy_RetriesOnBusy: the wrapper must keep retrying while
// the underlying op returns a BUSY error, and stop the moment the
// op succeeds. We count the calls to fn() so we can assert the
// exact number of retries.
//
// This is the test that catches a future refactor where someone
// "simplifies" retryBusy down to a one-shot call: with the synthetic
// error path that mirrors what SQLite returns under contention, we
// reliably reproduce the historical drop-write bug if retry is
// regressed.
func TestRetryBusy_RetriesOnBusy(t *testing.T) {
	var calls int
	err := retryBusy(context.Background(), "test_retry", func() error {
		calls++
		if calls < 3 {
			return fakeBusyErr
		}
		return nil
	})
	if err != nil {
		t.Fatalf("retryBusy returned error: %v", err)
	}
	if calls != 3 {
		t.Fatalf("expected fn called 3 times, got %d", calls)
	}
}

// TestRetryBusy_GivesUpAfterMaxAttempts: when every attempt returns
// BUSY, the wrapper must surface the last BUSY error to the caller
// after sqliteRetryAttempts tries — never spin forever and never
// silently swallow the error.
func TestRetryBusy_GivesUpAfterMaxAttempts(t *testing.T) {
	var calls int
	err := retryBusy(context.Background(), "test_retry_giveup", func() error {
		calls++
		return fakeBusyErr
	})
	if err == nil {
		t.Fatalf("expected BUSY error after max attempts, got nil")
	}
	if !isSQLiteBusy(err) {
		t.Fatalf("expected BUSY error to surface, got %v", err)
	}
	if calls != sqliteRetryAttempts {
		t.Fatalf("expected %d attempts, got %d", sqliteRetryAttempts, calls)
	}
}

// TestRetryBusy_PassThroughNonBusyError: any non-BUSY error must
// short-circuit the loop immediately — we do not want to retry
// constraint failures, type mismatches, or other deterministic
// errors that would never succeed on a re-run and would just waste
// 300ms of backoff for nothing.
func TestRetryBusy_PassThroughNonBusyError(t *testing.T) {
	var calls int
	err := retryBusy(context.Background(), "test_retry_passthrough", func() error {
		calls++
		return fakeOtherErr
	})
	if !errors.Is(err, fakeOtherErr) {
		t.Fatalf("expected sentinel error to pass through, got %v", err)
	}
	if calls != 1 {
		t.Fatalf("expected 1 call for non-BUSY error, got %d", calls)
	}
}

// TestRetryBusy_HonoursContextCancellation: a cancelled context must
// terminate the retry loop with ctx.Err() instead of waiting through
// the remaining backoff slots. This matters for request-scoped audit
// writes where the caller has already given up and we are just
// burning CPU/lock-time.
func TestRetryBusy_HonoursContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // pre-cancel so the very first sleep returns immediately

	var calls int
	err := retryBusy(ctx, "test_retry_ctx", func() error {
		calls++
		return fakeBusyErr
	})
	if !errors.Is(err, context.Canceled) {
		t.Fatalf("expected context.Canceled, got %v", err)
	}
	// One call before the wrapper observes cancellation between
	// attempts; never the full sqliteRetryAttempts.
	if calls >= sqliteRetryAttempts {
		t.Fatalf("expected early cancellation, got %d calls", calls)
	}
}

// TestExecDB_RetriesAndPropagates is the end-to-end check: drive
// execDB against a real (in-memory) SQLite DB and assert the helper
// behaves correctly on real success. The "BUSY under load" scenario
// is already covered by TestStore_ConcurrentWritersSerialize; this
// test pins the happy path.
func TestExecDB_RetriesAndPropagates(t *testing.T) {
	store, err := NewStore(":memory:")
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	// Real INSERT through execDB succeeds.
	if _, err := store.execDB(context.Background(), "test_insert",
		`INSERT INTO audit_events (id, timestamp, action, target, actor, details, severity)
		 VALUES (?, ?, ?, ?, ?, ?, ?)`,
		"abc", "2026-01-01T00:00:00Z", "test", "x", "y", "", "INFO"); err != nil {
		t.Fatalf("execDB success path failed: %v", err)
	}
}

// codedErr is a test double that implements the structural
// sqliteCoded interface (Code() int). Used to verify isSQLiteBusy
// detects BUSY / LOCKED via the modernc driver's typed error path —
// the only authoritative source of the SQLite result code — even
// when the error is wrapped through fmt.Errorf("...: %w").
type codedErr struct {
	code int
	msg  string
}

func (e *codedErr) Error() string { return e.msg }
func (e *codedErr) Code() int     { return e.code }

// TestIsSQLiteBusy_CodedDetection pins the L8 fix: SQLITE_BUSY (5)
// and SQLITE_LOCKED (6) must both retry. Any other code falls
// through to the substring path, which we also exercise.
func TestIsSQLiteBusy_CodedDetection(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"sqlite_busy_typed", &codedErr{code: sqliteCodeBusy, msg: "busy"}, true},
		{"sqlite_locked_typed", &codedErr{code: sqliteCodeLocked, msg: "locked"}, true},
		{"sqlite_constraint_typed", &codedErr{code: 19, msg: "constraint"}, false},
		{"wrapped_typed_busy", fmt.Errorf("audit: %w", &codedErr{code: sqliteCodeBusy, msg: "busy"}), true},
		{"substring_locked_message", errors.New("SQLITE_LOCKED: shared cache contention"), true},
		{"substring_busy_message", errors.New("database is locked"), true},
		{"substring_legacy_busy", errors.New("SQLITE_BUSY: cannot start a transaction within a transaction"), true},
		{"non_busy_message", errors.New("syntax error near 'FROM'"), false},
		{"nil_error", nil, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := isSQLiteBusy(tc.err); got != tc.want {
				t.Fatalf("isSQLiteBusy(%v) = %v, want %v", tc.err, got, tc.want)
			}
		})
	}
}

// TestJudgeBatch_CommitFailureLeavesRollbackable pins the M4 fix:
// when tx.Commit() returns an error, JudgeBatch.committed MUST
// remain false so a subsequent Rollback() actually drives the
// underlying tx.Rollback() (and releases the SQLite write lock).
// The old code set committed=true *before* commit and left the
// connection pinned mid-tx on any commit failure.
//
// We force a deterministic commit failure by rolling back the
// underlying tx out-of-band before calling JudgeBatch.Commit(). The
// stdlib then returns "sql: transaction has already been committed
// or rolled back" from tx.Commit(). White-box access to JudgeBatch.tx
// is the cleanest way to set this up without standing up an
// elaborate fault-injection harness.
func TestJudgeBatch_CommitFailureLeavesRollbackable(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	tx, err := store.db.BeginTx(context.Background(), nil)
	if err != nil {
		t.Fatalf("BeginTx: %v", err)
	}
	// Pre-roll-back the tx so JudgeBatch.Commit() sees a guaranteed
	// failure path. White-box construction is intentional — we need
	// to drive the exact M4 code path.
	if err := tx.Rollback(); err != nil {
		t.Fatalf("seed rollback: %v", err)
	}
	batch := &JudgeBatch{tx: tx}

	if err := batch.Commit(); err == nil {
		t.Fatal("Commit on already-rolled-back tx returned nil; cannot exercise M4")
	}

	// The committed flag must still be false. A second Commit call
	// must again return an error (regression: old code returned nil
	// here because committed=true short-circuited the second call).
	if err := batch.Commit(); err == nil {
		t.Fatal("second Commit after failure returned nil; committed flag set prematurely (regression: M4)")
	}

	// Rollback after a failed Commit must NOT be a no-op. The first
	// call attempts the real tx.Rollback (which itself returns an
	// error because the tx is already done), then flips committed=true
	// for subsequent idempotency. The first call MUST return non-nil
	// — that's how we know it didn't short-circuit on committed=true.
	if err := batch.Rollback(); err == nil {
		t.Fatal("first Rollback after failed Commit returned nil; committed flag was set prematurely (regression: M4)")
	}

	// Second Rollback IS a no-op — committed=true after the first.
	if err := batch.Rollback(); err != nil {
		t.Fatalf("second Rollback returned %v, want nil (idempotency)", err)
	}
}

// TestJudgeBatch_CommitSuccessIsIdempotent: the post-Commit state
// is "no further work needed" — calling Commit again must be a
// safe no-op, and Rollback must also be a safe no-op. This pins
// the post-success branch of the M4 logic that we did NOT touch.
func TestJudgeBatch_CommitSuccessIsIdempotent(t *testing.T) {
	store, err := NewStore(filepath.Join(t.TempDir(), "audit.db"))
	if err != nil {
		t.Fatalf("NewStore: %v", err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatalf("Init: %v", err)
	}

	batch, err := store.BeginJudgeBatch(context.Background())
	if err != nil {
		t.Fatalf("BeginJudgeBatch: %v", err)
	}
	if err := batch.Commit(); err != nil {
		t.Fatalf("first Commit: %v", err)
	}
	if err := batch.Commit(); err != nil {
		t.Fatalf("second Commit (idempotency): %v", err)
	}
	if err := batch.Rollback(); err != nil {
		t.Fatalf("post-commit Rollback (idempotency): %v", err)
	}
}
