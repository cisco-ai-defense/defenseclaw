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
