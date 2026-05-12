// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"errors"
	"testing"
)

var fakeBusyErr = errors.New("database is locked (synthetic)")

// TestInvRetryBusy_RetriesOnBusy keeps the inventory retry helper
// in lockstep with the audit store one: BUSY errors retry until the
// underlying call succeeds.
func TestInvRetryBusy_RetriesOnBusy(t *testing.T) {
	var calls int
	err := retryBusy(context.Background(), "inv_retry", func() error {
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
		t.Fatalf("expected 3 calls, got %d", calls)
	}
}

// TestInvRetryBusy_GivesUpAfterMaxAttempts mirrors the audit-side
// max-attempts guard: every attempt BUSY surfaces the error.
func TestInvRetryBusy_GivesUpAfterMaxAttempts(t *testing.T) {
	var calls int
	err := retryBusy(context.Background(), "inv_retry_giveup", func() error {
		calls++
		return fakeBusyErr
	})
	if err == nil {
		t.Fatalf("expected BUSY error after max attempts")
	}
	if !isSQLiteBusy(err) {
		t.Fatalf("expected BUSY error to surface, got %v", err)
	}
	if calls != sqliteRetryAttempts {
		t.Fatalf("expected %d attempts, got %d", sqliteRetryAttempts, calls)
	}
}
