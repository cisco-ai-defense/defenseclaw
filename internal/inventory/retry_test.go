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

// invCodedErr is the inventory mirror of the audit codedErr test
// double — implements the structural sqliteCoded interface so
// errors.As inside isSQLiteBusy can extract Code().
type invCodedErr struct {
	code int
	msg  string
}

func (e *invCodedErr) Error() string { return e.msg }
func (e *invCodedErr) Code() int     { return e.code }

// TestInvIsSQLiteBusy_CodedDetection mirrors the audit-side L8 test:
// the inventory store's isSQLiteBusy must recognize SQLITE_BUSY (5)
// AND SQLITE_LOCKED (6) via the typed driver error path, and fall
// back to the substring match for legacy/test inputs.
func TestInvIsSQLiteBusy_CodedDetection(t *testing.T) {
	cases := []struct {
		name string
		err  error
		want bool
	}{
		{"sqlite_busy_typed", &invCodedErr{code: sqliteCodeBusy, msg: "busy"}, true},
		{"sqlite_locked_typed", &invCodedErr{code: sqliteCodeLocked, msg: "locked"}, true},
		{"non_transient_typed", &invCodedErr{code: 19, msg: "constraint"}, false},
		{"substring_locked", errors.New("SQLITE_LOCKED: cache contention"), true},
		{"substring_busy", errors.New("SQLITE_BUSY: locked"), true},
		{"substring_locked_legacy", errors.New("database is locked"), true},
		{"non_busy", errors.New("syntax error"), false},
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
