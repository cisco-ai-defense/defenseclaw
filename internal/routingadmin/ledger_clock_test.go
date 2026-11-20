// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingadmin

import (
	"testing"
	"time"
)

// A ledger with its own clock counts a charge on the day it is dated, also
// when that day is after the real today; the real clock moved such a charge
// to the real today, and the budget at the pinned date then read 0.
func TestLedgerClockPinsToday(t *testing.T) {
	for _, now := range []time.Time{
		time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		time.Date(2028, 2, 29, 0, 0, 0, 0, time.UTC),
		time.Date(2026, 2, 28, 23, 59, 59, 999999999, time.UTC),
		time.Date(2031, 6, 30, 12, 0, 0, 0, time.UTC),
	} {
		l := NewLedgerClock(func() time.Time { return now })
		l.ApplyRemote([]string{"daily"}, nil, now)
		l.Charge([]string{"user:daily:*:1001"}, 4, now)
		if got, known := l.Spend("user:daily:*:1001", "day", now); !known || got != 4 {
			t.Fatalf("at %s: spend = %v known %v, want 4", now, got, known)
		}
		// A charge dated after the ledger's today still counts today (a clock step).
		l.Charge([]string{"user:daily:*:1001"}, 1, now.Add(48*time.Hour))
		if got, _ := l.Spend("user:daily:*:1001", "day", now); got != 5 {
			t.Fatalf("at %s: spend after a future-dated charge = %v, want 5", now, got)
		}
	}
	if NewLedgerClock(nil).now == nil {
		t.Fatal("a nil clock is the real clock")
	}
	rt := NewRuntimeClock(nil)
	if rt.clock().IsZero() {
		t.Fatal("a nil runtime clock is the real clock")
	}
}
