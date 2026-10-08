// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"fmt"
	"testing"
)

// A disconnected session counts when the caller allows it, after the
// active ones; the guardian keeps acting only in active sessions (GAP-0835).
func TestWindowsTargetSessionOrderCountsDisconnectedWhenAllowed(t *testing.T) {
	sessions := []windowsSessionState{{ID: 7, Disconnected: true}, {ID: 3, Active: true}, {ID: 1}, {ID: 2, Disconnected: true}}
	if got := fmt.Sprint(windowsTargetSessionOrder(sessions, true)); got != "[3 2 7]" {
		t.Fatalf("signed-in order = %s, want [3 2 7]", got)
	}
	if got := fmt.Sprint(windowsTargetSessionOrder(sessions, false)); got != "[3]" {
		t.Fatalf("active-only order = %s, want [3]", got)
	}
}

func TestIsWindowsTargetSessionUnavailableRequiresTypedCause(t *testing.T) {
	typed := &WindowsTargetSessionUnavailableError{
		SID: "S-1-5-21-1-2-3-1001",
	}
	if !IsWindowsTargetSessionUnavailable(fmt.Errorf("wrapped: %w", typed)) {
		t.Fatal("wrapped typed target-session absence was not recognized")
	}
	lookalike := fmt.Errorf("enterprise hooks: no active interactive session token matches explicit target SID S-1-5-21-1-2-3-1001; guardian will retry")
	if IsWindowsTargetSessionUnavailable(lookalike) {
		t.Fatal("message lookalike was downgraded to deferred session absence")
	}
}
