// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
)

// GAP-1034: a blocked row prints the administrator's wording and its next
// step with no state prefix; the other states print as before.
func TestOwnStateTextPrintsABlockedRowAsTheSentence(t *testing.T) {
	const reason = "blocked until this account signs in or reconnects (DefenseClaw refuses every tool call of the agent)"
	got := ownStateText(ownStatusRow{State: "blocked", Reason: reason, NextStep: "Stay signed in."})
	if got != reason+". Stay signed in" {
		t.Fatalf("blocked row = %q", got)
	}
	if got := ownStateText(ownStatusRow{State: "blocked", Reason: reason}); got != reason {
		t.Fatalf("blocked row without a next step = %q", got)
	}
	if got := ownStateText(ownStatusRow{State: "blocked"}); got != "blocked" {
		t.Fatalf("blocked row without a reason = %q", got)
	}
	if got := ownStateText(ownStatusRow{State: "not confirmed", Reason: "why", NextStep: "next"}); got != "not confirmed: why. next" {
		t.Fatalf("another state changed: %q", got)
	}
	if strings.HasPrefix(ownStateText(ownStatusRow{State: "blocked", Reason: reason}), "blocked:") {
		t.Fatal("the state is repeated")
	}
}
