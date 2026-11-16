// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package kernelpolicy

import "testing"

// rolloutChanges counts uid's ready and back-to-burn-in change events.
func rolloutChanges(h *harness, uid int) int {
	n := 0
	for _, ch := range h.status().Changes {
		if ch.UID != nil && *ch.UID == uid && (ch.Event == EventUIDReady || ch.Event == EventUIDBurnIn) {
			n++
		}
	}
	return n
}

// GAP-0166: status called a user enforcing with anchored_roots 0 while a
// fresh agent session of theirs read a key unopposed. The controls deny only
// for a session Tetragon marked at its start, so a user with no such session
// running is armed, never enforcing; anchored_roots and roots.anchored count
// the sessions a binaries anchor marked, not only pid anchors.
func TestEnforcedUserIsArmedUntilASessionIsAnchored(t *testing.T) {
	h := enforcing(t) // alice's session 4001 was running before the load
	if alice := userState(h, 1001); alice.State != UIDArmed || alice.AnchoredRoots != 0 {
		t.Fatalf("alice with only a session older than the controls = %+v, want armed with 0 anchored", alice)
	}
	changes := rolloutChanges(h, 1001)

	h.procs = []Proc{codexProc(5001, 1, 120, 1002)}
	h.pass()
	if alice := userState(h, 1001); alice.State != UIDArmed || alice.AnchoredRoots != 0 {
		t.Fatalf("alice with no session = %+v, want armed with 0 anchored", alice)
	}
	before := h.status().Roots.Anchored

	h.procs = append(h.procs, nativeProc(4010, 1, 300, 1001, aliceClaudeNew))
	h.pass()
	if alice := userState(h, 1001); alice.State != UIDEnforcing || alice.AnchoredRoots != 1 {
		t.Fatalf("alice with a session started after the load = %+v, want enforcing with 1 anchored", alice)
	}
	if got := h.status().Roots.Anchored; got != before+1 {
		t.Fatalf("roots.anchored = %d, want %d: the marked session counts", got, before+1)
	}

	h.procs = []Proc{codexProc(5001, 1, 120, 1002)}
	h.pass()
	if alice := userState(h, 1001); alice.State != UIDArmed || alice.AnchoredRoots != 0 {
		t.Fatalf("alice after the session exits = %+v, want armed again", alice)
	}
	if got := rolloutChanges(h, 1001); got != changes {
		t.Fatalf("%d rollout changes after sessions came and went, want %d: armed and enforcing are one step", got, changes)
	}
	for _, user := range h.status().UIDs {
		if user.State == UIDEnforcing && user.AnchoredRoots == 0 {
			t.Fatalf("%+v: enforcing with no anchored session", user)
		}
	}
}
