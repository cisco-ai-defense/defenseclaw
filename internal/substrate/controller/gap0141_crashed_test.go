// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
)

// crashThenRevert runs alice's actor to CRASHED, then reverts it and leaves
// it in after, both inside one 2 s poll, and returns the lifecycle events
// the leader got.
func crashThenRevert(t *testing.T, after ateapi.ActorState) []string {
	t.Helper()
	r, life := lifeRig(t)
	a := r.actor("eng-web", "alice-g141", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	for _, st := range []ateapi.ActorState{ateapi.ActorStateSuspended, ateapi.ActorStateRunning, ateapi.ActorStateCrashed} {
		r.clk.Add(time.Second)
		if err := r.api.SetState(ref, st); err != nil {
			t.Fatal(err)
		}
		r.pass()
	}
	r.clk.Add(time.Second)
	if err := r.api.Revert(ref); err != nil {
		t.Fatal(err)
	}
	if after != ateapi.ActorStateSuspended {
		if err := r.api.SetState(ref, after); err != nil {
			t.Fatal(err)
		}
	}
	r.pass()
	return life.names()
}

// Only a revert brings a crashed actor back. A revert and a resume inside
// one poll are seen as CRASHED -> RUNNING; the leader still gets reverted
// (the mutation barrier) after crashed (substrate-1 GAP-0141, lane R4's
// TestR4GAP0141CrashedRevertResumeInOnePoll).
func TestGAP0141CrashedRevertResumeInOnePollIsSent(t *testing.T) {
	got := crashThenRevert(t, ateapi.ActorStateRunning)
	tail := got[slices.Index(got, "crashed")+1:]
	if !slices.Equal(tail, []string{"reverted"}) {
		t.Fatalf("lifecycle = %v, want reverted once after crashed", got)
	}
}

// The CRASHED -> SUSPENDED outcome of a revert keeps its two events:
// suspended (the retention clock) and reverted (the barrier).
func TestGAP0141CrashedRevertToSuspendedIsSent(t *testing.T) {
	got := crashThenRevert(t, ateapi.ActorStateSuspended)
	tail := got[slices.Index(got, "crashed")+1:]
	if !slices.Equal(tail, []string{"suspended", "reverted"}) {
		t.Fatalf("lifecycle = %v, want suspended then reverted after crashed", got)
	}
}
