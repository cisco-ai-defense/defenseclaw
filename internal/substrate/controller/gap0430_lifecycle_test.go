// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// gap0430Records creates alice's launcher actor in start, runs it through
// steps (one pass per step, then a second pass that must add nothing),
// deletes it, and returns the actor's discovery records in order:
// inventory, lifecycle and deleted as "type:message", resume re-checks as
// "recheck".
func gap0430Records(t *testing.T, start ateapi.ActorState, steps ...ateapi.ActorState) []string {
	t.Helper()
	r := newRig(t, nil)
	a := r.actor("eng-web", "alice-g430", start, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	uid := a.GetMetadata().GetUid()
	r.pass()
	for _, st := range steps {
		r.clk.Add(time.Second)
		if err := r.api.SetState(ref, st); err != nil {
			t.Fatal(err)
		}
		r.pass()
		r.clk.Add(time.Second)
		r.pass() // a poll that sees the same state records nothing
	}
	if _, err := r.api.DeleteActor(context.Background(), ref, nil); err != nil {
		t.Fatal(err)
	}
	r.pass()
	var got []string
	for _, ev := range r.sink.Events(controller.EventInventory, controller.EventLifecycle, controller.EventDeleted, controller.EventResumeRecheck) {
		if ev.ActorUID != uid || ev.Actor != "alice-g430" {
			t.Fatalf("record %+v lacks the actor or its uid", ev)
		}
		if ev.Type == controller.EventResumeRecheck {
			got = append(got, "recheck")
			continue
		}
		got = append(got, ev.Type+":"+ev.Message)
		if ev.Type == controller.EventLifecycle && (ev.Detail["previous_state"] == nil || ev.Detail["state"] == nil || ev.Detail["transition"] == nil) {
			t.Fatalf("lifecycle record without previous state, state or transition: %+v", ev)
		}
	}
	return got
}

// substrate-1 GAP-0430: create, suspend, resume and delete of a launcher
// actor leave one discovery record each, and the resume its re-check, when
// the polls see only the settled states (a kubectl ate suspend or resume
// takes well under the poll interval).
func TestGAP0430SuspendResumeBetweenPollsAreRecorded(t *testing.T) {
	got := gap0430Records(t, ateapi.ActorStateRunning, ateapi.ActorStateSuspended, ateapi.ActorStateRunning)
	want := []string{"sandbox.inventory:actor seen", "sandbox.lifecycle:actor suspended", "sandbox.lifecycle:actor resumed", "recheck", "sandbox.deleted:actor deleted"}
	if !slices.Equal(got, want) {
		t.Fatalf("records = %q\nwant      %q", got, want)
	}
}

// The same with RESUMING seen in two polls: one record per transition and
// one re-check per resume, not one per poll.
func TestGAP0430ResumingSeenTwiceRechecksOnce(t *testing.T) {
	got := gap0430Records(t, ateapi.ActorStateRunning, ateapi.ActorStateSuspended, ateapi.ActorStateResuming, ateapi.ActorStateRunning)
	want := []string{"sandbox.inventory:actor seen", "sandbox.lifecycle:actor suspended", "recheck", "sandbox.lifecycle:actor resumed", "sandbox.deleted:actor deleted"}
	if !slices.Equal(got, want) {
		t.Fatalf("records = %q\nwant      %q", got, want)
	}
}

// The first resume of a new actor (created SUSPENDED, no snapshot
// generation yet) seen as RESUMING in two polls re-checks once too.
func TestGAP0430FirstResumeRechecksOnce(t *testing.T) {
	got := gap0430Records(t, ateapi.ActorStateSuspended, ateapi.ActorStateResuming, ateapi.ActorStateRunning)
	want := []string{"sandbox.inventory:actor seen", "recheck", "sandbox.lifecycle:actor resumed", "sandbox.deleted:actor deleted"}
	if !slices.Equal(got, want) {
		t.Fatalf("records = %q\nwant      %q", got, want)
	}
}

// The suspended record names the states it went between.
func TestGAP0430LifecycleRecordStates(t *testing.T) {
	r := newRig(t, nil)
	a := r.actor("eng-web", "alice-g430s", ateapi.ActorStateRunning, "sub-alice")
	r.pass()
	if err := r.api.SetState(ateapi.RefOf(a.GetMetadata()), ateapi.ActorStateSuspended); err != nil {
		t.Fatal(err)
	}
	r.clk.Add(time.Second)
	r.pass()
	evs := r.sink.Events(controller.EventLifecycle)
	if len(evs) != 1 {
		t.Fatalf("lifecycle records = %+v, want one", evs)
	}
	d := evs[0].Detail
	if d["transition"] != "suspended" || d["previous_state"] != ateapi.ActorStateRunning.String() || d["state"] != ateapi.ActorStateSuspended.String() {
		t.Fatalf("detail = %v", d)
	}
}
