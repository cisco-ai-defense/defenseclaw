// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// substrate-1 GAP-0486: a suspend and a resume inside one poll (a
// checkpoint, kubectl ate suspend then a connect) left no lifecycle record
// and no resume re-check: the pass saw RUNNING both times. The new snapshot
// generation tells it; a suspend then a resume and a suspend inside one
// poll is told the same way.
func TestGAP0486SuspendAndResumeInsideOnePollLeaveRecords(t *testing.T) {
	r := newRig(t, nil)
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	if err := r.api.SetState(ref, ateapi.ActorStateSuspended); err != nil {
		t.Fatal(err)
	}
	if err := r.api.SetState(ref, ateapi.ActorStateRunning); err != nil {
		t.Fatal(err)
	}
	r.pass()
	r.pass() // nothing changed: no record
	want := []string{"actor seen", "actor suspended", "actor resumed"}
	inventory := func() []string {
		var msgs []string
		for _, ev := range r.sink.Events(controller.EventInventory) {
			msgs = append(msgs, ev.Message)
		}
		return msgs
	}
	if got := inventory(); len(got) != len(want) || got[1] != want[1] || got[2] != want[2] {
		t.Fatalf("inventory = %q, want %q", got, want)
	}
	if rc := r.sink.Events(controller.EventResumeRecheck); len(rc) != 1 {
		t.Fatalf("resume re-check records = %d, want 1", len(rc))
	}

	// Suspended at a pass, then resumed and suspended again inside one poll.
	if err := r.api.SetState(ref, ateapi.ActorStateSuspended); err != nil {
		t.Fatal(err)
	}
	r.pass()
	if err := r.api.SetState(ref, ateapi.ActorStateRunning); err != nil {
		t.Fatal(err)
	}
	if err := r.api.SetState(ref, ateapi.ActorStateSuspended); err != nil {
		t.Fatal(err)
	}
	r.pass()
	got := inventory()
	if len(got) != 6 || got[4] != "actor resumed" || got[5] != "actor suspended" {
		t.Fatalf("inventory = %q, want a resume and a suspend after the third record pair", got)
	}
}
