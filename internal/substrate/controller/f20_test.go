// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
)

// GAP-0292 (lane F20): atelet detaches a suspended actor after
// --snapshot-detach-delay (30 minutes by default): the node copy of its
// uploaded snapshot goes, the snapshot stays, and the actor resumes from
// it. Read as a revert, the barrier it sent ended the actor's
// secret-read-then-egress chain after a 40-minute suspend (SMK J44).
func TestGAP0292DetachIsNotARevert(t *testing.T) {
	r, life := lifeRig(t)
	a := r.actor("eng-web", "alice-f20a", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	step := func(f func() error) {
		t.Helper()
		r.clk.Add(time.Second)
		if err := f(); err != nil {
			t.Fatal(err)
		}
		r.pass()
	}
	step(func() error { return r.api.SetState(ref, ateapi.ActorStateSuspended) })
	step(func() error { return r.api.CompleteUpload(ref) })
	step(func() error { return r.api.Detach(ref) })
	wantLife(t, life, "suspended")
	step(func() error { return r.api.SetState(ref, ateapi.ActorStateRunning) })
	wantLife(t, life, "suspended", "resumed")
}

// The controller can miss the whole suspend (a restart, or a pass stalled
// past the detach delay): the next pass sees RUNNING, then SUSPENDED and
// already detached. Still the suspend's own snapshot: no revert.
func TestGAP0292SuspendAndDetachInsideOnePassIsNotARevert(t *testing.T) {
	r, life := lifeRig(t)
	a := r.actor("eng-web", "alice-f20b", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	r.clk.Add(time.Second)
	for _, f := range []func() error{
		func() error { return r.api.SetState(ref, ateapi.ActorStateSuspended) },
		func() error { return r.api.CompleteUpload(ref) },
		func() error { return r.api.Detach(ref) },
	} {
		if err := f(); err != nil {
			t.Fatal(err)
		}
	}
	r.pass()
	wantLife(t, life, "suspended")
}

// A detach can't run before the upload finishes (the API refuses), and a
// revert that drops a snapshot not uploaded is still sent.
func TestGAP0292RevertOfAPendingSnapshotIsStillSent(t *testing.T) {
	r, life := lifeRig(t)
	a := r.actor("eng-web", "alice-f20c", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	r.clk.Add(time.Second)
	if err := r.api.SetState(ref, ateapi.ActorStateSuspended); err != nil {
		t.Fatal(err)
	}
	r.pass()
	if err := r.api.Detach(ref); err == nil {
		t.Fatal("detached a snapshot that is not uploaded")
	}
	r.clk.Add(time.Second)
	if err := r.api.Revert(ref); err != nil {
		t.Fatal(err)
	}
	r.pass()
	wantLife(t, life, "suspended", "reverted")
}
