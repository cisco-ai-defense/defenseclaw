// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// GAP-0141 (lane F8): the controller tells a revert from the actor's
// snapshot identity (newest generation, its node-local files, the last
// assigned generation, the worker process), not from the state transition it
// happens to see between two 2 s passes. The fake follows what a real
// cluster does (E1, evidence substrate-1/f8/snapexp-2.log).

func lifeRig(t *testing.T) (*rig, *lifeRec) {
	t.Helper()
	life := &lifeRec{}
	return newRig(t, func(_ *config.Config, o *controller.Options) { o.Lifecycle = life }), life
}

func wantLife(t *testing.T, life *lifeRec, want ...string) {
	t.Helper()
	if got := life.names(); !slices.Equal(got, want) {
		t.Fatalf("lifecycle = %v, want %v", got, want)
	}
}

// R3b's proof (evidence substrate-1/r3/GAP-0141): RevertActor also accepts
// a SUSPENDED actor with a node-local snapshot, and the controller sees
// SUSPENDED -> SUSPENDED.
func TestR3bRevertOfASuspendedActorIsSent(t *testing.T) {
	r, life := lifeRig(t)
	a := r.actor("eng-web", "alice-r3b1", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	r.clk.Add(time.Second)
	if err := r.api.SetState(ref, ateapi.ActorStateSuspended); err != nil {
		t.Fatal(err)
	}
	r.pass()
	r.clk.Add(time.Second)
	if err := r.api.Revert(ref); err != nil {
		t.Fatal(err)
	}
	r.pass()
	if got := life.names(); !slices.Contains(got, "reverted") {
		t.Fatalf("lifecycle = %v: the revert of a suspended actor sent no reverted event (no barrier)", got)
	}
	wantLife(t, life, "suspended", "reverted")
	r.pass()
	wantLife(t, life, "suspended", "reverted") // once, not on every pass
}

// R3b's proof: a suspend and a revert inside one poll are seen as
// RUNNING -> SUSPENDED with the suspend's new generation.
func TestR3bSuspendThenRevertBetweenPassesIsSent(t *testing.T) {
	r, life := lifeRig(t)
	a := r.actor("eng-web", "alice-r3b2", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	r.clk.Add(time.Second)
	if err := r.api.SetState(ref, ateapi.ActorStateSuspended); err != nil {
		t.Fatal(err)
	}
	if err := r.api.Revert(ref); err != nil {
		t.Fatal(err)
	}
	r.pass()
	if got := life.names(); !slices.Contains(got, "reverted") {
		t.Fatalf("lifecycle = %v: suspend + revert inside one poll sent no reverted event", got)
	}
	// The clock pauses (suspended) and the barrier goes in (reverted).
	wantLife(t, life, "suspended", "reverted")
}

// A sync suspend (upload done) keeps the snapshot; the revert only drops its
// node-local files. Still a revert.
func TestRevertOfAnUploadedSuspendedActorIsSent(t *testing.T) {
	r, life := lifeRig(t)
	a := r.actor("eng-web", "alice-f8a", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	r.clk.Add(time.Second)
	if err := r.api.SetState(ref, ateapi.ActorStateSuspended); err != nil {
		t.Fatal(err)
	}
	if err := r.api.CompleteUpload(ref); err != nil {
		t.Fatal(err)
	}
	r.pass()
	r.clk.Add(time.Second)
	if err := r.api.Revert(ref); err != nil {
		t.Fatal(err)
	}
	r.pass()
	wantLife(t, life, "suspended", "reverted")
}

// A revert of a running actor followed at once by a resume: the controller
// sees RUNNING -> RUNNING on another worker process.
func TestRevertAndResumeInsideOnePollIsSent(t *testing.T) {
	r, life := lifeRig(t)
	a := r.actor("eng-web", "alice-f8b", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	r.clk.Add(time.Second)
	if err := r.api.SetState(ref, ateapi.ActorStateSuspended); err != nil {
		t.Fatal(err)
	}
	r.pass()
	r.clk.Add(time.Second)
	if err := r.api.SetState(ref, ateapi.ActorStateRunning); err != nil {
		t.Fatal(err)
	}
	r.pass()
	r.clk.Add(time.Second)
	if err := r.api.Revert(ref); err != nil {
		t.Fatal(err)
	}
	if err := r.api.SetState(ref, ateapi.ActorStateRunning); err != nil {
		t.Fatal(err)
	}
	r.pass()
	wantLife(t, life, "suspended", "resumed", "reverted")
}

// A revert of a running actor seen only as RUNNING -> SUSPENDED pauses the
// clock too (the leader pauses running time only on suspended).
func TestRevertOfARunningActorPausesTheClock(t *testing.T) {
	r, life := lifeRig(t)
	a := r.actor("eng-web", "alice-f8c", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	r.clk.Add(time.Second)
	if err := r.api.Revert(ref); err != nil {
		t.Fatal(err)
	}
	r.pass()
	wantLife(t, life, "suspended", "reverted")
}

// Suspends and resumes alone never send reverted: not one per pass, not after
// an upload, not for a suspend plus resume inside one poll.
func TestPlainSuspendAndResumeSendNoRevert(t *testing.T) {
	r, life := lifeRig(t)
	a := r.actor("eng-web", "alice-f8d", ateapi.ActorStateRunning, "sub-alice")
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
	suspend := func() error { return r.api.SetState(ref, ateapi.ActorStateSuspended) }
	resume := func() error { return r.api.SetState(ref, ateapi.ActorStateRunning) }
	step(suspend)
	step(func() error { return r.api.CompleteUpload(ref) })
	r.pass()
	step(resume)
	r.pass()
	step(func() error {
		if err := suspend(); err != nil {
			return err
		}
		return resume()
	})
	step(suspend)
	step(func() error {
		if err := resume(); err != nil {
			return err
		}
		return suspend()
	})
	wantLife(t, life, "suspended", "resumed", "suspended")
}
