// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// GAP-0274: a finished --task actor kept its worker, so a batch larger than
// the pool started only as many tasks as there were workers. It is now
// suspended DefaultTaskEndGrace after its task ended.
func TestFinishedTaskFreesItsWorker(t *testing.T) {
	r := newRig(t, nil)
	task := func(name string) *ateapi.Actor {
		a := r.actor("eng-web", name, ateapi.ActorStateRunning, "")
		_ = r.reg.Put(context.Background(), controller.Registration{Atespace: "eng-web", Name: name, UID: a.GetMetadata().GetUid(),
			Person: "sub-e", Profile: "eng", Task: true, BatchID: "b-1", Source: controller.SourceLauncher})
		return a
	}
	done, running, asking, busy := task("done"), task("running"), task("asking"), task("busy")
	r.pass() // running since now
	r.clk.Add(10 * time.Second)
	for _, a := range []*ateapi.Actor{done, asking, busy} {
		r.act.EndTask(a.GetMetadata().GetUid(), r.clk.Now())
	}
	r.act.SetAsk(asking.GetMetadata().GetUid(), true)
	state := func(a *ateapi.Actor) ateapi.ActorState {
		got, _ := r.api.GetActor(context.Background(), ateapi.RefOf(a.GetMetadata()))
		return got.GetStatus().GetState()
	}
	r.clk.Add(30 * time.Second)
	r.pass()
	if state(done) != ateapi.ActorStateRunning {
		t.Fatal("suspended inside the grace: the launcher that follows it may still read the end")
	}
	// Something reached the gateway well after the end: it still runs.
	r.act.Touch(busy.GetMetadata().GetUid(), r.clk.Now())
	r.clk.Add(controller.DefaultTaskEndGrace)
	r.pass()
	if state(done) != ateapi.ActorStateSuspended {
		t.Fatal("a finished task kept its worker")
	}
	for name, a := range map[string]*ateapi.Actor{"no task end": running, "pending ask": asking, "activity after the end": busy} {
		if state(a) != ateapi.ActorStateRunning {
			t.Errorf("%s: suspended", name)
		}
	}
	ev := r.sink.Events(controller.EventTaskEndSuspend)
	if len(ev) != 1 || ev[0].Actor != "done" {
		t.Fatalf("task-end events %+v", ev)
	}
	if len(r.sink.Events(controller.EventIdleSuspend)) != 0 {
		t.Fatal("a task end was reported as an idle suspend")
	}
	// Woken later (pull): the old end does not suspend it at once; it is
	// idle like any actor from then on.
	if _, _, err := r.api.ResumeActor(context.Background(), ateapi.RefOf(done.GetMetadata())); err != nil {
		t.Fatal(err)
	}
	r.pass()
	r.clk.Add(2 * time.Minute)
	r.pass()
	if state(done) != ateapi.ActorStateRunning {
		t.Fatal("a woken finished task was suspended again by its old end")
	}
	r.act.SetCPU(done.GetMetadata().GetUid(), 0.01, r.clk.Now().Add(31*time.Minute))
	r.clk.Add(31 * time.Minute)
	r.pass()
	if state(done) != ateapi.ActorStateSuspended {
		t.Fatal("a woken finished task is not idle-suspended")
	}
}
