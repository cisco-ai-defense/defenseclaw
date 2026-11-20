// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"fmt"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// GAP-0411: a batch larger than the pool drains even when every task is
// shorter than a controller pass, so the controller never sees a task run
// before it ends (E5: --batch 100 over 20 workers, finished actors kept
// their workers for an hour and tasks 21+ never started).
func TestGAP0411BatchLargerThanPoolDrainsWithShortTasks(t *testing.T) {
	r := newRig(t, nil)
	const tasks, workers = 6, 2
	type task struct {
		a     *ateapi.Actor
		state string // queued, running, done
	}
	var all []*task
	for i := 0; i < tasks; i++ {
		name := fmt.Sprintf("b-%d", i+1)
		a := r.actor("eng-web", name, ateapi.ActorStateSuspended, "")
		if err := r.reg.Put(context.Background(), controller.Registration{Atespace: "eng-web", Name: name, UID: a.GetMetadata().GetUid(),
			Person: "sub-e", Profile: "eng", Task: true, BatchID: "b-big", Source: controller.SourceLauncher}); err != nil {
			t.Fatal(err)
		}
		all = append(all, &task{a: a, state: "queued"})
	}
	state := func(a *ateapi.Actor) ateapi.ActorState {
		got, _ := r.api.GetActor(context.Background(), ateapi.RefOf(a.GetMetadata()))
		return got.GetStatus().GetState()
	}
	r.pass() // every actor seen SUSPENDED, as the launcher creates them
	for step := 0; step < 200; step++ {
		running, left := 0, 0
		for _, tk := range all {
			if tk.state == "running" && state(tk.a) == ateapi.ActorStateSuspended {
				tk.state = "done" // the controller freed its worker
			}
			switch tk.state {
			case "running":
				running++
			case "queued":
				left++
			}
		}
		if left == 0 && running == 0 {
			return
		}
		// The launcher resumes the next tasks while the pool has room; each
		// task runs 2 s, reports its end, and is over before the next pass.
		for _, tk := range all {
			if tk.state != "queued" || running >= workers {
				continue
			}
			if _, _, err := r.api.ResumeActor(context.Background(), ateapi.RefOf(tk.a.GetMetadata())); err != nil {
				t.Fatal(err)
			}
			tk.state = "running"
			running++
			uid := tk.a.GetMetadata().GetUid()
			end := r.clk.Now().Add(2 * time.Second)
			r.act.Touch(uid, end) // the end report is relay traffic
			r.act.EndTask(uid, end)
		}
		r.clk.Add(5 * time.Second)
		r.pass()
	}
	done := 0
	for _, tk := range all {
		if tk.state == "done" {
			done++
		}
	}
	t.Fatalf("the batch did not drain: %d of %d tasks freed their worker after %s; finished actors keep their workers",
		done, tasks, 200*5*time.Second)
}

// GAP-0411: a controller that starts (or restarts) after a task ended frees
// that worker too; it first sees the finished actor already running.
func TestGAP0411TaskEndedBeforeControllerStartFreesWorker(t *testing.T) {
	r := newRig(t, nil)
	a := r.actor("eng-web", "ended-early", ateapi.ActorStateRunning, "")
	uid := a.GetMetadata().GetUid()
	if err := r.reg.Put(context.Background(), controller.Registration{Atespace: "eng-web", Name: "ended-early", UID: uid,
		Person: "sub-e", Profile: "eng", Task: true, Source: controller.SourceLauncher}); err != nil {
		t.Fatal(err)
	}
	r.act.Touch(uid, r.clk.Now())
	r.act.EndTask(uid, r.clk.Now())
	r.clk.Add(10 * time.Second)
	r.pass() // the controller's first look: RUNNING
	r.clk.Add(controller.DefaultTaskEndGrace)
	r.pass()
	got, _ := r.api.GetActor(context.Background(), ateapi.RefOf(a.GetMetadata()))
	if got.GetStatus().GetState() != ateapi.ActorStateSuspended {
		t.Fatalf("state %s: a task that ended before the controller first saw its actor keeps its worker", got.GetStatus().GetState())
	}
	if ev := r.sink.Events(controller.EventTaskEndSuspend); len(ev) != 1 {
		t.Fatalf("task-end events %+v", ev)
	}
}
