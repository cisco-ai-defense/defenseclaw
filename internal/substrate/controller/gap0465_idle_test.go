// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// GAP-0465: the chart runs the controller without a usage receiver
// (--usage-listen), so it has no CPU source. Idle suspend then needed a
// CPU sample that never came, and idle_suspend_after suspended nothing in
// any chart install. Without a CPU source, silence for idle_suspend_after
// is enough once the actor's activity is known and no terminal is attached
// (the fake reports no attachment here; GAP-0534 covers attached actors);
// a CPU source, when wired, still has the last word.
func TestGAP0465IdleSuspendWithoutCPUSource(t *testing.T) {
	r := newRig(t, func(_ *config.Config, o *controller.Options) { o.CPU = nil })
	state := func(a *ateapi.Actor) ateapi.ActorState {
		got, _ := r.api.GetActor(context.Background(), ateapi.RefOf(a.GetMetadata()))
		return got.GetStatus().GetState()
	}
	quiet := r.actor("eng-web", "quiet", ateapi.ActorStateRunning, "sub-a")
	active := r.actor("eng-web", "active", ateapi.ActorStateRunning, "sub-b")
	asking := r.actor("eng-web", "asking", ateapi.ActorStateRunning, "sub-c")
	unknown := r.actor("eng-web", "unknown", ateapi.ActorStateRunning, "sub-d")
	running := r.actor("eng-web", "task-running", ateapi.ActorStateRunning, "")
	reached := r.actor("eng-web", "task-reached", ateapi.ActorStateRunning, "")
	for _, a := range []*ateapi.Actor{running, reached} {
		if err := r.reg.Put(context.Background(), controller.Registration{Atespace: "eng-web", Name: a.GetMetadata().GetName(),
			UID: a.GetMetadata().GetUid(), Person: "sub-e", Profile: "eng", Task: true, Source: controller.SourceLauncher}); err != nil {
			t.Fatal(err)
		}
	}
	r.pass() // running since now
	start := r.clk.Now()
	for _, a := range []*ateapi.Actor{quiet, active, asking, running} {
		r.act.Touch(a.GetMetadata().GetUid(), start.Add(time.Second))
	}
	r.act.SetAsk(asking.GetMetadata().GetUid(), true)
	// J08: a detached --task ended, then a connect reached the gateway.
	r.act.EndTask(reached.GetMetadata().GetUid(), start.Add(5*time.Second))
	r.act.Touch(reached.GetMetadata().GetUid(), start.Add(5*time.Minute))
	r.clk.Add(36 * time.Minute)
	r.act.Touch(active.GetMetadata().GetUid(), r.clk.Now().Add(-time.Minute))
	r.pass()

	for name, a := range map[string]*ateapi.Actor{"quiet": quiet, "--task reached after its end": reached} {
		if state(a) != ateapi.ActorStateSuspended {
			t.Errorf("%s: not suspended after idle_suspend_after without a CPU source", name)
		}
	}
	for name, a := range map[string]*ateapi.Actor{"active a minute ago": active, "pending ask": asking,
		"activity never known": unknown, "running --task": running} {
		if state(a) != ateapi.ActorStateRunning {
			t.Errorf("%s: suspended", name)
		}
	}
	if evs := r.sink.Events(controller.EventIdleSuspend); len(evs) != 2 {
		t.Fatalf("idle events: %+v", evs)
	}

	// The create path's controller (no activity feed) never suspends.
	g := newRig(t, func(_ *config.Config, o *controller.Options) { o.Activity, o.CPU = controller.NoActivity{}, nil })
	b := g.actor("eng-web", "b", ateapi.ActorStateRunning, "sub-a")
	g.pass()
	g.clk.Add(time.Hour)
	g.pass()
	if got, _ := g.api.GetActor(context.Background(), ateapi.RefOf(b.GetMetadata())); got.GetStatus().GetState() != ateapi.ActorStateRunning {
		t.Fatal("a controller without an activity feed suspended an actor")
	}
}
