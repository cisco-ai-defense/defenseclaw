// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"slices"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// GAP-0526 (J20, E16): a worker pod force-deleted under an actor with a
// queued ask left the actor CRASHED and its ask closed, but no controller
// record named the crash: the lifecycle event went to the leader only. The
// crash is now a controller event of its own, once per crash, with the
// reason the leader closes the actor's asks with.
func TestCrashIsAControllerRecordGAP0526(t *testing.T) {
	r, life := lifeRig(t)
	a := r.actor("eng-web", "alice-g526", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	if n := len(r.sink.Events(controller.EventCrashed)); n != 0 {
		t.Fatalf("a running actor has %d crash records", n)
	}
	r.clk.Add(time.Second)
	if err := r.api.SetState(ref, ateapi.ActorStateCrashed); err != nil {
		t.Fatal(err)
	}
	r.pass()
	r.clk.Add(time.Second)
	r.pass() // still CRASHED: no second record
	if !slices.Contains(life.names(), "crashed") {
		t.Fatalf("lifecycle = %v, want crashed", life.names())
	}
	ev := r.sink.Events(controller.EventCrashed)
	if len(ev) != 1 {
		t.Fatalf("crash records = %d, want 1", len(ev))
	}
	e := ev[0]
	if e.Atespace != "eng-web" || e.Actor != "alice-g526" || e.ActorUID != a.GetMetadata().GetUid() || e.Severity != controller.SeverityWarn {
		t.Fatalf("crash record names %s/%s (%s) severity %s", e.Atespace, e.Actor, e.ActorUID, e.Severity)
	}
	if e.Detail["reason"] != "actor_crashed" || e.Detail["lifecycle"] != "crashed" {
		t.Fatalf("crash record detail %v, want reason actor_crashed", e.Detail)
	}
}
