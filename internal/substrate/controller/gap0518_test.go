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

// substrate-1 GAP-0518 (residual, from t6/close-auth 469f1e79fd): live on d5 the GAP-0411 fix freed no worker. The chart's
// controller has no CPU source, so the wiring turns idle suspend off
// (IdleSuspendAfter 0), and idle() returned at "after <= 0" before it
// looked at the task end: a finished --task actor kept its worker forever.
// The unit rig had a CPU source and a 30 m idle timeout, so it never saw
// it. A task end frees the worker whether idle suspend is on or not.
func TestGAP0518TaskEndFreesWorkerWithIdleSuspendOff(t *testing.T) {
	for name, mutate := range map[string]func(*config.Config, *controller.Options){
		"no idle timeout, no CPU source (the chart)": func(_ *config.Config, o *controller.Options) {
			o.IdleSuspendAfter, o.CPU = 0, nil
		},
		"no idle timeout": func(_ *config.Config, o *controller.Options) { o.IdleSuspendAfter = 0 },
	} {
		t.Run(name, func(t *testing.T) {
			r := newRig(t, mutate)
			a := r.actor("eng-web", "short-task", ateapi.ActorStateSuspended, "")
			uid := a.GetMetadata().GetUid()
			if err := r.reg.Put(context.Background(), controller.Registration{Atespace: "eng-web", Name: "short-task", UID: uid,
				Person: "sub-e", Profile: "eng", Task: true, BatchID: "b-d5", Source: controller.SourceLauncher}); err != nil {
				t.Fatal(err)
			}
			r.pass() // created SUSPENDED by the launcher
			if _, _, err := r.api.ResumeActor(context.Background(), ateapi.RefOf(a.GetMetadata())); err != nil {
				t.Fatal(err)
			}
			r.pass()                                // the controller sees it RUNNING (the ended-before-seen case is GAP-0411)
			end := r.clk.Now().Add(7 * time.Second) // 'exit 0 after 7s'
			r.act.Touch(uid, end)
			r.act.EndTask(uid, end)
			r.clk.Add(10 * time.Second)
			r.pass()
			r.clk.Add(controller.DefaultTaskEndGrace)
			r.pass()
			got, _ := r.api.GetActor(context.Background(), ateapi.RefOf(a.GetMetadata()))
			if got.GetStatus().GetState() != ateapi.ActorStateSuspended {
				t.Fatalf("state %s: a finished task keeps its worker when idle suspend is off", got.GetStatus().GetState())
			}
			if ev := r.sink.Events(controller.EventTaskEndSuspend); len(ev) != 1 {
				t.Fatalf("task-end events %+v", ev)
			}
			// Idle suspend stays off for an interactive actor.
			b := r.actor("eng-web", "interactive", ateapi.ActorStateRunning, "")
			if err := r.reg.Put(context.Background(), controller.Registration{Atespace: "eng-web", Name: "interactive", UID: b.GetMetadata().GetUid(),
				Person: "sub-e", Profile: "eng", Source: controller.SourceLauncher}); err != nil {
				t.Fatal(err)
			}
			r.clk.Add(2 * time.Hour)
			r.pass()
			if got, _ := r.api.GetActor(context.Background(), ateapi.RefOf(b.GetMetadata())); got.GetStatus().GetState() != ateapi.ActorStateRunning {
				t.Fatalf("an interactive actor was suspended with idle suspend off: %s", got.GetStatus().GetState())
			}
		})
	}
}
