// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// R11 probe: a finished --task actor that saw any gateway traffic more than
// taskEndSlack after its end (a pull, logs, a connect) is never suspended.

package controller_test

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

func TestR11ActivityAfterTaskEndKeepsWorker(t *testing.T) {
	r := newRig(t, nil)
	a := r.actor("eng-web", "ci", ateapi.ActorStateRunning, "")
	uid := a.GetMetadata().GetUid()
	_ = r.reg.Put(context.Background(), controller.Registration{Atespace: "eng-web", Name: "ci", UID: uid,
		Person: "sub-e", Profile: "eng", Task: true, Source: controller.SourceLauncher})
	state := func() ateapi.ActorState {
		got, _ := r.api.GetActor(context.Background(), ateapi.RefOf(a.GetMetadata()))
		return got.GetStatus().GetState()
	}
	r.pass()
	r.clk.Add(10 * time.Second)
	r.act.EndTask(uid, r.clk.Now())
	// The CI step after `run --task`: `pull NAME`, 20 s after the end.
	r.clk.Add(20 * time.Second)
	r.act.Touch(uid, r.clk.Now())
	// Then nothing for 2 hours, CPU idle.
	for i := 0; i < 8; i++ {
		r.clk.Add(15 * time.Minute)
		r.act.SetCPU(uid, 0.0, r.clk.Now())
		r.pass()
	}
	if state() == ateapi.ActorStateRunning {
		t.Errorf("R11 FINDING: a finished task actor touched 20 s after its end still holds its worker after 2 h idle (neither task-end nor idle suspend)")
	}
}
