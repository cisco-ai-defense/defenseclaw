// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// substrate-1 GAP-0534: substrate.idle_suspend_without_cpu (an opt-in)
// makes silence alone idle without a CPU source, an attached actor's too;
// off, the attached actor is kept. The fake feed reports attachments
// (controller.AttachSource), as the leader's activity.Source does.
func TestGAP0534IdleSuspendWithoutCPUOptIn(t *testing.T) {
	for _, optIn := range []bool{false, true} {
		r := newRig(t, func(_ *config.Config, o *controller.Options) { o.CPU, o.IdleSuspendWithoutCPU = nil, optIn })
		var _ controller.AttachSource = r.act
		a := r.actor("eng-web", "attached", ateapi.ActorStateRunning, "sub-a")
		r.pass()
		uid := a.GetMetadata().GetUid()
		r.act.Touch(uid, r.clk.Now().Add(time.Second))
		r.clk.Add(time.Hour)
		r.act.Attach(uid, r.clk.Now().Add(-30*time.Second))
		r.pass()
		want := ateapi.ActorStateRunning
		if optIn {
			want = ateapi.ActorStateSuspended
		}
		if s := gap0534State(r, a); s != want {
			t.Errorf("idle_suspend_without_cpu %v: attached quiet actor %s, want %s", optIn, s, want)
		}
	}
}
