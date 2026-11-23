// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"bytes"
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller/controllerfake"
)

// GAP-0518 (d5): the controller the substrate-controller command builds
// (newSubstrateController with an activity feed, no CPU source because the
// chart wires no --usage-listen, the cluster's substrate.idle_suspend_after
// set and no profile override) must free a finished --task actor's worker
// TaskEndGrace after its end, with a task_end_suspend event. It used to turn
// the cluster setting off without a CPU source, and idle() returns before
// the task-end branch when the delay is 0: a finished task kept its worker
// for good and a batch larger than the pool failed to start.
//
// The controller runs on the real clock here (the wiring sets no clock), so
// the test waits out the one-minute TaskEndGrace.
func TestGAP0518WiredControllerFreesAFinishedTaskWithoutCPUSource(t *testing.T) {
	t.Parallel()
	cfg := &config.Config{}
	cfg.Substrate.Enabled = true
	off := false
	cfg.Substrate.RequireAttestedTemplates = &off
	cfg.Substrate.LauncherAtespaces = map[string][]string{"eng": {"dc-eng"}}
	cfg.Substrate.IdleSuspendAfter = "30m" // d5: the cluster setting, not a profile's
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"eng": {Description: "engineering"}}
	cfg.Guardrail.DefaultProfile = "eng"

	ctx := context.Background()
	api := ateapifake.New()
	api.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "dc-eng", Name: "claude"}})
	a := api.PutActor(&ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "dc-eng", Name: "eng2-task"},
		ActorTemplate: ateapi.Ref("dc-eng", "claude"), Status: &ateapi.ActorStatus{State: ateapi.ActorStateRunning}})
	uid := a.GetMetadata().GetUid()
	reg := controller.NewMemoryRegistry()
	if err := reg.Put(ctx, controller.Registration{Atespace: "dc-eng", Name: "eng2-task", UID: uid, Person: "eng2",
		Profile: "eng", Task: true, Source: controller.SourceLauncher}); err != nil {
		t.Fatal(err)
	}
	act := &controllerfake.Activity{}
	var _ controller.TaskEndSource = act
	sink := &controllerfake.Sink{}
	var log bytes.Buffer
	ctl, err := newSubstrateController(cfg, api, reg, act, nil, multiSink{sink, &controller.JSONSink{W: &log}}, true, nil, "", nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	state := func() ateapi.ActorState {
		got, _ := api.GetActor(ctx, ateapi.RefOf(a.GetMetadata()))
		return got.GetStatus().GetState()
	}

	// The controller sees the task run, then the actor reports its end
	// (the gateway records the report as relay activity at the same time).
	if err := ctl.Reconcile(ctx); err != nil {
		t.Fatal(err)
	}
	ended := time.Now()
	act.EndTask(uid, ended)
	act.Touch(uid, ended)

	deadline := ended.Add(controller.DefaultTaskEndGrace + 15*time.Second)
	for state() == ateapi.ActorStateRunning && time.Now().Before(deadline) {
		time.Sleep(time.Second)
		if err := ctl.Reconcile(ctx); err != nil {
			t.Fatal(err)
		}
	}
	if s := state(); s != ateapi.ActorStateSuspended {
		t.Fatalf("a finished --task actor is %v %s after its end, want SUSPENDED (its worker freed); controller log:\n%s",
			s, time.Since(ended).Round(time.Second), log.String())
	}
	if evs := sink.Events(controller.EventTaskEndSuspend); len(evs) != 1 || evs[0].ActorUID != uid {
		t.Fatalf("task_end_suspend events: %+v", evs)
	}
	if took := time.Since(ended); took < controller.DefaultTaskEndGrace {
		t.Fatalf("suspended %s after the end, before TaskEndGrace", took)
	}
}

// multiSink sends every event to each sink.
type multiSink []controller.Sink

func (m multiSink) Emit(e controller.Event) {
	for _, s := range m {
		s.Emit(e)
	}
}
