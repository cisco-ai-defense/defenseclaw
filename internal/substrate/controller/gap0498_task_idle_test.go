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

package controller_test

import (
	"context"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// GAP-0498 (J36 task-optin): the docs say a running --task run is exempt
// from idle suspend unless its profile opts in, but no key set
// Registration.IdleSuspendTask. A profile with idle_suspend_tasks: true now
// lets a quiet task be suspended; a task with a pending ask is still not,
// and a task of a profile without the key still runs.
func TestGAP0498ProfileOptsTaskRunsIntoIdleSuspend(t *testing.T) {
	var profiles map[string]config.GuardrailProfile
	if err := yaml.Unmarshal([]byte("eng:\n  sandbox:\n    idle_suspend_tasks: true\nci: {}\n"), &profiles); err != nil {
		t.Fatal(err)
	}
	r := newRig(t, func(cfg *config.Config, _ *controller.Options) { cfg.Guardrail.Profiles = profiles })
	task := func(name, profile string) *ateapi.Actor {
		a := r.actor("eng-web", name, ateapi.ActorStateRunning, "")
		if err := r.reg.Put(context.Background(), controller.Registration{Atespace: "eng-web", Name: name, UID: a.GetMetadata().GetUid(),
			Person: "sub-" + name, Profile: profile, Task: true, Source: controller.SourceLauncher}); err != nil {
			t.Fatal(err)
		}
		return a
	}
	quiet, asking, other := task("quiet", "eng"), task("asking", "eng"), task("other", "ci")
	r.pass()
	r.clk.Add(31 * time.Minute)
	now := r.clk.Now()
	for _, a := range []*ateapi.Actor{quiet, asking, other} {
		r.act.SetCPU(a.GetMetadata().GetUid(), 0.01, now)
	}
	r.act.SetAsk(asking.GetMetadata().GetUid(), true)
	r.pass()
	state := func(a *ateapi.Actor) ateapi.ActorState {
		got, _ := r.api.GetActor(context.Background(), ateapi.RefOf(a.GetMetadata()))
		return got.GetStatus().GetState()
	}
	if state(quiet) != ateapi.ActorStateSuspended {
		t.Errorf("a quiet --task run of a profile with idle_suspend_tasks: true was not suspended")
	}
	if state(asking) != ateapi.ActorStateRunning {
		t.Errorf("a --task run with a pending ask was suspended")
	}
	if state(other) != ateapi.ActorStateRunning {
		t.Errorf("a --task run of a profile without the key was suspended")
	}
}
