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
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest/templatecli"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

func TestSandboxClassLabelMatchesTemplateBuild(t *testing.T) {
	if controller.SandboxClassLabel != templatecli.ClassLabel {
		t.Fatalf("controller reads %q, template build writes %q", controller.SandboxClassLabel, templatecli.ClassLabel)
	}
}

func withSandbox(sb *config.SandboxAdminConfig) func(*config.Config, *controller.Options) {
	return func(cfg *config.Config, _ *controller.Options) {
		cfg.Guardrail.Profiles["eng"] = config.GuardrailProfile{Sandbox: sb}
	}
}

func refusedWith(r *rig, want string) bool {
	for _, ev := range r.sink.Events(controller.EventProfileRefused) {
		if strings.Contains(ev.Message, want) {
			return true
		}
	}
	return false
}

// runtimes without substrate: the profile's actors get no policy.
func TestRuntimesWithoutSubstrateRefuseTheActor(t *testing.T) {
	r := newRig(t, withSandbox(&config.SandboxAdminConfig{Runtimes: []string{config.SandboxRuntimeOpenShell}}))
	a := r.actor("eng-web", "a", ateapi.ActorStateSuspended, "sub-a")
	r.pass()
	if r.api.Policy(ateapi.RefOf(a.GetMetadata())) != nil {
		t.Fatal("an actor of an openshell-only profile got a policy")
	}
	if !refusedWith(r, "runs agents only on openshell, not on Agent Substrate (runtimes)") {
		t.Fatalf("refusal events: %+v", r.sink.Events(controller.EventProfileRefused))
	}
	ok := newRig(t, withSandbox(&config.SandboxAdminConfig{Runtimes: []string{config.SandboxRuntimeSubstrate}}))
	b := ok.actor("eng-web", "b", ateapi.ActorStateSuspended, "sub-a")
	ok.pass()
	if ok.api.Policy(ateapi.RefOf(b.GetMetadata())) == nil {
		t.Fatal("runtimes [substrate] refused the actor")
	}
}

// sandbox_class microvm: an actor on a gVisor (or unlabelled) template gets
// no policy; one on a microvm template, or with a microvm worker selector,
// does.
func TestSandboxClassMicroVMRefusesAGVisorActor(t *testing.T) {
	r := newRig(t, withSandbox(&config.SandboxAdminConfig{SandboxClass: config.SubstrateSandboxMicroVM}))
	plain := r.actor("eng-web", "plain", ateapi.ActorStateSuspended, "sub-a")
	r.api.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "vm"},
		WorkerSelector: &ateapi.Selector{MatchLabels: map[string]string{controller.SandboxClassLabel: "microvm"}}})
	vm := r.api.PutActor(&ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "vm"}, ActorTemplate: ateapi.Ref("eng-web", "vm"),
		Status: &ateapi.ActorStatus{State: ateapi.ActorStateSuspended}})
	sel := r.api.PutActor(&ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "sel"}, ActorTemplate: ateapi.Ref("eng-web", "claude"),
		WorkerSelector: &ateapi.Selector{MatchLabels: map[string]string{controller.SandboxClassLabel: "microvm"}},
		Status:         &ateapi.ActorStatus{State: ateapi.ActorStateSuspended}})
	for _, a := range []*ateapi.Actor{vm, sel} {
		if err := r.reg.Put(context.Background(), controller.Registration{Atespace: "eng-web", Name: a.GetMetadata().GetName(),
			UID: a.GetMetadata().GetUid(), Person: "sub-b", Profile: "eng", Source: controller.SourceLauncher}); err != nil {
			t.Fatal(err)
		}
	}
	r.pass()
	if r.api.Policy(ateapi.RefOf(plain.GetMetadata())) != nil {
		t.Fatal("a gVisor actor got a policy under sandbox_class microvm")
	}
	if !refusedWith(r, "requires sandbox_class microvm; the actor's template runs on gvisor") {
		t.Fatalf("refusal events: %+v", r.sink.Events(controller.EventProfileRefused))
	}
	for _, a := range []*ateapi.Actor{vm, sel} {
		if r.api.Policy(ateapi.RefOf(a.GetMetadata())) == nil {
			t.Fatalf("%s runs on microvm and got no policy", a.GetMetadata().GetName())
		}
	}
}

// idle_suspend_after: the profile's delay replaces the controller's, and
// turns idle suspend on where the cluster has it off.
func TestProfileIdleSuspendAfter(t *testing.T) {
	r := newRig(t, func(cfg *config.Config, o *controller.Options) {
		withSandbox(&config.SandboxAdminConfig{IdleSuspendAfter: "5m"})(cfg, o)
		o.IdleSuspendAfter = 0
	})
	a := r.actor("eng-web", "a", ateapi.ActorStateRunning, "sub-a")
	r.pass()
	r.clk.Add(6 * time.Minute)
	r.act.SetCPU(a.GetMetadata().GetUid(), 0.01, r.clk.Now())
	r.pass()
	got, _ := r.api.GetActor(context.Background(), ateapi.RefOf(a.GetMetadata()))
	if got.GetStatus().GetState() != ateapi.ActorStateSuspended {
		t.Fatal("the profile's 5m idle_suspend_after did not suspend an idle actor")
	}
	if evs := r.sink.Events(controller.EventIdleSuspend); len(evs) != 1 || !strings.Contains(evs[0].Message, "5m0s") {
		t.Fatalf("idle events: %+v", evs)
	}
}
