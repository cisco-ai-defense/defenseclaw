// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	pb "github.com/defenseclaw/defenseclaw/third_party/substrate/api/ateapi/v1"
)

// GAP-0386: the class Substrate recorded for an actor's worker assignment
// decides sandbox_class, whatever labels its template's selector carries:
// an actor running on a microVM worker keeps its policy, one on a gVisor
// worker under a microvm-labelled selector does not.
func TestSandboxClassReadsTheAssignedRuntime(t *testing.T) {
	r := newRig(t, withSandbox(&config.SandboxAdminConfig{SandboxClass: config.SubstrateSandboxMicroVM}))
	r.actor("eng-web", "seed", ateapi.ActorStateSuspended, "") // the unlabelled claude template
	put := func(name, ran string, sel map[string]string) *ateapi.Actor {
		a := &ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: name}, ActorTemplate: ateapi.Ref("eng-web", "claude"),
			Status: &ateapi.ActorStatus{State: ateapi.ActorStateRunning, WorkerAssignment: &ateapi.WorkerAssignment{
				SandboxRuntime: &pb.ActorSandboxRuntime{SandboxClass: ran}}}}
		if sel != nil {
			a.WorkerSelector = &ateapi.Selector{MatchLabels: sel}
		}
		a = r.api.PutActor(a)
		if err := r.reg.Put(context.Background(), controller.Registration{Atespace: "eng-web", Name: name,
			UID: a.GetMetadata().GetUid(), Person: "sub-a", Profile: "eng", Source: controller.SourceLauncher}); err != nil {
			t.Fatal(err)
		}
		return a
	}
	onMV := put("on-mv", "microvm", nil)
	onGV := put("on-gv", "gvisor", map[string]string{controller.SandboxClassLabel: "microvm"})
	r.pass()
	if r.api.Policy(ateapi.RefOf(onMV.GetMetadata())) == nil {
		t.Fatalf("an actor running on a microVM worker got no policy: %+v", r.sink.Events(controller.EventProfileRefused))
	}
	if r.api.Policy(ateapi.RefOf(onGV.GetMetadata())) != nil {
		t.Fatal("an actor running on a gVisor worker got a policy under sandbox_class microvm")
	}
	if !refusedWith(r, "requires sandbox_class microvm; the actor runs on gvisor") {
		t.Fatalf("refusal events: %+v", r.sink.Events(controller.EventProfileRefused))
	}
}
