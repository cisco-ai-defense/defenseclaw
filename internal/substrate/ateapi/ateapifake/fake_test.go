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

package ateapifake

import (
	"context"
	"fmt"
	"testing"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
)

func TestPolicyGuards(t *testing.T) {
	f := New()
	ctx := context.Background()
	f.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "a", Name: "tmpl"}})
	act := f.PutActor(&ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "a", Name: "x"}, ActorTemplate: ateapi.Ref("a", "tmpl")})
	ref := ateapi.RefOf(act.GetMetadata())
	if _, err := f.GetActorEgressPolicy(ctx, ref); !ateapi.IsNotFound(err) {
		t.Fatalf("no policy yet: %v", err)
	}
	p, err := f.CreateActorEgressPolicy(ctx, ref, &ateapi.EgressPolicy{Rules: []*ateapi.EgressRule{{}}})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := f.CreateActorEgressPolicy(ctx, ref, &ateapi.EgressPolicy{}); !ateapi.IsAlreadyExists(err) {
		t.Fatalf("second create: %v", err)
	}
	stale := p
	p.Rules = nil
	p2, err := f.UpdateActorEgressPolicy(ctx, ref, p)
	if err != nil || p2.GetMetadata().GetVersion() != 2 {
		t.Fatalf("update: %v %v", p2, err)
	}
	if _, err := f.UpdateActorEgressPolicy(ctx, ref, stale); !ateapi.IsConflict(err) {
		t.Fatalf("stale update: %v", err)
	}
	if err := f.ForeignSetPolicy(ref, []*ateapi.EgressRule{{}, {}}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.UpdateActorEgressPolicy(ctx, ref, p2); !ateapi.IsConflict(err) {
		t.Fatalf("update after a foreign write: %v", err)
	}
	if _, err := f.CreateActorEgressPolicy(ctx, ref, &ateapi.EgressPolicy{Metadata: &ateapi.ResourceMetadata{Name: "other"}}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("wrong name: %v", err)
	}
	w := f.PolicyWrites()
	if len(w) != 3 || w[0].Method != "create" || w[2].Method != "foreign" || w[0].ActorState != ateapi.ActorStateSuspended {
		t.Fatalf("writes = %+v", w)
	}
}

func TestForkAndRecreate(t *testing.T) {
	f := New()
	f.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "a", Name: "tmpl"}})
	parent := f.PutActor(&ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "a", Name: "p"}, ActorTemplate: ateapi.Ref("a", "tmpl")})
	pref := ateapi.RefOf(parent.GetMetadata())
	_ = f.SetState(pref, ateapi.ActorStateRunning)
	if _, err := f.Fork(pref, "t1", "child"); status.Code(err) != codes.FailedPrecondition {
		t.Fatalf("fork of a running actor: %v", err)
	}
	if _, err := f.SuspendActor(context.Background(), pref); err != nil {
		t.Fatal(err)
	}
	child, err := f.Fork(pref, "t1", "child")
	if err != nil {
		t.Fatal(err)
	}
	if child.GetSourceTag().GetName() != "t1" || child.GetMetadata().GetUid() == parent.GetMetadata().GetUid() {
		t.Fatalf("child = %v", child)
	}
	tag, err := f.GetTag(context.Background(), child.GetSourceTag())
	if err != nil || tag.GetSourceActor().GetName() != "p" || tag.GetStatus().GetActorTemplateUid() == "" {
		t.Fatalf("tag = %v err = %v", tag, err)
	}
	re, err := f.Recreate(pref)
	if err != nil || re.GetMetadata().GetUid() == parent.GetMetadata().GetUid() {
		t.Fatalf("recreate = %v %v", re, err)
	}
}

func TestPagination(t *testing.T) {
	f := New()
	f.PageSize = 4
	for i := range 10 {
		f.PutActor(&ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "a", Name: fmt.Sprintf("x%02d", i)}})
	}
	f.PutActor(&ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "b", Name: "y"}})
	all, err := ateapi.AllActors(context.Background(), f, "a", 0)
	if err != nil || len(all) != 10 {
		t.Fatalf("a: %d %v", len(all), err)
	}
	every, _ := ateapi.AllActors(context.Background(), f, "", 3)
	if len(every) != 11 {
		t.Fatalf("all atespaces: %d", len(every))
	}
	if f.Calls("ListActors") != 3+4 {
		t.Fatalf("ListActors calls = %d", f.Calls("ListActors"))
	}
	if _, err := f.ListActors(context.Background(), "a", ateapi.ListOptions{PageToken: "bogus"}); status.Code(err) != codes.InvalidArgument {
		t.Fatalf("bad token: %v", err)
	}
	spaces, _ := ateapi.AllAtespaces(context.Background(), f, 0)
	if len(spaces) != 2 {
		t.Fatalf("atespaces = %d", len(spaces))
	}
}

func TestErrInjectionAndClose(t *testing.T) {
	f := New()
	f.Err = func(method, key string) error {
		if method == "GetActor" {
			return status.Error(codes.Unavailable, "down")
		}
		return nil
	}
	if _, err := f.GetActor(context.Background(), ateapi.Ref("a", "b")); !ateapi.IsRetryable(err) {
		t.Fatalf("err = %v", err)
	}
	_ = f.Close()
	if _, err := f.ListAtespaces(context.Background(), ateapi.ListOptions{}); status.Code(err) != codes.Canceled {
		t.Fatalf("after close: %v", err)
	}
}

func TestFakeCreateResumeDelete(t *testing.T) {
	f := New()
	ctx := context.Background()
	f.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "cc"}})
	mk := func(name, tmpl string) (*ateapi.Actor, error) {
		return f.CreateActor(ctx, &ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: name},
			ActorTemplate: ateapi.Ref("eng-web", tmpl)})
	}
	a, err := mk("a1", "cc")
	if err != nil || a.GetStatus().GetState() != ateapi.ActorStateSuspended || a.GetMetadata().GetUid() == "" {
		t.Fatalf("create %v %v", a, err)
	}
	if _, err := mk("a1", "cc"); !ateapi.IsAlreadyExists(err) {
		t.Fatalf("duplicate %v", err)
	}
	if _, err := mk("a2", "nope"); !ateapi.IsNotFound(err) {
		t.Fatalf("missing template %v", err)
	}
	ref := ateapi.Ref("eng-web", "a1")
	if got, resumed, err := f.ResumeActor(ctx, ref); err != nil || !resumed || got.GetStatus().GetState() != ateapi.ActorStateRunning {
		t.Fatalf("resume %v %v %v", got, resumed, err)
	}
	if _, resumed, _ := f.ResumeActor(ctx, ref); resumed {
		t.Fatal("second resume resumed")
	}
	if _, err := f.DeleteActor(ctx, ref, &ateapi.DeleteOptions{Uid: "other"}); !ateapi.IsConflict(err) {
		t.Fatalf("uid precondition %v", err)
	}
	if _, err := f.DeleteActor(ctx, ref, &ateapi.DeleteOptions{Uid: a.GetMetadata().GetUid()}); err != nil {
		t.Fatal(err)
	}
	if _, err := f.GetActor(ctx, ref); !ateapi.IsNotFound(err) {
		t.Fatalf("after delete %v", err)
	}
}
