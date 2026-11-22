// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// GAP-0425 (PLAN E17): DefenseClaw makes no forks, so a fork found in a
// launcher atespace (kubectl ate as a cluster administrator) was made
// outside DefenseClaw: sandbox.fork says forked_by unknown with no person,
// and the fork is refused like an actor created there outside DefenseClaw
// (foreign_actor, no policy).
func TestGAP0425ForkMadeOutsideDefenseClawIsNotItsOwn(t *testing.T) {
	r := newRig(t, nil)
	parent := r.actor("eng-web", "alice-1", ateapi.ActorStateSuspended, "sub-alice")
	r.pass()
	child, err := r.api.Fork(ateapi.RefOf(parent.GetMetadata()), "t1", "alice-1-fork")
	if err != nil {
		t.Fatal(err)
	}
	cref, uid := ateapi.RefOf(child.GetMetadata()), child.GetMetadata().GetUid()
	r.pass()
	r.pass()
	fk := r.sink.Events(controller.EventFork)
	if len(fk) != 1 || fk[0].ActorUID != uid || fk[0].Detail["forked_by"] != controller.ForkedByUnknown || fk[0].Detail["person_bound"] != false {
		t.Fatalf("fork events = %+v", fk)
	}
	if r.api.Policy(cref) != nil {
		t.Fatal("a fork made outside DefenseClaw in a launcher atespace got a policy")
	}
	fa := r.sink.Events(controller.EventForeignActor)
	if len(fa) != 1 || fa[0].ActorUID != uid || fa[0].Signal == nil || fa[0].Signal.SignalID != controller.SignalForeignActor {
		t.Fatalf("foreign_actor events = %+v", fa)
	}
	if reg, ok, _ := r.reg.Get(context.Background(), "eng-web", uid); ok && reg.Person != "" {
		t.Fatalf("the fork is bound to its parent's person: %+v", reg)
	}
}
