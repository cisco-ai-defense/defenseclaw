// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// GAP-0428: an actor created outside DefenseClaw in a launcher atespace
// from an unattested template is a foreign actor, and its template is
// shadow AI too: template_unverified names the template and its digest,
// once. The actor keeps no policy. An attested template adds no event.
func TestGAP0428ForeignActorReportsItsUnattestedTemplate(t *testing.T) {
	r := newRig(t, nil)
	r.api.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "rogue"}})
	r.att.Set("eng-web/rogue", controller.Attestation{Digest: "sha256:ab12cd3400000000000000000000000000000000000000000000000000000000", Reason: "no DefenseClaw attestation"})
	rogue := r.api.PutActor(&ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "rogue-1"}, ActorTemplate: ateapi.Ref("eng-web", "rogue"),
		Status: &ateapi.ActorStatus{State: ateapi.ActorStateSuspended}})
	plain := r.actor("eng-web", "intruder", ateapi.ActorStateSuspended, "") // attested template
	r.clk.Add(16 * time.Second)                                             // past the launcher registration grace
	r.pass()
	r.pass()
	if r.api.Policy(ateapi.RefOf(rogue.GetMetadata())) != nil {
		t.Fatal("a foreign actor from an unattested template got a policy")
	}
	if n := len(r.sink.Events(controller.EventForeignActor)); n != 2 {
		t.Fatalf("foreign_actor events = %d, want 2", n)
	}
	tu := r.sink.Events(controller.EventTemplateUnverified)
	if len(tu) != 1 || tu[0].ActorUID != rogue.GetMetadata().GetUid() || tu[0].Detail["template"] != "eng-web/rogue" ||
		tu[0].Signal == nil || tu[0].Signal.SignalID != controller.SignalUnattestedTemplate || tu[0].Signal.Version == "" {
		t.Fatalf("template_unverified events = %+v", tu)
	}
	for _, ev := range tu {
		if ev.ActorUID == plain.GetMetadata().GetUid() {
			t.Fatal("an attested template was reported")
		}
	}
}
