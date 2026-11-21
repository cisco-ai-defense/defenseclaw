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

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// GAP-0428: an actor made with kubectl ate from an unattested template in a
// launcher atespace is foreign and gets no network; shadow AI must also name
// the unattested template (template_unverified with its digest and the
// unattested-template signal), once, not only foreign_actor.
func TestGAP0428ForeignActorNamesUnattestedTemplate(t *testing.T) {
	r := newRig(t, nil)
	r.att.Set("eng-web/claude", controller.Attestation{Reason: "no attestation for the digest", Digest: "sha256:48365ae2"})
	a := r.actor("eng-web", "sub-j18-raw1", ateapi.ActorStateSuspended, "")
	r.pass()
	r.clk.Add(16 * time.Second)
	r.pass()
	r.pass()
	if r.api.Policy(ateapi.RefOf(a.GetMetadata())) != nil {
		t.Fatal("a foreign actor got a policy")
	}
	if ev := r.sink.Events(controller.EventForeignActor); len(ev) != 1 {
		t.Fatalf("foreign_actor records = %+v", ev)
	}
	tu := r.sink.Events(controller.EventTemplateUnverified)
	if len(tu) != 1 {
		t.Fatalf("template_unverified records = %+v, want one", tu)
	}
	ev := tu[0]
	if ev.Signal == nil || ev.Signal.SignalID != controller.SignalUnattestedTemplate || ev.Signal.Version != "sha256:48365ae2" ||
		ev.Detail["template"] != "eng-web/claude" || !strings.Contains(ev.Message, "not attested") {
		t.Fatalf("template_unverified = %+v", ev)
	}

	// An attested template behind a foreign actor is only foreign.
	r2 := newRig(t, nil)
	r2.actor("eng-web", "intruder", ateapi.ActorStateSuspended, "")
	r2.pass()
	r2.clk.Add(16 * time.Second)
	r2.pass()
	if n := len(r2.sink.Events(controller.EventTemplateUnverified)); n != 0 {
		t.Fatalf("an attested template was reported unverified (%d)", n)
	}
}

// GAP-0495: the record was one-shot. A template read error on the pass that
// first called the actor foreign meant it was never sent. It is sent on the
// first pass whose read succeeds, and only once.
func TestGAP0495ForeignTemplateRecordRetriesAfterAReadError(t *testing.T) {
	r := newRig(t, nil)
	r.att.Set("eng-web/claude", controller.Attestation{Reason: "no attestation for the digest", Digest: "sha256:48365ae2"})
	r.actor("eng-web", "sub-j18-raw2", ateapi.ActorStateSuspended, "")
	r.pass()
	r.clk.Add(16 * time.Second)
	fail := true
	r.api.Err = func(method, key string) error {
		if fail && method == "GetActorTemplate" {
			return status.Error(codes.Unavailable, "api server restarting")
		}
		return nil
	}
	_ = r.ctl.Reconcile(context.Background())
	if n := len(r.sink.Events(controller.EventTemplateUnverified)); n != 0 {
		t.Fatalf("a record was sent without a template read: %d", n)
	}
	fail = false
	r.clk.Add(time.Minute)
	r.pass()
	r.pass()
	if tu := r.sink.Events(controller.EventTemplateUnverified); len(tu) != 1 || tu[0].Detail["foreign_actor"] != true {
		t.Fatalf("template_unverified after the read recovered = %+v, want one", tu)
	}
}

// GAP-0531: a foreign actor whose template is gone (NotFound) is not read
// again every pass.
func TestGAP0531ForeignActorMissingTemplateIsNotReReadEveryPass(t *testing.T) {
	r := newRig(t, nil)
	r.actor("eng-web", "orphan", ateapi.ActorStateSuspended, "")
	r.api.Err = func(method, key string) error {
		if method == "GetActorTemplate" {
			return status.Error(codes.NotFound, "actor template eng-web/claude not found")
		}
		return nil
	}
	r.pass()
	r.clk.Add(16 * time.Second)
	_ = r.ctl.Reconcile(context.Background())
	first := r.api.Calls("GetActorTemplate")
	for range 5 {
		r.clk.Add(time.Minute)
		_ = r.ctl.Reconcile(context.Background())
	}
	if n := r.api.Calls("GetActorTemplate"); n != first {
		t.Fatalf("template reads went from %d to %d over 5 passes, want no more", first, n)
	}
}
