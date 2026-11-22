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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// GAP-0430: a launcher actor that is suspended and resumed between passes
// (kubectl ate suspend / resume) leaves one inventory record per
// transition with the same actor UID, and the resume gets its re-check
// record although the pass never saw RESUMING.
func TestGAP0430SuspendResumeLeaveInventoryAndRecheck(t *testing.T) {
	r := newRig(t, nil)
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	uid := a.GetMetadata().GetUid()
	r.pass()
	if err := r.api.SetState(ref, ateapi.ActorStateSuspended); err != nil {
		t.Fatal(err)
	}
	r.pass()
	if err := r.api.SetState(ref, ateapi.ActorStateRunning); err != nil {
		t.Fatal(err)
	}
	r.pass()
	r.pass() // nothing changed: no record

	var msgs []string
	for _, ev := range r.sink.Events(controller.EventInventory) {
		if ev.ActorUID != uid {
			t.Fatalf("inventory record for another actor: %+v", ev)
		}
		msgs = append(msgs, ev.Message)
	}
	want := []string{"actor seen", "actor suspended", "actor resumed"}
	if len(msgs) != len(want) {
		t.Fatalf("inventory = %q, want %q", msgs, want)
	}
	for i := range want {
		if msgs[i] != want[i] {
			t.Fatalf("inventory = %q, want %q", msgs, want)
		}
	}
	rc := r.sink.Events(controller.EventResumeRecheck)
	if len(rc) != 1 || rc[0].ActorUID != uid {
		t.Fatalf("resume re-check records = %+v, want one for the actor", rc)
	}
	// A second suspend and resume is a new generation: one more of each.
	_ = r.api.SetState(ref, ateapi.ActorStateSuspended)
	r.pass()
	_ = r.api.SetState(ref, ateapi.ActorStateRunning)
	r.pass()
	if n, m := len(r.sink.Events(controller.EventInventory)), len(r.sink.Events(controller.EventResumeRecheck)); n != 5 || m != 2 {
		t.Fatalf("after a second cycle: %d inventory, %d re-check records; want 5 and 2", n, m)
	}
}
