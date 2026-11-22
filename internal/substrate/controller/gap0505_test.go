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
	"errors"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/render"
	"github.com/defenseclaw/defenseclaw/internal/substrate/setup"
)

// slotReader is the egress callout slot as the cluster shows it.
type slotReader struct {
	mu    sync.Mutex
	slot  setup.CalloutSlot
	err   error
	reads int
}

func (s *slotReader) ReadCalloutSlot(context.Context) (setup.CalloutSlot, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.reads++
	return s.slot, s.err
}

func (s *slotReader) set(slot setup.CalloutSlot, err error) {
	s.mu.Lock()
	s.slot, s.err = slot, err
	s.mu.Unlock()
}

var (
	ourSlot   = setup.CalloutSlot{Holder: "dc/defenseclaw-callout:9443", Ours: true}
	otherSlot = setup.CalloutSlot{Holder: "default/other-callout:9443"}
)

// next moves past the slot read interval and runs a pass.
func (r *rig) next() {
	r.t.Helper()
	r.clk.Add(6 * time.Second)
	r.pass()
}

func (r *rig) denyOnly() *ateapi.EgressPolicy {
	r.t.Helper()
	deny, err := render.DenyOnly(controller.SettingsFromConfig(r.cfg))
	if err != nil {
		r.t.Fatal(err)
	}
	return deny
}

// GAP-0505 (J32 ours-then-other): an ate-setup deploy that names another
// callout replaced DefenseClaw's, and the actors' policies still allowed the
// hosts only the DefenseClaw callout refused (example.com: 200 instead of
// 403 ask_denied), with no record anywhere. At base the controller has no
// slot check at all. Now the replacement is one alert, the fail mode
// (closed by default) gives every managed actor only the DefenseClaw rule,
// and the full policy comes back with the DefenseClaw callout.
func TestCalloutReplacedFailsClosedGAP0505(t *testing.T) {
	r := newRig(t, nil)
	slots := &slotReader{slot: ourSlot}
	r.ctl.SetCallout(slots)
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	full := r.want(ref)
	if !render.Equal(r.api.Policy(ref), full) {
		t.Fatal("the DefenseClaw callout holds the slot: the actor must get its full policy")
	}
	if n := len(r.sink.Events(controller.EventCalloutReplaced, controller.EventCalloutRestored)); n != 0 {
		t.Fatalf("callout events with the DefenseClaw callout registered: %d", n)
	}

	slots.set(otherSlot, nil)
	r.next()
	if !render.Equal(r.api.Policy(ref), r.denyOnly()) {
		t.Fatalf("another callout holds the slot, fail closed: policy = %v", r.api.Policy(ref).GetRules())
	}
	ev := r.sink.Events(controller.EventCalloutReplaced)
	if len(ev) != 1 || ev[0].Severity != controller.SeverityAlert || ev[0].Detail["holder"] != otherSlot.Holder ||
		ev[0].Detail["failure_mode"] != controller.CalloutFailClosed || !strings.Contains(ev[0].Message, otherSlot.Holder) {
		t.Fatalf("callout_replaced events = %+v", ev)
	}
	var why bool
	for _, w := range r.sink.Events(controller.EventWarning) {
		if w.Actor == "alice-1" && strings.Contains(w.Message, "callout_replaced") && strings.Contains(w.Message, otherSlot.Holder) {
			why = true
		}
	}
	if !why {
		t.Fatalf("no actor record names the callout problem: %+v", r.sink.Events(controller.EventWarning))
	}

	// Bounded: more passes, no more alerts, the actor stays deny-only.
	r.next()
	r.next()
	if n := len(r.sink.Events(controller.EventCalloutReplaced)); n != 1 {
		t.Fatalf("callout_replaced repeats: %d", n)
	}
	if !render.Equal(r.api.Policy(ref), r.denyOnly()) {
		t.Fatal("the deny-only policy did not hold")
	}

	// Back: the full policy and one restored event.
	slots.set(ourSlot, nil)
	r.next()
	if !render.Equal(r.api.Policy(ref), full) {
		t.Fatalf("the DefenseClaw callout is back: policy = %v", r.api.Policy(ref).GetRules())
	}
	if n := len(r.sink.Events(controller.EventCalloutRestored)); n != 1 {
		t.Fatalf("callout_restored events = %d", n)
	}
	// DefenseClaw's own writes are never counted as foreign changes.
	if n := len(r.sink.Events(controller.EventForeignRule, controller.EventPolicyConflict)); n != 0 {
		t.Fatalf("own writes counted as foreign: %d", n)
	}
}

// The create path (the gateway's EnsurePolicy) writes the same deny-only
// policy, so it and the controller never undo each other.
func TestCalloutReplacedCreatePathGAP0505(t *testing.T) {
	r := newRig(t, nil)
	slots := &slotReader{slot: otherSlot}
	r.ctl.SetCallout(slots)
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateSuspended, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	if err := r.ctl.EnsurePolicy(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	if !render.Equal(r.api.Policy(ref), r.denyOnly()) {
		t.Fatalf("create path: policy = %v", r.api.Policy(ref).GetRules())
	}
	writes := len(r.api.PolicyWrites())
	r.pass()
	if n := len(r.api.PolicyWrites()); n != writes {
		t.Fatalf("the pass rewrote the create path's policy: %d writes", n-writes)
	}
	// No callout at all is the same as another one.
	slots.set(setup.CalloutSlot{}, nil)
	r.next()
	ev := r.sink.Events(controller.EventCalloutReplaced)
	if len(ev) != 2 || !strings.Contains(ev[1].Message, "no egress callout is registered") {
		t.Fatalf("callout_replaced events = %+v", ev)
	}
	if !render.Equal(r.api.Policy(ref), r.denyOnly()) {
		t.Fatal("no callout: not deny-only")
	}
}

// Fail open (OSS, substrate.extproc.failure_mode: open): interactive actors
// keep their policies and the alert says what does not run; unattended
// actors are always closed (D8).
func TestCalloutReplacedFailOpenGAP0505(t *testing.T) {
	r := newRig(t, func(_ *config.Config, o *controller.Options) { o.CalloutMode = controller.CalloutFailOpen })
	slots := &slotReader{slot: ourSlot}
	r.ctl.SetCallout(slots)
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	task := r.actor("eng-web", "task-1", ateapi.ActorStateRunning, "")
	tref := ateapi.RefOf(task.GetMetadata())
	if err := r.reg.Put(context.Background(), controller.Registration{Atespace: "eng-web", Name: "task-1", UID: task.GetMetadata().GetUid(),
		Person: "sub-alice", Profile: "eng", Task: true, Source: controller.SourceLauncher}); err != nil {
		t.Fatal(err)
	}
	r.pass()
	full := r.want(ref)
	slots.set(otherSlot, nil)
	r.next()
	if !render.Equal(r.api.Policy(ref), full) {
		t.Fatalf("fail open: the interactive actor lost its policy: %v", r.api.Policy(ref).GetRules())
	}
	if !render.Equal(r.api.Policy(tref), r.denyOnly()) {
		t.Fatalf("an unattended actor is always closed: %v", r.api.Policy(tref).GetRules())
	}
	ev := r.sink.Events(controller.EventCalloutReplaced)
	if len(ev) != 1 || ev[0].Severity != controller.SeverityAlert || ev[0].Detail["failure_mode"] != controller.CalloutFailOpen ||
		!strings.Contains(ev[0].Message, "URL rules") {
		t.Fatalf("callout_replaced events = %+v", ev)
	}
}

// substrate.extproc.enabled: false is an install without the DefenseClaw
// callout on purpose: recorded, policies unchanged.
func TestCalloutReplacedExtprocOffGAP0505(t *testing.T) {
	r := newRig(t, func(_ *config.Config, o *controller.Options) { o.CalloutMode = controller.CalloutOff })
	r.ctl.SetCallout(&slotReader{slot: otherSlot})
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	if !render.Equal(r.api.Policy(ref), r.want(ref)) {
		t.Fatal("extproc off: the policy changed")
	}
	if ev := r.sink.Events(controller.EventCalloutReplaced); len(ev) != 1 || ev[0].Severity != controller.SeverityWarn {
		t.Fatalf("callout_replaced events = %+v", ev)
	}
}

// A slot that cannot be read is not "no callout": nothing changes, one
// warning; a replacement already seen stays in force through read errors,
// and the status says unknown.
func TestCalloutUnreadableKeepsLastStateGAP0505(t *testing.T) {
	r := newRig(t, nil)
	slots := &slotReader{err: errors.New("kubernetes API 403: forbidden")}
	r.ctl.SetCallout(slots)
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	r.next()
	if !render.Equal(r.api.Policy(ref), r.want(ref)) {
		t.Fatal("an unreadable slot changed the policy")
	}
	var warned int
	for _, w := range r.sink.Events(controller.EventWarning) {
		if strings.Contains(w.Message, "cannot read which egress callout") {
			warned++
		}
	}
	if warned != 1 {
		t.Fatalf("read warnings = %d", warned)
	}
	slots.set(otherSlot, nil)
	r.next()
	slots.set(setup.CalloutSlot{}, errors.New("timeout"))
	r.next()
	if !render.Equal(r.api.Policy(ref), r.denyOnly()) {
		t.Fatal("a read error lifted the fail-closed policy")
	}
	// The status of a slot that cannot be read now is unknown (GAP-0505
	// RBAC ruling), while the replacement already seen stays in force.
	st, ok := r.ctl.CalloutStatus(context.Background())
	if !ok || st.Known || st.Ours || st.Holder != "" || st.Err == "" || st.FailMode != controller.CalloutFailClosed {
		t.Fatalf("status = %+v, %v", st, ok)
	}
	// Reads are bounded: one per interval, not one per call.
	before := slots.reads
	for range 5 {
		_, _ = r.ctl.CalloutStatus(context.Background())
	}
	if slots.reads != before {
		t.Fatalf("%d extra reads inside the interval", slots.reads-before)
	}
}

func TestCalloutFailModeFromConfigGAP0505(t *testing.T) {
	off := false
	for _, tc := range []struct {
		mode, failure string
		enabled       *bool
		want          string
	}{
		{"", "", nil, controller.CalloutFailClosed},
		{"", "open", nil, controller.CalloutFailOpen},
		{"", "OPEN", nil, controller.CalloutFailOpen},
		{"managed_enterprise", "open", nil, controller.CalloutFailClosed},
		{"", "closed", &off, controller.CalloutOff},
	} {
		cfg := &config.Config{DeploymentMode: tc.mode}
		cfg.Substrate.Extproc.FailureMode, cfg.Substrate.Extproc.Enabled = tc.failure, tc.enabled
		if got := controller.CalloutFailModeFromConfig(cfg); got != tc.want {
			t.Errorf("%+v: %s, want %s", tc, got, tc.want)
		}
	}
}
