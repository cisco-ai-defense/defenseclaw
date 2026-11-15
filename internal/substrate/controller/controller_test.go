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
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller/controllerfake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/render"
)

type clock struct {
	mu sync.Mutex
	t  time.Time
}

func (c *clock) Now() time.Time      { c.mu.Lock(); defer c.mu.Unlock(); return c.t }
func (c *clock) Add(d time.Duration) { c.mu.Lock(); c.t = c.t.Add(d); c.mu.Unlock() }

type rig struct {
	t     *testing.T
	api   *ateapifake.Fake
	att   *controllerfake.Attestor
	act   *controllerfake.Activity
	sink  *controllerfake.Sink
	reg   *controller.MemoryRegistry
	clk   *clock
	cfg   *config.Config
	ctl   *controller.Controller
	tmpls map[string]bool
}

func newRig(t *testing.T, mutate func(*config.Config, *controller.Options)) *rig {
	t.Helper()
	cfg := &config.Config{}
	cfg.Substrate = config.SubstrateConfig{
		Enabled:           true,
		LauncherAtespaces: map[string][]string{"eng": {"eng-web"}},
		Egress:            config.SubstrateEgressConfig{Allow: []string{"github.com"}, EcosystemPacks: []string{"pypi"}},
	}
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"eng": {}, "ci": {}}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "ci", Match: config.ProfileMatch{Substrate: &config.ProfileMatchSubstrate{Atespaces: []string{"ci-runs", "eng-*"}}}},
		// Host selectors never apply to actors.
		{Profile: "eng", Match: config.ProfileMatch{Users: []string{"alice"}}},
	}
	r := &rig{t: t, api: ateapifake.New(), att: &controllerfake.Attestor{Default: controller.Attestation{Attested: true, KitVersion: "1.0.10"}},
		act: &controllerfake.Activity{}, sink: &controllerfake.Sink{}, reg: controller.NewMemoryRegistry(),
		clk: &clock{t: time.Date(2026, 11, 12, 20, 0, 0, 0, time.UTC)}, cfg: cfg, tmpls: map[string]bool{}}
	r.api.Now = r.clk.Now
	o := controller.Options{
		Client: r.api, Attestor: r.att, Activity: r.act, CPU: r.act, Registry: r.reg, Sink: r.sink,
		Resolver:           &controller.ConfigResolver{Config: cfg},
		RequireAttestation: true, KitVersion: "1.0.10", IdleSuspendAfter: 30 * time.Minute, Now: r.clk.Now,
	}
	if mutate != nil {
		mutate(cfg, &o)
	}
	o.Settings = controller.SettingsFromConfig(cfg)
	o.Secrets = controller.SecretsFromConfig(cfg)
	o.LauncherAtespaces = controller.LauncherSet(cfg)
	ctl, err := controller.New(o)
	if err != nil {
		t.Fatal(err)
	}
	r.ctl = ctl
	return r
}

func (r *rig) actor(ns, name string, state ateapi.ActorState, person string) *ateapi.Actor {
	r.t.Helper()
	if !r.tmpls[ns] {
		r.api.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: ns, Name: "claude"}})
		r.tmpls[ns] = true
	}
	a := r.api.PutActor(&ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: ns, Name: name}, ActorTemplate: ateapi.Ref(ns, "claude"),
		Status: &ateapi.ActorStatus{State: state}})
	if person != "" {
		if err := r.reg.Put(context.Background(), controller.Registration{Atespace: ns, Name: name, UID: a.GetMetadata().GetUid(),
			Person: person, Profile: "eng", Source: controller.SourceLauncher}); err != nil {
			r.t.Fatal(err)
		}
	}
	return a
}

func (r *rig) pass() {
	r.t.Helper()
	if err := r.ctl.Reconcile(context.Background()); err != nil {
		r.t.Fatalf("reconcile: %v", err)
	}
}

func (r *rig) want(ref *ateapi.ObjectRef) *ateapi.EgressPolicy {
	r.t.Helper()
	reg, _, _ := r.reg.Get(context.Background(), ref.GetAtespace(), mustUID(r, ref))
	res, err := render.EgressPolicy(render.Input{Settings: controller.SettingsFromConfig(r.cfg), Profile: render.Profile{Name: "eng"}, Person: reg.Person})
	if err != nil {
		r.t.Fatal(err)
	}
	return res.Policy
}

func mustUID(r *rig, ref *ateapi.ObjectRef) string {
	a, err := r.api.GetActor(context.Background(), ref)
	if err != nil {
		r.t.Fatal(err)
	}
	return a.GetMetadata().GetUid()
}

func TestPolicyWrittenBeforeFirstResume(t *testing.T) {
	r := newRig(t, nil)
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateSuspended, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	if err := r.ctl.EnsurePolicy(context.Background(), ref); err != nil {
		t.Fatal(err)
	}
	w := r.api.PolicyWrites()
	if len(w) != 1 || w[0].Method != "create" || w[0].ActorState != ateapi.ActorStateSuspended {
		t.Fatalf("writes = %+v", w)
	}
	if !render.Equal(r.api.Policy(ref), r.want(ref)) {
		t.Fatal("policy differs from the rendering")
	}
	// Resume: the next pass re-checks and does not rewrite.
	_ = r.api.SetState(ref, ateapi.ActorStateResuming)
	r.pass()
	if n := len(r.api.PolicyWrites()); n != 1 {
		t.Fatalf("rewrote on resume: %d writes", n)
	}
	if len(r.sink.Events(controller.EventResumeRecheck)) != 1 {
		t.Fatal("no resume re-check event")
	}
	// A policy deleted while suspended is restored on the next resume pass.
	_, _ = r.api.DeleteActorEgressPolicy(context.Background(), ref, nil)
	_ = r.api.SetState(ref, ateapi.ActorStateResuming)
	r.pass()
	if r.api.Policy(ref) == nil {
		t.Fatal("the policy was not restored before the resume finished")
	}
}

func TestUnattestedTemplateGetsNoNetwork(t *testing.T) {
	r := newRig(t, nil)
	r.att.Set("eng-web/claude", controller.Attestation{Reason: "no attestation for the digest", Digest: "sha256:abc"})
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateSuspended, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	_ = r.api.ForeignSetPolicy(ref, []*ateapi.EgressRule{{Https: &ateapi.HttpsRule{Hostnames: []string{"evil.example.com"}}}})
	err := r.ctl.EnsurePolicy(context.Background(), ref)
	if !errors.Is(err, controller.ErrRefused) {
		t.Fatalf("err = %v", err)
	}
	if r.api.Policy(ref) != nil {
		t.Fatal("an unattested template kept a policy")
	}
	ev := r.sink.Events(controller.EventTemplateUnverified)
	if len(ev) != 1 || ev[0].Signal == nil || ev[0].Signal.SignalID != controller.SignalUnattestedTemplate || ev[0].Signal.Category != "shadow_ai" {
		t.Fatalf("events = %+v", ev)
	}
	r.pass()
	if len(r.sink.Events(controller.EventTemplateUnverified)) != 1 {
		t.Fatal("the refusal event repeats every pass")
	}
}

func TestKitSkew(t *testing.T) {
	for _, tc := range []struct {
		ours, kit string
		ok        bool
	}{{"1.10.0", "1.10.2", true}, {"1.10.0", "1.9.9", true}, {"1.10.0", "1.8.0", false}, {"1.10.0", "2.10.0", false},
		{"1.10.0", "1.11.0", true}, {"dev", "0.1.0", true}, {"1.10.0", "garbage", false}} {
		if controller.KitAccepted(tc.ours, tc.kit) != tc.ok {
			t.Errorf("KitAccepted(%s, %s) != %v", tc.ours, tc.kit, tc.ok)
		}
	}
	r := newRig(t, func(_ *config.Config, o *controller.Options) { o.KitVersion = "1.10.0" })
	r.att.Default = controller.Attestation{Attested: true, KitVersion: "1.8.0"}
	a := r.actor("eng-web", "old", ateapi.ActorStateSuspended, "sub-alice")
	if err := r.ctl.EnsurePolicy(context.Background(), ateapi.RefOf(a.GetMetadata())); !errors.Is(err, controller.ErrRefused) {
		t.Fatalf("old kit: %v", err)
	}
	ev := r.sink.Events(controller.EventKitRefused)
	if len(ev) != 1 || !strings.Contains(ev[0].Message, "migrate") {
		t.Fatalf("kit events = %+v", ev)
	}
}

func TestForks(t *testing.T) {
	r := newRig(t, nil)
	parent := r.actor("eng-web", "alice-1", ateapi.ActorStateSuspended, "sub-alice")
	pref := ateapi.RefOf(parent.GetMetadata())
	r.pass()
	child, err := r.api.Fork(pref, "t1", "alice-1-fork")
	if err != nil {
		t.Fatal(err)
	}
	cref := ateapi.RefOf(child.GetMetadata())
	r.pass()
	if !render.Equal(r.api.Policy(cref), r.api.Policy(pref)) {
		t.Fatal("the fork did not get the parent's policy")
	}
	reg, ok, _ := r.reg.Get(context.Background(), "eng-web", child.GetMetadata().GetUid())
	if !ok || reg.Person != "sub-alice" || reg.ParentUID != parent.GetMetadata().GetUid() || reg.ForkedBy != controller.ForkedByDefenseClaw || reg.Source != controller.SourceFork {
		t.Fatalf("fork registration = %+v", reg)
	}
	for _, w := range r.api.PolicyWrites() {
		if w.Key == "eng-web/alice-1-fork" && w.ActorState != ateapi.ActorStateSuspended {
			t.Fatalf("fork policy written while %s", w.ActorState)
		}
	}
	// Outside a launcher atespace: parent attribution, forked_by unknown.
	p2 := r.actor("ci-runs", "job-1", ateapi.ActorStateSuspended, "")
	r.pass()
	c2, err := r.api.Fork(ateapi.RefOf(p2.GetMetadata()), "t2", "job-1-fork")
	if err != nil {
		t.Fatal(err)
	}
	r.pass()
	reg2, _, _ := r.reg.Get(context.Background(), "ci-runs", c2.GetMetadata().GetUid())
	if reg2.ForkedBy != controller.ForkedByUnknown || reg2.ParentUID != p2.GetMetadata().GetUid() || r.api.Policy(ateapi.RefOf(c2.GetMetadata())) == nil {
		t.Fatalf("foreign-atespace fork = %+v", reg2)
	}
	if len(r.sink.Events(controller.EventFork)) != 2 {
		t.Fatal("fork events")
	}
}

func TestForeignActorInLauncherAtespace(t *testing.T) {
	r := newRig(t, nil)
	a := r.actor("eng-web", "intruder", ateapi.ActorStateSuspended, "")
	r.pass()
	if len(r.sink.Events(controller.EventForeignActor)) != 0 {
		t.Fatal("called foreign inside the launcher grace (GAP-0145)")
	}
	r.clk.Add(16 * time.Second)
	r.pass()
	if r.api.Policy(ateapi.RefOf(a.GetMetadata())) != nil {
		t.Fatal("an unregistered actor in a launcher atespace got a policy")
	}
	ev := r.sink.Events(controller.EventForeignActor)
	if len(ev) != 1 || ev[0].Signal.SignalID != controller.SignalForeignActor {
		t.Fatalf("events = %+v", ev)
	}
}

func TestAtespaceGlobOnlyForOwned(t *testing.T) {
	r := newRig(t, nil)
	evil := r.actor("eng-evil", "x", ateapi.ActorStateSuspended, "")
	listed := r.actor("ci-runs", "y", ateapi.ActorStateSuspended, "")
	r.pass()
	if r.api.Policy(ateapi.RefOf(evil.GetMetadata())) != nil {
		t.Fatal("eng-evil got the eng-* profile (E3)")
	}
	if r.api.Policy(ateapi.RefOf(listed.GetMetadata())) == nil {
		t.Fatal("an exactly listed atespace got no policy")
	}
	ws := r.sink.Events(controller.EventWarning)
	if len(ws) != 1 || !strings.Contains(ws[0].Message, "eng-evil") {
		t.Fatalf("warnings = %+v", ws)
	}
	r.pass()
	if len(r.sink.Events(controller.EventWarning)) != 1 {
		t.Fatal("the glob warning repeats")
	}
	inv := r.sink.Events(controller.EventInventory)
	if len(inv) != 2 {
		t.Fatalf("inventory events = %d (unmanaged actors are inventoried too)", len(inv))
	}
}

func TestDriftRevertAndConflictRule(t *testing.T) {
	r := newRig(t, nil)
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	want := r.api.Policy(ref)
	deny, err := render.DenyOnly(controller.SettingsFromConfig(r.cfg))
	if err != nil {
		t.Fatal(err)
	}
	wide := []*ateapi.EgressRule{{Https: &ateapi.HttpsRule{Hostnames: []string{"*"}}}}
	for i := 1; i <= 3; i++ {
		r.clk.Add(time.Minute)
		_ = r.api.ForeignSetPolicy(ref, wide)
		r.pass()
		exp := want
		if i == 3 {
			exp = deny // the third revert marks the conflict: deny-only
		}
		if !render.Equal(r.api.Policy(ref), exp) {
			t.Fatalf("revert %d: policy = %v", i, r.api.Policy(ref).GetRules())
		}
	}
	if n := len(r.sink.Events(controller.EventForeignRule)); n != 3 {
		t.Fatalf("foreign_rule events = %d", n)
	}
	conf := r.sink.Events(controller.EventPolicyConflict)
	if len(conf) != 1 || conf[0].Severity != controller.SeverityAlert || conf[0].Signal.SignalID != controller.SignalPolicyConflict {
		t.Fatalf("conflict events = %+v", conf)
	}
	// Idle passes keep the conflict: the deny-only policy is DefenseClaw's
	// own write (live run, TST A3-C3).
	r.pass()
	r.pass()
	if len(r.sink.Events(controller.EventConflictCleared)) != 0 {
		t.Fatal("the conflict cleared on DefenseClaw's own write")
	}
	// A fourth foreign change never stays in force (GAP-0055): it is
	// replaced with deny-only again, without a new alert.
	for range 3 {
		r.clk.Add(time.Minute)
		_ = r.api.ForeignSetPolicy(ref, wide)
		r.pass()
		if !render.Equal(r.api.Policy(ref), deny) {
			t.Fatalf("a foreign policy stayed in force in policy_conflict: %v", r.api.Policy(ref).GetRules())
		}
	}
	if len(r.sink.Events(controller.EventPolicyConflict)) != 1 {
		t.Fatal("a second conflict alert")
	}
	// A deleted policy comes back deny-only.
	if _, err := r.api.DeleteActorEgressPolicy(context.Background(), ref, nil); err != nil {
		t.Fatal(err)
	}
	r.pass()
	if !render.Equal(r.api.Policy(ref), deny) {
		t.Fatal("a deleted policy in conflict did not come back deny-only")
	}
	// The conflict clears once another writer restores DefenseClaw's policy.
	_ = r.api.ForeignSetPolicy(ref, want.GetRules())
	r.pass()
	if len(r.sink.Events(controller.EventConflictCleared)) != 1 {
		t.Fatal("conflict not cleared")
	}
	r.pass()
	if !render.Equal(r.api.Policy(ref), want) {
		t.Fatal("after the conflict cleared the policy is not DefenseClaw's")
	}
}

func TestRevertsOutsideTheWindowDoNotConflict(t *testing.T) {
	r := newRig(t, nil)
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	for range 5 {
		r.clk.Add(6 * time.Minute)
		_ = r.api.ForeignSetPolicy(ref, nil)
		r.pass()
	}
	if len(r.sink.Events(controller.EventPolicyConflict)) != 0 {
		t.Fatal("reverts 6 minutes apart marked a conflict")
	}
}

func TestConfigChangeIsNotDrift(t *testing.T) {
	r := newRig(t, nil)
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	r.pass()
	// A restarted controller with a new allow list updates without a foreign_rule.
	r2 := newRig(t, func(cfg *config.Config, _ *controller.Options) { cfg.Substrate.Egress.Allow = []string{"gitlab.com"} })
	r2.api, r2.reg = r.api, r.reg
	o := controller.Options{Client: r.api, Attestor: r.att, Activity: r.act, Registry: r.reg, Sink: r2.sink,
		Resolver: &controller.ConfigResolver{Config: r2.cfg}, RequireAttestation: true, Now: r.clk.Now,
		Settings: controller.SettingsFromConfig(r2.cfg), LauncherAtespaces: controller.LauncherSet(r2.cfg)}
	ctl, _ := controller.New(o)
	if err := ctl.Reconcile(context.Background()); err != nil {
		t.Fatal(err)
	}
	if len(r2.sink.Events(controller.EventForeignRule)) != 0 {
		t.Fatal("a config change counted as drift")
	}
	p := r.api.Policy(ateapi.RefOf(a.GetMetadata()))
	if !strings.Contains(render.Canonical(p), "gitlab.com") {
		t.Fatal("the new allow list was not written")
	}
}

func TestIdleSuspend(t *testing.T) {
	r := newRig(t, nil)
	busy := r.actor("eng-web", "busy", ateapi.ActorStateRunning, "sub-a")
	quiet := r.actor("eng-web", "quiet", ateapi.ActorStateRunning, "sub-b")
	asking := r.actor("eng-web", "asking", ateapi.ActorStateRunning, "sub-c")
	task := r.actor("eng-web", "task", ateapi.ActorStateRunning, "")
	nosample := r.actor("eng-web", "nosample", ateapi.ActorStateRunning, "sub-d")
	_ = r.reg.Put(context.Background(), controller.Registration{Atespace: "eng-web", Name: "task", UID: task.GetMetadata().GetUid(),
		Person: "sub-e", Profile: "eng", Task: true, Source: controller.SourceLauncher})
	r.pass() // running since now
	r.clk.Add(31 * time.Minute)
	now := r.clk.Now()
	for _, a := range []*ateapi.Actor{busy, quiet, asking, task} {
		r.act.SetCPU(a.GetMetadata().GetUid(), 0.01, now)
	}
	r.act.SetCPU(busy.GetMetadata().GetUid(), 1.5, now) // a silent build burning CPU
	r.act.SetAsk(asking.GetMetadata().GetUid(), true)
	r.pass()
	state := func(a *ateapi.Actor) ateapi.ActorState {
		got, _ := r.api.GetActor(context.Background(), ateapi.RefOf(a.GetMetadata()))
		return got.GetStatus().GetState()
	}
	if state(quiet) != ateapi.ActorStateSuspended {
		t.Fatal("the idle actor was not suspended")
	}
	for name, a := range map[string]*ateapi.Actor{"busy CPU": busy, "pending ask": asking, "--task": task, "no CPU sample": nosample} {
		if state(a) != ateapi.ActorStateRunning {
			t.Errorf("%s: suspended", name)
		}
	}
	if len(r.sink.Events(controller.EventIdleSuspend)) != 1 {
		t.Fatal("idle events")
	}
	// Recent activity resets the clock.
	r2 := newRig(t, nil)
	b := r2.actor("eng-web", "b", ateapi.ActorStateRunning, "sub-a")
	r2.pass()
	r2.clk.Add(31 * time.Minute)
	r2.act.Touch(b.GetMetadata().GetUid(), r2.clk.Now().Add(-time.Minute))
	r2.act.SetCPU(b.GetMetadata().GetUid(), 0, r2.clk.Now())
	r2.pass()
	if got, _ := r2.api.GetActor(context.Background(), ateapi.RefOf(b.GetMetadata())); got.GetStatus().GetState() != ateapi.ActorStateRunning {
		t.Fatal("an actor active a minute ago was suspended")
	}
}

func TestBatchStartPolicyBeforeResume(t *testing.T) {
	r := newRig(t, nil)
	var refs []*ateapi.ObjectRef
	for i := range 50 {
		a := r.actor("eng-web", fmt.Sprintf("batch-%02d", i), ateapi.ActorStateSuspended, "sub-ci")
		refs = append(refs, ateapi.RefOf(a.GetMetadata()))
	}
	r.pass()
	for _, ref := range refs {
		if r.api.Policy(ref) == nil {
			t.Fatalf("%s has no policy after one pass", ateapi.Key(ref))
		}
	}
	if n := r.api.Calls("CreateActorEgressPolicy"); n != 50 {
		t.Fatalf("creates = %d", n)
	}
	r.pass()
	if n := r.api.Calls("CreateActorEgressPolicy") + r.api.Calls("UpdateActorEgressPolicy"); n != 50 {
		t.Fatalf("a steady pass wrote again: %d writes", n)
	}
}

func TestDeletedActorsAndErrors(t *testing.T) {
	r := newRig(t, nil)
	a := r.actor("eng-web", "gone", ateapi.ActorStateSuspended, "sub-a")
	r.pass()
	r.api.RemoveActor(ateapi.RefOf(a.GetMetadata()))
	r.pass()
	if len(r.sink.Events(controller.EventDeleted)) != 1 {
		t.Fatal("no deleted event")
	}
	r.api.Err = func(method, key string) error {
		if method == "ListActors" {
			return errors.New("down")
		}
		return nil
	}
	if err := r.ctl.Reconcile(context.Background()); err == nil {
		t.Fatal("a list failure was swallowed")
	}
	if _, err := controller.New(controller.Options{}); err == nil {
		t.Fatal("New accepted empty options")
	}
}

func TestProfileRefusesSandboxes(t *testing.T) {
	no := false
	r := newRig(t, func(cfg *config.Config, _ *controller.Options) {
		cfg.Guardrail.Profiles["eng"] = config.GuardrailProfile{Sandbox: &config.OpenShellAdminConfig{Allowed: &no}}
	})
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateSuspended, "sub-alice")
	if err := r.ctl.EnsurePolicy(context.Background(), ateapi.RefOf(a.GetMetadata())); !errors.Is(err, controller.ErrRefused) {
		t.Fatalf("err = %v", err)
	}
	if len(r.sink.Events(controller.EventProfileRefused)) != 1 {
		t.Fatal("no profile refusal event")
	}
}

func TestMatchAtespace(t *testing.T) {
	for _, tc := range []struct {
		pats  []string
		ns    string
		owned bool
		match bool
		warn  bool
	}{
		{[]string{"eng-web"}, "eng-web", false, true, false},
		{[]string{"eng-*"}, "eng-web", true, true, false},
		{[]string{"eng-*"}, "eng-evil", false, false, true},
		{[]string{"ops"}, "eng-web", false, false, false},
	} {
		m, w := controller.MatchAtespace(tc.pats, tc.ns, tc.owned)
		if m != tc.match || (w != "") != tc.warn {
			t.Errorf("%v %s owned=%v: match=%v warn=%q", tc.pats, tc.ns, tc.owned, m, w)
		}
	}
}

func TestStrictestCombinationAndTemplates(t *testing.T) {
	r := newRig(t, func(cfg *config.Config, _ *controller.Options) {
		cfg.Guardrail.Profiles["tight"] = config.GuardrailProfile{Sandbox: &config.OpenShellAdminConfig{EgressBlock: []string{"github.com"}}}
		cfg.Guardrail.ProfileAssignments = append(cfg.Guardrail.ProfileAssignments, config.ProfileAssignment{Profile: "tight",
			Match: config.ProfileMatch{Substrate: &config.ProfileMatchSubstrate{Templates: []string{"ci-runs/claude"}}}})
	})
	a := r.actor("ci-runs", "job", ateapi.ActorStateSuspended, "")
	r.pass()
	p := render.Canonical(r.api.Policy(ateapi.RefOf(a.GetMetadata())))
	if strings.Contains(p, " github.com") || !strings.Contains(p, "pypi.org") {
		t.Fatalf("the template-matched profile did not tighten the atespace one:\n%s", p)
	}
}

func TestScopedListingWithoutGlobalViewer(t *testing.T) {
	r := newRig(t, nil)
	in := r.actor("ci-runs", "job", ateapi.ActorStateSuspended, "")
	r.actor("other-team", "x", ateapi.ActorStateSuspended, "")
	r.api.Err = func(method, key string) error {
		if method == "ListActors" && key == "" {
			return status.Error(codes.PermissionDenied, "no global viewer")
		}
		return nil
	}
	r.pass()
	r.pass()
	if r.api.Policy(ateapi.RefOf(in.GetMetadata())) == nil {
		t.Fatal("a managed atespace was not reconciled in scoped mode")
	}
	if r.api.Calls("ListActors") != 1+2*2 { // one refused global list, then eng-web and ci-runs each pass
		t.Fatalf("ListActors calls = %d", r.api.Calls("ListActors"))
	}
	ws := r.sink.Events(controller.EventWarning)
	if len(ws) != 1 || !strings.Contains(ws[0].Message, "global viewer") {
		t.Fatalf("warnings = %+v", ws)
	}
	if n := len(r.sink.Events(controller.EventInventory)); n != 1 {
		t.Fatalf("inventory = %d, want only the managed atespace", n)
	}
}
