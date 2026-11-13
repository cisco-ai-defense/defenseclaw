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
	"sync"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
	"github.com/defenseclaw/defenseclaw/internal/substrate/chainstate"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/render"
	"github.com/defenseclaw/defenseclaw/internal/substrate/setup"
)

const (
	digA = "sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digB = "sha256:bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// GAP-0054: an unchanged template is attested again after the TTL, so a
// revocation takes its actors' policies away.
func TestReattestAfterTTL(t *testing.T) {
	r := newRig(t, nil)
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	if r.api.Policy(ref) == nil {
		t.Fatal("no policy")
	}
	r.att.Default = controller.Attestation{Reason: "key_revoked: the signing key is revoked"}
	r.clk.Add(10 * time.Second)
	r.pass()
	if r.api.Policy(ref) == nil {
		t.Fatal("re-attested before the TTL")
	}
	r.clk.Add(25 * time.Second)
	r.pass()
	if r.api.Policy(ref) != nil {
		t.Fatal("a revoked template kept its policy after the TTL")
	}
	if len(r.sink.Events(controller.EventPolicyRemoved)) != 1 {
		t.Fatal("no policy_removed event")
	}
}

// GAP-0054: the verifier's ValidUntil shortens the controller's TTL.
func TestReattestAtValidUntil(t *testing.T) {
	r := newRig(t, nil)
	r.att.Default = controller.Attestation{Attested: true, KitVersion: "1.0.10", ValidUntil: r.clk.Now().Add(5 * time.Second)}
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	r.att.Default = controller.Attestation{Reason: "key_revoked"}
	r.clk.Add(6 * time.Second)
	r.pass()
	if r.api.Policy(ref) != nil {
		t.Fatal("the verdict outlived its ValidUntil")
	}
}

// GAP-0053: admission applies the image allow lists per profile.
func TestImageAllowLists(t *testing.T) {
	r := newRig(t, func(_ *config.Config, o *controller.Options) {
		o.Templates = config.SubstrateTemplatesConfig{
			AllowedImages: []string{"reg.example.com/dc/*"},
			ProfileImages: map[string][]string{"ci": {"reg.example.com/dc/ci-*"}},
		}
	})
	put := func(ns, name, image string) *ateapi.ObjectRef {
		r.api.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: ns, Name: name},
			Containers: []*ateapi.Container{{Name: "agent", Image: image}}})
		a := r.api.PutActor(&ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: ns, Name: name + "-1"}, ActorTemplate: ateapi.Ref(ns, name),
			Status: &ateapi.ActorStatus{State: ateapi.ActorStateSuspended}})
		return ateapi.RefOf(a.GetMetadata())
	}
	ok := put("ci-runs", "good", "reg.example.com/dc/ci-claude@"+digA)
	other := put("ci-runs", "other", "reg.example.com/dc/claude@"+digA) // allowed globally, not for ci
	foreign := put("ci-runs", "foreign", "evil.example.com/x@"+digA)
	r.pass()
	if r.api.Policy(ok) == nil {
		t.Fatal("an allowed image got no policy")
	}
	if r.api.Policy(other) != nil || r.api.Policy(foreign) != nil {
		t.Fatal("an image outside the allow lists got a policy")
	}
	var msgs []string
	for _, e := range r.sink.Events(controller.EventTemplateUnverified) {
		msgs = append(msgs, e.Message)
	}
	if len(msgs) != 2 || !strings.Contains(strings.Join(msgs, "|"), "not allowed for profile ci") {
		t.Fatalf("refusals = %q", msgs)
	}
}

// GAP-0082: a fork never inherits ask approvals, and a fork made outside
// DefenseClaw loses the person binding.
func TestForkDropsApprovalsAndForeignPerson(t *testing.T) {
	r := newRig(t, nil)
	ctx := context.Background()
	// Launcher atespace: DefenseClaw forked it; the person stays, asks go.
	p := r.actor("eng-web", "alice-1", ateapi.ActorStateSuspended, "sub-alice")
	reg, _, _ := r.reg.Get(ctx, "eng-web", p.GetMetadata().GetUid())
	reg.Approved = []string{"api.example.org"}
	_ = r.reg.Put(ctx, reg)
	r.pass()
	c, err := r.api.Fork(ateapi.RefOf(p.GetMetadata()), "t1", "alice-1-fork")
	if err != nil {
		t.Fatal(err)
	}
	r.pass()
	cr, _, _ := r.reg.Get(ctx, "eng-web", c.GetMetadata().GetUid())
	if cr.Person != "sub-alice" || len(cr.Approved) != 0 {
		t.Fatalf("launcher fork = %+v", cr)
	}
	// Elsewhere: forked_by unknown, no person.
	p2 := r.actor("ci-runs", "job-1", ateapi.ActorStateSuspended, "")
	r.pass()
	reg2, _, _ := r.reg.Get(ctx, "ci-runs", p2.GetMetadata().GetUid())
	reg2.Person, reg2.Approved = "sub-bob", []string{"api.example.org"}
	_ = r.reg.Put(ctx, reg2)
	r.clk.Add(time.Minute) // past the registration TTL
	r.pass()
	c2, err := r.api.Fork(ateapi.RefOf(p2.GetMetadata()), "t2", "job-1-fork")
	if err != nil {
		t.Fatal(err)
	}
	r.pass()
	cr2, _, _ := r.reg.Get(ctx, "ci-runs", c2.GetMetadata().GetUid())
	if cr2.ForkedBy != controller.ForkedByUnknown || cr2.Person != "" || len(cr2.Approved) != 0 {
		t.Fatalf("foreign fork = %+v", cr2)
	}
}

// GAP-0083: registrations are re-read (approvals and revocations reach the
// policy), and an actor that is no longer managed loses DefenseClaw's
// policy.
func TestRegistrationReReadAndUnmanaged(t *testing.T) {
	r := newRig(t, nil)
	ctx := context.Background()
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	reg, _, _ := r.reg.Get(ctx, "eng-web", a.GetMetadata().GetUid())
	reg.Approved = []string{"api.example.org"}
	_ = r.reg.Put(ctx, reg)
	r.clk.Add(31 * time.Second)
	r.pass()
	if !hasHost(r.api.Policy(ref), "api.example.org") {
		t.Fatal("an approval did not reach the policy after the registration TTL")
	}

	// ci-runs loses its profile assignment: the actor is unmanaged now.
	b := r.actor("ci-runs", "job-1", ateapi.ActorStateRunning, "")
	bref := ateapi.RefOf(b.GetMetadata())
	r.pass()
	if r.api.Policy(bref) == nil {
		t.Fatal("no policy while managed")
	}
	r.cfg.Guardrail.ProfileAssignments = nil
	r.clk.Add(31 * time.Second)
	r.pass()
	if r.api.Policy(bref) != nil {
		t.Fatal("an unmanaged actor kept DefenseClaw's policy")
	}
	// A third party's policy on an unmanaged actor is left alone.
	_ = r.api.ForeignSetPolicy(bref, []*ateapi.EgressRule{{Https: &ateapi.HttpsRule{Hostnames: []string{"pypi.org"}}}})
	r.pass()
	if r.api.Policy(bref) == nil {
		t.Fatal("removed a policy DefenseClaw did not write")
	}
}

func hasHost(p *ateapi.EgressPolicy, host string) bool {
	for _, r := range p.GetRules() {
		if slices.Contains(r.GetHttps().GetHostnames(), host) || slices.Contains(r.GetHttp().GetHostnames(), host) {
			return true
		}
	}
	return false
}

type fakeVerifier struct {
	by map[string]*attest.Verified
}

func (f fakeVerifier) Verify(_ context.Context, image string) (*attest.Verified, error) {
	if v, ok := f.by[image]; ok {
		return v, nil
	}
	return nil, &attest.Rejection{Code: attest.CodeNoAttestation, Detail: image + " has no attestation"}
}

func verified(digest, kit string, until time.Time) *attest.Verified {
	st := &attest.Statement{}
	st.Predicate.Kit.Version = kit
	st.Predicate.Template.Connector = "claudecode"
	st.Predicate.Template.AgentVersion = "2.1.317"
	st.Predicate.Kit.HookContract = "claudecode-hooks-v2"
	return &attest.Verified{Digest: digest, Statement: st, ValidUntil: until}
}

// GAP-0053: the template attestor checks every container, the digest it
// runs, and image volumes.
func TestTemplateAttestor(t *testing.T) {
	now := time.Date(2026, 11, 12, 22, 0, 0, 0, time.UTC)
	imgA, imgB := "reg.example.com/dc/claude@"+digA, "reg.example.com/dc/side@"+digB
	ta := &controller.TemplateAttestor{
		Verifier: fakeVerifier{by: map[string]*attest.Verified{
			imgA: verified(digA, "1.0.10", now.Add(2*time.Minute)),
			imgB: verified(digB, "1.0.10", now.Add(time.Minute)),
			// A verifier that answers for another digest is never trusted.
			"reg.example.com/dc/moved@" + digA: verified(digB, "1.0.10", now),
		}},
		VolumeImages: []string{"reg.example.com/models/*"},
		Registries:   []string{"reg.example.com"},
	}
	tmpl := func(images []string, vols ...string) *ateapi.ActorTemplate {
		t := &ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "a", Name: "t"}}
		for _, i := range images {
			t.Containers = append(t.Containers, &ateapi.Container{Image: i})
		}
		for n, v := range vols {
			t.Volumes = append(t.Volumes, &ateapi.Volume{Name: "v" + string(rune('0'+n)), Image: &ateapi.ImageVolumeSource{Reference: v}})
		}
		return t
	}
	for name, tc := range map[string]struct {
		t      *ateapi.ActorTemplate
		ok     bool
		reason string
	}{
		"both attested":      {t: tmpl([]string{imgA, imgB}), ok: true},
		"no container":       {t: tmpl(nil), reason: "no container"},
		"tag":                {t: tmpl([]string{"reg.example.com/dc/claude:1.0"}), reason: "not pinned by digest"},
		"second unattested":  {t: tmpl([]string{imgA, "reg.example.com/dc/x@" + digB}), reason: "no_attestation"},
		"digest mismatch":    {t: tmpl([]string{"reg.example.com/dc/moved@" + digA}), reason: "the attestation is for"},
		"allowed volume":     {t: tmpl([]string{imgA}, "reg.example.com/models/m@"+digB), ok: true},
		"volume not allowed": {t: tmpl([]string{imgA}, "reg.example.com/other/m@"+digB), reason: "volume_images"},
		"volume by tag":      {t: tmpl([]string{imgA}, "reg.example.com/models/m:v1"), reason: "digest-pinned"},
		"registry not named": {t: tmpl([]string{"evil.example.net/x@" + digA}), reason: "not in substrate.templates.allowed_images"},
	} {
		t.Run(name, func(t *testing.T) {
			att, err := ta.Attest(context.Background(), tc.t)
			if err != nil {
				t.Fatal(err)
			}
			if att.Attested != tc.ok || !strings.Contains(att.Reason, tc.reason) {
				t.Fatalf("attestation = %+v", att)
			}
			if tc.ok && (att.Digest != digA || att.KitVersion != "1.0.10" || att.Connector != "claudecode" ||
				att.AgentVersion != "2.1.317" || att.HookContract != "claudecode-hooks-v2") {
				t.Fatalf("attestation = %+v", att)
			}
			if name == "both attested" && !att.ValidUntil.Equal(now.Add(time.Minute)) {
				t.Fatalf("ValidUntil = %v, want the earliest", att.ValidUntil)
			}
		})
	}
}

func TestAllowedRegistries(t *testing.T) {
	got := controller.AllowedRegistries(config.SubstrateTemplatesConfig{
		AllowedImages: []string{"reg.example.com/dc/*", "10.0.0.1:5000/f1/*"}, PlainHTTPRegistries: []string{"10.0.0.1:5000"}})
	if !slices.Equal(got, []string{"10.0.0.1:5000", "reg.example.com"}) {
		t.Fatalf("registries = %v", got)
	}
	if got := controller.AllowedRegistries(config.SubstrateTemplatesConfig{AllowedImages: []string{"*.example.com/dc/*"}}); len(got) != 0 {
		t.Fatalf("a host glob names no registry: %v", got)
	}
}

// The anchor file is re-read when it changes; a missing one fails closed.
func TestAnchorFileReload(t *testing.T) {
	dir := t.TempDir()
	p := filepath.Join(dir, "anchors.pem")
	af := &controller.AnchorFile{Path: p}
	if _, err := af.Get(); err == nil {
		t.Fatal("a missing anchors file must be an error")
	}
	s1, err := attest.GenerateSigner()
	if err != nil {
		t.Fatal(err)
	}
	pem1, err := s1.PublicKeyPEM()
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, pem1, 0o600); err != nil {
		t.Fatal(err)
	}
	a1, err := af.Get()
	if err != nil || a1.Len() != 1 {
		t.Fatalf("anchors = %v, %v", a1, err)
	}
	s2, _ := attest.GenerateSigner()
	pem2, _ := s2.PublicKeyPEM()
	if err := os.WriteFile(p, append(append([]byte{}, pem1...), pem2...), 0o600); err != nil {
		t.Fatal(err)
	}
	future := time.Now().Add(time.Hour)
	_ = os.Chtimes(p, future, future)
	a2, err := af.Get()
	if err != nil || a2.Len() != 2 {
		t.Fatalf("anchors after rotation = %v, %v", a2, err)
	}
	if err := os.Remove(p); err != nil {
		t.Fatal(err)
	}
	if _, err := af.Get(); err == nil {
		t.Fatal("a removed anchors file must fail closed")
	}
}

// GAP-0105: new UIDs are swept and capped, not only on a rate update.
func TestUsageCPUSweepsOnInsert(t *testing.T) {
	now := time.Date(2026, 11, 12, 22, 0, 0, 0, time.UTC)
	clk := &clock{t: now}
	u := controller.NewUsageCPU(clk.Now)
	for i := range 500 {
		u.Ingest(controller.UsageSample{UID: "flood-" + strings.Repeat("x", i%7) + string(rune('a'+i%26)) + time.Duration(i).String(), Epoch: 1, CPUTime: 1, At: now})
	}
	if u.Len() != 500 {
		t.Fatalf("tracked %d", u.Len())
	}
	clk.Add(11 * time.Minute)
	u.Ingest(controller.UsageSample{UID: "fresh", Epoch: 1, CPUTime: 1, At: clk.Now()})
	if u.Len() != 1 {
		t.Fatalf("stale actors not swept on insert: %d", u.Len())
	}
}

type memResets struct {
	cms map[string]*setup.ConfigMap
}

func (m *memResets) GetConfigMap(_ context.Context, ns, name string) (*setup.ConfigMap, error) {
	cm := m.cms[ns+"/"+name]
	if cm == nil {
		return nil, nil
	}
	c := *cm
	c.Data = map[string]string{}
	for k, v := range cm.Data {
		c.Data[k] = v
	}
	return &c, nil
}
func (m *memResets) UpdateConfigMap(_ context.Context, cm *setup.ConfigMap) error {
	m.cms[cm.Namespace+"/"+cm.Name] = cm
	return nil
}
func (m *memResets) CreateConfigMap(_ context.Context, cm *setup.ConfigMap) error {
	m.cms[cm.Namespace+"/"+cm.Name] = cm
	return nil
}

// Lead 11-12: an audited admin reset clears policy_conflict; the next pass
// writes DefenseClaw's policy and drift handling starts over.
func TestAdminPolicyReset(t *testing.T) {
	store := &memResets{cms: map[string]*setup.ConfigMap{}}
	r := newRig(t, func(_ *config.Config, o *controller.Options) { o.Resets, o.Namespace = store, "defenseclaw-system" })
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	full := r.api.Policy(ref)
	wide := []*ateapi.EgressRule{{Https: &ateapi.HttpsRule{Hostnames: []string{"*"}}}}
	for range 3 {
		r.clk.Add(time.Minute)
		_ = r.api.ForeignSetPolicy(ref, wide)
		r.pass()
	}
	if len(r.sink.Events(controller.EventPolicyConflict)) != 1 {
		t.Fatal("no conflict")
	}
	if err := controller.RequestReset(context.Background(), store, "defenseclaw-system",
		controller.ResetRequest{Atespace: "eng-web", Actor: "alice-1", By: "admin@example.com", Reason: "GitOps fixed"}); err != nil {
		t.Fatal(err)
	}
	if err := controller.RequestReset(context.Background(), store, "defenseclaw-system", controller.ResetRequest{Atespace: "eng-web", Actor: "alice-1"}); err == nil {
		t.Fatal("a reset without a requester was accepted")
	}
	r.pass()
	if !render.Equal(r.api.Policy(ref), full) {
		t.Fatal("the reset did not write DefenseClaw's policy")
	}
	ev := r.sink.Events(controller.EventConflictReset)
	if len(ev) != 1 || ev[0].Detail["by"] != "admin@example.com" || ev[0].Detail["was_in_conflict"] != true {
		t.Fatalf("reset events = %+v", ev)
	}
	if cm := store.cms["defenseclaw-system/"+controller.ResetConfigMap]; len(cm.Data) != 0 {
		t.Fatalf("handled request left: %v", cm.Data)
	}
	// Drift handling starts over: one foreign change is reverted to the
	// full policy, not to deny-only.
	r.clk.Add(time.Minute)
	_ = r.api.ForeignSetPolicy(ref, wide)
	r.pass()
	if !render.Equal(r.api.Policy(ref), full) {
		t.Fatal("after the reset a foreign change was not reverted to DefenseClaw's policy")
	}
}

// GAP-0119 (found live on E1): one managed atespace that cannot be listed
// must not stop the others.
func TestScopedListingSkipsAnUnlistableAtespace(t *testing.T) {
	r := newRig(t, nil)
	in := r.actor("ci-runs", "job", ateapi.ActorStateSuspended, "")
	web := r.actor("eng-web", "alice-1", ateapi.ActorStateSuspended, "sub-alice")
	r.pass() // both reconciled with full listing
	denyWeb := true
	r.api.Err = func(method, key string) error {
		if method == "ListActors" && (key == "" || (key == "eng-web" && denyWeb)) {
			return status.Error(codes.PermissionDenied, "denied")
		}
		return nil
	}
	in2 := r.actor("ci-runs", "job-2", ateapi.ActorStateSuspended, "")
	r.pass()
	r.pass()
	if r.api.Policy(ateapi.RefOf(in2.GetMetadata())) == nil || r.api.Policy(ateapi.RefOf(in.GetMetadata())) == nil {
		t.Fatal("ci-runs was not reconciled while eng-web could not be listed")
	}
	if len(r.sink.Events(controller.EventDeleted)) != 0 {
		t.Fatal("actors of the unlistable atespace were reported deleted")
	}
	var warns int
	for _, w := range r.sink.Events(controller.EventWarning) {
		if strings.Contains(w.Message, "managed atespace eng-web") {
			if w.Severity != controller.SeverityAlert {
				t.Fatalf("the skip is not an alert: %+v", w)
			}
			warns++
		}
	}
	if warns != 1 {
		t.Fatalf("warnings for eng-web = %d, want 1", warns)
	}
	denyWeb = false
	r.pass()
	if r.api.Policy(ateapi.RefOf(web.GetMetadata())) == nil {
		t.Fatal("eng-web actor lost its policy")
	}
}

// GAP-0133: a new UID under an old name in a launcher atespace warns.
func TestRecreatedSameNameWarns(t *testing.T) {
	r := newRig(t, nil)
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateSuspended, "sub-alice")
	r.pass()
	if _, err := r.api.DeleteActor(context.Background(), ateapi.RefOf(a.GetMetadata()), nil); err != nil {
		t.Fatal(err)
	}
	r.pass()
	b := r.actor("eng-web", "alice-1", ateapi.ActorStateSuspended, "sub-alice")
	r.pass()
	ev := r.sink.Events(controller.EventRecreatedSameName)
	if len(ev) != 1 || ev[0].ActorUID != b.GetMetadata().GetUid() || ev[0].Detail["previous_uid"] != a.GetMetadata().GetUid() || ev[0].Severity != controller.SeverityWarn {
		t.Fatalf("recreated events = %+v", ev)
	}
	// Outside launcher atespaces names are not tracked for this.
	c := r.actor("ci-runs", "job", ateapi.ActorStateSuspended, "")
	r.pass()
	_, _ = r.api.DeleteActor(context.Background(), ateapi.RefOf(c.GetMetadata()), nil)
	r.pass()
	r.actor("ci-runs", "job", ateapi.ActorStateSuspended, "")
	r.pass()
	if len(r.sink.Events(controller.EventRecreatedSameName)) != 1 {
		t.Fatal("a managed-atespace actor warned")
	}
}

// GAP-0131: no named registry admits nothing.
func TestTemplateAttestorNeedsNamedRegistries(t *testing.T) {
	ta := &controller.TemplateAttestor{Verifier: fakeVerifier{}}
	att, _ := ta.Attest(context.Background(), &ateapi.ActorTemplate{Containers: []*ateapi.Container{{Image: "reg.example.com/dc/claude@" + digA}}})
	if att.Attested || !strings.Contains(att.Reason, "names no registry") {
		t.Fatalf("attestation = %+v", att)
	}
}

// GAP-0127: a registry outage keeps the last good verdict of an unchanged
// template for the grace, with one alert; a real refusal cuts at once.
func TestRegistryOutageKeepsTheLastGoodVerdict(t *testing.T) {
	r := newRig(t, nil)
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	r.att.Default = controller.Attestation{Retryable: true, Reason: "registry_error: connection refused"}
	r.clk.Add(31 * time.Second)
	r.pass()
	r.clk.Add(31 * time.Second)
	r.pass()
	if r.api.Policy(ref) == nil {
		t.Fatal("a registry outage cut the actor's network")
	}
	var alerts int
	for _, e := range r.sink.Events(controller.EventWarning) {
		if e.Severity == controller.SeverityAlert && strings.Contains(e.Message, "cannot be re-attested") {
			alerts++
		}
	}
	if alerts != 1 {
		t.Fatalf("outage alerts = %d", alerts)
	}
	// Past the grace the refusal applies.
	r.clk.Add(16 * time.Minute)
	r.pass()
	if r.api.Policy(ref) != nil {
		t.Fatal("the grace outlived its bound")
	}
	// A non-retryable refusal (revoked key) cuts at once, outage or not.
	r2 := newRig(t, nil)
	b := r2.actor("eng-web", "bob-1", ateapi.ActorStateRunning, "sub-bob")
	r2.pass()
	r2.att.Default = controller.Attestation{Reason: "key_revoked"}
	r2.clk.Add(31 * time.Second)
	r2.pass()
	if r2.api.Policy(ateapi.RefOf(b.GetMetadata())) != nil {
		t.Fatal("a revoked key did not cut at once")
	}
}

// GAP-0131: the image allow lists apply with attestation off.
func TestImageAllowListsWithoutAttestation(t *testing.T) {
	r := newRig(t, func(_ *config.Config, o *controller.Options) {
		o.RequireAttestation = false
		o.Templates = config.SubstrateTemplatesConfig{AllowedImages: []string{"reg.example.com/dc/*"}}
	})
	r.att.Default = controller.Attestation{}
	r.api.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "ci-runs", Name: "foreign"},
		Containers: []*ateapi.Container{{Name: "agent", Image: "evil.example.net/x@" + digA}}})
	a := r.api.PutActor(&ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "ci-runs", Name: "f-1"}, ActorTemplate: ateapi.Ref("ci-runs", "foreign"),
		Status: &ateapi.ActorStatus{State: ateapi.ActorStateSuspended}})
	r.pass()
	if r.api.Policy(ateapi.RefOf(a.GetMetadata())) != nil {
		t.Fatal("an image outside allowed_images got a policy with attestation off")
	}
}

type lifeRec struct {
	mu   sync.Mutex
	evs  []chainstate.LifecycleEvent
	down bool
}

func (l *lifeRec) Lifecycle(_ context.Context, ev chainstate.LifecycleEvent) (chainstate.LifecycleResult, error) {
	l.mu.Lock()
	defer l.mu.Unlock()
	if l.down {
		return chainstate.LifecycleResult{}, errors.New("leader unreachable")
	}
	l.evs = append(l.evs, ev)
	return chainstate.LifecycleResult{}, nil
}

func (l *lifeRec) names() []string {
	l.mu.Lock()
	defer l.mu.Unlock()
	var out []string
	for _, e := range l.evs {
		n := e.Event
		if e.Parent != nil {
			n += "<" + e.Parent.UID
		}
		out = append(out, n)
	}
	return out
}

// A13 wiring: the controller sends suspend, resume, fork (with ParentUID),
// revert, crash and delete with its own time, and retries while the leader
// is down.
func TestLifecycleEventsToTheLeader(t *testing.T) {
	life := &lifeRec{}
	r := newRig(t, func(_ *config.Config, o *controller.Options) { o.Lifecycle = life })
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	step := func(s ateapi.ActorState) {
		r.clk.Add(time.Second)
		if err := r.api.SetState(ref, s); err != nil {
			t.Fatal(err)
		}
		r.pass()
	}
	step(ateapi.ActorStateSuspended)
	step(ateapi.ActorStateRunning)
	step(ateapi.ActorStateReverting)
	step(ateapi.ActorStateCrashed)
	step(ateapi.ActorStateSuspended) // a revert brings a crashed actor back
	child, err := r.api.Fork(ref, "t1", "alice-1-fork")
	if err != nil {
		t.Fatal(err)
	}
	r.pass()
	// CRASHED -> SUSPENDED is a revert of the crashed actor; it also pauses
	// the clock (GAP-0141).
	want := []string{"suspended", "resumed", "reverted", "crashed", "suspended", "reverted", "forked<" + a.GetMetadata().GetUid()}
	if got := life.names(); !slices.Equal(got, want) {
		t.Fatalf("lifecycle = %v, want %v", got, want)
	}
	for _, e := range life.evs {
		if e.AtUnixNano == 0 || e.Actor.Atespace != "eng-web" {
			t.Fatalf("event without controller time or actor: %+v", e)
		}
	}
	if life.evs[6].Actor.UID != child.GetMetadata().GetUid() {
		t.Fatal("the fork event names the wrong actor")
	}
	// Leader down: events wait and go out in order when it is back.
	life.down = true
	cref := ateapi.RefOf(child.GetMetadata())
	r.clk.Add(time.Second)
	_ = r.api.SetState(cref, ateapi.ActorStateRunning)
	r.pass()
	r.clk.Add(time.Second)
	_ = r.api.SetState(cref, ateapi.ActorStateSuspended)
	r.pass()
	if _, err := r.api.DeleteActor(context.Background(), cref, nil); err != nil {
		t.Fatal(err)
	}
	r.pass()
	life.down = false
	r.pass()
	got := life.names()[7:]
	if !slices.Equal(got, []string{"resumed", "suspended", "deleted"}) {
		t.Fatalf("after the outage: %v", got)
	}
}

// GAP-0164: the attestor carries the admitted skill folder digests of every
// image; a blocked item's digest never counts.
func TestTemplateAttestorCarriesSkillDigests(t *testing.T) {
	now := time.Date(2026, 11, 13, 2, 0, 0, 0, time.UTC)
	img := "reg.example.com/dc/claude@" + digA
	v := verified(digA, "1.0.10", now.Add(time.Minute))
	v.Statement.Predicate.Scan.Items = []attest.ScanItem{
		{Kind: "skill", Name: "github", Verdict: attest.VerdictClean, Digest: "sha256:good"},
		{Kind: "skill", Name: "fmt", Verdict: attest.VerdictWarn, Digest: "sha256:warn"},
		{Kind: "skill", Name: "evil", Verdict: attest.VerdictBlock, Digest: "sha256:evil"},
		{Kind: "mcp", Name: "x", Verdict: attest.VerdictClean, Digest: "sha256:mcp"},
	}
	ta := &controller.TemplateAttestor{Verifier: fakeVerifier{by: map[string]*attest.Verified{img: v}}, Registries: []string{"reg.example.com"}}
	att, err := ta.Attest(context.Background(), &ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "a", Name: "t"},
		Containers: []*ateapi.Container{{Image: img}}})
	if err != nil || !att.Attested {
		t.Fatalf("attest: %+v %v", att, err)
	}
	if strings.Join(att.SkillDigests, ",") != "sha256:good,sha256:warn" {
		t.Fatalf("skill digests %v", att.SkillDigests)
	}
}
