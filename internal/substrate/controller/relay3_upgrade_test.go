// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// restart replaces the rig's controller with a new one on the same cluster,
// as an upgrade does.
func restart(r *rig) {
	r.t.Helper()
	o := controller.Options{
		Client: r.api, Attestor: r.att, Activity: r.act, CPU: r.act, Registry: r.reg, Sink: r.sink,
		Resolver:           &controller.ConfigResolver{Config: r.cfg},
		RequireAttestation: true, KitVersion: "1.0.10", IdleSuspendAfter: 30 * time.Minute, Now: r.clk.Now,
		Settings: controller.SettingsFromConfig(r.cfg), Secrets: controller.SecretsFromConfig(r.cfg), LauncherAtespaces: controller.LauncherSet(r.cfg),
	}
	ctl, err := controller.New(o)
	if err != nil {
		r.t.Fatal(err)
	}
	r.ctl = ctl
}

func countMsg(r *rig, typ, sub string) int {
	n := 0
	for _, e := range r.sink.Events(typ) {
		if strings.Contains(e.Message, sub) {
			n++
		}
	}
	return n
}

// Owner decision for 1.0.10 (GAP-0354, GAP-0355): a template that now fails
// the allowlist keeps its running actors (their network stays up; the
// re-check after the TTL and the upgrade only write a warning row), refuses
// new ones with the reason, and is named once in an audit alert.
func TestAllowlistKeepsRunningActorsAndRefusesNewOnes(t *testing.T) {
	r := newRig(t, nil)
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	if r.api.Policy(ref) == nil {
		t.Fatal("no policy")
	}
	reason := "container 0: env sets variables the actor environment allowlist does not permit: LD_PRELOAD (not on the allowlist)"
	r.att.Default = controller.Attestation{Allowlist: true, Reason: reason, KitVersion: "1.0.9", Connector: "claudecode"}

	// The re-check after the TTL.
	r.clk.Add(31 * time.Second)
	r.pass()
	r.clk.Add(31 * time.Second)
	r.pass()
	if r.api.Policy(ref) == nil {
		t.Fatal("the re-check after the TTL cut a running actor's network")
	}
	if n := countMsg(r, controller.EventWarning, "keeps running on template eng-web/claude"); n != 1 {
		t.Fatalf("warning rows for the running actor = %d", n)
	}
	if n := countMsg(r, controller.EventTemplateAllowlist, "template eng-web/claude fails the actor allowlist"); n != 1 {
		t.Fatalf("template alerts = %d", n)
	}

	// The upgrade: a new controller finds the actor with DefenseClaw's policy.
	r.clk.Add(time.Minute)
	restart(r)
	r.pass()
	if r.api.Policy(ref) == nil {
		t.Fatal("the upgrade cut a running actor's network")
	}
	if n := countMsg(r, controller.EventWarning, "keeps running on template eng-web/claude"); n != 2 {
		t.Fatalf("warning rows after the upgrade = %d", n)
	}
	for _, e := range r.sink.Events(controller.EventTemplateAllowlist) {
		if e.Severity != controller.SeverityAlert || !strings.Contains(e.Message, "New actors from it are refused") {
			t.Fatalf("template alert %+v", e)
		}
	}

	// A new start from the template is refused with the reason.
	r.clk.Add(time.Second)
	b := r.actor("eng-web", "bob-1", ateapi.ActorStateRunning, "sub-bob")
	r.pass()
	if r.api.Policy(ateapi.RefOf(b.GetMetadata())) != nil {
		t.Fatal("a new actor of the template got a policy")
	}
	if n := countMsg(r, controller.EventTemplateUnverified, "LD_PRELOAD (not on the allowlist)"); n != 1 {
		t.Fatalf("refusals of the new actor = %d", n)
	}
	if err := r.ctl.EnsurePolicy(context.Background(), ateapi.RefOf(b.GetMetadata())); err == nil || !strings.Contains(err.Error(), "LD_PRELOAD") {
		t.Fatalf("the create path's answer: %v", err)
	}
	// Other refusals still cut a running actor at once.
	r.att.Default = controller.Attestation{Reason: "key_revoked"}
	r.clk.Add(31 * time.Second)
	r.pass()
	if r.api.Policy(ref) != nil {
		t.Fatal("a revoked key did not cut")
	}
}

// GAP-0354: doctor names every template the allowlist refuses, with why.
func TestDoctorListsTemplatesFailingTheAllowlist(t *testing.T) {
	r := newRig(t, nil)
	for _, n := range []string{"good", "bad", "revoked"} {
		r.api.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: n}})
	}
	r.att.Set("eng-web/good", controller.Attestation{Attested: true})
	r.att.Set("eng-web/bad", controller.Attestation{Allowlist: true, Reason: "container 0: command [\"/bin/sh\"] is not the attested entrypoint"})
	r.att.Set("eng-web/revoked", controller.Attestation{Reason: "key_revoked"})
	ts, err := controller.TemplatesFailingAllowlist(context.Background(), r.api, r.att)
	if err != nil || len(ts) != 1 || ts[0].Template != "eng-web/bad" {
		t.Fatalf("templates = %+v %v", ts, err)
	}
	status, detail, fix := controller.AllowlistCheck(ts, nil)
	if status != "warn" || !strings.Contains(detail, "eng-web/bad (container 0: command") || !strings.Contains(fix, "refused from the next release") {
		t.Fatalf("doctor row %s %q %q", status, detail, fix)
	}
	if status, _, _ := controller.AllowlistCheck(nil, nil); status != "pass" {
		t.Fatalf("no template: %s", status)
	}
}
