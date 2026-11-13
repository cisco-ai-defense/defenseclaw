// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// GAP-0182: on stk (11-13 03:36:19Z, actor dc-eng/claude-ef3c8916) the
// gateway's create path and the controller deployment wrote the new actor's
// egress policy at the same moment. The controller created it first; the
// create path's CreateActorEgressPolicy got ALREADY_EXISTS, left the policy
// to "the next pass" (EnsurePolicy has none) and answered "not managed by
// DefenseClaw", so the gateway deleted a properly registered actor.

// deployController is a second controller on the same control plane and
// registry: the controller Deployment next to the gateway's create path.
func deployController(t *testing.T, r *rig) *controller.Controller {
	t.Helper()
	o := controller.Options{
		Client: r.api, Attestor: r.att, Activity: r.act, CPU: r.act, Registry: r.reg, Sink: r.sink,
		Resolver:           &controller.ConfigResolver{Config: r.cfg},
		RequireAttestation: true, KitVersion: "1.0.10", Now: r.clk.Now,
		Settings: controller.SettingsFromConfig(r.cfg), Secrets: controller.SecretsFromConfig(r.cfg),
		LauncherAtespaces: controller.LauncherSet(r.cfg),
	}
	ctl, err := controller.New(o)
	if err != nil {
		t.Fatal(err)
	}
	return ctl
}

// beforeFirst runs fn once, just before the first call of method reaches the
// fake: the other writer wins the race by a few milliseconds.
func beforeFirst(r *rig, method string, fn func()) {
	done := false
	r.api.Err = func(m, _ string) error {
		if m == method && !done {
			done = true
			fn()
		}
		return nil
	}
}

func TestGAP0182CreatePathLosesThePolicyCreateRace(t *testing.T) {
	r := newRig(t, nil)
	a := r.actor("eng-web", "alice-0182a", ateapi.ActorStateSuspended, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	deploy := deployController(t, r)
	beforeFirst(r, "CreateActorEgressPolicy", func() {
		if err := deploy.Reconcile(context.Background()); err != nil {
			t.Errorf("deploy pass: %v", err)
		}
	})
	if err := r.ctl.EnsurePolicy(context.Background(), ref); err != nil {
		t.Fatalf("a registered launcher actor was refused after another DefenseClaw writer created its policy first: %v", err)
	}
	if p := r.api.Policy(ref); p == nil || p.GetMetadata().GetVersion() != 1 {
		t.Fatalf("policy %v: want the one policy the deployment wrote, confirmed", p)
	}
}

func TestGAP0182CreatePathLosesThePolicyUpdateRace(t *testing.T) {
	r := newRig(t, nil)
	a := r.actor("eng-web", "alice-0182b", ateapi.ActorStateSuspended, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	// A policy is there already (made before DefenseClaw knew the actor):
	// both writers replace it.
	if err := r.api.ForeignSetPolicy(ref, []*ateapi.EgressRule{{Https: &ateapi.HttpsRule{Hostnames: []string{"old.example.test"}}}}); err != nil {
		t.Fatal(err)
	}
	deploy := deployController(t, r)
	beforeFirst(r, "UpdateActorEgressPolicy", func() {
		if err := deploy.Reconcile(context.Background()); err != nil {
			t.Errorf("deploy pass: %v", err)
		}
	})
	if err := r.ctl.EnsurePolicy(context.Background(), ref); err != nil {
		t.Fatalf("a registered launcher actor was refused after another DefenseClaw writer updated its policy first: %v", err)
	}
	if hasHost(r.api.Policy(ref), "old.example.test") {
		t.Fatal("the old policy is still in force")
	}
}
