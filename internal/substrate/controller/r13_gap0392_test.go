// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/configwatch"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

func lastLagMS(t *testing.T, r *rig) int64 {
	t.Helper()
	ev := r.sink.Events(controller.EventPolicyWritten)
	if len(ev) == 0 {
		t.Fatal("no sandbox.policy.written event")
	}
	ms, ok := ev[len(ev)-1].Detail["policy_lag_ms"].(int64)
	if !ok {
		t.Fatalf("policy_lag_ms = %#v", ev[len(ev)-1].Detail["policy_lag_ms"])
	}
	return ms
}

// GAP-0392: policy_lag_ms of a rewrite is the time from the change (as the
// controller saw it) to the write, not the actor's age.
func TestGAP0392PolicyLagIsFromTheChangeNotTheActorAge(t *testing.T) {
	r := newLiveRig(t)
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	if got := lastLagMS(t, r.rig); got != 0 {
		t.Fatalf("first policy: policy_lag_ms = %d, want 0 (written on the pass that saw the actor)", got)
	}

	// A config change an hour into the actor's life: written on the pass
	// that applies it.
	r.clk.Add(time.Hour)
	r.cm.set("v2", j9Config(func(c *config.Config) { c.Substrate.Egress.Allow = without(c.Substrate.Egress.Allow, j9Host) }))
	r.pass()
	if got := lastLagMS(t, r.rig); got != 0 {
		t.Fatalf("config change: policy_lag_ms = %d, want 0 (the actor age is %s)", got, time.Hour)
	}

	// A foreign change, reverted on the next pass.
	r.clk.Add(time.Hour)
	if err := r.api.ForeignSetPolicy(ref, nil); err != nil {
		t.Fatal(err)
	}
	r.pass()
	if got := lastLagMS(t, r.rig); got != 0 {
		t.Fatalf("revert: policy_lag_ms = %d, want 0", got)
	}

	// A config change whose first write fails: the lag runs from when the
	// change was applied to the write that lands.
	r.clk.Add(time.Hour)
	failing := true
	r.api.Err = func(method, _ string) error {
		if failing && method == "UpdateActorEgressPolicy" {
			return errors.New("unavailable")
		}
		return nil
	}
	r.cm.set("v1", nil)
	r.clk.Add(configwatch.DefaultInterval)
	_ = r.ctl.Reconcile(context.Background())
	failing = false
	r.clk.Add(30 * time.Second)
	r.pass()
	if !r.policyHas(ref, j9Host) {
		t.Fatal("the restored host is not in the policy")
	}
	if got := lastLagMS(t, r.rig); got != 30_000 {
		t.Fatalf("retried write: policy_lag_ms = %d, want 30000", got)
	}
}
