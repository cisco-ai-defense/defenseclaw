// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/render"
)

// GAP-0400 (runbook J24): a policy another writer deletes is a foreign
// change like an edit. It is restored, it is a foreign_rule row, and three
// in the window mark policy_conflict (deny-only), as edits do.
func TestGAP0400DeletedPolicyCountsAsAForeignChange(t *testing.T) {
	r := newRig(t, nil)
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	r.pass()
	want := r.api.Policy(ref)
	if len(r.sink.Events(controller.EventForeignRule)) != 0 {
		t.Fatal("the first policy is a foreign change")
	}
	deny, err := render.DenyOnly(controller.SettingsFromConfig(r.cfg))
	if err != nil {
		t.Fatal(err)
	}
	for i := 1; i <= 3; i++ {
		r.clk.Add(time.Minute)
		if _, err := r.api.DeleteActorEgressPolicy(context.Background(), ref, nil); err != nil {
			t.Fatal(err)
		}
		r.pass()
		exp := want
		if i == 3 {
			exp = deny
		}
		if got := r.api.Policy(ref); got == nil || !render.Equal(got, exp) {
			t.Fatalf("delete %d: policy = %v", i, got.GetRules())
		}
		fr := r.sink.Events(controller.EventForeignRule)
		if len(fr) != i {
			t.Fatalf("delete %d: foreign_rule events = %d, want %d", i, len(fr), i)
		}
		if d := fr[i-1].Detail; d["deleted"] != true || d["reverts_in_window"] != i {
			t.Fatalf("delete %d: foreign_rule detail = %v", i, d)
		}
	}
	conf := r.sink.Events(controller.EventPolicyConflict)
	if len(conf) != 1 || conf[0].Severity != controller.SeverityAlert {
		t.Fatalf("policy_conflict events = %+v", conf)
	}
}
