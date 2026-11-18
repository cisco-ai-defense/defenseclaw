// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// GAP-0583: the unattested-templates gauge counted every template verdict
// the controller had cached, and the cache never dropped a template, so
// after the last actor of an unattested template was deleted the gauge
// (and the DefenseClawUnattestedTemplates alert) stayed up until a
// controller restart. Only templates of the actors the last pass listed
// count now.
func TestGAP0583UnattestedTemplatesCountsOnlyTemplatesInUse(t *testing.T) {
	r := newRig(t, nil)
	r.att.Set("eng-web/claude", controller.Attestation{Reason: "no attestation for the digest", Digest: "sha256:abc"})
	a := r.actor("eng-web", "alice-g583", ateapi.ActorStateSuspended, "sub-alice")
	ref := ateapi.RefOf(a.GetMetadata())
	if err := r.ctl.EnsurePolicy(context.Background(), ref); !errors.Is(err, controller.ErrRefused) {
		t.Fatalf("err = %v", err)
	}
	r.pass()
	if n := r.ctl.UnattestedTemplates(); n != 1 {
		t.Fatalf("unattested templates = %d with the actor running, want 1", n)
	}
	if _, err := r.api.DeleteActor(context.Background(), ref, nil); err != nil {
		t.Fatal(err)
	}
	r.clk.Add(time.Second)
	r.pass()
	if n := r.ctl.UnattestedTemplates(); n != 0 {
		t.Fatalf("unattested templates = %d after the template's last actor was deleted, want 0", n)
	}
}
