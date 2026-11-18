// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"errors"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

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

// GAP-0583 (review 2): an atespace the pass could not list kept its
// templates by the template's atespace, not the actor's. An actor's
// template can live in another atespace, so an unattested template of an
// actor in an unlisted atespace stopped counting while the actor still ran.
func TestGAP0583UnlistedAtespaceKeepsTemplatesFromOtherAtespaces(t *testing.T) {
	r := newRig(t, nil)
	r.api.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "shared-tmpl", Name: "claude"}})
	r.att.Set("shared-tmpl/claude", controller.Attestation{Reason: "no attestation for the digest", Digest: "sha256:abc"})
	a := r.api.PutActor(&ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "alice-g583x"},
		ActorTemplate: ateapi.Ref("shared-tmpl", "claude"), Status: &ateapi.ActorStatus{State: ateapi.ActorStateSuspended}})
	if err := r.reg.Put(context.Background(), controller.Registration{Atespace: "eng-web", Name: "alice-g583x", UID: a.GetMetadata().GetUid(),
		Person: "sub-alice", Profile: "eng", Source: controller.SourceLauncher}); err != nil {
		t.Fatal(err)
	}
	ref := ateapi.RefOf(a.GetMetadata())
	if err := r.ctl.EnsurePolicy(context.Background(), ref); !errors.Is(err, controller.ErrRefused) {
		t.Fatalf("err = %v", err)
	}
	r.pass()
	if n := r.ctl.UnattestedTemplates(); n != 1 {
		t.Fatalf("unattested templates = %d with the actor listed, want 1", n)
	}
	// eng-web can no longer be listed (and no global list): its actor is
	// kept, and so is its template.
	r.api.Err = func(method, key string) error {
		if method == "ListActors" && (key == "" || key == "eng-web") {
			return status.Error(codes.PermissionDenied, "denied")
		}
		return nil
	}
	r.actor("ci-runs", "job-g583x", ateapi.ActorStateSuspended, "")
	r.clk.Add(time.Second)
	r.pass()
	if n := r.ctl.UnattestedTemplates(); n != 1 {
		t.Fatalf("unattested templates = %d while the actor's atespace could not be listed, want 1", n)
	}
}
