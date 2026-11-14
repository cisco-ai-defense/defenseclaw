// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
)

// imageAttestor attests a template only when every container runs good.
type imageAttestor struct{ good string }

func (a imageAttestor) Attest(_ context.Context, t *ateapi.ActorTemplate) (controller.Attestation, error) {
	for _, c := range t.GetContainers() {
		if c.GetImage() != a.good {
			return controller.Attestation{Reason: "no DefenseClaw attestation for " + c.GetImage()}, nil
		}
	}
	return controller.Attestation{Attested: true, KitVersion: "1.0.10"}, nil
}

const (
	f6Good = "reg.example.com/dc/claude@" + digA
	f6Bad  = "reg.example.com/evil/claude@" + digB
)

// f6Rig is the rig with the image attestor; opts is kept for a restart.
func f6Rig(t *testing.T) (*rig, *controller.Options) {
	t.Helper()
	var saved *controller.Options
	r := newRig(t, func(_ *config.Config, o *controller.Options) {
		o.Attestor = imageAttestor{good: f6Good}
		saved = o
	})
	r.api.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "claude"},
		Containers: []*ateapi.Container{{Name: "agent", Image: f6Good}}})
	r.tmpls["eng-web"] = true
	return r, saved
}

func (r *rig) setImage(image string) {
	r.api.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "claude"},
		Containers: []*ateapi.Container{{Name: "agent", Image: image}}})
}

// GAP-0053: an editor swaps the template's image, starts an actor and swaps
// the image back, all inside the controller's 30 s template cache and
// before its next poll. The actor booted the unattested image; the
// template the controller reads is attested again. It must get no network.
func TestGAP0053ImageSwapAndRevertInsideTheCacheWindow(t *testing.T) {
	r, _ := f6Rig(t)
	before := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	r.pass()
	if r.api.Policy(ateapi.RefOf(before.GetMetadata())) == nil {
		t.Fatal("the attested actor got no policy")
	}
	r.clk.Add(time.Second)
	r.setImage(f6Bad)
	r.clk.Add(100 * time.Millisecond)
	swapped := r.actor("eng-web", "alice-2", ateapi.ActorStateRunning, "sub-alice")
	r.clk.Add(100 * time.Millisecond)
	r.setImage(f6Good)
	r.clk.Add(time.Second)
	r.pass()
	if r.api.Policy(ateapi.RefOf(swapped.GetMetadata())) != nil {
		t.Fatal("an actor started on a swapped image was admitted from the cache")
	}
	found := false
	for _, ev := range r.sink.Events(controller.EventTemplateUnverified) {
		if ev.ActorUID == swapped.GetMetadata().GetUid() && strings.Contains(ev.Message, "changed after the actor was created") {
			found = true
		}
	}
	if !found {
		t.Fatalf("no template_unverified event naming the edit: %+v", r.sink.Events(controller.EventTemplateUnverified))
	}
	// The actor admitted before the edit keeps its policy, and one made
	// after the revert is admitted.
	if r.api.Policy(ateapi.RefOf(before.GetMetadata())) == nil {
		t.Fatal("an actor admitted before the edit lost its policy")
	}
	r.clk.Add(time.Second)
	after := r.actor("eng-web", "alice-3", ateapi.ActorStateRunning, "sub-alice")
	r.pass()
	if r.api.Policy(ateapi.RefOf(after.GetMetadata())) == nil {
		t.Fatal("an actor made after the revert was refused")
	}
}

// GAP-0053: a swap that is not reverted is seen at the first admission of
// a new actor, inside the cache window: the template is read fresh.
func TestGAP0053FirstAdmissionReadsTheTemplateFresh(t *testing.T) {
	r, _ := f6Rig(t)
	r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	r.pass()
	r.clk.Add(time.Second)
	r.setImage(f6Bad)
	r.clk.Add(time.Second)
	a := r.actor("eng-web", "alice-2", ateapi.ActorStateRunning, "sub-alice")
	r.pass()
	if r.api.Policy(ateapi.RefOf(a.GetMetadata())) != nil {
		t.Fatal("a new actor on a swapped template was admitted from the cached verdict")
	}
}

// A controller restart after a legitimate template update keeps the
// policies of actors a controller admitted before (they carry a DefenseClaw
// policy); the boot check never cuts running actors on a restart.
func TestGAP0053RestartKeepsActorsAdmittedBeforeAnUpdate(t *testing.T) {
	r, opts := f6Rig(t)
	a := r.actor("eng-web", "alice-1", ateapi.ActorStateRunning, "sub-alice")
	r.pass()
	ref := ateapi.RefOf(a.GetMetadata())
	if r.api.Policy(ref) == nil {
		t.Fatal("no policy")
	}
	r.clk.Add(time.Minute)
	r.setImage(f6Good) // a new template version, same attested image
	ctl, err := controller.New(*opts)
	if err != nil {
		t.Fatal(err)
	}
	r.ctl = ctl
	r.clk.Add(time.Second)
	r.pass()
	if r.api.Policy(ref) == nil {
		t.Fatal("a restart removed the policy of an actor admitted before the update")
	}
}
