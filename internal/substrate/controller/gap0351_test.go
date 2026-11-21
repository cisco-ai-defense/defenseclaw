// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package controller_test

import (
	"context"
	"testing"
	"time"

	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

var gap0351Kit = controller.Attestation{Attested: true, Digest: digA, Connector: "claudecode", KitVersion: "1.0.10",
	AgentVersion: "2.1.317", HookContract: "claudecode-hooks-v2"}

func gap0351Reg(t *testing.T, r *rig, a *ateapi.Actor) controller.Registration {
	t.Helper()
	reg, ok, err := r.reg.Get(context.Background(), a.GetMetadata().GetAtespace(), a.GetMetadata().GetUid())
	if err != nil || !ok {
		t.Fatalf("registration: ok=%v err=%v", ok, err)
	}
	return reg
}

// substrate-1 GAP-0351: an attributed actor whose template read or
// attestation failed transiently at its first attribution gets its attested
// kit on a later pass, instead of no connector for its life. Until then it
// names none (its steps are reported unrecorded: fail closed).
func TestGAP0351AttestedKitIsRecordedOnALaterPass(t *testing.T) {
	for _, tc := range []struct {
		name  string
		blip  func(r *rig)
		clear func(r *rig)
	}{
		{"retryable attestation (registry outage)",
			func(r *rig) {
				r.att.Default = controller.Attestation{Reason: "attestation check failed: registry unreachable", Retryable: true}
			},
			func(r *rig) { r.att.Default = gap0351Kit }},
		{"template read error (ATE API blip)",
			func(r *rig) {
				r.att.Default = gap0351Kit
				r.api.Err = func(method, _ string) error {
					if method == "GetActorTemplate" {
						return status.Error(codes.Unavailable, "ate api blip")
					}
					return nil
				}
			},
			func(r *rig) { r.api.Err = nil }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			r := newRig(t, func(_ *config.Config, o *controller.Options) { o.RequireAttestation = false })
			tc.blip(r)
			a := r.actor("ci-runs", "job-1", ateapi.ActorStateRunning, "")
			r.pass()
			if reg := gap0351Reg(t, r, a); reg.Source != controller.SourceAtespace || reg.Connector != "" {
				t.Fatalf("first pass during the outage: %+v, want an attributed registration with no connector", reg)
			}
			tc.clear(r)
			r.clk.Add(time.Minute) // past the registration and template cache TTLs
			r.pass()
			reg := gap0351Reg(t, r, a)
			if reg.Connector != "claudecode" || reg.AgentVersion != "2.1.317" || reg.HookContract != "claudecode-hooks-v2" ||
				reg.KitVersion != "1.0.10" || reg.TemplateDigest != digA {
				t.Fatalf("after the outage: %+v, want the attested kit recorded", reg)
			}
		})
	}
}

// A template edited after the actor was created is not the one the actor
// booted: its attestation fills no kit (GAP-0053), and an unattested
// template never does.
func TestGAP0351NoKitFromAnEditedOrUnattestedTemplate(t *testing.T) {
	t.Run("edited after the actor was created", func(t *testing.T) {
		r := newRig(t, func(_ *config.Config, o *controller.Options) { o.RequireAttestation = false })
		r.att.Default = controller.Attestation{Reason: "attestation check failed: registry unreachable", Retryable: true}
		a := r.actor("ci-runs", "job-1", ateapi.ActorStateRunning, "")
		r.pass()
		r.clk.Add(time.Second)
		r.api.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "ci-runs", Name: "claude"}})
		r.att.Default = gap0351Kit
		r.clk.Add(time.Minute)
		r.pass()
		if reg := gap0351Reg(t, r, a); reg.Connector != "" || reg.TemplateDigest != "" {
			t.Fatalf("kit from a template edited after the actor was created: %+v", reg)
		}
	})
	t.Run("unattested", func(t *testing.T) {
		r := newRig(t, func(_ *config.Config, o *controller.Options) { o.RequireAttestation = false })
		r.att.Default = controller.Attestation{Connector: "claudecode", AgentVersion: "2.1.317"}
		a := r.actor("ci-runs", "job-1", ateapi.ActorStateRunning, "")
		r.pass()
		r.clk.Add(time.Minute)
		r.pass()
		if reg := gap0351Reg(t, r, a); reg.Connector != "" {
			t.Fatalf("kit from an unattested template: %+v", reg)
		}
	})
}

// The leader record takes the kit once, only into an attributed record that
// names none; a launcher's record and a recorded kit never change.
func TestGAP0351LeaderRecordTakesTheKitOnce(t *testing.T) {
	dir := t.TempDir()
	fs, err := registry.OpenFileStore(dir)
	if err != nil {
		t.Fatal(err)
	}
	l := &controller.LeaderRegistry{Store: fs}
	ctx := context.Background()
	const uid = "1b4e28ba-2fa1-41d2-883f-0016d3cca427"
	bare := controller.Registration{Atespace: "ci-runs", Name: "job-1", UID: uid, Source: controller.SourceAtespace}
	if err := l.Put(ctx, bare); err != nil {
		t.Fatal(err)
	}
	kit := bare
	kit.Connector, kit.AgentVersion, kit.HookContract, kit.KitVersion, kit.TemplateDigest =
		"claudecode", "2.1.317", "claudecode-hooks-v2", "1.0.10", digA
	if err := l.Put(ctx, kit); err != nil {
		t.Fatalf("kit fill: %v", err)
	}
	got, ok, err := fs.Get(ctx, "ci-runs", uid)
	if err != nil || !ok || !got.Attributed || got.Connector != "claudecode" || got.HarnessVersion != "2.1.317" ||
		got.HookContract != "claudecode-hooks-v2" || got.KitVersion != "1.0.10" || got.TemplateDigest != digA {
		t.Fatalf("leader record after the fill: %+v ok=%v err=%v", got, ok, err)
	}
	other := kit
	other.Connector, other.TemplateDigest = "codex", digB
	if err := l.Put(ctx, other); err != nil {
		t.Fatal(err)
	}
	if got, _, _ := fs.Get(ctx, "ci-runs", uid); got.Connector != "claudecode" || got.TemplateDigest != digA {
		t.Fatalf("a recorded kit changed: %+v", got)
	}
	// The store itself refuses a second connector change.
	got.Connector = "codex"
	if err := fs.Put(ctx, got); err == nil {
		t.Fatal("the file store let a recorded connector change")
	}
	// An attributed fork record (it inherits from its parent) never takes a
	// kit this way.
	const fuid = "2c5f39cb-3fb2-42e3-994d-1127e4ddb538"
	fork := registry.Registration{Atespace: "ci-runs", Name: "job-2", UID: fuid, Attributed: true, ParentUID: uid}
	if err := fs.Put(ctx, fork); err != nil {
		t.Fatal(err)
	}
	fork.Connector = "claudecode"
	if err := fs.Put(ctx, fork); err == nil {
		t.Fatal("the file store let a fork record take a connector")
	}
}
