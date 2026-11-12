// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"context"
	"os"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ateapi/ateapifake"
	"github.com/defenseclaw/defenseclaw/internal/substrate/controller"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

const wireUID1 = "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a"

// The controller sees the launcher's registration (so a launcher actor is
// not foreign), and its fork records keep the parent's person.
func TestControllerRegistryOverTheGatewayStore(t *testing.T) {
	fs, err := registry.OpenFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	person := registry.Person{Kind: identity.PersonHuman, Issuer: "https://idp", Subject: "alice"}
	if err := fs.Put(ctx, registry.Registration{Atespace: "eng-web", Name: "a1", UID: wireUID1, Person: person, Connector: "claudecode", Profile: "eng"}); err != nil {
		t.Fatal(err)
	}
	cr := &controller.LeaderRegistry{Store: fs}
	got, ok, err := cr.Get(ctx, "eng-web", wireUID1)
	if err != nil || !ok || got.Person != "alice" || got.Profile != "eng" || got.Source != controller.SourceLauncher {
		t.Fatalf("get %+v %v %v", got, ok, err)
	}
	child := "5f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4b"
	if err := cr.Put(ctx, controller.Registration{Atespace: "eng-web", Name: "a1-fork", UID: child, ParentUID: wireUID1,
		Source: controller.SourceFork, ForkedBy: controller.ForkedByDefenseClaw, Profile: "eng"}); err != nil {
		t.Fatal(err)
	}
	r, ok, _ := fs.Get(ctx, "eng-web", child)
	if !ok || r.Person.ID() != person.ID() || r.Connector != "claudecode" || r.Attributed {
		t.Fatalf("fork record %+v", r)
	}
	other := "6f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4c"
	if err := cr.Put(ctx, controller.Registration{Atespace: "team-x", Name: "x", UID: other, Source: controller.SourceAtespace}); err != nil {
		t.Fatal(err)
	}
	if r, ok, _ := fs.Get(ctx, "team-x", other); !ok || !r.Attributed || r.Person.Subject != "" {
		t.Fatalf("attributed record %+v", r)
	}
	// An approval change reaches an existing record.
	got.Approved = []string{"pypi.example.org"}
	if err := cr.Put(ctx, got); err != nil {
		t.Fatal(err)
	}
	if r, _, _ := fs.Get(ctx, "eng-web", wireUID1); len(r.Approved) != 1 {
		t.Fatalf("approved %+v", r)
	}
}

// The create path's controller writes the policy of a launcher actor
// whose registration exists, and refuses one without it.
func TestCreatePathEnsurePolicy(t *testing.T) {
	cfg := &config.Config{}
	cfg.Substrate.Enabled = true
	cfg.Substrate.Identity.Issuer = "https://idp.ate-system.svc"
	f := false
	cfg.Substrate.RequireAttestedTemplates = &f
	cfg.Substrate.LauncherAtespaces = map[string][]string{"eng": {"eng-web"}}
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"eng": {}}
	fake := ateapifake.New()
	fake.PutTemplate(&ateapi.ActorTemplate{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: "cc"}})
	fs, _ := registry.OpenFileStore(t.TempDir())
	ctl, err := newSubstrateController(cfg, fake, &controller.LeaderRegistry{Store: fs}, nil, nil, &controller.JSONSink{W: os.Stderr}, false, nil, "", nil)
	if err != nil {
		t.Fatal(err)
	}
	ensure := substrateEnsurer(ctl)
	ctx := context.Background()
	mk := func(name string) *ateapi.Actor {
		a, err := fake.CreateActor(ctx, &ateapi.Actor{Metadata: &ateapi.ResourceMetadata{Atespace: "eng-web", Name: name}, ActorTemplate: ateapi.Ref("eng-web", "cc")})
		if err != nil {
			t.Fatal(err)
		}
		return a
	}
	orphan := mk("orphan")
	_ = orphan
	if err := ensure(ctx, "eng-web", "orphan"); err == nil {
		t.Fatal("an actor without a registration got a policy")
	}
	a := mk("alice-1")
	if err := fs.Put(ctx, registry.Registration{Atespace: "eng-web", Name: "alice-1", UID: a.GetMetadata().GetUid(),
		Person: registry.Person{Kind: identity.PersonHuman, Issuer: "https://idp", Subject: "alice"}, Connector: "claudecode", Profile: "eng"}); err != nil {
		t.Fatal(err)
	}
	if err := ensure(ctx, "eng-web", "alice-1"); err != nil {
		t.Fatalf("launcher actor: %v", err)
	}
	if fake.Policy(ateapi.Ref("eng-web", "alice-1")) == nil {
		t.Fatal("no policy written")
	}
}
