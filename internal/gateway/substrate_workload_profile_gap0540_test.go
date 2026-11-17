// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// GAP-0540: an actor a CI workload started ran its hook verdicts under the
// default profile: a match.substrate.workloads assignment (the profile the
// create path gave it, list and status said ops) never selected on the hook
// path, because every substrate selector was refused there. A workloads
// entry now selects the workload that started the actor; atespace and
// template selectors still never select on a hook, and a person's actor is
// not selected by a workloads entry.
func TestSubstrateWorkloadActorHooksUseItsAssignedProfileGAP0540(t *testing.T) {
	restore := identityFactsEnabled.Load()
	identityFactsEnabled.Store(true)
	t.Cleanup(func() { identityFactsEnabled.Store(restore) })

	const workloadSub = "repo:acme/ci-throwaway:ref:refs/heads/main"
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"eng": {}, "ops": {}, "pinned": {}}
	cfg.Guardrail.DefaultProfile = "eng"
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "pinned", Match: config.ProfileMatch{Substrate: &config.ProfileMatchSubstrate{Atespaces: []string{"dc-ops"}}}},
		{Profile: "ops", Match: config.ProfileMatch{Substrate: &config.ProfileMatchSubstrate{Workloads: []string{"repo:acme/ci-throwaway:*"}}}},
	}
	set, err := newGuardrailProfileSet(cfg, guardrail.NewRulePackCache(), false)
	if err != nil {
		t.Fatal(err)
	}
	const uid = "8f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4f"
	actorCtx := func(person registry.Person) context.Context {
		key, err := sandboxreg.SubstrateKey("dc-ops", uid)
		if err != nil {
			t.Fatal(err)
		}
		reg := registry.Registration{Key: key, Atespace: "dc-ops", Name: "cit1", UID: uid, Connector: "claudecode",
			Person: person, Unattended: true, Profile: "ops", CreatedAt: time.Now()}
		ctx := sandboxauth.WithRequest(context.Background(), sandboxauth.Binding{ID: key, SandboxID: uid, SandboxName: "dc-ops/cit1",
			Connector: "claudecode", RegistrationID: key}, nil)
		ctx = withSubstrateActor(ctx, verifiedSubstrateActor("dc-ops", "cit1", uid, "actor/dc-ops/cit1", key))
		ctx = context.WithValue(ctx, substrateRegistrationKey{}, reg)
		if userID, name, source, facts, ok := substrateVerifiedSubject(reg, reg.CreatedAt); ok {
			ctx = bindVerifiedSubject(ctx, VerifiedSubject{UserID: userID, IDKind: substrateSubjectIDKind, UserName: name, Directory: facts, Source: source})
		}
		return ctx
	}
	workload := registry.Person{Kind: identity.PersonWorkload, Issuer: "https://token.actions.githubusercontent.com", Subject: workloadSub}
	got := resolveGuardrailProfileFor(actorCtx(workload), set)
	if got == nil || got.decision.Name != "ops" {
		t.Fatalf("the workload actor's hook profile is %+v, want ops (its match.substrate.workloads assignment)", got)
	}
	person := registry.Person{Kind: identity.PersonHuman, Issuer: "https://idp.example", Subject: "eng1", Principal: "eng1@example.com"}
	if got := resolveGuardrailProfileFor(actorCtx(person), set); got == nil || got.decision.Name == "ops" || got.decision.Name == "pinned" {
		t.Fatalf("a person's actor got %+v; a workloads or atespace entry must not select it", got)
	}
}
