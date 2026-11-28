// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// GAP-0485: the hook and model records of a verified Substrate actor name
// the person or CI workload the launcher bound to it, with
// defenseclaw.user.identity.source (workload_oidc for a pipeline) and a
// verified principal assurance, never the gateway pod's own account. An
// actor with no bound person has no user.
func TestSubstrateActorRecordsCarryTheBoundWorkloadGAP0485(t *testing.T) {
	restoreFacts, restorePrincipal := identityFactsEnabled.Load(), userPrincipalCollectionEnabled.Load()
	identityFactsEnabled.Store(true)
	userPrincipalCollectionEnabled.Store(true)
	t.Cleanup(func() {
		identityFactsEnabled.Store(restoreFacts)
		userPrincipalCollectionEnabled.Store(restorePrincipal)
	})

	const uid = "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a"
	actorCtx := func(person registry.Person, attributed bool) context.Context {
		key, err := sandboxreg.SubstrateKey("dc-ci", uid)
		if err != nil {
			t.Fatal(err)
		}
		reg := registry.Registration{Key: key, Atespace: "dc-ci", Name: "cit1", UID: uid, Connector: "claudecode",
			Person: person, Attributed: attributed, Unattended: true, CreatedAt: time.Now()}
		ctx := sandboxauth.WithRequest(context.Background(), sandboxauth.Binding{ID: key, SandboxID: uid, SandboxName: "dc-ci/cit1",
			Connector: "claudecode", RegistrationID: key}, nil)
		ctx = withSubstrateActor(ctx, verifiedSubstrateActor("dc-ci", "cit1", uid, "actor/dc-ci/cit1", key))
		ctx = context.WithValue(ctx, substrateRegistrationKey{}, reg)
		if userID, name, source, facts, ok := substrateVerifiedSubject(reg, reg.CreatedAt); ok {
			ctx = bindVerifiedSubject(ctx, VerifiedSubject{UserID: userID, IDKind: substrateSubjectIDKind, UserName: name, Directory: facts, Source: source})
		}
		return ctx
	}
	workload := registry.Person{Kind: identity.PersonWorkload, Issuer: "https://t-oidc.t.svc", Subject: "system:serviceaccount:t:ci-workload",
		Principal: "system:serviceaccount:t:ci-workload"}
	ctx := actorCtx(workload, false)
	req := httptest.NewRequest("POST", "/llm/bedrock/model/x/converse", nil).WithContext(ctx)
	for name, user := range map[string]llmEventUser{
		"hook":  resolveHookUserIdentity(ctx, "claudecode", nil),
		"model": resolveHTTPUserIdentity(req, nil),
	} {
		if user.ID != workload.Subject || user.IDKind != substrateSubjectIDKind {
			t.Errorf("%s record user %q (%s), want the bound workload %q (%s)", name, user.ID, user.IDKind, workload.Subject, substrateSubjectIDKind)
			continue
		}
		attrs := user.Identity.v8()
		source, _ := attrs.Source.Get()
		assurance, _ := attrs.Assurance.Get()
		principal, _ := attrs.Principal.Get()
		if source != "workload_oidc" || assurance != "verified" || principal != workload.Principal {
			t.Errorf("%s record identity source %q assurance %q principal %q, want workload_oidc, verified and the workload", name, source, assurance, principal)
		}
	}
	// An actor made outside DefenseClaw has no person: no user at all, not
	// the gateway's own account.
	if user := resolveHookUserIdentity(actorCtx(registry.Person{}, true), "claudecode", nil); user.ID != "" || user.Name != "" {
		t.Errorf("attributed actor's record user %q/%q, want none", user.ID, user.Name)
	}
}
