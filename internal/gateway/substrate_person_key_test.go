// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"regexp"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/modelusage"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

func substrateActorCallContext(t *testing.T, p identity.Person, name, uid string) context.Context {
	t.Helper()
	reg := registry.Registration{Atespace: "eng-web", Name: name, UID: uid, Connector: "claudecode", Profile: "eng", Person: ownerOf(p)}
	key, err := sandboxreg.SubstrateKey(reg.Atespace, reg.UID)
	if err != nil {
		t.Fatal(err)
	}
	reg.Key = key
	ctx := withSubstrateActor(context.Background(), verifiedSubstrateActor(reg.Atespace, reg.Name, reg.UID, "actor/eng-web/"+name, key))
	ctx = context.WithValue(ctx, substrateRegistrationKey{}, reg)
	return (*APIServer)(nil).attachSubstrateSubject(ctx, reg)
}

// TestSubstrateCallerKeyIncludesIssuer: the routing charge key and the
// usage owner of an actor call are its person's sha256(issuer#subject)
// key, so one subject at two issuers is two people, and the bare subject
// is not the key (D4-4).
func TestSubstrateCallerKeyIncludesIssuer(t *testing.T) {
	prev := identityFactsEnabled.Load()
	t.Cleanup(func() { setIdentityFactsEnabled(prev) })
	setIdentityFactsEnabled(true)

	atA := identity.Person{Kind: identity.PersonHuman, Issuer: "https://idp-a.example", Subject: "alice", Principal: "alice@example.com"}
	atB := atA
	atB.Issuer = "https://idp-b.example"
	ctxA := substrateActorCallContext(t, atA, "fix-login", "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a")
	ctxB := substrateActorCallContext(t, atB, "fix-login", "5f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4b")

	callerA, _ := routeCallerFromContext(ctxA)
	callerB, _ := routeCallerFromContext(ctxB)
	if !callerA.Verified || !callerB.Verified {
		t.Fatal("an actor with a bound person must be a verified caller")
	}
	if callerA.Key == callerB.Key {
		t.Fatalf("one subject at two issuers shares the charge key %q", callerA.Key)
	}
	re := regexp.MustCompile(`^p:[0-9a-f]{16}$`)
	for _, k := range []string{callerA.Key, callerB.Key} {
		if !re.MatchString(k) || strings.Contains(k, "alice") {
			t.Fatalf("charge key %q: want the pseudonymous person key", k)
		}
	}

	var fA, fB modelusage.CallFacts
	usageIdentity(ctxA, &fA)
	usageIdentity(ctxB, &fB)
	ownerA, ownerB := modelusage.OwnerID(fA), modelusage.OwnerID(fB)
	if ownerA == "" || ownerA == ownerB || strings.Contains(ownerA, "alice") {
		t.Fatalf("usage owners %q and %q: want two pseudonymous owners", ownerA, ownerB)
	}
	// The second actor of the same person is the same owner and key.
	ctxA2 := substrateActorCallContext(t, atA, "fix-tests", "6f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4c")
	callerA2, _ := routeCallerFromContext(ctxA2)
	var fA2 modelusage.CallFacts
	usageIdentity(ctxA2, &fA2)
	if callerA2.Key != callerA.Key || modelusage.OwnerID(fA2) != ownerA {
		t.Fatal("two actors of one person must share the person key and usage owner")
	}

	// A host caller keeps its own subject key.
	host := attachVerifiedSubjectFacts(context.Background(), nil, "1001", "posix_uid", "alice", "kernel_peer", useridentity.DirectoryFacts{})
	if c, _ := routeCallerFromContext(host); c.Key != "1001" {
		t.Fatalf("host caller key %q, want 1001", c.Key)
	}
}

// TestSubstrateRouteActorFromRegistration: routing.admin reads an actor
// call's registration key and match.substrate facts from the verified
// registration (never headers); a workload actor names its workload, and a
// host call has no actor.
func TestSubstrateRouteActorFromRegistration(t *testing.T) {
	prev := identityFactsEnabled.Load()
	t.Cleanup(func() { setIdentityFactsEnabled(prev) })
	setIdentityFactsEnabled(true)

	human := identity.Person{Kind: identity.PersonHuman, Issuer: "https://idp-a.example", Subject: "alice"}
	caller, _ := routeCallerFromContext(substrateActorCallContext(t, human, "fix-login", "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a"))
	if a := caller.Actor; a == nil || !a.Person || a.Atespace != "eng-web" || a.Workload != "" || !strings.HasPrefix(a.Key, sandboxreg.SubstrateKeyPrefix) {
		t.Fatalf("person actor facts = %+v", a)
	}
	workload := identity.Person{Kind: identity.PersonWorkload, Issuer: "https://k8s.example", Subject: "system:serviceaccount:ci:runner"}
	caller, _ = routeCallerFromContext(substrateActorCallContext(t, workload, "nightly", "5f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4b"))
	if a := caller.Actor; a == nil || !a.Person || a.Workload != workload.Subject {
		t.Fatalf("workload actor facts = %+v", a)
	}
	if c, _ := routeCallerFromContext(context.Background()); c.Actor != nil {
		t.Fatalf("a host call has an actor: %+v", c.Actor)
	}
}
