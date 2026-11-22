// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// GAP-0418, GAP-0422: a Substrate actor's hooks carry an agent identity
// (agt-) derived from the verified person and connector, so one person's
// agents of one connector share it on every actor, and a session's instance
// (ais-) is the same whichever gateway replica answers. An actor with no
// bound person gets one per atespace and connector.
func TestSubstrateActorAgentIdentityIsPerPersonAndConnectorGAP0418(t *testing.T) {
	eng1 := registry.Person{Kind: identity.PersonHuman, Issuer: "https://idp.example", Subject: "eng1", Principal: "eng1@example.com"}
	eng2 := registry.Person{Kind: identity.PersonHuman, Issuer: "https://idp.example", Subject: "eng2", Principal: "eng2@example.com"}
	uids := []string{"4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a", "5f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4b", "6f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4c"}
	id := func(atespace string, n int, person registry.Person, connector string) agentIdentityFacts {
		t.Helper()
		name := "a" + string(rune('0'+n))
		key, err := sandboxreg.SubstrateKey(atespace, uids[n])
		if err != nil {
			t.Fatal(err)
		}
		reg := registry.Registration{Key: key, Atespace: atespace, Name: name, UID: uids[n], Connector: connector, Person: person}
		ctx := withSubstrateActor(context.Background(), verifiedSubstrateActor(atespace, name, uids[n], "actor/"+atespace+"/"+name, key))
		ctx = context.WithValue(ctx, substrateRegistrationKey{}, reg)
		return resolveHookAgentIdentity(ctx, agentHookRequest{ConnectorName: connector, SessionID: "s-1"})
	}
	a := id("dc-eng", 0, eng1, "claudecode")
	b := id("dc-eng", 1, eng1, "claudecode")
	if !strings.HasPrefix(a.ID, "agt-") || a.ID != b.ID {
		t.Fatalf("one person's two claudecode actors: %q and %q, want one agt- id", a.ID, b.ID)
	}
	if other := id("dc-eng", 2, eng2, "claudecode"); other.ID == a.ID || other.ID == "" {
		t.Errorf("another person got %q (eng1 %q)", other.ID, a.ID)
	}
	if codex := id("dc-eng", 2, eng1, "codex"); codex.ID == a.ID || codex.ID == "" {
		t.Errorf("another connector got %q (claudecode %q)", codex.ID, a.ID)
	}
	if !a.Verified {
		t.Error("a launcher actor's identity is not marked verified")
	}
	x := id("l5-other", 0, registry.Person{}, "claudecode")
	y := id("l5-other", 1, registry.Person{}, "claudecode")
	z := id("l5-third", 2, registry.Person{}, "claudecode")
	if x.ID == "" || x.ID != y.ID || z.ID == x.ID || x.ID == a.ID || x.Verified {
		t.Errorf("atespace-only actors: %q %q (same atespace), %q (other), verified %v; person actor %q", x.ID, y.ID, z.ID, x.Verified, a.ID)
	}
	// Two replicas mint the same session instance for one actor's session.
	r1, r2 := NewAgentRegistry("", ""), NewAgentRegistry("", "")
	i1 := r1.AgentInstanceFor(a.ID, "5c75a8ea-session")
	i2 := r2.AgentInstanceFor(b.ID, "5c75a8ea-session")
	if !strings.HasPrefix(i1, "ais-") || i1 != i2 {
		t.Errorf("replicas gave %q and %q for one session", i1, i2)
	}
}

// GAP-0514: the agent identity follows the connector the actor is
// registered with, not the connector a hook request names.
func TestSubstrateAgentIdentityUsesTheRegisteredConnectorGAP0514(t *testing.T) {
	eng1 := registry.Person{Kind: identity.PersonHuman, Issuer: "https://idp.example", Subject: "eng1", Principal: "eng1@example.com"}
	const uid = "7f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4d"
	key, err := sandboxreg.SubstrateKey("dc-eng", uid)
	if err != nil {
		t.Fatal(err)
	}
	reg := registry.Registration{Key: key, Atespace: "dc-eng", Name: "a9", UID: uid, Connector: "claudecode", Person: eng1}
	ctx := withSubstrateActor(context.Background(), verifiedSubstrateActor("dc-eng", "a9", uid, "actor/dc-eng/a9", key))
	ctx = context.WithValue(ctx, substrateRegistrationKey{}, reg)
	own := resolveHookAgentIdentity(ctx, agentHookRequest{ConnectorName: "claudecode", SessionID: "s-1"})
	named := resolveHookAgentIdentity(ctx, agentHookRequest{ConnectorName: "codex", SessionID: "s-1"})
	if own.ID == "" || named.ID != own.ID || named.Connector != "claudecode" {
		t.Fatalf("a request naming codex for a claudecode actor got %q (%s), want the claudecode identity %q", named.ID, named.Connector, own.ID)
	}
}
