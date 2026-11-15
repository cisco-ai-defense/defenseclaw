// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"strings"
	"testing"
	"time"
)

// uniqueIssuer is a per-cluster actor issuer that resolves nowhere, as
// `substrate setup --issuer` and the EKS page advise (GAP-0194).
const uniqueIssuer = "https://substrate-e2.idp.invalid"

// newKeysURLFixture is newFixture with the unique issuer: ate-idp-server
// names it in its discovery document, ate-api-server puts it in iss, and
// the verifier reads the keys from the idp Service's keys URL.
func newKeysURLFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{idp: newIDP(t), now: time.Unix(1_800_000_000, 0), actors: map[string]LiveActor{}}
	f.idp.issuer = uniqueIssuer
	f.key = f.idp.addKey(t, "k1", "ES256")
	ks, err := NewKeySet(KeySetOptions{Issuer: uniqueIssuer, KeysURL: f.idp.srv.URL + "/openid/v1/jwks",
		HTTPClient: f.idp.srv.Client(), Now: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	f.ks = ks
	f.actors["team-a/agent-1"] = LiveActor{UID: "uid-1", State: ActorRunning}
	v, err := NewActorVerifier(ActorVerifierOptions{KeySet: ks, Now: f.clock, Lookup: ActorLookupFunc(
		func(_ context.Context, atespace, name string) (LiveActor, error) {
			a, ok := f.actors[atespace+"/"+name]
			if !ok {
				return LiveActor{}, ErrActorNotFound
			}
			return a, nil
		})})
	if err != nil {
		t.Fatal(err)
	}
	f.v = v
	return f
}

func uniqueIss(c map[string]any) { c["iss"] = uniqueIssuer }

func TestActorVerifierUniqueIssuerReadsTheKeysURL(t *testing.T) {
	f := newKeysURLFixture(t)
	a, err := f.v.Verify(context.Background(), f.token(t, uniqueIss))
	if err != nil {
		t.Fatalf("a token of the unique issuer was refused: %v", err)
	}
	if a.Issuer != uniqueIssuer || a.Ref() != "team-a/agent-1" || a.UID != "uid-1" {
		t.Fatalf("actor %+v", a)
	}
	if f.idp.jwksHit.Load() != 1 {
		t.Fatalf("key set fetched %d times, want 1", f.idp.jwksHit.Load())
	}
	if f.ks.KeysURL() == "" || f.ks.Issuer() != uniqueIssuer {
		t.Fatalf("key set %q %q", f.ks.Issuer(), f.ks.KeysURL())
	}
}

// The keys URL changes where the keys come from, never which tokens pass:
// iss is still compared exactly, and aud, exp, sub and the live UID still
// bind the token to one actor incarnation.
func TestActorVerifierKeysURLKeepsEveryCheck(t *testing.T) {
	f := newKeysURLFixture(t)
	cases := map[string]struct {
		mut  func(map[string]any)
		want Reason
	}{
		"the idp host as iss":    {func(c map[string]any) { c["iss"] = f.idp.srv.URL }, ReasonIssuer},
		"iss with a slash":       {func(c map[string]any) { c["iss"] = uniqueIssuer + "/" }, ReasonIssuer},
		"iss in another case":    {func(c map[string]any) { c["iss"] = strings.ToUpper(uniqueIssuer) }, ReasonIssuer},
		"another audience":       {func(c map[string]any) { uniqueIss(c); c["aud"] = []string{"someone-else"} }, ReasonAudience},
		"expired":                {func(c map[string]any) { uniqueIss(c); c["exp"] = f.now.Unix() - 3600 }, ReasonExpired},
		"sub of another actor":   {func(c map[string]any) { uniqueIss(c); c["sub"] = "actor/team-a/agent-2" }, ReasonSubject},
		"sub not an actor":       {func(c map[string]any) { uniqueIss(c); c["sub"] = "system:serviceaccount:x:y" }, ReasonSubject},
		"an older incarnation":   {func(c map[string]any) { uniqueIss(c); setUID(c, "uid-0") }, ReasonActorUID},
		"a worker-for-actor sub": {func(c map[string]any) { uniqueIss(c); c["sub"] = "worker-for-actor/team-a/agent-1" }, ReasonWorkerToken},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := f.v.Verify(context.Background(), f.token(t, tc.mut))
			wantReason(t, err, tc.want)
		})
	}
}

func setUID(c map[string]any, uid string) {
	c["actor.ate.dev"] = map[string]string{"atespace": "team-a", "actorName": "agent-1", "actorUID": uid}
}

// The fixture's discovery document is never read with a keys URL: the
// unique issuer's host does not exist.
func TestKeySetKeysURLNeedsNoDiscovery(t *testing.T) {
	f := newKeysURLFixture(t)
	f.idp.issuer = "https://someone-else.example" // discovery would refuse this
	if _, err := f.v.Verify(context.Background(), f.token(t, uniqueIss)); err != nil {
		t.Fatalf("verify read discovery: %v", err)
	}
}

// Without a keys URL the unique issuer is fetched by its own host, which
// does not resolve: the GAP-0194 failure, kept for person issuers.
func TestKeySetDiscoveryOfAnUnresolvableIssuerFails(t *testing.T) {
	ks, err := NewKeySet(KeySetOptions{Issuer: uniqueIssuer})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ks.Probe(context.Background()); ReasonOf(err) != ReasonKeysetFailed {
		t.Fatalf("probe %v, want keyset_unavailable", err)
	}
}

func TestKeySetProbeAndServedIssuer(t *testing.T) {
	f := newKeysURLFixture(t)
	f.idp.addKey(t, "k2", "ES256")
	n, err := f.ks.Probe(context.Background())
	if err != nil || n != 2 {
		t.Fatalf("probe %d %v, want 2 keys", n, err)
	}
	if f.ks.Fetches() != 0 {
		t.Fatalf("a probe counted as a request-path fetch")
	}
	got, err := f.ks.ServedIssuer(context.Background())
	if err != nil || got != uniqueIssuer {
		t.Fatalf("served issuer %q %v", got, err)
	}
	// A keys URL that answers 404 is a keyset failure the probe names.
	bad, err := NewKeySet(KeySetOptions{Issuer: uniqueIssuer, KeysURL: f.idp.srv.URL + "/nothing", HTTPClient: f.idp.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := bad.Probe(context.Background()); ReasonOf(err) != ReasonKeysetFailed || !strings.Contains(err.Error(), "404") {
		t.Fatalf("probe of a 404 keys URL: %v", err)
	}
}

func TestKeySetRefusesABadKeysURL(t *testing.T) {
	for _, u := range []string{"http://idp.ate-system.svc/openid/v1/jwks", "https:///openid/v1/jwks",
		"https://idp.ate-system.svc/openid/v1/jwks?x=1", "https://u@idp.ate-system.svc/jwks", "https://idp.ate-system.svc/jwks#k"} {
		if _, err := NewKeySet(KeySetOptions{Issuer: uniqueIssuer, KeysURL: u}); err == nil {
			t.Errorf("keys URL %q accepted", u)
		}
	}
}
