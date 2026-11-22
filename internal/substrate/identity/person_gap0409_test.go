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
	"testing"
	"time"
)

// GAP-0409: after logout a copied sign-in token worked on the admin listener
// until its exp (60 to 90 minutes on some issuers). A person sign-in is
// accepted only while it is younger than MaxPersonSignInAge, whatever its
// exp says; a CI workload token keeps its exp.
func TestPersonSignInAgeLimitGAP0409(t *testing.T) {
	p := newIDP(t)
	key := p.addKey(t, "p1", "RS256")
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }
	ks, err := NewKeySet(KeySetOptions{Issuer: p.srv.URL, HTTPClient: p.srv.Client(), Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewPersonVerifier([]PersonIssuer{
		{KeySet: ks, Audience: "dc-launcher"},
		{KeySet: ks, Audience: "dc-ci", Kind: PersonWorkload, Binding: WorkloadBinding{Claims: map[string]string{"repository": "acme/web"}}},
	}, clock)
	if err != nil {
		t.Fatal(err)
	}
	hdr := map[string]any{"typ": "JWT", "alg": "RS256", "kid": "p1"}
	person := func(age time.Duration) string {
		iat := now.Add(-age).Unix()
		return sign(t, key, hdr, map[string]any{"iss": p.srv.URL, "sub": "00u1", "aud": "dc-launcher",
			"iat": iat, "exp": now.Add(time.Hour).Unix(), "email": "alice@example.com"})
	}

	// Issued 20 minutes ago, exp an hour ahead: refused as expired, the
	// reason the admin listener's refusal rows count (GAP-0408).
	_, err = v.Verify(context.Background(), person(20*time.Minute))
	wantReason(t, err, ReasonExpired)

	// Issued 5 minutes ago: accepted, and it expires 10 minutes from now
	// (iat + 15m), not at its exp.
	got, err := v.Verify(context.Background(), person(5*time.Minute))
	if err != nil {
		t.Fatalf("a 5-minute-old sign-in was refused: %v", err)
	}
	if want := now.Add(10 * time.Minute); !got.Expires.Equal(want) {
		t.Fatalf("Expires = %v, want %v", got.Expires, want)
	}

	// One second inside the limit: accepted. The limit has no skew grace
	// (GAP-0569, TestPersonAndWorkloadTokensRefusedTheSecondTheyExpireGAP0569).
	if _, err := v.Verify(context.Background(), person(MaxPersonSignInAge-time.Second)); err != nil {
		t.Fatalf("a sign-in inside the age limit was refused: %v", err)
	}

	// A CI workload token issued 20 minutes ago with a valid exp: accepted.
	wl := sign(t, key, hdr, map[string]any{"iss": p.srv.URL, "sub": "repo:acme/web:ref:refs/heads/main", "aud": "dc-ci",
		"repository": "acme/web", "iat": now.Add(-20 * time.Minute).Unix(), "exp": now.Add(40 * time.Minute).Unix()})
	got, err = v.Verify(context.Background(), wl)
	if err != nil || got.Kind != PersonWorkload {
		t.Fatalf("a 20-minute-old workload token: %+v %v", got, err)
	}
	if want := now.Add(40 * time.Minute); !got.Expires.Equal(want) {
		t.Fatalf("workload Expires = %v, want its exp %v", got.Expires, want)
	}
}
