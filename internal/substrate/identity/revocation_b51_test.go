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
	"encoding/json"
	"strings"
	"testing"
	"time"
)

// B5.1: a verified person says which sign-in the request came with (iat,
// jti and the deny-list key), so a revoked copy of a token can be refused.
func TestB51PersonCarriesTheSignIn(t *testing.T) {
	p := newIDP(t)
	key := p.addKey(t, "p1", "RS256")
	now := time.Unix(1_800_000_000, 0)
	clock := func() time.Time { return now }
	ks, err := NewKeySet(KeySetOptions{Issuer: p.srv.URL, HTTPClient: p.srv.Client(), Now: clock})
	if err != nil {
		t.Fatal(err)
	}
	v, err := NewPersonVerifier([]PersonIssuer{{KeySet: ks, Audience: "dc-launcher"}}, clock)
	if err != nil {
		t.Fatal(err)
	}
	hdr := map[string]any{"typ": "JWT", "alg": "RS256", "kid": "p1"}
	claims := map[string]any{"iss": p.srv.URL, "sub": "00u1", "aud": "dc-launcher", "exp": now.Unix() + 600, "iat": now.Unix() - 30, "jti": "j-1"}
	tok := sign(t, key, hdr, claims)
	got, err := v.Verify(context.Background(), tok)
	if err != nil {
		t.Fatal(err)
	}
	if got.TokenID != "j-1" || !got.IssuedAt.Equal(now.Add(-30*time.Second)) || got.TokenKey != TokenKey(p.srv.URL, "j-1", "") {
		t.Fatalf("person %+v", got)
	}
	delete(claims, "jti")
	tok2 := sign(t, key, hdr, claims)
	got2, err := v.Verify(context.Background(), tok2)
	if err != nil {
		t.Fatal(err)
	}
	if got2.TokenKey != TokenKey(p.srv.URL, "", tok2) || !strings.HasPrefix(got2.TokenKey, "clm:") || strings.Contains(got2.TokenKey, tok2) {
		t.Fatalf("a JWT without jti is keyed by a hash of its claims: %q", got2.TokenKey)
	}
	// The sign-in fields never travel with a stored person.
	b, _ := json.Marshal(got)
	if strings.Contains(string(b), "j-1") || strings.Contains(string(b), got.TokenKey) {
		t.Fatalf("stored person carries the sign-in: %s", b)
	}
}
