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
	"sync/atomic"
	"testing"
	"time"
)

// GAP-0793 (owner list p): an ES256 signature (r, s) has a second valid
// form (r, n-s). The verifier keeps both, since issuers that do not
// normalise s sign either way, so the copy of an ended token written with
// the other s must keep the ended token's key: a token end is looked up by
// person and key, so the copy is refused like the token. The key is over
// the jti or the verified claims, never the signature. This holds through
// the combined verifier too, and the copy never reaches the TokenReview.
func TestHighSES256CopyOfAnEndedTokenHasItsKey(t *testing.T) {
	p := newIDP(t)
	ecKey := p.addKey(t, "e1", "ES256")
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
	var reviews atomic.Int64
	pv := PersonVerifiers{OIDC: v, Kube: gap0787Kube(t, now, &reviews)}
	for _, jti := range []string{"", "j-1"} {
		claims := map[string]any{"iss": p.srv.URL, "sub": "00u1", "aud": "dc-launcher", "exp": now.Unix() + 600, "iat": now.Unix() - 30}
		prefix := "clm:"
		if jti != "" {
			claims["jti"], prefix = jti, "jti:"
		}
		tok := sign(t, ecKey, map[string]any{"typ": "JWT", "alg": "ES256", "kid": "e1"}, claims)
		ended, err := pv.Verify(context.Background(), tok)
		if err != nil || !strings.HasPrefix(ended.TokenKey, prefix) {
			t.Fatalf("jti=%q: token %+v %v", jti, ended, err)
		}
		copyTok := gap0789HighS(t, tok)
		if copyTok == tok {
			t.Fatal("the (r, n-s) copy is the token")
		}
		got, err := pv.Verify(context.Background(), copyTok)
		if err != nil {
			t.Fatalf("jti=%q: the (r, n-s) copy no longer verifies: %v", jti, err)
		}
		if got.ID() != ended.ID() || got.TokenKey != ended.TokenKey || !got.IssuedAt.Equal(ended.IssuedAt) {
			t.Fatalf("jti=%q: ended %s %s, (r, n-s) copy %s %s", jti, ended.ID(), ended.TokenKey, got.ID(), got.TokenKey)
		}
		if reviews.Load() != 0 {
			t.Fatalf("jti=%q: the copy went to the TokenReview", jti)
		}
	}
}
