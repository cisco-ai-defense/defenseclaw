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
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync/atomic"
	"testing"
	"time"
)

// GAP-0569: DefenseClaw's own token checks accepted a token for 60 s after
// its exp (the clock-skew allowance was applied to exp too), and the
// Kubernetes TokenReview answer was reused for 30 s whatever the token's
// exp. Every check now refuses a token from the second it expires; the
// skew stays on nbf and iat, for an issuer whose clock runs ahead of ours.
// These tests use only the API that existed before the fix.

func TestActorTokenRefusedTheSecondItExpiresGAP0569(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	at := func(exp int64) string {
		return f.token(t, func(c map[string]any) { c["exp"] = f.now.Unix() + exp; c["iat"] = f.now.Unix() - 900 })
	}
	if _, err := f.v.Verify(ctx, at(1)); err != nil {
		t.Fatalf("an actor token 1 s before its exp was refused: %v", err)
	}
	for _, d := range []int64{0, -1, -30} {
		_, err := f.v.Verify(ctx, at(d))
		wantReason(t, err, ReasonExpired)
	}
	// The skew still covers an issuer whose clock runs ahead: nbf and iat
	// 30 s in the future are accepted, nbf 61 s ahead is not.
	if _, err := f.v.Verify(ctx, f.token(t, func(c map[string]any) { c["nbf"] = f.now.Unix() + 30; c["iat"] = f.now.Unix() + 30 })); err != nil {
		t.Fatalf("nbf and iat inside the skew were refused: %v", err)
	}
	_, err := f.v.Verify(ctx, f.token(t, func(c map[string]any) { c["nbf"] = f.now.Unix() + 61 }))
	wantReason(t, err, ReasonNotYetValid)
}

func TestPersonAndWorkloadTokensRefusedTheSecondTheyExpireGAP0569(t *testing.T) {
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
	ctx := context.Background()
	person := func(iat, exp time.Duration) string {
		return sign(t, key, hdr, map[string]any{"iss": p.srv.URL, "sub": "00u1", "aud": "dc-launcher",
			"iat": now.Add(iat).Unix(), "exp": now.Add(exp).Unix(), "email": "alice@example.com"})
	}
	workload := func(exp time.Duration) string {
		return sign(t, key, hdr, map[string]any{"iss": p.srv.URL, "sub": "repo:acme/web:ref:refs/heads/main", "aud": "dc-ci",
			"repository": "acme/web", "iat": now.Add(-20 * time.Minute).Unix(), "exp": now.Add(exp).Unix()})
	}
	// exp: accepted 1 s before it, refused at it and after it.
	if _, err := v.Verify(ctx, person(-5*time.Minute, time.Second)); err != nil {
		t.Fatalf("a sign-in 1 s before its exp was refused: %v", err)
	}
	if _, err := v.Verify(ctx, workload(time.Second)); err != nil {
		t.Fatalf("a workload token 1 s before its exp was refused: %v", err)
	}
	for _, d := range []time.Duration{0, -time.Second, -30 * time.Second} {
		_, err := v.Verify(ctx, person(-5*time.Minute, d))
		wantReason(t, err, ReasonExpired)
		_, err = v.Verify(ctx, workload(d))
		wantReason(t, err, ReasonExpired)
	}
	// The sign-in age limit (GAP-0409) ends the same way: 1 s inside it
	// accepted, at it and 1 s past it refused.
	if _, err := v.Verify(ctx, person(-(MaxPersonSignInAge-time.Second), time.Hour)); err != nil {
		t.Fatalf("a sign-in 1 s inside the age limit was refused: %v", err)
	}
	for _, age := range []time.Duration{MaxPersonSignInAge, MaxPersonSignInAge + time.Second} {
		_, err := v.Verify(ctx, person(-age, time.Hour))
		wantReason(t, err, ReasonExpired)
	}
}

func TestSessionTokenRefusedTheSecondItExpiresGAP0569(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s, err := NewSessionSigner(key, "https://defenseclaw-admin.defenseclaw-system.svc")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	s.SetClock(func() time.Time { return now })
	tok, exp, err := s.Issue(SessionSignIn{Person: "oidc|alice", TokenKey: "jti:a"}, SessionActor{Atespace: "eng-web", Name: "alice-1", UID: "u-1"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	now = exp.Add(-time.Second)
	if _, err := s.Verify(tok); err != nil {
		t.Fatalf("a session token 1 s before its exp was refused: %v", err)
	}
	for _, d := range []time.Duration{0, time.Second, 30 * time.Second} {
		now = exp.Add(d)
		_, err := s.Verify(tok)
		wantReason(t, err, ReasonExpired)
	}
}

// kubeJWT is a JWT-shaped bearer with an exp claim. The fake API server
// below authenticates any token, as a real one does within its own leeway
// after exp.
func kubeJWT(exp int64) string {
	enc := base64.RawURLEncoding.EncodeToString
	c, _ := json.Marshal(map[string]any{"iss": "https://kubernetes.default.svc", "sub": "system:serviceaccount:ci:builder", "exp": exp})
	return enc([]byte(`{"alg":"RS256","kid":"k"}`)) + "." + enc(c) + "." + enc([]byte("sig"))
}

func TestKubeTokenAnswerEndsAtTheTokensExpGAP0569(t *testing.T) {
	var reviews atomic.Int64
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/authentication.k8s.io/v1/tokenreviews" || r.Header.Get("Authorization") != "Bearer gateway-sa" {
			w.WriteHeader(403)
			return
		}
		reviews.Add(1)
		w.WriteHeader(201)
		_ = json.NewEncoder(w).Encode(map[string]any{"status": map[string]any{"authenticated": true,
			"user": map[string]any{"username": "alice@example.com", "groups": []string{"dc-devs"}}}})
	}))
	t.Cleanup(srv.Close)
	gw := filepath.Join(t.TempDir(), "token")
	if err := os.WriteFile(gw, []byte("gateway-sa"), 0o600); err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	k := &KubeTokenVerifier{Server: srv.URL, TokenFile: gw, HTTP: srv.Client(), Now: func() time.Time { return now }}
	ctx := context.Background()

	exp := now.Add(10 * time.Second)
	tok := kubeJWT(exp.Unix())
	p, err := k.Verify(ctx, tok)
	if err != nil {
		t.Fatalf("a Kubernetes token 10 s before its exp was refused: %v", err)
	}
	if !p.Expires.Equal(exp) {
		t.Fatalf("Expires = %v, want the token's exp %v, not the end of the 30 s review cache", p.Expires, exp)
	}
	now = exp.Add(-time.Second)
	if _, err := k.Verify(ctx, tok); err != nil {
		t.Fatalf("1 s before its exp: %v", err)
	}
	for _, at := range []time.Time{exp, exp.Add(time.Second)} {
		now = at
		_, err := k.Verify(ctx, tok)
		wantReason(t, err, ReasonExpired)
	}
	// A token already past its exp is refused without a review, although
	// the API server, with its own leeway, would still authenticate it.
	before := reviews.Load()
	_, err = k.Verify(ctx, kubeJWT(now.Unix()-1))
	wantReason(t, err, ReasonExpired)
	if got := reviews.Load(); got != before {
		t.Fatalf("an expired token was sent for review (%d reviews, want %d)", got, before)
	}
	// A token that is not a JWT has no exp to read: its answer keeps the
	// 30 s review cache.
	p, err = k.Verify(ctx, "kube-opaque")
	if err != nil || !p.Expires.Equal(now.Add(kubeReviewTTL)) {
		t.Fatalf("opaque token: %+v %v", p, err)
	}
}
