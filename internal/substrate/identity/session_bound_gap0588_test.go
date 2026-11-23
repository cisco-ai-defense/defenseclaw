// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package identity

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// GAP-0588: a relay session token ends no later than the caller's own
// bearer.

func TestIssueUntilEndsAtTheBoundGAP0588(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s, err := NewSessionSigner(key, "https://defenseclaw-admin.defenseclaw-system.svc")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	s.SetClock(func() time.Time { return now })
	act := SessionActor{Atespace: "eng-web", Name: "alice-1", UID: "u-1"}

	// The RKAUTH69 shape: 3600 s asked, the bearer ends in 2.5 s. The
	// bound rounds down to a whole second.
	tok, exp, err := s.IssueUntil(SessionSignIn{Person: "oidc|alice", TokenKey: "jti:a"}, act, time.Hour, now.Add(2500*time.Millisecond))
	if err != nil {
		t.Fatal(err)
	}
	if want := now.Add(2 * time.Second); !exp.Equal(want) {
		t.Fatalf("exp = %v, want %v", exp, want)
	}
	if _, err := s.Verify(tok); err != nil {
		t.Fatalf("the capped token does not verify inside its life: %v", err)
	}
	now = exp
	_, err = s.Verify(tok)
	wantReason(t, err, ReasonExpired)
	now = time.Unix(1_800_000_000, 0)

	// A bound later than the ttl, or none, keeps the ttl.
	for _, bound := range []time.Time{{}, now.Add(2 * time.Hour)} {
		_, exp, err := s.IssueUntil(SessionSignIn{Person: "oidc|alice", TokenKey: "jti:a"}, act, 10*time.Minute, bound)
		if err != nil || !exp.Equal(now.Add(10*time.Minute)) {
			t.Fatalf("bound %v: exp %v %v, want the 10 m ttl", bound, exp, err)
		}
	}
	// ttl 0 is still the default, under the bound.
	if _, exp, err := s.IssueUntil(SessionSignIn{Person: "oidc|alice", TokenKey: "jti:a"}, act, 0, now.Add(time.Hour)); err != nil || !exp.Equal(now.Add(DefaultSessionLifetime)) {
		t.Fatalf("default ttl: %v %v", exp, err)
	}
	// No whole second left, or a bound already past: no token.
	for _, bound := range []time.Time{now.Add(500 * time.Millisecond), now, now.Add(-time.Minute)} {
		if tok, _, err := s.IssueUntil(SessionSignIn{Person: "oidc|alice", TokenKey: "jti:a"}, act, time.Hour, bound); !errors.Is(err, ErrSessionBound) || tok != "" {
			t.Fatalf("bound %v: token %q err %v, want ErrSessionBound", bound.Sub(now), tok, err)
		}
	}
}

func TestSessionBoundPerCallerKindGAP0588(t *testing.T) {
	end := time.Unix(1_800_000_600, 0)
	for _, kind := range []string{PersonHuman, PersonWorkload} {
		if got := (Person{Kind: kind, Expires: end}).SessionBound(); !got.Equal(end) {
			t.Fatalf("%s: SessionBound %v, want Expires %v", kind, got, end)
		}
	}
	// A Kubernetes caller's Expires is the review cache: never the bound.
	cache := time.Unix(1_800_000_030, 0)
	if got := (Person{Kind: PersonKube, Expires: cache}).SessionBound(); !got.IsZero() {
		t.Fatalf("opaque Kubernetes token: SessionBound %v, want none", got)
	}
	if got := (Person{Kind: PersonKube, Expires: cache, TokenExpires: end}).SessionBound(); !got.Equal(end) {
		t.Fatalf("Kubernetes JWT: SessionBound %v, want its exp %v", got, end)
	}
}

func TestKubeCallerCarriesItsTokenExpGAP0588(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/apis/authentication.k8s.io/v1/tokenreviews" || r.Header.Get("Authorization") != "Bearer gateway-sa" {
			w.WriteHeader(403)
			return
		}
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

	// A token with an hour left: Expires is the 30 s review cache, the
	// token's own end is TokenExpires, and SessionBound is that end.
	exp := now.Add(time.Hour)
	tok := kubeJWT(exp.Unix())
	for i := 0; i < 2; i++ { // the review, then the cached answer
		p, err := k.Verify(ctx, tok)
		if err != nil {
			t.Fatal(err)
		}
		if !p.Expires.Equal(now.Add(kubeReviewTTL)) || !p.TokenExpires.Equal(exp) || !p.SessionBound().Equal(exp) {
			t.Fatalf("verify %d: Expires %v TokenExpires %v SessionBound %v", i, p.Expires, p.TokenExpires, p.SessionBound())
		}
	}
	// An opaque token has no exp: no bound, so a session keeps its own
	// cap, never the cache time.
	p, err := k.Verify(ctx, "kube-opaque")
	if err != nil || !p.TokenExpires.IsZero() || !p.SessionBound().IsZero() {
		t.Fatalf("opaque token: %+v %v", p, err)
	}
}
