// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

// GAP-0588: a relay session token never outlives the sign-in it was minted
// from. Each route that mints one (create, session-cert, attach) is called
// by a person whose sign-in ends in 2 s (the RKAUTH69 probe shape).

// signedInFor is alice with a sign-in that ends d after t0. Each test pins
// the session signer at t0, so no wall-clock window can flake.
func signedInFor(d time.Duration) (identity.Person, time.Time) {
	p := alice
	t0 := time.Now().Truncate(time.Second)
	p.Expires = t0.Add(d)
	return p, t0
}

func TestSessionCertEndsWithTheSignInGAP0588(t *testing.T) {
	p, t0 := signedInFor(2 * time.Second)
	f := newSubstrateFixture(t, func(sc *SubstrateConfig) { sc.People = fakePeople{"p-alice": p} })
	f.sessions.SetClock(func() time.Time { return t0 })
	b, _ := json.Marshal(map[string]any{"atespace": "eng-web", "name": "alice-1", "ttl_seconds": 3600})
	rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/session-cert", "p-alice", string(b))
	if rec.Code != http.StatusOK {
		t.Fatalf("session-cert: %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Token   string    `json:"token"`
		Expires time.Time `json:"expires"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil {
		t.Fatal(err)
	}
	if out.Expires.After(p.Expires) {
		t.Fatalf("the session token outlives the sign-in by %s (asked for 3600 s)", out.Expires.Sub(p.Expires).Round(time.Second))
	}
	// The token's own exp claim says the same as the answer.
	s, err := f.sessions.Verify(out.Token)
	if err != nil {
		t.Fatalf("the capped token does not verify: %v", err)
	}
	if s.Expires.After(p.Expires) {
		t.Fatalf("the token's exp %s is after the sign-in's end %s", s.Expires, p.Expires)
	}
}

func TestSessionCertRefusedWhenTheSignInEndedGAP0588(t *testing.T) {
	// The person check has passed, but the sign-in ends within this
	// second: no token can start before it ends.
	p, t0 := signedInFor(-time.Second)
	f := newSubstrateFixture(t, func(sc *SubstrateConfig) { sc.People = fakePeople{"p-alice": p} })
	f.sessions.SetClock(func() time.Time { return t0 })
	rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/session-cert", "p-alice", `{"atespace":"eng-web","name":"alice-1"}`)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("session-cert for an ended sign-in: %d %s, want 401", rec.Code, rec.Body)
	}
	if strings.Contains(rec.Body.String(), `"token"`) {
		t.Fatalf("a token was minted: %s", rec.Body)
	}
}

func TestCreateSessionTokenEndsWithTheSignInGAP0588(t *testing.T) {
	p, t0 := signedInFor(2 * time.Second)
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.People = fakePeople{"p-alice": p}
		c.Profiles = func(_ identity.Person, requested, _ string, _ bool) (string, string, error) {
			if requested != "eng" {
				return "", "", errors.New("no")
			}
			return "eng", "eng-web", nil
		}
	})
	f.sessions.SetClock(func() time.Time { return t0 })
	f.api.substrateState().cfg.Actions = &fakeActions{f: f}
	rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice", `{"profile":"eng","template":"claude-wave1","connector":"claudecode","task":"fix the tests"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create %d %s", rec.Code, rec.Body)
	}
	var out struct {
		Token   string    `json:"session_token"`
		Expires time.Time `json:"session_expires"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &out); err != nil || out.Token == "" {
		t.Fatalf("create answer has no session token: %v %s", err, rec.Body)
	}
	if out.Expires.After(p.Expires) {
		t.Fatalf("the create session token outlives the sign-in by %s", out.Expires.Sub(p.Expires).Round(time.Second))
	}
}

func TestAttachSessionTokenEndsWithTheSignInGAP0588(t *testing.T) {
	p, t0 := signedInFor(2 * time.Second)
	f := newSubstrateFixture(t, func(sc *SubstrateConfig) { sc.People = fakePeople{"p-alice": p} })
	f.sessions.SetClock(func() time.Time { return t0 })
	var mu sync.Mutex
	var exps []time.Time
	relay := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		s, err := f.sessions.Verify(strings.TrimPrefix(r.Header.Get("Authorization"), "Bearer "))
		if err != nil {
			w.WriteHeader(http.StatusUnauthorized)
			return
		}
		mu.Lock()
		exps = append(exps, s.Expires)
		mu.Unlock()
		_, _ = w.Write([]byte(`{"ok":true}`))
	}))
	defer relay.Close()
	f.api.substrateState().cfg.Relays = &dialRelay{addr: strings.TrimPrefix(relay.URL, "http://")}
	srv := httptest.NewServer(f.admin)
	defer srv.Close()
	req, _ := http.NewRequest(http.MethodGet, srv.URL+"/api/v1/substrate/actors/eng-web/alice-1/attach/status", nil)
	req.Header.Set("Authorization", "Bearer p-alice")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("attach status %d", resp.StatusCode)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(exps) != 1 {
		t.Fatalf("the relay saw %d session tokens", len(exps))
	}
	if exps[0].After(p.Expires) {
		t.Fatalf("the attach session token outlives the sign-in by %s", exps[0].Sub(p.Expires).Round(time.Second))
	}
}
