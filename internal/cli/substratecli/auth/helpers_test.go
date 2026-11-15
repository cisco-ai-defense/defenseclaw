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

package auth

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

// testJWT builds an unsigned JWT-shaped string with the given claims and
// a marker that tests look for in errors.
func testJWT(t *testing.T, marker string, c map[string]any) string {
	t.Helper()
	cc := map[string]any{"marker": marker}
	for k, v := range c {
		cc[k] = v
	}
	b, err := json.Marshal(cc)
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	return enc([]byte(`{"alg":"none"}`)) + "." + enc(b) + "." + enc([]byte("sig-"+marker))
}

// fakeIdP is an OIDC issuer with the device flow, refresh and revocation.
type fakeIdP struct {
	t   *testing.T
	srv *httptest.Server

	mu          sync.Mutex
	issuerName  string   // what discovery says; "" = the server URL
	noDevice    bool     // discovery without device_authorization_endpoint
	steps       []string // device poll answers: pending, slow_down, denied, expired, ok
	polls       int
	deviceForms []map[string]string
	tokenOK     map[string]any // body of the success answer
	refreshes   int
	refreshFn   func(form map[string]string) (int, map[string]any)
	revoked     []string
	completeURI bool
}

func newFakeIdP(t *testing.T) *fakeIdP {
	f := &fakeIdP{t: t, completeURI: true}
	mux := http.NewServeMux()
	mux.HandleFunc("/realms/r/.well-known/openid-configuration", func(w http.ResponseWriter, r *http.Request) {
		f.mu.Lock()
		defer f.mu.Unlock()
		iss := f.issuerName
		if iss == "" {
			iss = f.issuer()
		}
		doc := map[string]any{
			"issuer":              iss,
			"token_endpoint":      f.srv.URL + "/token",
			"revocation_endpoint": f.srv.URL + "/revoke",
		}
		if !f.noDevice {
			doc["device_authorization_endpoint"] = f.srv.URL + "/device"
		}
		writeJSON(w, 200, doc)
	})
	mux.HandleFunc("/device", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		defer f.mu.Unlock()
		f.deviceForms = append(f.deviceForms, flat(r))
		ans := map[string]any{
			"device_code":      "devcode-marker-0001",
			"user_code":        "ABCD-EFGH",
			"verification_uri": f.srv.URL + "/activate",
			"expires_in":       600,
			"interval":         5,
		}
		if f.completeURI {
			ans["verification_uri_complete"] = f.srv.URL + "/activate?user_code=ABCD-EFGH"
		}
		writeJSON(w, 200, ans)
	})
	mux.HandleFunc("/token", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		form := flat(r)
		f.mu.Lock()
		defer f.mu.Unlock()
		switch form["grant_type"] {
		case deviceGrant:
			step := "pending"
			if f.polls < len(f.steps) {
				step = f.steps[f.polls]
			}
			f.polls++
			switch step {
			case "ok":
				writeJSON(w, 200, f.tokenOK)
			case "slow_down":
				writeJSON(w, 400, map[string]any{"error": "slow_down"})
			case "denied":
				writeJSON(w, 400, map[string]any{"error": "access_denied"})
			case "expired":
				writeJSON(w, 400, map[string]any{"error": "expired_token"})
			case "echo":
				writeJSON(w, 400, map[string]any{"error": "invalid_request", "error_description": "bad device_code " + form["device_code"]})
			case "weird":
				writeJSON(w, 400, map[string]any{"error": "invalid_client", "error_description": "client not allowed"})
			default:
				writeJSON(w, 400, map[string]any{"error": "authorization_pending"})
			}
		case "refresh_token":
			f.refreshes++
			if f.refreshFn == nil {
				writeJSON(w, 400, map[string]any{"error": "invalid_grant"})
				return
			}
			code, body := f.refreshFn(form)
			writeJSON(w, code, body)
		default:
			writeJSON(w, 400, map[string]any{"error": "unsupported_grant_type"})
		}
	})
	mux.HandleFunc("/revoke", func(w http.ResponseWriter, r *http.Request) {
		_ = r.ParseForm()
		f.mu.Lock()
		f.revoked = append(f.revoked, r.Form.Get("token"))
		f.mu.Unlock()
		w.WriteHeader(200)
	})
	f.srv = httptest.NewServer(mux)
	t.Cleanup(f.srv.Close)
	return f
}

func (f *fakeIdP) issuer() string { return f.srv.URL + "/realms/r" }

func (f *fakeIdP) context() Context {
	return Context{AdminURL: "https://admin.example.test:8443", Issuer: f.issuer(), ClientID: "defenseclaw-launcher"}
}

func flat(r *http.Request) map[string]string {
	m := map[string]string{}
	for k, v := range r.Form {
		if len(v) > 0 {
			m[k] = v[0]
		}
	}
	return m
}

func writeJSON(w http.ResponseWriter, code int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(code)
	_ = json.NewEncoder(w).Encode(v)
}

// fakeClock advances only when the device loop sleeps.
type fakeClock struct {
	mu     sync.Mutex
	now    time.Time
	sleeps []time.Duration
}

func newClock() *fakeClock { return &fakeClock{now: time.Unix(1_900_000_000, 0)} }

func (c *fakeClock) Now() time.Time { c.mu.Lock(); defer c.mu.Unlock(); return c.now }

func (c *fakeClock) Sleep(ctx context.Context, d time.Duration) error {
	if err := ctx.Err(); err != nil {
		return err
	}
	c.mu.Lock()
	defer c.mu.Unlock()
	c.sleeps = append(c.sleeps, d)
	c.now = c.now.Add(d)
	return nil
}

func (c *fakeClock) Add(d time.Duration) { c.mu.Lock(); c.now = c.now.Add(d); c.mu.Unlock() }

// memStore is an in-memory Store that counts calls.
type memStore struct {
	mu      sync.Mutex
	m       map[string]Token
	loads   int
	saves   int
	deletes int
	failAll bool
}

func newMemStore() *memStore { return &memStore{m: map[string]Token{}} }

func (s *memStore) Load(name string) (*Token, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.loads++
	if s.failAll {
		panic("store used in workload mode")
	}
	t, ok := s.m[name]
	if !ok {
		return nil, nil
	}
	return &t, nil
}

func (s *memStore) Save(name string, t *Token) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.saves++
	s.m[name] = *t
	return nil
}

func (s *memStore) Delete(name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.deletes++
	delete(s.m, name)
	return nil
}

func (s *memStore) Describe() string { return "memory" }

// noSecret fails when err's text carries any of the markers.
func noSecret(t *testing.T, err error, markers ...string) {
	t.Helper()
	if err == nil {
		return
	}
	for _, m := range markers {
		if m != "" && strings.Contains(err.Error(), m) {
			t.Fatalf("error text carries a secret marker %q", m)
		}
	}
}
