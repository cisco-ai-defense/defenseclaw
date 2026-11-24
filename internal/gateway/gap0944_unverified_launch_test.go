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

//go:build !windows

package gateway

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxreg"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// unverifiedSignIn is a one-key OIDC issuer: a real PersonVerifier and a
// signed sign-in token whose email the issuer marked unverified.
func unverifiedSignIn(t *testing.T) (*identity.PersonVerifier, string, string) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	var srv *httptest.Server
	srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": srv.URL, "jwks_uri": srv.URL + "/jwks"})
		case "/jwks":
			raw, err := key.PublicKey.Bytes() // 0x04 || X || Y
			if err != nil {
				http.Error(w, err.Error(), 500)
				return
			}
			enc := base64.RawURLEncoding.EncodeToString
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{"kty": "EC", "kid": "k1", "use": "sig",
				"alg": "ES256", "crv": "P-256", "x": enc(raw[1:33]), "y": enc(raw[33:])}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	ks, err := identity.NewKeySet(identity.KeySetOptions{Issuer: srv.URL, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	v, err := identity.NewPersonVerifier([]identity.PersonIssuer{{KeySet: ks, Audience: "dc-launcher"}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now().Unix()
	seg := func(v any) string {
		b, _ := json.Marshal(v)
		return base64.RawURLEncoding.EncodeToString(b)
	}
	input := seg(map[string]any{"typ": "JWT", "alg": "ES256", "kid": "k1"}) + "." + seg(map[string]any{
		"iss": srv.URL, "sub": "kc-unv-sub", "aud": "dc-launcher", "iat": now, "exp": now + 600,
		"email": "unv@example.com", "email_verified": false, "preferred_username": "kc-unverified"})
	sum := sha256.Sum256([]byte(input))
	r, s, err := ecdsa.Sign(rand.Reader, key, sum[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := append(r.FillBytes(make([]byte, 32)), s.FillBytes(make([]byte, 32))...)
	return v, input + "." + base64.RawURLEncoding.EncodeToString(sig), srv.URL
}

// GAP-0944: a person who signs in with an email the issuer did not verify
// launches through the create route; the stored registration carries the
// mark (and not the email as the principal), and the actor's hook audit row
// names the lower assurance. Nothing sets the mark by hand.
func TestSubstrateUnverifiedSignInLaunchIsMarkedGAP0944(t *testing.T) {
	verifier, tok, issuer := unverifiedSignIn(t)
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.People = verifier
		c.Profiles = func(_ identity.Person, requested, _ string, _ bool) (string, string, error) {
			if requested != "eng" {
				return "", "", errors.New("no")
			}
			return "eng", "eng-web", nil
		}
	})
	f.api.substrateState().cfg.Actions = &fakeActions{f: f}
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", tok, `{"profile":"eng","template":"claude-wave1","connector":"claudecode"}`); rec.Code != http.StatusCreated {
		t.Fatalf("create as the unverified person: %d %s", rec.Code, rec.Body)
	}
	reg, ok, err := f.regs.Get(context.Background(), "eng-web", subUIDOther)
	if err != nil || !ok {
		t.Fatalf("registration: %v %v", ok, err)
	}
	if p := reg.Person; p.Issuer != issuer || p.Subject != "kc-unv-sub" || p.Principal != "kc-unverified" || !p.EmailUnverified || p.Assurance() != registry.AssuranceEmailUnverified {
		t.Fatalf("stored person %+v: want the user name as principal and the email_unverified mark", p)
	}

	// The actor's hook row, from the stored registration as the actor
	// listener puts it on the request.
	injectHealthyAllowForProfile(t, "claudecode")
	store, logger := testStoreAndLogger(t)
	cfg := config.DefaultConfig()
	cfg.DataDir = t.TempDir()
	cfg.Guardrail.Mode, cfg.Guardrail.HookFailMode, cfg.Guardrail.Connector = "action", "closed", "claudecode"
	server := &APIServer{scannerCfg: cfg, store: store, logger: logger}
	key, err := sandboxreg.SubstrateKey(reg.Atespace, reg.UID)
	if err != nil {
		t.Fatal(err)
	}
	ctx := withSubstrateActor(context.Background(), verifiedSubstrateActor(reg.Atespace, reg.Name, reg.UID, "actor/"+reg.Atespace+"/"+reg.Name, key))
	ctx = context.WithValue(ctx, substrateRegistrationKey{}, reg)
	const session = "gap0944-unverified"
	payload, _ := panicTestPayload("claudecode", "PreToolUse", t.TempDir())
	payload["session_id"] = session
	body, err := json.Marshal(payload)
	if err != nil {
		t.Fatal(err)
	}
	req := httptest.NewRequest(http.MethodPost, "/api/v1/claudecode/hook", bytes.NewReader(body)).WithContext(ctx)
	req.Header.Set("Content-Type", "application/json")
	w := httptest.NewRecorder()
	server.handleAgentHook("claudecode").ServeHTTP(w, req)
	if w.Code != http.StatusOK {
		t.Fatalf("hook status=%d body=%s", w.Code, w.Body.String())
	}
	row := newestHookDecision(t, store, session)
	seen := row.Details + fmt.Sprint(row.Structured)
	if !strings.Contains(seen, "substrate_person_assurance") || !strings.Contains(seen, registry.AssuranceEmailUnverified) {
		t.Fatalf("the hook row of an unverified person's actor has no lower-assurance mark: %s", seen)
	}
}
