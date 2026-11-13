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

package gateway

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
)

// keysURLIssuer is a per-cluster actor issuer that resolves nowhere, the
// value `substrate setup --issuer` and the EKS page advise (GAP-0194).
const keysURLIssuer = "https://substrate-e2.idp.invalid"

// fakeIDPService is ate-idp-server behind the in-cluster idp Service: its
// discovery document names the configured issuer and its key set is at
// /openid/v1/jwks, on a host that is not the issuer's.
func fakeIDPService(t *testing.T) (*httptest.Server, *ecdsa.PrivateKey) {
	t.Helper()
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	raw, _ := key.PublicKey.Bytes()
	enc := base64.RawURLEncoding.EncodeToString
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": keysURLIssuer, "jwks_uri": keysURLIssuer + "/openid/v1/jwks"})
		case "/openid/v1/jwks":
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": []map[string]string{{
				"kty": "EC", "kid": "k1", "use": "sig", "alg": "ES256", "crv": "P-256", "x": enc(raw[1:33]), "y": enc(raw[33:]),
			}}})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(srv.Close)
	return srv, key
}

func signActorToken(t *testing.T, key *ecdsa.PrivateKey, iss, atespace, name, uid string) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	now := time.Now().Unix()
	hb, _ := json.Marshal(map[string]any{"typ": "JWT", "alg": "ES256", "kid": "k1"})
	cb, _ := json.Marshal(map[string]any{
		"iss": iss, "sub": "actor/" + atespace + "/" + name, "aud": []string{"defenseclaw"},
		"exp": now + 300, "nbf": now - 5, "iat": now, "jti": "j-" + name,
		"actor.ate.dev": map[string]string{"atespace": atespace, "actorName": name, "actorUID": uid},
	})
	in := enc(hb) + "." + enc(cb)
	d := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return in + "." + enc(sig)
}

// keysURLVerifier is the real actor verifier the serve command builds for
// a unique issuer, with keysURL "" for the discovery path it used before.
func keysURLVerifier(t *testing.T, srv *httptest.Server, keysURL string) *identity.ActorVerifier {
	t.Helper()
	ks, err := identity.NewKeySet(identity.KeySetOptions{Issuer: keysURLIssuer, KeysURL: keysURL, HTTPClient: srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	v, err := identity.NewActorVerifier(identity.ActorVerifierOptions{KeySet: ks, Audience: "defenseclaw",
		Lookup: identity.ActorLookupFunc(func(_ context.Context, atespace, name string) (identity.LiveActor, error) {
			if atespace == "eng-web" && name == "alice-1" {
				return identity.LiveActor{UID: subUID1, State: identity.ActorRunning}, nil
			}
			return identity.LiveActor{}, identity.ErrActorNotFound
		})})
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// GAP-0194 through the real listener: with a unique issuer, a hook call of
// a live actor is answered when the keys come from the idp Service's keys
// URL, and refused keyset_unavailable on the discovery path (the issuer's
// host does not resolve), which is what E2 showed.
func TestSubstrateUniqueIssuerHookThroughTheRealVerifier(t *testing.T) {
	srv, key := fakeIDPService(t)
	hook := envelope("claudecode", map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash",
		"tool_input": map[string]any{"command": "ls -la"}, "session_id": "f12-a", "cwd": "/work/app"})
	tok := signActorToken(t, key, keysURLIssuer, "eng-web", "alice-1", subUID1)

	ok := newSubstrateFixture(t, func(sc *SubstrateConfig) { sc.Actors = keysURLVerifier(t, srv, srv.URL+"/openid/v1/jwks") })
	if rec := ok.do(t, ok.actor, http.MethodPost, "/api/v1/substrate/hook/claudecode", tok, hook); rec.Code != http.StatusOK {
		t.Fatalf("hook with the keys URL: %d %s", rec.Code, rec.Body)
	}

	old := newSubstrateFixture(t, func(sc *SubstrateConfig) { sc.Actors = keysURLVerifier(t, srv, "") })
	rec := old.do(t, old.actor, http.MethodPost, "/api/v1/substrate/hook/claudecode", tok, hook)
	if rec.Code != http.StatusServiceUnavailable || reasonOf(t, rec) != string(identity.ReasonKeysetFailed) {
		t.Fatalf("hook on the discovery path: %d %s, want 503 keyset_unavailable", rec.Code, rec.Body)
	}

	// iss is still compared exactly: a token naming the idp host, signed
	// by the same key, is refused.
	other := signActorToken(t, key, srv.URL, "eng-web", "alice-1", subUID1)
	rec = ok.do(t, ok.actor, http.MethodPost, "/api/v1/substrate/hook/claudecode", other, hook)
	if rec.Code != http.StatusUnauthorized || reasonOf(t, rec) != string(identity.ReasonIssuer) {
		t.Fatalf("a token of another issuer: %d %s, want 401 issuer", rec.Code, rec.Body)
	}
	// And the UID still binds the token to one incarnation.
	stale := signActorToken(t, key, keysURLIssuer, "eng-web", "alice-1", subUIDOther)
	rec = ok.do(t, ok.actor, http.MethodPost, "/api/v1/substrate/hook/claudecode", stale, hook)
	if rec.Code != http.StatusUnauthorized || reasonOf(t, rec) != string(identity.ReasonActorUID) {
		t.Fatalf("a token of an older incarnation: %d %s, want 401 actor_uid_mismatch", rec.Code, rec.Body)
	}
}

// /info reports a cluster-wide refusal so the launcher can say the task's
// calls were refused, and stops once a token verifies again.
func TestSubstrateInfoReportsActorTokenRefusals(t *testing.T) {
	srv, key := fakeIDPService(t)
	hook := envelope("claudecode", map[string]any{"hook_event_name": "PreToolUse", "tool_name": "Bash",
		"tool_input": map[string]any{"command": "ls"}, "session_id": "f12-b", "cwd": "/work/app"})
	tok := signActorToken(t, key, keysURLIssuer, "eng-web", "alice-1", subUID1)
	info := func(f *substrateFixture) map[string]any {
		rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/info", "", "")
		var m map[string]any
		if err := json.Unmarshal(rec.Body.Bytes(), &m); err != nil {
			t.Fatalf("info %d %s", rec.Code, rec.Body)
		}
		return m
	}
	old := newSubstrateFixture(t, func(sc *SubstrateConfig) { sc.Actors = keysURLVerifier(t, srv, "") })
	if _, ok := info(old)["actor_tokens"]; ok {
		t.Fatal("actor_tokens reported before any refusal")
	}
	old.do(t, old.actor, http.MethodPost, "/api/v1/substrate/hook/claudecode", tok, hook)
	got, _ := info(old)["actor_tokens"].(map[string]any)
	if got["state"] != "refusing" || got["reason"] != string(identity.ReasonKeysetFailed) || got["since"] == "" {
		t.Fatalf("actor_tokens %v", got)
	}

	// A refusal of one bad token (another incarnation) is not cluster-wide.
	ok := newSubstrateFixture(t, func(sc *SubstrateConfig) { sc.Actors = keysURLVerifier(t, srv, srv.URL+"/openid/v1/jwks") })
	ok.do(t, ok.actor, http.MethodPost, "/api/v1/substrate/hook/claudecode",
		signActorToken(t, key, keysURLIssuer, "eng-web", "alice-1", subUIDOther), hook)
	if _, there := info(ok)["actor_tokens"]; there {
		t.Fatal("a single stale token reported as a cluster-wide refusal")
	}
}

func TestActorTokenHealthWindow(t *testing.T) {
	var h actorTokenHealth
	t0 := time.Unix(1_800_000_000, 0)
	h.refused(identity.ReasonSignature, t0)
	if _, ok := h.report(t0); ok {
		t.Fatal("signature refusals are per token")
	}
	h.refused(identity.ReasonIssuer, t0)
	if s, ok := h.report(t0.Add(time.Minute)); !ok || s.Reason != "issuer" {
		t.Fatalf("issuer refusal not reported: %+v", s)
	}
	if _, ok := h.report(t0.Add(actorTokenRefusalWindow + time.Second)); ok {
		t.Fatal("reported past the window")
	}
	h.verified(t0.Add(2 * time.Second))
	if _, ok := h.report(t0.Add(3 * time.Second)); ok {
		t.Fatal("reported after a token verified")
	}
}
