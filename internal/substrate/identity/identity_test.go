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
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

// idp is a fake ate-idp-server: discovery plus a key set it can rotate.
type idp struct {
	srv     *httptest.Server
	mu      sync.Mutex
	keys    map[string]crypto.Signer
	algs    map[string]string
	jwksHit atomic.Int64
	issuer  string // what discovery claims (defaults to the URL)
}

func newIDP(t *testing.T) *idp {
	t.Helper()
	p := &idp{keys: map[string]crypto.Signer{}, algs: map[string]string{}}
	p.srv = httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		switch r.URL.Path {
		case "/.well-known/openid-configuration":
			iss := p.srv.URL
			p.mu.Lock()
			if p.issuer != "" {
				iss = p.issuer
			}
			p.mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]string{"issuer": iss, "jwks_uri": p.srv.URL + "/openid/v1/jwks"})
		case "/openid/v1/jwks":
			p.jwksHit.Add(1)
			p.mu.Lock()
			defer p.mu.Unlock()
			var keys []map[string]string
			for kid, k := range p.keys {
				keys = append(keys, jwkOf(kid, p.algs[kid], k.Public()))
			}
			_ = json.NewEncoder(w).Encode(map[string]any{"keys": keys})
		default:
			http.NotFound(w, r)
		}
	}))
	t.Cleanup(p.srv.Close)
	return p
}

func jwkOf(kid, alg string, pub crypto.PublicKey) map[string]string {
	enc := base64.RawURLEncoding.EncodeToString
	switch k := pub.(type) {
	case *ecdsa.PublicKey:
		raw, err := k.Bytes() // 0x04 || X || Y
		if err != nil {
			panic(err)
		}
		x, y := raw[1:33], raw[33:]
		return map[string]string{"kty": "EC", "kid": kid, "use": "sig", "alg": alg, "crv": "P-256", "x": enc(x), "y": enc(y)}
	case *rsa.PublicKey:
		return map[string]string{"kty": "RSA", "kid": kid, "use": "sig", "alg": alg, "n": enc(k.N.Bytes()), "e": enc(big.NewInt(int64(k.E)).Bytes())}
	}
	return nil
}

func (p *idp) addKey(t *testing.T, kid, alg string) crypto.Signer {
	t.Helper()
	var k crypto.Signer
	var err error
	if alg == "RS256" {
		k, err = rsa.GenerateKey(rand.Reader, 2048)
	} else {
		k, err = ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	}
	if err != nil {
		t.Fatal(err)
	}
	p.mu.Lock()
	p.keys[kid], p.algs[kid] = k, alg
	p.mu.Unlock()
	return k
}

// sign makes a compact JWS of header and claims with key.
func sign(t *testing.T, key crypto.Signer, header, claims map[string]any) string {
	t.Helper()
	hb, _ := json.Marshal(header)
	cb, _ := json.Marshal(claims)
	return signRaw(t, key, header["alg"], hb, cb)
}

func signRaw(t *testing.T, key crypto.Signer, alg any, hb, cb []byte) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	in := enc(hb) + "." + enc(cb)
	d := sha256.Sum256([]byte(in))
	var sig []byte
	switch k := key.(type) {
	case *ecdsa.PrivateKey:
		r, s, err := ecdsa.Sign(rand.Reader, k, d[:])
		if err != nil {
			t.Fatal(err)
		}
		sig = make([]byte, 64)
		r.FillBytes(sig[:32])
		s.FillBytes(sig[32:])
	case *rsa.PrivateKey:
		var err error
		sig, err = rsa.SignPKCS1v15(rand.Reader, k, crypto.SHA256, d[:])
		if err != nil {
			t.Fatal(err)
		}
	}
	_ = alg
	return in + "." + enc(sig)
}

type fixture struct {
	idp    *idp
	key    crypto.Signer
	now    time.Time
	v      *ActorVerifier
	ks     *KeySet
	actors map[string]LiveActor
	calls  atomic.Int64
	down   atomic.Bool
}

func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{idp: newIDP(t), now: time.Unix(1_800_000_000, 0), actors: map[string]LiveActor{}}
	f.key = f.idp.addKey(t, "k1", "ES256")
	ks, err := NewKeySet(KeySetOptions{Issuer: f.idp.srv.URL, HTTPClient: f.idp.srv.Client(), Now: f.clock})
	if err != nil {
		t.Fatal(err)
	}
	f.ks = ks
	f.actors["team-a/agent-1"] = LiveActor{UID: "uid-1", State: ActorRunning}
	v, err := NewActorVerifier(ActorVerifierOptions{KeySet: ks, Now: f.clock, Lookup: ActorLookupFunc(
		func(_ context.Context, atespace, name string) (LiveActor, error) {
			f.calls.Add(1)
			if f.down.Load() {
				return LiveActor{}, errors.New("unavailable")
			}
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

func (f *fixture) clock() time.Time { return f.now }

func (f *fixture) claims(mut ...func(map[string]any)) map[string]any {
	c := map[string]any{
		"iss": f.idp.srv.URL, "sub": "actor/team-a/agent-1", "aud": []string{"defenseclaw"},
		"exp": f.now.Unix() + 900, "nbf": f.now.Unix() - 300, "iat": f.now.Unix(), "jti": "j1",
		"actor.ate.dev": map[string]string{"atespace": "team-a", "actorName": "agent-1", "actorUID": "uid-1"},
	}
	for _, m := range mut {
		m(c)
	}
	return c
}

func (f *fixture) token(t *testing.T, mut ...func(map[string]any)) string {
	return sign(t, f.key, map[string]any{"typ": "JWT", "alg": "ES256", "kid": "k1"}, f.claims(mut...))
}

func wantReason(t *testing.T, err error, want Reason) {
	t.Helper()
	if err == nil {
		t.Fatalf("verified, want %s", want)
	}
	if got := ReasonOf(err); got != want {
		t.Fatalf("reason %s (%v), want %s", got, err, want)
	}
}

func TestActorVerifierAcceptsAGoodToken(t *testing.T) {
	f := newFixture(t)
	a, err := f.v.Verify(context.Background(), f.token(t))
	if err != nil {
		t.Fatal(err)
	}
	if a.Atespace != "team-a" || a.Name != "agent-1" || a.UID != "uid-1" || a.Subject != "actor/team-a/agent-1" {
		t.Fatalf("actor %+v", a)
	}
	// RS256 too.
	rk := f.idp.addKey(t, "r1", "RS256")
	f.now = f.now.Add(11 * time.Second) // past the refetch interval
	tok := sign(t, rk, map[string]any{"typ": "JWT", "alg": "RS256", "kid": "r1"}, f.claims())
	if _, err := f.v.Verify(context.Background(), tok); err != nil {
		t.Fatalf("RS256: %v", err)
	}
}

func TestActorVerifierGoldenRefusals(t *testing.T) {
	f := newFixture(t)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	hdr := map[string]any{"typ": "JWT", "alg": "ES256", "kid": "k1"}
	cases := map[string]struct {
		tok  func() string
		want Reason
	}{
		"empty":     {func() string { return "" }, ReasonMissing},
		"not a jws": {func() string { return "abc.def" }, ReasonMalformed},
		"oversize":  {func() string { return strings.Repeat("a", MaxTokenBytes+1) }, ReasonMalformed},
		"forged":    {func() string { return sign(t, other, hdr, f.claims()) }, ReasonSignature},
		"alg none":  {func() string { return noneToken(f.claims()) }, ReasonAlgorithm},
		"alg HS256": {func() string {
			return sign(t, f.key, map[string]any{"typ": "JWT", "alg": "HS256", "kid": "k1"}, f.claims())
		}, ReasonAlgorithm},
		"alg mismatch": {func() string {
			return sign(t, f.key, map[string]any{"typ": "JWT", "alg": "RS256", "kid": "k1"}, f.claims())
		}, ReasonAlgorithm},
		"session typ": {func() string {
			return sign(t, f.key, map[string]any{"typ": SessionTokenType, "alg": "ES256", "kid": "k1"}, f.claims())
		}, ReasonType},
		"crit": {func() string {
			return sign(t, f.key, map[string]any{"typ": "JWT", "alg": "ES256", "kid": "k1", "crit": []string{"x"}}, f.claims())
		}, ReasonMalformed},
		"no kid":       {func() string { return sign(t, f.key, map[string]any{"typ": "JWT", "alg": "ES256"}, f.claims()) }, ReasonMalformed},
		"wrong issuer": {func() string { return f.token(t, func(c map[string]any) { c["iss"] = "https://idp.other.svc" }) }, ReasonIssuer},
		"wrong aud": {func() string {
			return f.token(t, func(c map[string]any) { c["aud"] = []string{"https://api.example.com"} })
		}, ReasonAudience},
		"no aud": {func() string { return f.token(t, func(c map[string]any) { delete(c, "aud") }) }, ReasonAudience},
		"expired": {func() string {
			return f.token(t, func(c map[string]any) { c["exp"] = f.now.Unix() - 61; c["iat"] = f.now.Unix() - 900 })
		}, ReasonExpired},
		"not yet valid": {func() string { return f.token(t, func(c map[string]any) { c["nbf"] = f.now.Unix() + 61 }) }, ReasonNotYetValid},
		"future iat": {func() string {
			return f.token(t, func(c map[string]any) { c["iat"] = f.now.Unix() + 120; c["nbf"] = nil })
		}, ReasonNotYetValid},
		"too long": {func() string { return f.token(t, func(c map[string]any) { c["exp"] = f.now.Unix() + 7200 }) }, ReasonLifetime},
		"no exp":   {func() string { return f.token(t, func(c map[string]any) { delete(c, "exp") }) }, ReasonClaims},
		"worker token": {func() string {
			return f.token(t, func(c map[string]any) {
				c["sub"] = "worker-for-actor/team-a/agent-1"
				delete(c, "actor.ate.dev")
				c["worker-for-actor.ate.dev"] = map[string]string{"atespace": "team-a", "actorName": "agent-1", "actorUID": "uid-1"}
			})
		}, ReasonWorkerToken},
		"worker claim with actor sub": {func() string {
			return f.token(t, func(c map[string]any) {
				c["worker-for-actor.ate.dev"] = map[string]string{"atespace": "team-a", "actorName": "agent-1", "actorUID": "uid-1"}
			})
		}, ReasonWorkerToken},
		"other subject":  {func() string { return f.token(t, func(c map[string]any) { c["sub"] = "user/alice" }) }, ReasonSubject},
		"sub mismatch":   {func() string { return f.token(t, func(c map[string]any) { c["sub"] = "actor/team-a/agent-2" }) }, ReasonSubject},
		"no actor claim": {func() string { return f.token(t, func(c map[string]any) { delete(c, "actor.ate.dev") }) }, ReasonClaims},
		"bad uid": {func() string {
			return f.token(t, func(c map[string]any) {
				c["actor.ate.dev"] = map[string]string{"atespace": "team-a", "actorName": "agent-1", "actorUID": "a/b"}
			})
		}, ReasonClaims},
		"duplicate claim": {func() string {
			hb, _ := json.Marshal(hdr)
			cb, _ := json.Marshal(f.claims())
			cb = append(cb[:len(cb)-1], []byte(`,"sub":"actor/team-a/agent-1"}`)...)
			return signRaw(t, f.key, "ES256", hb, cb)
		}, ReasonMalformed},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := f.v.Verify(context.Background(), tc.tok())
			wantReason(t, err, tc.want)
			if strings.Contains(err.Error(), "eyJ") {
				t.Fatalf("error carries token bytes: %v", err)
			}
		})
	}
}

func noneToken(claims map[string]any) string {
	enc := base64.RawURLEncoding.EncodeToString
	hb, _ := json.Marshal(map[string]any{"typ": "JWT", "alg": "none", "kid": "k1"})
	cb, _ := json.Marshal(claims)
	return enc(hb) + "." + enc(cb) + "." + enc([]byte("x"))
}

func TestActorVerifierLiveUID(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	good := f.token(t)
	if _, err := f.v.Verify(ctx, good); err != nil {
		t.Fatal(err)
	}
	// Recreated same-name actor: a new UID. The old incarnation's token
	// (upstream #2208) must be refused, the new one accepted.
	f.actors["team-a/agent-1"] = LiveActor{UID: "uid-2", State: ActorRunning}
	f.v.Invalidate("team-a", "agent-1")
	_, err := f.v.Verify(ctx, good)
	wantReason(t, err, ReasonActorUID)
	newTok := f.token(t, func(c map[string]any) {
		c["actor.ate.dev"] = map[string]string{"atespace": "team-a", "actorName": "agent-1", "actorUID": "uid-2"}
	})
	if _, err := f.v.Verify(ctx, newTok); err != nil {
		t.Fatalf("new incarnation: %v", err)
	}
	// Without Invalidate, a new UID forces a re-check after a second.
	f.actors["team-a/agent-1"] = LiveActor{UID: "uid-3", State: ActorRunning}
	third := f.token(t, func(c map[string]any) {
		c["actor.ate.dev"] = map[string]string{"atespace": "team-a", "actorName": "agent-1", "actorUID": "uid-3"}
	})
	f.now = f.now.Add(2 * time.Second)
	if _, err := f.v.Verify(ctx, third); err != nil {
		t.Fatalf("recreated without invalidate: %v", err)
	}
	// Suspended and deleted.
	f.actors["team-a/agent-1"] = LiveActor{UID: "uid-3", State: "SUSPENDED"}
	f.v.Invalidate("team-a", "agent-1")
	_, err = f.v.Verify(ctx, third)
	wantReason(t, err, ReasonActorState)
	delete(f.actors, "team-a/agent-1")
	f.v.Invalidate("team-a", "agent-1")
	_, err = f.v.Verify(ctx, third)
	wantReason(t, err, ReasonActorGone)
}

func TestActorVerifierControlAPIDown(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	tok := f.token(t)
	if _, err := f.v.Verify(ctx, tok); err != nil {
		t.Fatal(err)
	}
	f.down.Store(true)
	f.now = f.now.Add(59 * time.Second)
	if _, err := f.v.Verify(ctx, tok); err != nil {
		t.Fatalf("within the live cache: %v", err)
	}
	f.now = f.now.Add(2 * time.Second)
	_, err := f.v.Verify(ctx, tok)
	wantReason(t, err, ReasonUnavailable)
	if !Unavailable(err) {
		t.Fatal("not reported as unavailable")
	}
}

func TestActorVerifierLookupStorm(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	stale := f.token(t)
	f.actors["team-a/agent-1"] = LiveActor{UID: "uid-9", State: ActorRunning}
	f.v.Invalidate("team-a", "agent-1")
	before := f.calls.Load()
	for i := 0; i < 500; i++ {
		_, err := f.v.Verify(ctx, stale)
		wantReason(t, err, ReasonActorUID)
	}
	if n := f.calls.Load() - before; n > 1 {
		t.Fatalf("%d control API lookups for one stale actor in one second", n)
	}
}

func TestKeySetRotationAndKidFlood(t *testing.T) {
	f := newFixture(t)
	ctx := context.Background()
	if _, err := f.v.Verify(ctx, f.token(t)); err != nil {
		t.Fatal(err)
	}
	fetches := f.ks.Fetches()
	// Flood of unknown kids: at most one fetch per refetch interval.
	for i := 0; i < 1000; i++ {
		tok := sign(t, f.key, map[string]any{"typ": "JWT", "alg": "ES256", "kid": fmt.Sprintf("x%d", i)}, f.claims())
		_, err := f.v.Verify(ctx, tok)
		wantReason(t, err, ReasonUnknownKey)
	}
	if n := f.ks.Fetches() - fetches; n > 1 {
		t.Fatalf("kid flood caused %d key-set fetches", n)
	}
	// Rotation: a key added to the pool verifies once the interval passed.
	k2 := f.idp.addKey(t, "k2", "ES256")
	f.now = f.now.Add(DefaultRefetchInterval + time.Second)
	tok := sign(t, k2, map[string]any{"typ": "JWT", "alg": "ES256", "kid": "k2"}, f.claims())
	if _, err := f.v.Verify(ctx, tok); err != nil {
		t.Fatalf("rotated key: %v", err)
	}
	// Removal: a key dropped from the pool stops verifying after MaxAge.
	f.idp.mu.Lock()
	delete(f.idp.keys, "k1")
	f.idp.mu.Unlock()
	f.now = f.now.Add(DefaultKeyMaxAge + time.Second)
	_, err := f.v.Verify(ctx, f.token(t))
	wantReason(t, err, ReasonUnknownKey)
}

func TestKeySetDiscoveryChecks(t *testing.T) {
	f := newFixture(t)
	f.idp.mu.Lock()
	f.idp.issuer = "https://idp.elsewhere.svc"
	f.idp.mu.Unlock()
	_, err := f.v.Verify(context.Background(), f.token(t))
	wantReason(t, err, ReasonKeysetFailed)
	if !Unavailable(err) {
		t.Fatal("a key set that cannot be fetched is not a refusal of the token")
	}
	for _, bad := range []string{"http://idp.svc", "https://", "https://idp.svc/", "https://idp.svc?x=1", "https://u@idp.svc"} {
		if _, err := NewKeySet(KeySetOptions{Issuer: bad}); err == nil {
			t.Errorf("issuer %q accepted", bad)
		}
	}
}

func TestSessionSignerRoundTripAndRefusals(t *testing.T) {
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	s, err := NewSessionSigner(key, "https://defenseclaw-admin.defenseclaw-system.svc")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Unix(1_800_000_000, 0)
	s.SetClock(func() time.Time { return now })
	act := SessionActor{Atespace: "eng-web", Name: "alice-1", UID: "u-1"}
	tok, exp, err := s.Issue("oidc|alice", act, 0)
	if err != nil {
		t.Fatal(err)
	}
	if exp.Sub(now) != DefaultSessionLifetime {
		t.Fatalf("lifetime %v", exp.Sub(now))
	}
	got, err := s.Verify(tok)
	if err != nil {
		t.Fatal(err)
	}
	if got.Person != "oidc|alice" || got.ActorRef != "eng-web/alice-1" || got.ActorUID != "u-1" {
		t.Fatalf("session %+v", got)
	}
	// The header and claims are the shape lane A5's relay verifies.
	parts := strings.Split(tok, ".")
	hb, _ := base64.RawURLEncoding.DecodeString(parts[0])
	cb, _ := base64.RawURLEncoding.DecodeString(parts[1])
	var h map[string]string
	var c map[string]any
	_ = json.Unmarshal(hb, &h)
	_ = json.Unmarshal(cb, &c)
	if h["typ"] != "dcrelay+jwt" || h["alg"] != "ES256" || h["kid"] != s.KeyID() {
		t.Fatalf("header %v", h)
	}
	if aud, _ := c["aud"].([]any); len(aud) != 1 || aud[0] != "dcrelay" {
		t.Fatalf("aud %v", c["aud"])
	}
	if a, _ := c["dc.actor"].(map[string]any); a["actorUID"] != "u-1" || a["atespace"] != "eng-web" || a["actorName"] != "alice-1" {
		t.Fatalf("dc.actor %v", c["dc.actor"])
	}
	if _, _, err := s.Issue("actor/eng-web/alice-1", act, 0); err == nil {
		t.Fatal("issued a session to an actor subject")
	}
	if _, _, err := s.Issue("alice", SessionActor{Atespace: "eng-web", Name: "alice-1"}, 0); err == nil {
		t.Fatal("issued a session without an actor UID")
	}
	now = now.Add(DefaultSessionLifetime + 2*time.Minute)
	_, err = s.Verify(tok)
	wantReason(t, err, ReasonExpired)
	other, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	o, _ := NewSessionSigner(other, s.Issuer())
	otok, _, _ := o.Issue("alice", act, 0)
	_, err = s.Verify(otok)
	wantReason(t, err, ReasonUnknownKey)
}

func TestPersonVerifier(t *testing.T) {
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
	claims := func(mut ...func(map[string]any)) map[string]any {
		c := map[string]any{"iss": p.srv.URL, "sub": "00u1", "aud": "dc-launcher", "exp": now.Unix() + 600,
			"iat": now.Unix(), "email": "alice@example.com", "groups": []string{"eng", "eng-web"}}
		for _, m := range mut {
			m(c)
		}
		return c
	}
	hdr := map[string]any{"typ": "JWT", "alg": "RS256", "kid": "p1"}
	got, err := v.Verify(context.Background(), sign(t, key, hdr, claims()))
	if err != nil {
		t.Fatal(err)
	}
	if got.Subject != "00u1" || got.Principal != "alice@example.com" || len(got.Groups) != 2 || got.Kind != PersonHuman {
		t.Fatalf("person %+v", got)
	}
	_, err = v.Verify(context.Background(), sign(t, key, hdr, claims(func(c map[string]any) { c["aud"] = "other"; c["azp"] = "other" })))
	wantReason(t, err, ReasonAudience)
	if _, err := v.Verify(context.Background(), sign(t, key, hdr, claims(func(c map[string]any) { c["aud"] = "other"; c["azp"] = "dc-launcher" }))); err != nil {
		t.Fatalf("azp: %v", err)
	}
	_, err = v.Verify(context.Background(), sign(t, key, hdr, claims(func(c map[string]any) { c["sub"] = "actor/a/b" })))
	wantReason(t, err, ReasonSubject)
	_, err = v.Verify(context.Background(), sign(t, key, hdr, claims(func(c map[string]any) { c["iss"] = "https://evil.example" })))
	wantReason(t, err, ReasonIssuer)
}
