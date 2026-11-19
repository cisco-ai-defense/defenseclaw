//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
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
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"runtime"
	"sort"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ratelimit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

// j43Issuer signs actor tokens the way ate-idp-server does (ES256) and
// serves its key set, so the actor listener verifies real signatures.
type j43Issuer struct {
	key *ecdsa.PrivateKey
	srv *httptest.Server
}

const j43IssuerURL = "https://idp.ate-system.svc"

func newJ43Issuer(t *testing.T) *j43Issuer {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	raw, err := key.PublicKey.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	enc := base64.RawURLEncoding.EncodeToString
	jwks, _ := json.Marshal(map[string]any{"keys": []map[string]string{{"kty": "EC", "kid": "k1", "use": "sig", "alg": "ES256",
		"crv": "P-256", "x": enc(raw[1:33]), "y": enc(raw[33:])}}})
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwks)
	}))
	t.Cleanup(srv.Close)
	return &j43Issuer{key: key, srv: srv}
}

func (p *j43Issuer) token(t *testing.T, atespace, name, uid string) string {
	t.Helper()
	enc := base64.RawURLEncoding.EncodeToString
	now := time.Now().Unix()
	hb, _ := json.Marshal(map[string]string{"alg": "ES256", "kid": "k1", "typ": "JWT"})
	cb, _ := json.Marshal(map[string]any{"iss": j43IssuerURL, "sub": "actor/" + atespace + "/" + name, "aud": []string{identity.DefaultAudience},
		"exp": now + 900, "nbf": now - 60, "iat": now, "jti": uid,
		"actor.ate.dev": map[string]string{"atespace": atespace, "actorName": name, "actorUID": uid}})
	in := enc(hb) + "." + enc(cb)
	d := sha256.Sum256([]byte(in))
	r, s, err := ecdsa.Sign(rand.Reader, p.key, d[:])
	if err != nil {
		t.Fatal(err)
	}
	sig := make([]byte, 64)
	r.FillBytes(sig[:32])
	s.FillBytes(sig[32:])
	return in + "." + enc(sig)
}

func j43Pct(v []time.Duration, q float64) time.Duration {
	if len(v) == 0 {
		return 0
	}
	v = append([]time.Duration(nil), v...)
	sort.Slice(v, func(i, j int) bool { return v[i] < v[j] })
	return v[min(len(v)-1, int(float64(len(v))*q))]
}

// TestSubstrateGAP0565FloodingActorKeepsTheOthersFast is the gateway's part
// of CERT-110 J43 (substrate-1 GAP-0565): 50 steady actors each post a
// PreToolUse every 0.5 s to one actor listener with real actor tokens
// (ES256, the default fair-share limits 20 and 500), on two CPUs as a
// gateway pod has; then one more actor floods the hook route with about
// 2700 requests a second (64 workers), as J43's flooder did. J43's bar:
// the steady actors' hook p95 in the flood stays within 20 percent of the
// p95 before it, with no 429 for them. DEFENSECLAW_J43_PHASE_SECS sets the
// length of each phase (default 6). It measures wall-clock latency, so it
// runs only with DEFENSECLAW_J43_LOAD=1; the gate is the cost test below.
func TestSubstrateGAP0565FloodingActorKeepsTheOthersFast(t *testing.T) {
	if os.Getenv("DEFENSECLAW_J43_LOAD") != "1" {
		t.Skip("a wall-clock load measurement: DEFENSECLAW_J43_LOAD=1 runs it (on a quiet box)")
	}
	phase := 6 * time.Second
	if v := os.Getenv("DEFENSECLAW_J43_PHASE_SECS"); v != "" {
		n, err := strconv.Atoi(v)
		if err != nil || n <= 0 {
			t.Fatalf("DEFENSECLAW_J43_PHASE_SECS=%q", v)
		}
		phase = time.Duration(n) * time.Second
	}
	installCorrelationHMACForTest(t)
	installDefaultProfileConnector(t, "claudecode")
	issuer := newJ43Issuer(t)
	ks, err := identity.NewKeySet(identity.KeySetOptions{Issuer: j43IssuerURL, KeysURL: issuer.srv.URL + "/jwks", HTTPClient: issuer.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	const steady = 50
	live := map[string]identity.LiveActor{}
	verifier, err := identity.NewActorVerifier(identity.ActorVerifierOptions{KeySet: ks,
		Lookup: identity.ActorLookupFunc(func(_ context.Context, atespace, name string) (identity.LiveActor, error) {
			if a, ok := live[atespace+"/"+name]; ok {
				return a, nil
			}
			return identity.LiveActor{}, identity.ErrActorNotFound
		})})
	if err != nil {
		t.Fatal(err)
	}
	_, chains := newTestChainLeaderService(t)
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Actors, c.Chains = verifier, chains
		c.Limiter = ratelimit.New(ratelimit.Config{})
	})
	f.api.store, f.api.logger = testStoreAndV8Logger(t)
	tokens := make([]string, steady+1)
	for i := range tokens {
		name, uid := fmt.Sprintf("j43-%d", i), fmt.Sprintf("0000%04d-0000-4000-8000-000000000043", i)
		live["eng-web/"+name] = identity.LiveActor{UID: uid, State: identity.ActorRunning}
		if err := f.regs.Put(context.Background(), registry.Registration{Atespace: "eng-web", Name: name, UID: uid,
			Connector: "claudecode", Profile: "eng", Person: ownerOf(alice), Unattended: true,
			HarnessVersion: kit.AgentVersion("claudecode", ""), HookContract: "claudecode-hooks-v2"}); err != nil {
			t.Fatal(err)
		}
		tokens[i] = issuer.token(t, "eng-web", name, uid)
	}
	body := substrateKitEnvelope("claudecode-hooks-v2", map[string]any{"hook_event_name": "PreToolUse", "session_id": "j43-load",
		"cwd": "/work", "tool_name": "Bash", "tool_input": map[string]any{"command": "echo hi"}})
	post := func(tok string) int {
		return f.do(t, f.actor, http.MethodPost, "/api/v1/substrate/hook/claudecode", tok, body).Code
	}
	// Warm the key set, the live cache and the stores.
	for _, tok := range tokens {
		if code := post(tok); code != http.StatusOK {
			t.Fatalf("warm-up hook: %d", code)
		}
	}
	prev := runtime.GOMAXPROCS(2)
	defer runtime.GOMAXPROCS(prev)

	start := time.Now()
	floodAt, end := start.Add(phase), start.Add(2*phase)
	var mu sync.Mutex
	lat := map[string][]time.Duration{}
	perSec := map[int][]time.Duration{}
	codes := map[string]map[int]int{"base": {}, "flood": {}}
	var wg sync.WaitGroup
	for i := range steady {
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(time.Duration(i) * 10 * time.Millisecond)
			for now := time.Now(); now.Before(end); now = time.Now() {
				t0 := time.Now()
				code := post(tokens[i])
				d := time.Since(t0)
				name := "base"
				if !t0.Before(floodAt) {
					name = "flood"
				}
				mu.Lock()
				lat[name] = append(lat[name], d)
				codes[name][code]++
				sec := int(t0.Sub(start) / time.Second)
				perSec[sec] = append(perSec[sec], d)
				mu.Unlock()
				time.Sleep(time.Until(t0.Add(500 * time.Millisecond)))
			}
		}()
	}
	flooded := map[int]int{}
	for range 64 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			time.Sleep(time.Until(floodAt))
			n := map[int]int{}
			for time.Now().Before(end) {
				t0 := time.Now()
				n[post(tokens[steady])]++
				// About 42 a second per worker: J43's 2700 a second.
				time.Sleep(time.Until(t0.Add(24 * time.Millisecond)))
			}
			mu.Lock()
			for k, v := range n {
				flooded[k] += v
			}
			mu.Unlock()
		}()
	}
	wg.Wait()
	base, flood := j43Pct(lat["base"], .95), j43Pct(lat["flood"], .95)
	t.Logf("J43 steady base  n=%d codes=%v p50=%v p95=%v", len(lat["base"]), codes["base"], j43Pct(lat["base"], .5), base)
	t.Logf("J43 steady flood n=%d codes=%v p50=%v p95=%v (x%.2f)", len(lat["flood"]), codes["flood"], j43Pct(lat["flood"], .5), flood,
		float64(flood)/float64(max(base, 1)))
	t.Logf("J43 flooder %v over %s", flooded, phase)
	for sec := range int(2 * phase / time.Second) {
		t.Logf("J43 second %2d: n=%d p50=%v p95=%v", sec, len(perSec[sec]), j43Pct(perSec[sec], .5), j43Pct(perSec[sec], .95))
	}
	for name, c := range codes {
		if c[http.StatusTooManyRequests] > 0 || len(c) != 1 || c[http.StatusOK] == 0 {
			t.Errorf("steady actors in %s: statuses %v, want only 200", name, c)
		}
	}
	if flooded[http.StatusTooManyRequests] == 0 {
		t.Errorf("the flooder was never limited: %v", flooded)
	}
	if float64(flood) > 1.2*float64(base) {
		t.Errorf("steady hook p95 %v in the flood vs %v before (x%.2f), J43 wants at most x1.2", flood, base, float64(flood)/float64(base))
	}
}

// TestSubstrateGAP0565RefusedFloodRequestIsCheap: substrate-1 GAP-0565. A
// flooding actor's requests that its bucket refuses must cost the replica
// next to nothing, or a flood slows every other actor of the replica (J43
// on E5: their hook p95 x1.45, x2.05 on the model route, where 98 percent
// of the flood was refused). The bucket already runs before the
// registration lookup and the body read (GAP-0057); the actor token's
// signature and claims check ran before it on every refused request. The
// allocation count of one refused request through the actor listener
// (with a real ES256 actor token) is deterministic; its time is logged.
func TestSubstrateGAP0565RefusedFloodRequestIsCheap(t *testing.T) {
	installCorrelationHMACForTest(t)
	issuer := newJ43Issuer(t)
	ks, err := identity.NewKeySet(identity.KeySetOptions{Issuer: j43IssuerURL, KeysURL: issuer.srv.URL + "/jwks", HTTPClient: issuer.srv.Client()})
	if err != nil {
		t.Fatal(err)
	}
	const name, uid = "j43-flooder", "00009999-0000-4000-8000-000000000043"
	verifier, err := identity.NewActorVerifier(identity.ActorVerifierOptions{KeySet: ks,
		Lookup: identity.ActorLookupFunc(func(_ context.Context, atespace, n string) (identity.LiveActor, error) {
			if atespace == "eng-web" && n == name {
				return identity.LiveActor{UID: uid, State: identity.ActorRunning}, nil
			}
			return identity.LiveActor{}, identity.ErrActorNotFound
		})})
	if err != nil {
		t.Fatal(err)
	}
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Actors = verifier
		c.Limiter = ratelimit.New(ratelimit.Config{PerActorRPS: 0.001})
	})
	if err := f.regs.Put(context.Background(), registry.Registration{Atespace: "eng-web", Name: name, UID: uid,
		Connector: "claudecode", Profile: "eng", Person: ownerOf(alice), Unattended: true}); err != nil {
		t.Fatal(err)
	}
	tok := issuer.token(t, "eng-web", name, uid)
	body := substrateKitEnvelope("claudecode-hooks-v2", map[string]any{"hook_event_name": "PreToolUse", "session_id": "j43-load",
		"cwd": "/work", "tool_name": "Bash", "tool_input": map[string]any{"command": "echo hi"}})
	refused := func() {
		if code := f.do(t, f.actor, http.MethodPost, "/api/v1/substrate/hook/claudecode", tok, body).Code; code != http.StatusTooManyRequests {
			t.Fatalf("flood request: %d, want 429", code)
		}
	}
	// The burst (2 x 0.001 rounds to one request), then only refusals.
	_ = f.do(t, f.actor, http.MethodPost, "/api/v1/substrate/hook/claudecode", tok, body)
	refused()
	allocs := testing.AllocsPerRun(300, refused)
	res := testing.Benchmark(func(b *testing.B) {
		for b.Loop() {
			refused()
		}
	})
	t.Logf("GAP-0565: one refused flood request: %.0f allocations, %d ns, %d B", allocs, res.NsPerOp(), res.AllocedBytesPerOp())
	if allocs > refusedRequestAllocs {
		t.Fatalf("one refused flood request took %.0f allocations, want at most %d: the actor token is checked again before its bucket refuses it", allocs, refusedRequestAllocs)
	}
}

// refusedRequestAllocs bounds the allocations of one refused flood request
// (1.0.10 at 630d67c33f: 261, with the verified-token cache: 55).
const refusedRequestAllocs = 100
