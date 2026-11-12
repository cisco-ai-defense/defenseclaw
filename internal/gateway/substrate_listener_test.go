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
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
	"github.com/defenseclaw/defenseclaw/internal/substrate/identity"
	"github.com/defenseclaw/defenseclaw/internal/substrate/kit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/ratelimit"
	"github.com/defenseclaw/defenseclaw/internal/substrate/registry"
)

const (
	subUID1     = "4f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4a"
	subUID2     = "5f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4b"
	subUIDOther = "6f9c3a1e-8d2b-4c77-9e0a-6b5f1d2c3e4c"
	subCallout  = "callout-service-token-0123456789"
)

// fakeActorTokens maps a token to its verification result.
type fakeActorTokens struct {
	mu     sync.Mutex
	tokens map[string]identity.Actor
	errs   map[string]error
}

func (f *fakeActorTokens) Verify(_ context.Context, tok string) (identity.Actor, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if err, ok := f.errs[tok]; ok {
		return identity.Actor{}, err
	}
	a, ok := f.tokens[tok]
	if !ok {
		return identity.Actor{}, &identity.Error{Reason: identity.ReasonSignature, Message: "x"}
	}
	return a, nil
}

type fakePeople map[string]identity.Person

func (f fakePeople) Verify(_ context.Context, tok string) (identity.Person, error) {
	p, ok := f[tok]
	if !ok {
		return identity.Person{}, &identity.Error{Reason: identity.ReasonSignature, Message: "x"}
	}
	return p, nil
}

type substrateFixture struct {
	api      *APIServer
	actor    http.Handler
	admin    http.Handler
	regs     *registry.FileStore
	sessions *identity.SessionSigner
	live     map[string]identity.LiveActor
	activity []string
	limited  []ratelimit.Scope
	mu       sync.Mutex
}

var (
	alice = identity.Person{Kind: identity.PersonHuman, Issuer: "https://idp.example", Subject: "alice", Principal: "alice@example.com"}
	bob   = identity.Person{Kind: identity.PersonHuman, Issuer: "https://idp.example", Subject: "bob", Principal: "bob@example.com"}
	admin = identity.Person{Kind: identity.PersonHuman, Issuer: "https://idp.example", Subject: "root", Groups: []string{"dc-admins"}}
)

func newSubstrateFixture(t *testing.T, mutate ...func(*SubstrateConfig)) *substrateFixture {
	t.Helper()
	cfg := &config.Config{DataDir: t.TempDir(), Gateway: config.GatewayConfig{Token: sandboxTestMasterToken}}
	api := NewAPIServer("127.0.0.1:18970", NewSidecarHealth(), nil, nil, nil, cfg)
	regs, err := registry.OpenFileStore(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	for _, r := range []registry.Registration{
		{Atespace: "eng-web", Name: "alice-1", UID: subUID1, Connector: "claudecode", Profile: "eng", Person: ownerOf(alice)},
		{Atespace: "eng-web", Name: "bob-1", UID: subUID2, Connector: "codex", Profile: "eng", Person: ownerOf(bob), Unattended: true, BatchID: "b1"},
	} {
		if err := regs.Put(ctx, r); err != nil {
			t.Fatal(err)
		}
	}
	key, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	sessions, _ := identity.NewSessionSigner(key, "https://defenseclaw-admin.defenseclaw-system.svc")
	f := &substrateFixture{api: api, regs: regs, sessions: sessions, live: map[string]identity.LiveActor{
		"eng-web/alice-1": {UID: subUID1, State: identity.ActorRunning},
		"eng-web/bob-1":   {UID: subUID2, State: identity.ActorRunning},
	}}
	tokens := &fakeActorTokens{
		tokens: map[string]identity.Actor{
			"tok-alice":  {Atespace: "eng-web", Name: "alice-1", UID: subUID1, Subject: "actor/eng-web/alice-1"},
			"tok-bob":    {Atespace: "eng-web", Name: "bob-1", UID: subUID2, Subject: "actor/eng-web/bob-1"},
			"tok-orphan": {Atespace: "eng-web", Name: "orphan", UID: subUIDOther, Subject: "actor/eng-web/orphan"},
		},
		errs: map[string]error{
			"tok-worker": &identity.Error{Reason: identity.ReasonWorkerToken, Message: "x"},
			"tok-stale":  &identity.Error{Reason: identity.ReasonActorUID, Message: "x"},
			"tok-down":   &identity.Error{Reason: identity.ReasonUnavailable, Message: "x"},
		},
	}
	sc := SubstrateConfig{
		ActorAddr: "127.0.0.1:0", AdminAddr: "127.0.0.1:1",
		Actors: tokens, People: fakePeople{"p-alice": alice, "p-bob": bob, "p-admin": admin},
		Sessions: sessions, Registrations: regs,
		Limiter: ratelimit.New(ratelimit.Config{PerActorRPS: 1000, PerAtespaceRPS: 10000}),
		Lookup: identity.ActorLookupFunc(func(_ context.Context, atespace, name string) (identity.LiveActor, error) {
			if l, ok := f.live[atespace+"/"+name]; ok {
				return l, nil
			}
			return identity.LiveActor{}, identity.ErrActorNotFound
		}),
		IsAdmin:      func(p identity.Person) bool { return len(p.Groups) > 0 && p.Groups[0] == "dc-admins" },
		CalloutToken: func() (string, error) { return subCallout, nil },
		Activity: substrateActivityFunc(func(kind, atespace, uid string) {
			f.mu.Lock()
			f.activity = append(f.activity, kind+":"+uid)
			f.mu.Unlock()
		}),
		OnRateLimited: func(s ratelimit.Scope, _ string) {
			f.mu.Lock()
			f.limited = append(f.limited, s)
			f.mu.Unlock()
		},
	}
	for _, m := range mutate {
		m(&sc)
	}
	if err := api.SetSubstrate(sc); err != nil {
		t.Fatal(err)
	}
	if f.actor, err = api.SubstrateActorHandler(); err != nil {
		t.Fatal(err)
	}
	if f.admin, err = api.SubstrateAdminHandler(); err != nil {
		t.Fatal(err)
	}
	return f
}

type substrateActivityFunc func(kind, atespace, uid string)

func (f substrateActivityFunc) ObserveActivity(kind, atespace, uid string, _ time.Time) {
	f(kind, atespace, uid)
}

func (f *substrateFixture) do(t *testing.T, h http.Handler, method, path, token, body string, headers ...string) *httptest.ResponseRecorder {
	t.Helper()
	req := httptest.NewRequest(method, path, strings.NewReader(body))
	req.RemoteAddr = "10.0.0.7:43210"
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("X-DefenseClaw-Client", "actor-hook/1.0")
	if token != "" {
		if reflect.ValueOf(h).Pointer() == reflect.ValueOf(f.actor).Pointer() {
			req.Header.Set(substrateActorHeader, "Bearer "+token)
		} else {
			req.Header.Set("Authorization", "Bearer "+token)
		}
	}
	for i := 0; i+1 < len(headers); i += 2 {
		if headers[i+1] == "-" {
			req.Header.Del(headers[i]) // "-" removes a header the helper sets
			continue
		}
		req.Header.Set(headers[i], headers[i+1])
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	return rec
}

func envelope(connector string, payload map[string]any) string {
	p, _ := json.Marshal(payload)
	b, _ := json.Marshal(map[string]any{"v": substrateEnvelopeVersion, "connector": connector, "mode": "interactive", "kit_version": "0.1.0",
		"payload": json.RawMessage(p)})
	return string(b)
}

func reasonOf(t *testing.T, rec *httptest.ResponseRecorder) string {
	t.Helper()
	var m map[string]string
	_ = json.Unmarshal(rec.Body.Bytes(), &m)
	return m["reason"]
}

func TestSubstrateActorListenerServesOnlyItsRoutes(t *testing.T) {
	f := newSubstrateFixture(t)
	admin := []string{"/api/v1/substrate/actors", "/api/v1/substrate/asks", "/api/v1/substrate/decisions",
		"/api/v1/substrate/policy/explain", "/api/v1/substrate/usage", "/api/v1/substrate/secrets",
		"/api/v1/substrate/batches", "/api/v1/substrate/session-cert", substrateCalloutPath,
		"/api/v1/substrate/fleet/status", "/api/v1/substrate/fleet/verify",
		"/api/v1/substrate/hook/", "/api/v1/substrate/hook/notaconnector", "/api/v1/substrate/notify/claudecode",
		"/api/v1/substrate/inspect/other", "/llm/", "/", "/api/v1/claude-code/hook", "/api/v1/codex/notify"}
	for _, path := range append(mainAPIRoutePaths(t), admin...) {
		if path == "/v1/logs" || path == "/v1/metrics" || path == "/v1/traces" {
			continue
		}
		for _, method := range []string{http.MethodGet, http.MethodPost} {
			if rec := f.do(t, f.actor, method, path, "tok-alice", `{}`); rec.Code != http.StatusNotFound {
				t.Errorf("%s %s on the actor listener: %d, want 404", method, path, rec.Code)
			}
		}
	}
}

func TestSubstrateActorListenerAuthentication(t *testing.T) {
	f := newSubstrateFixture(t)
	hook := envelope("claudecode", map[string]any{"hook_event_name": "PreToolUse", "session_id": "s1",
		"tool_name": "Bash", "tool_input": map[string]any{"command": "ls"}, "cwd": "/work"})
	path := "/api/v1/substrate/hook/claudecode"
	cases := []struct {
		name    string
		token   string
		headers []string
		status  int
		reason  string
	}{
		{"no token", "", nil, 401, "missing_token"},
		{"forged header only", "", []string{"X-DefenseClaw-Actor-Uid", subUID1, "X-User-Id", "alice"}, 401, "missing_token"},
		{"gateway token as bearer", "", []string{"Authorization", "Bearer " + sandboxTestMasterToken}, 401, "missing_token"},
		{"bad token", "tok-forged", nil, 401, "signature"},
		{"worker token", "tok-worker", nil, 401, "worker_token"},
		{"recreated actor", "tok-stale", nil, 401, "actor_uid_mismatch"},
		{"verifier down", "tok-down", nil, 503, "verifier_unavailable"},
		{"unregistered actor", "tok-orphan", nil, 403, "actor_not_registered"},
		{"other connector", "tok-bob", nil, 403, "connector_mismatch"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rec := f.do(t, f.actor, http.MethodPost, path, tc.token, hook, tc.headers...)
			if rec.Code != tc.status || reasonOf(t, rec) != tc.reason {
				t.Fatalf("status %d reason %q, want %d %q (%s)", rec.Code, reasonOf(t, rec), tc.status, tc.reason, rec.Body)
			}
		})
	}
	// Two actor headers: none counts.
	req := httptest.NewRequest(http.MethodPost, path, strings.NewReader(hook))
	req.Header.Add(substrateActorHeader, "Bearer tok-alice")
	req.Header.Add(substrateActorHeader, "Bearer tok-bob")
	rec := httptest.NewRecorder()
	f.actor.ServeHTTP(rec, req)
	if rec.Code != http.StatusUnauthorized {
		t.Fatalf("two actor headers: %d", rec.Code)
	}
}

func TestSubstrateHookAnswersLikeTheSandboxIngress(t *testing.T) {
	f := newSubstrateFixture(t)
	sb := newSandboxIngressFixture(t)
	copyBinding, copyTok := sb.mint(t, "dc-claude-copy", "claudecode", "2.1.156", "claudecode-hooks-v1", "")
	_ = copyBinding
	events := []map[string]any{
		{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": map[string]any{"command": "ls -la"}},
		{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": map[string]any{"command": "cat ~/.aws/credentials"}},
		{"hook_event_name": "PreToolUse", "tool_name": "Read", "tool_input": map[string]any{"file_path": "/home/user/.ssh/id_rsa"}},
		{"hook_event_name": "PreToolUse", "tool_name": "Bash", "tool_input": map[string]any{"command": "curl -s http://169.254.169.254/latest/meta-data/iam/security-credentials/"}},
		{"hook_event_name": "UserPromptSubmit", "prompt": "list the files"},
	}
	for i, ev := range events {
		ev["session_id"] = "parity-" + string(rune('a'+i))
		ev["cwd"] = "/work/app"
		body, _ := json.Marshal(ev)
		want := sb.do(t, http.MethodPost, "/api/v1/claude-code/hook", copyTok, string(body))
		got := f.do(t, f.actor, http.MethodPost, "/api/v1/substrate/hook/claudecode", "tok-alice", envelope("claudecode", ev))
		if got.Code != want.Code {
			t.Fatalf("event %d: substrate %d, sandbox %d: %s", i, got.Code, want.Code, got.Body)
		}
		var w, g map[string]any
		_ = json.Unmarshal(want.Body.Bytes(), &w)
		_ = json.Unmarshal(got.Body.Bytes(), &g)
		for _, k := range []string{"action", "reason", "claude_code_output"} {
			wj, _ := json.Marshal(w[k])
			gj, _ := json.Marshal(g[k])
			if string(wj) != string(gj) {
				t.Errorf("event %d %s: substrate %s, sandbox %s", i, k, gj, wj)
			}
		}
		if got.Header().Get(substrateModeHeader) != "interactive" || got.Header().Get(substrateFailModeHeader) != "closed" {
			t.Errorf("mode headers %v", got.Header())
		}
		if strings.Contains(got.Body.String(), "tok-alice") {
			t.Fatal("answer echoes the actor token")
		}
		for name, vals := range got.Header() {
			for _, v := range vals {
				if strings.Contains(v, "tok-alice") {
					t.Fatalf("header %s echoes the actor token", name)
				}
			}
		}
	}
	f.mu.Lock()
	n := len(f.activity)
	f.mu.Unlock()
	if n != len(events) {
		t.Fatalf("activity %d, want %d", n, len(events))
	}
}

func TestSubstrateEnvelopeChecks(t *testing.T) {
	f := newSubstrateFixture(t)
	path := "/api/v1/substrate/hook/claudecode"
	for name, body := range map[string]string{
		"not json":         `nope`,
		"no payload":       `{"v":"dcactor/1","connector":"claudecode"}`,
		"wrong version":    `{"v":"2","connector":"claudecode","payload":{}}`,
		"other connector":  `{"v":"dcactor/1","connector":"codex","payload":{}}`,
		"attached too big": `{"v":"dcactor/1","connector":"claudecode","payload":{},"facts":{"files":[{"role":"read_target","path":"/x","content":"` + strings.Repeat("A", (2<<20)) + `"}]}}`,
	} {
		rec := f.do(t, f.actor, http.MethodPost, path, "tok-alice", body)
		if rec.Code != http.StatusBadRequest && rec.Code != http.StatusRequestEntityTooLarge {
			t.Errorf("%s: %d %s", name, rec.Code, rec.Body)
		}
	}
	// Warm-up.
	if rec := f.do(t, f.actor, http.MethodGet, path, "tok-alice", "", substrateWarmHeader, "1"); rec.Code != http.StatusNoContent {
		t.Fatalf("warm-up %d", rec.Code)
	}
	// Unattended: closed fail mode whatever the tier.
	f2 := newSubstrateFixture(t, func(c *SubstrateConfig) { c.FailOpenInteractive = true })
	rec := f2.do(t, f2.actor, http.MethodGet, "/api/v1/substrate/hook/codex", "tok-bob", "", substrateWarmHeader, "1")
	if rec.Header().Get(substrateModeHeader) != "unattended" || rec.Header().Get(substrateFailModeHeader) != "closed" {
		t.Fatalf("unattended headers %v", rec.Header())
	}
	rec = f2.do(t, f2.actor, http.MethodGet, path, "tok-alice", "", substrateWarmHeader, "1")
	if rec.Header().Get(substrateFailModeHeader) != "open" {
		t.Fatalf("interactive OSS fail mode %v", rec.Header())
	}
}

func TestSubstrateActorRateLimit(t *testing.T) {
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Limiter = ratelimit.New(ratelimit.Config{PerActorRPS: 2, PerAtespaceRPS: 1000})
	})
	path := "/api/v1/substrate/hook/claudecode"
	codes := map[int]int{}
	for i := 0; i < 10; i++ {
		rec := f.do(t, f.actor, http.MethodGet, path, "tok-alice", "", substrateWarmHeader, "1")
		codes[rec.Code]++
	}
	if codes[http.StatusNoContent] != 4 || codes[http.StatusTooManyRequests] != 6 {
		t.Fatalf("codes %v", codes)
	}
	// Another actor is not limited.
	if rec := f.do(t, f.actor, http.MethodGet, "/api/v1/substrate/hook/codex", "tok-bob", "", substrateWarmHeader, "1"); rec.Code != http.StatusNoContent {
		t.Fatalf("other actor %d", rec.Code)
	}
	if len(f.limited) != 6 || f.limited[0] != ratelimit.ScopeActor {
		t.Fatalf("metric %v", f.limited)
	}
}

func TestSubstrateRelayVerify(t *testing.T) {
	f := newSubstrateFixture(t)
	tok, _, err := f.sessions.Issue("alice", identity.SessionActor{Atespace: "eng-web", Name: "alice-1", UID: subUID1}, 0)
	if err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(map[string]string{"token": tok})
	rec := f.do(t, f.actor, http.MethodPost, substrateRelayVerify, "tok-alice", string(body))
	if rec.Code != http.StatusOK || !strings.Contains(rec.Body.String(), `"person":"alice"`) {
		t.Fatalf("own actor: %d %s", rec.Code, rec.Body)
	}
	// The same token presented by another actor (proxy takeover, E2).
	rec = f.do(t, f.actor, http.MethodPost, substrateRelayVerify, "tok-bob", string(body))
	if rec.Code != http.StatusForbidden || reasonOf(t, rec) != "session_for_another_actor" {
		t.Fatalf("other actor: %d %s", rec.Code, rec.Body)
	}
	// An actor token is not a session token.
	body, _ = json.Marshal(map[string]string{"token": "tok-alice"})
	if rec := f.do(t, f.actor, http.MethodPost, substrateRelayVerify, "tok-alice", string(body)); rec.Code != http.StatusForbidden {
		t.Fatalf("actor token as session: %d", rec.Code)
	}
}

func TestSubstrateAdminListener(t *testing.T) {
	f := newSubstrateFixture(t)
	if rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors", "", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("anonymous: %d", rec.Code)
	}
	if rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors", "tok-alice", ""); rec.Code != http.StatusUnauthorized {
		t.Fatalf("actor token on admin: %d", rec.Code)
	}
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/claude-code/hook", "p-alice", "{}"); rec.Code != http.StatusNotFound {
		t.Fatalf("hook path on admin: %d", rec.Code)
	}
	list := func(tok, q string) []map[string]any {
		rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors"+q, tok, "")
		if rec.Code != 200 {
			t.Fatalf("list %d %s", rec.Code, rec.Body)
		}
		var out struct {
			Actors []map[string]any `json:"actors"`
		}
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out.Actors
	}
	if a := list("p-alice", "?all=1"); len(a) != 1 || a[0]["name"] != "alice-1" {
		t.Fatalf("alice sees %v", a)
	}
	if a := list("p-admin", "?all=1"); len(a) != 2 {
		t.Fatalf("admin sees %v", a)
	}
	// Someone else's actor looks like a missing one.
	if rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors/eng-web/bob-1", "p-alice", ""); rec.Code != http.StatusNotFound {
		t.Fatalf("other's actor %d", rec.Code)
	}
	// Session certificates: own actor yes, another's no, admin yes.
	cert := func(tok, name string) *httptest.ResponseRecorder {
		b, _ := json.Marshal(map[string]string{"atespace": "eng-web", "name": name})
		return f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/session-cert", tok, string(b))
	}
	rec := cert("p-alice", "alice-1")
	if rec.Code != 200 {
		t.Fatalf("own session %d %s", rec.Code, rec.Body)
	}
	var sess struct{ Token string }
	_ = json.Unmarshal(rec.Body.Bytes(), &sess)
	if s, err := f.sessions.Verify(sess.Token); err != nil || s.Person != alice.ID() || s.ActorUID != subUID1 {
		t.Fatalf("issued session %+v %v", s, err)
	}
	if rec := cert("p-alice", "bob-1"); rec.Code != http.StatusNotFound {
		t.Fatalf("session for other's actor %d", rec.Code)
	}
	if rec := cert("p-admin", "bob-1"); rec.Code != 200 {
		t.Fatalf("admin session %d", rec.Code)
	}
	// Batches are own-only.
	rec = f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/batches/b1", "p-alice", "")
	if rec.Code != http.StatusNotFound {
		t.Fatalf("alice sees bob's batch: %d", rec.Code)
	}
	if rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/batches/b1", "p-bob", ""); rec.Code != 200 {
		t.Fatalf("bob's batch %d", rec.Code)
	}
	// A create without the launcher wiring.
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice", `{"profile":"eng","template":"t"}`); rec.Code != http.StatusNotImplemented {
		t.Fatalf("create without actions %d", rec.Code)
	}
}

// fakeActions creates actors in the fixture's live map.
type fakeActions struct {
	f     *substrateFixture
	order []string
}

func (a *fakeActions) Create(_ context.Context, req SubstrateCreate) (SubstrateCreated, error) {
	a.order = append(a.order, "create")
	a.f.live[req.Atespace+"/new-1"] = identity.LiveActor{UID: subUIDOther, State: "SUSPENDED"}
	return SubstrateCreated{Atespace: req.Atespace, Name: "new-1", UID: subUIDOther, Template: req.Template, Connector: "claudecode"}, nil
}

func (a *fakeActions) Resume(_ context.Context, atespace, name string) error {
	// The registration must exist before the actor runs.
	if _, ok, _ := a.f.regs.Get(context.Background(), atespace, subUIDOther); !ok {
		return errors.New("resumed before the registration was written")
	}
	a.order = append(a.order, "resume")
	return nil
}

func (a *fakeActions) Delete(context.Context, string, string) error {
	a.order = append(a.order, "delete")
	return nil
}

func TestSubstrateCreateWritesTheRegistrationFirst(t *testing.T) {
	var acts *fakeActions
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Profiles = func(p identity.Person, requested, _ string, _ bool) (string, string, error) {
			if requested != "eng" {
				return "", "", errors.New("no")
			}
			return "eng", "eng-web", nil
		}
	})
	acts = &fakeActions{f: f}
	st := f.api.substrateState()
	st.cfg.Actions = acts
	rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice", `{"profile":"eng","template":"claude-wave1","connector":"claudecode","task":"fix the tests"}`)
	if rec.Code != http.StatusCreated {
		t.Fatalf("create %d %s", rec.Code, rec.Body)
	}
	if strings.Join(acts.order, ",") != "create,resume" {
		t.Fatalf("order %v", acts.order)
	}
	reg, ok, _ := f.regs.Get(context.Background(), "eng-web", subUIDOther)
	if !ok || reg.Person.Subject != "alice" || reg.TaskDigest == "" || reg.Profile != "eng" {
		t.Fatalf("registration %+v", reg)
	}
	if !strings.Contains(rec.Body.String(), "session_token") {
		t.Fatal("interactive create has no session token")
	}
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice", `{"profile":"ops","template":"t","connector":"claudecode"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("other profile %d", rec.Code)
	}
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/actors", "p-alice", `{"profile":"eng","template":"t","connector":"claudecode","atespace":"eng-evil"}`); rec.Code != http.StatusForbidden {
		t.Fatalf("foreign atespace %d", rec.Code)
	}
}

func TestSubstrateCalloutVerdictRoute(t *testing.T) {
	f := newSubstrateFixture(t)
	req := `{"actor":{"atespace":"eng-web","name":"alice-1"},"mcp":{"host":"mcp.example.com","server":"docs","tool":"search","arguments":{"q":"hello"}}}`
	if rec := f.do(t, f.admin, http.MethodPost, substrateCalloutPath, "", req); rec.Code != http.StatusUnauthorized {
		t.Fatalf("no token %d", rec.Code)
	}
	if rec := f.do(t, f.admin, http.MethodPost, substrateCalloutPath, "p-admin", req); rec.Code != http.StatusUnauthorized {
		t.Fatalf("person token on the callout route %d", rec.Code)
	}
	rec := f.do(t, f.admin, http.MethodPost, substrateCalloutPath, subCallout, req)
	if rec.Code != 200 {
		t.Fatalf("callout %d %s", rec.Code, rec.Body)
	}
	var v SubstrateCalloutVerdict
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if v.Action != "allow" || v.ActorUID != subUID1 || v.Profile != "eng" {
		t.Fatalf("verdict %+v", v)
	}
	// A uid that is not the live one (a recreated actor) is blocked.
	stale := strings.Replace(req, `"name":"alice-1"`, `"name":"alice-1","uid":"`+subUIDOther+`"`, 1)
	rec = f.do(t, f.admin, http.MethodPost, substrateCalloutPath, subCallout, stale)
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if v.Action != "block" {
		t.Fatalf("stale uid %+v", v)
	}
	// A suspended actor makes no call (GAP-0061).
	f.live["eng-web/alice-1"] = identity.LiveActor{UID: subUID1, State: "SUSPENDED"}
	rec = f.do(t, f.admin, http.MethodPost, substrateCalloutPath, subCallout, req)
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if v.Action != "block" {
		t.Fatalf("suspended actor %+v", v)
	}
	f.live["eng-web/alice-1"] = identity.LiveActor{UID: subUID1, State: identity.ActorRunning}
	// The route is not on the actor listener.
	if rec := f.do(t, f.actor, http.MethodPost, substrateCalloutPath, "tok-alice", req); rec.Code != http.StatusNotFound {
		t.Fatalf("callout route on the actor listener %d", rec.Code)
	}
	// An unregistered or gone actor is denied.
	gone := strings.Replace(req, "alice-1", "ghost", 1)
	rec = f.do(t, f.admin, http.MethodPost, substrateCalloutPath, subCallout, gone)
	_ = json.Unmarshal(rec.Body.Bytes(), &v)
	if v.Action != "block" {
		t.Fatalf("gone actor %+v", v)
	}
	if rec := f.do(t, f.admin, http.MethodPost, substrateCalloutPath, subCallout, `{"extra":1}`); rec.Code != http.StatusBadRequest {
		t.Fatalf("bad body %d", rec.Code)
	}
}

func TestSubstrateSetValidation(t *testing.T) {
	api := NewAPIServer("127.0.0.1:18970", NewSidecarHealth(), nil, nil, nil, &config.Config{DataDir: t.TempDir()})
	if err := api.SetSubstrate(SubstrateConfig{ActorAddr: ":1"}); err == nil {
		t.Fatal("actor listener without a verifier")
	}
	regs, _ := registry.OpenFileStore(t.TempDir())
	if err := api.SetSubstrate(SubstrateConfig{ActorAddr: ":1", AdminAddr: ":1", Actors: &fakeActorTokens{}, People: fakePeople{}, Registrations: regs}); err == nil {
		t.Fatal("shared address")
	}
	_ = sandboxauth.RouteHook
}

// GAP-0037: the actor listener applies no browser CSRF gate (the actor
// token authenticates; agent SDKs and the kit send no client tag), and the
// admin listener keeps it.
func TestSubstrateCSRFOnlyOnTheAdminListener(t *testing.T) {
	llm := http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { w.WriteHeader(http.StatusNoContent) })
	f := newSubstrateFixture(t, func(c *SubstrateConfig) { c.LLM = llm })
	noTag := []string{"X-DefenseClaw-Client", "-"}
	hook := envelope("claudecode", map[string]any{"hook_event_name": "PreToolUse", "session_id": "csrf-1",
		"tool_name": "Bash", "tool_input": map[string]any{"command": "ls"}, "cwd": "/work"})
	for _, tc := range []struct{ path, body string }{
		{"/api/v1/substrate/hook/claudecode", hook},
		{"/api/v1/substrate/inspect/tool", `{"tool":"Bash","args":{"command":"ls"}}`},
		{"/llm/bedrock/model/m/invoke", `{}`},
	} {
		rec := f.do(t, f.actor, http.MethodPost, tc.path, "tok-alice", tc.body, noTag...)
		if rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
			t.Errorf("actor %s without a client tag: %d %s", tc.path, rec.Code, rec.Body)
		}
		// A cross-site browser fetch header changes nothing either: the
		// request still needs the actor token, which no page can set.
		rec = f.do(t, f.actor, http.MethodPost, tc.path, "tok-alice", tc.body, append(noTag, "Sec-Fetch-Site", "cross-site")...)
		if rec.Code == http.StatusForbidden || rec.Code == http.StatusUnauthorized {
			t.Errorf("actor %s with Sec-Fetch-Site: %d", tc.path, rec.Code)
		}
		// Without the actor token: refused.
		if rec := f.do(t, f.actor, http.MethodPost, tc.path, "", tc.body, noTag...); rec.Code != http.StatusUnauthorized {
			t.Errorf("actor %s without a token: %d", tc.path, rec.Code)
		}
	}
	// Admin: a state-changing request without the client tag is refused
	// before authentication, and a cross-site one too.
	cert := `{"atespace":"eng-web","name":"alice-1"}`
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/session-cert", "p-alice", cert, noTag...); rec.Code != http.StatusForbidden {
		t.Fatalf("admin POST without a client tag: %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/session-cert", "p-alice", cert, "Sec-Fetch-Site", "cross-site"); rec.Code != http.StatusForbidden {
		t.Fatalf("admin cross-site POST: %d", rec.Code)
	}
	if rec := f.do(t, f.admin, http.MethodPost, substrateCalloutPath, subCallout, `{}`, noTag...); rec.Code != http.StatusForbidden {
		t.Fatalf("callout POST without a client tag: %d", rec.Code)
	}
	if rec := f.do(t, f.admin, http.MethodPost, "/api/v1/substrate/session-cert", "p-alice", cert); rec.Code != http.StatusOK {
		t.Fatalf("admin POST with the client tag: %d %s", rec.Code, rec.Body)
	}
	// Reads need no tag.
	if rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/actors", "p-alice", "", noTag...); rec.Code != http.StatusOK {
		t.Fatalf("admin GET without a client tag: %d", rec.Code)
	}
}

type countingRegistrations struct {
	registry.Store
	mu   sync.Mutex
	gets int
}

func (c *countingRegistrations) Get(ctx context.Context, atespace, uid string) (registry.Registration, bool, error) {
	c.mu.Lock()
	c.gets++
	c.mu.Unlock()
	return c.Store.Get(ctx, atespace, uid)
}

// GAP-0057: the limits run right after the token check, so a refused
// request costs no registration lookup.
func TestSubstrateRateLimitBeforeTheRegistrationLookup(t *testing.T) {
	var counted *countingRegistrations
	f := newSubstrateFixture(t, func(c *SubstrateConfig) {
		c.Limiter = ratelimit.New(ratelimit.Config{PerActorRPS: 2, PerAtespaceRPS: 1000})
		counted = &countingRegistrations{Store: c.Registrations}
		c.Registrations = counted
	})
	ok := 0
	for i := 0; i < 50; i++ {
		if rec := f.do(t, f.actor, http.MethodGet, "/api/v1/substrate/hook/claudecode", "tok-alice", "", substrateWarmHeader, "1"); rec.Code == http.StatusNoContent {
			ok++
		}
	}
	counted.mu.Lock()
	defer counted.mu.Unlock()
	if counted.gets != ok || ok == 0 || ok > 5 {
		t.Fatalf("%d admitted, %d registration lookups", ok, counted.gets)
	}
}

// GAP-0106: batch IDs are checked, and an administrator's all=1 view keeps
// two owners' batches of the same ID apart.
func TestSubstrateBatchesStayPerOwner(t *testing.T) {
	f := newSubstrateFixture(t)
	ctx := context.Background()
	if err := f.regs.Put(ctx, registry.Registration{Atespace: "eng-web", Name: "alice-2", UID: subUIDOther, Connector: "claudecode",
		Profile: "eng", Person: ownerOf(alice), BatchID: "b1"}); err != nil {
		t.Fatal(err)
	}
	rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/batches?all=1", "p-admin", "")
	var list struct {
		Batches []map[string]any `json:"batches"`
	}
	_ = json.Unmarshal(rec.Body.Bytes(), &list)
	if len(list.Batches) != 2 {
		t.Fatalf("all=1 batches %s", rec.Body)
	}
	if rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/batches/b1?all=1", "p-admin", ""); rec.Code != http.StatusConflict {
		t.Fatalf("ambiguous batch %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/batches/b1?all=1&owner="+ownerOf(bob).ID(), "p-admin", ""); rec.Code != http.StatusOK {
		t.Fatalf("batch by owner %d %s", rec.Code, rec.Body)
	}
	// A person sees only their own b1.
	rec = f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/batches/b1", "p-alice", "")
	if rec.Code != http.StatusOK || strings.Contains(rec.Body.String(), "bob-1") {
		t.Fatalf("own batch %d %s", rec.Code, rec.Body)
	}
	if rec := f.do(t, f.admin, http.MethodGet, "/api/v1/substrate/batches/..%2Fx", "p-alice", ""); rec.Code == http.StatusOK {
		t.Fatalf("bad batch id %d", rec.Code)
	}
}

// GAP-0138: the gateway accepts exactly the envelope version the kit
// writes (kit.EnvelopeVersion); the old spelling and anything else are
// refused.
func TestSubstrateEnvelopeVersionFollowsTheKit(t *testing.T) {
	f := newSubstrateFixture(t)
	ev := map[string]any{"hook_event_name": "UserPromptSubmit", "session_id": "v1", "cwd": "/work", "prompt": "hi"}
	p, _ := json.Marshal(ev)
	for v, want := range map[string]int{kit.EnvelopeVersion: http.StatusOK, "dcactor/1": http.StatusBadRequest, "2": http.StatusBadRequest, "": http.StatusBadRequest} {
		b, _ := json.Marshal(map[string]any{"v": v, "connector": "claudecode", "mode": "interactive", "kit_version": "0.1.0", "payload": json.RawMessage(p)})
		if rec := f.do(t, f.actor, http.MethodPost, "/api/v1/substrate/hook/claudecode", "tok-alice", string(b)); rec.Code != want {
			t.Errorf("envelope v=%q: %d, want %d", v, rec.Code, want)
		}
	}
}

// GAP-0071: the relay check of a --task actor carries the registered task
// digest (never the text); an interactive actor's carries none.
func TestSubstrateRelayVerifyCarriesTheTaskDigest(t *testing.T) {
	f := newSubstrateFixture(t)
	ctx := context.Background()
	reg, _, _ := f.regs.Get(ctx, "eng-web", subUID2)
	reg.TaskDigest = "3f0a9c2e8b7d6f5a4c3b2a1908f7e6d5c4b3a29180f7e6d5c4b3a2918f7e6d5c"
	if err := f.regs.Put(ctx, reg); err != nil {
		t.Fatal(err)
	}
	verify := func(actorTok string, uid string, name string) map[string]any {
		tok, _, err := f.sessions.Issue(bob.ID(), identity.SessionActor{Atespace: "eng-web", Name: name, UID: uid}, 0)
		if err != nil {
			t.Fatal(err)
		}
		rec := f.do(t, f.actor, http.MethodPost, substrateRelayVerify, actorTok, `{"token":"`+tok+`"}`)
		var out map[string]any
		_ = json.Unmarshal(rec.Body.Bytes(), &out)
		return out
	}
	if got := verify("tok-bob", subUID2, "bob-1"); got["task_digest"] != reg.TaskDigest {
		t.Fatalf("task actor: %v", got)
	}
	if got := verify("tok-alice", subUID1, "alice-1"); got["task_digest"] != nil {
		t.Fatalf("interactive actor carries a digest: %v", got)
	}
}

// GAP-0138 contract test: the kit's own hook code (kit.RunHook, the
// resident helper's transport replaced by a direct call) posts to the real
// actor listener, and the listener answers the connector's verdict.
func TestKitEnvelopeAgainstTheRealListener(t *testing.T) {
	f := newSubstrateFixture(t)
	var status int
	send := func(_ context.Context, r kit.Request) (kit.Response, string, error) {
		req := httptest.NewRequest(http.MethodPost, r.Path, bytes.NewReader(r.Body))
		for k, v := range r.Header {
			req.Header.Set(k, v)
		}
		req.Header.Set("Content-Type", "application/json")
		req.Header.Set(substrateActorHeader, "Bearer tok-alice") // what egress injects
		rec := httptest.NewRecorder()
		f.actor.ServeHTTP(rec, req)
		status = rec.Code
		return kit.Response{Status: rec.Code, Body: rec.Body.Bytes()}, "", nil
	}
	ev, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "session_id": "contract", "cwd": "/work",
		"tool_name": "Bash", "tool_input": map[string]any{"command": "curl -s http://169.254.169.254/latest/meta-data/"}})
	var out, errOut bytes.Buffer
	code := kit.RunHook(context.Background(), kit.HookOptions{
		Connector: "claudecode", Event: "PreToolUse", Config: kit.DefaultConfig(),
		Stdin: bytes.NewReader(ev), Stdout: &out, Stderr: &errOut,
		Getenv: func(string) string { return "" }, Send: send, Home: t.TempDir(),
	})
	if status != http.StatusOK {
		t.Fatalf("listener answered %d to the kit's envelope (stderr %q)", status, errOut.String())
	}
	if !strings.Contains(out.String()+errOut.String(), "C2-METADATA") && code == 0 {
		t.Fatalf("the kit did not relay the block: code %d out %q err %q", code, out.String(), errOut.String())
	}
}
