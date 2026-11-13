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

package extproc

import (
	"context"
	"encoding/base64"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

// Test values are assembled at run time so no credential-shaped literal sits
// in the source.
var (
	fakeGitHubToken = "gh" + "p_" + strings.Repeat("aB3", 12)
	fakeAWSKey      = "AK" + "IA" + "QWERTYUIOP123456"
	fakeJWT         = "ey" + "JhbGciOiJFUzI1NiJ9.ey" + "JzdWIiOiJhY3Rvci94L3kifQ." + strings.Repeat("sig_", 6)
	injectedBearer  = "Bearer " + "gh" + "s_" + strings.Repeat("Zx9", 12)
)

type fakeUIDs struct {
	mu         sync.Mutex
	uid        string
	profile    string
	unattended bool
	live       bool
	err        error
	calls      int
}

func (f *fakeUIDs) ResolveActor(context.Context, string, string) (ActorRecord, bool, error) {
	f.mu.Lock()
	defer f.mu.Unlock()
	f.calls++
	return ActorRecord{UID: f.uid, Profile: f.profile, Unattended: f.unattended}, f.live, f.err
}

type fakeAsks struct {
	res   AskResult
	err   error
	delay time.Duration
	got   []AskRequest
}

func (f *fakeAsks) Ask(ctx context.Context, req AskRequest) (AskResult, error) {
	f.got = append(f.got, req)
	if f.delay > 0 {
		select {
		case <-time.After(f.delay):
		case <-ctx.Done():
			return AskResult{Outcome: AskPending, ID: "ask-1"}, ctx.Err()
		}
	}
	return f.res, f.err
}

type fakeChain struct {
	mu    sync.Mutex
	steps []ChainStep
	block chan struct{}
}

func (f *fakeChain) ObserveEgress(_ context.Context, s ChainStep) error {
	if f.block != nil {
		<-f.block
	}
	f.mu.Lock()
	f.steps = append(f.steps, s)
	f.mu.Unlock()
	return nil
}

func (f *fakeChain) snapshot() []ChainStep {
	f.mu.Lock()
	defer f.mu.Unlock()
	return append([]ChainStep(nil), f.steps...)
}

type fakeChecker struct {
	v     ChainVerdict
	err   error
	delay time.Duration
}

func (f fakeChecker) CheckEgress(ctx context.Context, _ ChainStep) (ChainVerdict, error) {
	if f.delay > 0 {
		time.Sleep(f.delay)
	}
	return f.v, f.err
}

type fakeJudge struct {
	block bool
	alert bool
	err   error
	calls []ToolCall
}

func (f *fakeJudge) JudgeToolCall(_ context.Context, c ToolCall) (ToolVerdict, error) {
	f.calls = append(f.calls, c)
	if f.err != nil {
		return ToolVerdict{}, f.err
	}
	return ToolVerdict{Block: f.block, Alert: f.alert, Reason: "rule TEST-MCP matched"}, nil
}

type captureSink struct {
	mu     sync.Mutex
	events []Event
}

func (c *captureSink) EgressEvent(e Event) {
	c.mu.Lock()
	c.events = append(c.events, e)
	c.mu.Unlock()
}

const testConfig = `
request_access: the platform team
mcp_hosts: ["mcp.example.com=tickets"]
body_hosts: [upload.example.org]
log_headers: true
secrets:
  - name: github-push
    hosts: [github.com, api.github.com]
    header: Authorization
    placeholder: DC_SECRET_GITHUB
default_profile: base
profiles:
  - name: eng
    atespaces: ["eng-*"]
    egress:
      admin_block: ["*.forbidden.example"]
      block: [blocked.example.net]
      allow: [pastebin.com]
    url_rules:
      - {name: no-delete, hosts: [api.github.com], methods: [DELETE], action: deny}
      - {name: ask-release, hosts: [api.github.com], path_prefix: /repos/acme/releases, action: ask}
    ask_hosts: [files.example.io]
    actor_secrets: [db-password]
  - name: base
`

type harness struct {
	eng    *Engine
	uids   *fakeUIDs
	asks   *fakeAsks
	chain  *fakeChain
	judge  *fakeJudge
	events *captureSink
	dir    string
}

func newHarness(t *testing.T, mutate func(*Config, *Options)) *harness {
	t.Helper()
	cfg, err := ParseConfig([]byte(testConfig))
	if err != nil {
		t.Fatal(err)
	}
	h := &harness{uids: &fakeUIDs{uid: "uid-1", live: true}, asks: &fakeAsks{res: AskResult{Outcome: AskApproved, ID: "ask-1"}},
		chain: &fakeChain{}, judge: &fakeJudge{}, events: &captureSink{}, dir: t.TempDir()}
	cfg.ActorSecretsDir = h.dir
	if err := os.WriteFile(filepath.Join(h.dir, "db-password"), []byte("s3cret-db-value-123\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	o := Options{Config: cfg, UIDs: h.uids, Asks: h.asks, ChainSink: h.chain, Judge: h.judge, Events: h.events}
	if mutate != nil {
		mutate(cfg, &o)
	}
	h.eng, err = NewEngine(o)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(h.eng.Close)
	return h
}

func req(atespace, method, authority, path string, headers ...string) *Request {
	r := &Request{Actor: ActorRef{Atespace: atespace, Name: "a1"}, Method: method, Authority: authority, Path: path,
		ContentLength: -1, EndOfStream: true, Start: time.Now()}
	r.Headers = []Header{{":method", method}, {":authority", authority}, {":path", path}}
	for i := 0; i+1 < len(headers); i += 2 {
		r.Headers = append(r.Headers, Header{strings.ToLower(headers[i]), headers[i+1]})
	}
	r.Host, _, _ = splitAuthority(authority)
	return r
}

func TestDecideFeedsAndLists(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	cases := []struct {
		name, atespace, host string
		allow                bool
		category             string
	}{
		{"feed block", "other", "pastebin.com", false, "paste_site"},
		{"feed block subdomain", "other", "x.webhook.site", false, "webhook_catcher"},
		{"open default", "other", "example.com", true, ""},
		{"cluster service", "other", "echo.ns.svc.cluster.local", true, ""},
		{"profile allow overrides feed", "eng-web", "pastebin.com", true, ""},
		{"profile block", "eng-web", "blocked.example.net", false, "operator_block"},
		{"admin block", "eng-web", "a.forbidden.example", false, "admin_block"},
		{"host internal", "other", "metadata.google.internal", false, "host_internal"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := h.eng.DecideHeaders(ctx, req(c.atespace, "GET", c.host, "/"))
			if v.Allow != c.allow || (!c.allow && v.Category != c.category) {
				t.Fatalf("got allow=%v category=%q reason=%q", v.Allow, v.Category, v.Reason)
			}
		})
	}
}

func TestAdminBlockUsesManagedRefusal(t *testing.T) {
	h := newHarness(t, nil)
	r := req("eng-web", "GET", "a.forbidden.example:443", "/")
	v := h.eng.DecideHeaders(context.Background(), r)
	body := string(h.eng.refusalBody(r, v))
	for _, want := range []string{`"error":"egress_blocked"`, "Blocked by your organization", "the platform team", "rule egress_block"} {
		if !strings.Contains(body, want) {
			t.Fatalf("refusal body lacks %q: %s", want, body)
		}
	}
}

func TestURLRules(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	v := h.eng.DecideHeaders(ctx, req("eng-web", "DELETE", "api.github.com", "/repos/acme/x"))
	if v.Allow || v.Category != CategoryURLRule || v.Rule != "no-delete" {
		t.Fatalf("delete: %+v", v)
	}
	v = h.eng.DecideHeaders(ctx, req("eng-web", "GET", "api.github.com", "/repos/acme/x"))
	if !v.Allow {
		t.Fatalf("get: %+v", v)
	}
	v = h.eng.DecideHeaders(ctx, req("eng-web", "POST", "api.github.com", "/repos/acme/releases?x=1"))
	if !v.Allow || v.AskID != "ask-1" || len(h.asks.got) != 1 || h.asks.got[0].Rule != "url_rules:ask-release" {
		t.Fatalf("ask rule: %+v asks=%+v", v, h.asks.got)
	}
}

func TestDLPHeadersAndURL(t *testing.T) {
	h := newHarness(t, func(c *Config, _ *Options) {})
	ctx := context.Background()
	b64 := base64.StdEncoding.EncodeToString([]byte("s3cret-db-value-123"))
	cases := []struct {
		name     string
		r        *Request
		allow    bool
		alert    bool
		category string
	}{
		{"token in query", req("eng-web", "GET", "example.com", "/x?token="+fakeGitHubToken), false, false, findSecretInURL},
		{"token percent-encoded twice", req("eng-web", "GET", "example.com", "/x?k=%2541KIAQWERTYUIOP123456"), false, false, findSecretInURL},
		{"token in data header", req("eng-web", "GET", "example.com", "/", "X-Data", fakeAWSKey), false, false, findSecretInHeader},
		{"jwt in actor header off-cluster", req("eng-web", "GET", "example.com", "/", "x-defenseclaw-actor", fakeJWT), false, false, findSecretInHeader},
		{"token in auth header alerts", req("eng-web", "GET", "example.com", "/", "Authorization", "Bearer "+fakeGitHubToken), true, true, ""},
		{"injected header on bound host", req("eng-web", "GET", "api.github.com", "/", "authorization", injectedBearer), true, false, ""},
		{"actor secret value", req("eng-web", "GET", "example.com", "/q?v=s3cret-db-value-123"), false, false, findActorSecret},
		{"actor secret base64 in header", req("eng-web", "GET", "example.com", "/", "x-blob", b64), false, false, findActorSecret},
		{"placeholder to unbound host", req("eng-web", "GET", "example.com", "/", "x-token", "DC_SECRET_GITHUB"), true, true, ""},
		{"placeholder to bound host", req("eng-web", "GET", "github.com", "/", "x-token", "DC_SECRET_GITHUB"), true, false, ""},
		{"actor secret only in its profile", req("other", "GET", "example.com", "/q?v=s3cret-db-value-123"), true, false, ""},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := h.eng.DecideHeaders(ctx, c.r)
			if v.Allow != c.allow || v.Alert != c.alert || (!c.allow && v.Category != c.category) {
				t.Fatalf("got %+v", v)
			}
		})
	}
}

func TestCredentialHeaderDenyMode(t *testing.T) {
	h := newHarness(t, func(c *Config, _ *Options) { c.DLP.CredentialHeaders = "deny" })
	v := h.eng.DecideHeaders(context.Background(), req("x", "GET", "example.com", "/", "authorization", "Bearer "+fakeGitHubToken))
	if v.Allow || v.Category != findSecretInCredential {
		t.Fatalf("got %+v", v)
	}
}

func TestOwnHostSkipsInspection(t *testing.T) {
	h := newHarness(t, nil)
	r := req("eng-web", "POST", "defenseclaw-actor.defenseclaw-system.svc", "/llm/bedrock?k="+fakeGitHubToken,
		"x-defenseclaw-actor", "Bearer "+fakeJWT, "content-type", "application/json")
	r.ContentLength, r.EndOfStream = 100, false
	v := h.eng.DecideHeaders(context.Background(), r)
	if !v.Allow || !v.OwnHost || v.WantBody {
		t.Fatalf("got %+v", v)
	}
	h.eng.Finish(r, v)
	if len(h.events.events) != 0 {
		t.Fatalf("own-host request logged: %+v", h.events.events)
	}
}

func TestIdentityAndUID(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil)
	r := req("x", "GET", "example.com", "/")
	r.IdentityErr = ErrNoIdentity
	if v := h.eng.DecideHeaders(ctx, r); v.Allow || v.Category != CategoryUnattributed {
		t.Fatalf("no identity: %+v", v)
	}
	h.uids.live = false
	if v := h.eng.DecideHeaders(ctx, req("gone", "GET", "example.com", "/")); v.Allow || v.Category != CategoryActorNotLive {
		t.Fatalf("not live: %+v", v)
	}
	h.uids.live, h.uids.err = true, errors.New("control API down")
	v := h.eng.DecideHeaders(ctx, req("down", "GET", "example.com", "/"))
	if v.Allow || v.Category != CategoryActorUnverified || !v.Retryable {
		t.Fatalf("outage closed: %+v", v)
	}
	ho := newHarness(t, func(c *Config, _ *Options) { c.FailureMode = FailureOpen })
	ho.uids.err = errors.New("control API down")
	if v := ho.eng.DecideHeaders(ctx, req("down", "GET", "example.com", "/")); !v.Allow || !v.Alert {
		t.Fatalf("outage open: %+v", v)
	}
}

func TestUIDCacheStaleAndInvalidate(t *testing.T) {
	f := &fakeUIDs{uid: "u1", live: true}
	now := time.Unix(1000, 0)
	c := NewUIDCache(f, 10*time.Second, 60*time.Second)
	c.now = func() time.Time { return now }
	a := ActorRef{Atespace: "s", Name: "n"}
	if rec, err := c.Resolve(context.Background(), a); rec.UID != "u1" || err != nil {
		t.Fatal(rec, err)
	}
	now = now.Add(5 * time.Second)
	_, _ = c.Resolve(context.Background(), a)
	if f.calls != 1 {
		t.Fatalf("fresh entry re-resolved: %d", f.calls)
	}
	f.err = errors.New("down")
	now = now.Add(30 * time.Second)
	if rec, err := c.Resolve(context.Background(), a); rec.UID != "u1" || err != nil {
		t.Fatalf("stale entry not served: %+v %v", rec, err)
	}
	now = now.Add(60 * time.Second)
	if _, err := c.Resolve(context.Background(), a); err == nil {
		t.Fatal("entry past stale_max served")
	}
	f.err, f.uid = nil, "u2"
	c.Invalidate("s", "n")
	if rec, _ := c.Resolve(context.Background(), a); rec.UID != "u2" {
		t.Fatalf("recreated actor kept old UID: %+v", rec)
	}
}

// An unregistered actor's miss is reused for uidMissTTL only, so a launched
// actor's registration is seen within a second (GAP-0090).
func TestUIDCacheMissIsShort(t *testing.T) {
	f := &fakeUIDs{live: true}
	now := time.Unix(1000, 0)
	c := NewUIDCache(f, 60*time.Second, 60*time.Second)
	c.now = func() time.Time { return now }
	a := ActorRef{Atespace: "s", Name: "n"}
	if rec, err := c.Resolve(context.Background(), a); rec.UID != "" || err != nil {
		t.Fatal(rec, err)
	}
	f.uid = "u1"
	now = now.Add(uidMissTTL / 2)
	if rec, _ := c.Resolve(context.Background(), a); rec.UID != "" || f.calls != 1 {
		t.Fatalf("miss not reused: %+v calls %d", rec, f.calls)
	}
	now = now.Add(uidMissTTL)
	if rec, _ := c.Resolve(context.Background(), a); rec.UID != "u1" {
		t.Fatalf("registration not seen after the miss TTL: %+v", rec)
	}
	f.live, f.uid = false, ""
	c.Invalidate("s", "n")
	if _, err := c.Resolve(context.Background(), a); !errors.Is(err, ErrActorNotLive) {
		t.Fatalf("deleted actor: %v", err)
	}
}

func TestChainCheckBudget(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, func(_ *Config, o *Options) {
		o.ChainChecker = fakeChecker{v: ChainVerdict{Deny: true, Rule: "secret-read-then-egress"}}
	})
	if v := h.eng.DecideHeaders(ctx, req("x", "POST", "example.com", "/")); v.Allow || v.Category != CategoryChainEgress {
		t.Fatalf("chain hit: %+v", v)
	}
	slow := newHarness(t, func(_ *Config, o *Options) {
		o.ChainChecker = fakeChecker{v: ChainVerdict{Deny: true}, delay: 200 * time.Millisecond}
	})
	start := time.Now()
	if v := slow.eng.DecideHeaders(ctx, req("x", "POST", "example.com", "/")); !v.Allow {
		t.Fatalf("slow chain check refused: %+v", v)
	}
	if d := time.Since(start); d > 150*time.Millisecond {
		t.Fatalf("chain check took %s, budget 20ms", d)
	}
	errc := newHarness(t, func(_ *Config, o *Options) { o.ChainChecker = fakeChecker{err: errors.New("leader down")} })
	if v := errc.eng.DecideHeaders(ctx, req("x", "POST", "example.com", "/")); !v.Allow {
		t.Fatalf("chain error refused: %+v", v)
	}
}

func TestAsks(t *testing.T) {
	ctx := context.Background()
	h := newHarness(t, nil)
	if v := h.eng.DecideHeaders(ctx, req("eng-web", "PUT", "files.example.io", "/")); !v.Allow || v.Source != sourceAsk {
		t.Fatalf("approved: %+v", v)
	}
	if got := h.asks.got[0]; got.Rule != "ask_hosts:files.example.io" || got.UnattendedAsks != "deny" || got.Actor.UID != "uid-1" {
		t.Fatalf("ask request: %+v", got)
	}
	h.asks.res = AskResult{Outcome: AskDenied, ID: "ask-2"}
	if v := h.eng.DecideHeaders(ctx, req("eng-web", "PUT", "files.example.io", "/")); v.Allow || v.Category != CategoryAskDenied {
		t.Fatalf("denied: %+v", v)
	}
	h.asks.res, h.asks.delay = AskResult{Outcome: AskApproved}, time.Hour
	h.eng.cfg.Ask.Hold = 20 * time.Millisecond
	r := req("eng-web", "PUT", "files.example.io", "/")
	v := h.eng.DecideHeaders(ctx, r)
	if v.Allow || v.Category != CategoryAskPending || v.AskID != "ask-1" {
		t.Fatalf("pending: %+v", v)
	}
	if body := string(h.eng.refusalBody(r, v)); !strings.Contains(body, "ask-1") {
		t.Fatalf("pending body lacks the ask id: %s", body)
	}
	none := newHarness(t, func(_ *Config, o *Options) { o.Asks = nil })
	none.eng.asks = nil
	if v := none.eng.DecideHeaders(ctx, req("eng-web", "PUT", "files.example.io", "/")); v.Allow || v.Category != CategoryAskDenied {
		t.Fatalf("no ask sink: %+v", v)
	}
}

func TestObservedEgressQueue(t *testing.T) {
	h := newHarness(t, nil)
	ctx := context.Background()
	for _, r := range []*Request{req("x", "GET", "example.com", "/a"), req("x", "GET", "pastebin.com", "/"),
		req("x", "GET", "defenseclaw-actor.defenseclaw-system.svc", "/hook")} {
		h.eng.Finish(r, h.eng.DecideHeaders(ctx, r))
	}
	h.eng.Close()
	steps := h.chain.snapshot()
	if len(steps) != 2 || steps[0].Host != "example.com" || !steps[0].Allowed || steps[1].Allowed {
		t.Fatalf("steps: %+v", steps)
	}
	if steps[0].Kind != StepObservedEgress || steps[0].Actor.UID != "uid-1" {
		t.Fatalf("step: %+v", steps[0])
	}
}

func TestObservedEgressQueueNeverBlocks(t *testing.T) {
	sink := &fakeChain{block: make(chan struct{})}
	h := newHarness(t, func(c *Config, o *Options) { c.Chain.QueueSize = 2; o.ChainSink = sink })
	r := req("x", "GET", "example.com", "/")
	v := h.eng.DecideHeaders(context.Background(), r)
	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			h.eng.Finish(r, v)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(2 * time.Second):
		t.Fatal("Finish blocked on a full chain queue")
	}
	if h.eng.ChainDropped() == 0 {
		t.Fatal("no drops counted")
	}
	close(sink.block)
}

func TestConfigValidation(t *testing.T) {
	cfg, err := ParseConfig(nil)
	if err != nil {
		t.Fatal(err)
	}
	if cfg.FailureMode != FailureClosed || cfg.BodyInspection != BodyAuto || cfg.BodyMaxBytes != 1<<20 ||
		cfg.Chain.CheckBudget != 20*time.Millisecond || cfg.UID.StaleMax != 60*time.Second {
		t.Fatalf("defaults: %+v", cfg)
	}
	for _, bad := range []string{
		"unknown_key: 1",
		"body_max_bytes: 2097152",
		"failure_mode: maybe",
		"profiles: [{name: p, url_rules: [{hosts: [x.com], action: nope}]}]",
		"profiles: [{name: p, ask_hosts: ['a*b.com']}]",
		"secrets: [{name: s, hosts: [x.com]}]",
		"default_profile: missing",
		"profiles: [{name: p, actor_secrets: ['../etc/passwd']}]",
	} {
		if _, err := ParseConfig([]byte(bad)); !errors.Is(err, ErrInvalidConfig) {
			t.Errorf("%q: got %v", bad, err)
		}
	}
}

func TestParseActorSPIFFE(t *testing.T) {
	a, err := ParseActorSPIFFE("spiffe://substrate-actor.local/worker-for-actor/eng-web/cc-1", "")
	if err != nil || a.Atespace != "eng-web" || a.Name != "cc-1" {
		t.Fatalf("%+v %v", a, err)
	}
	for _, bad := range []string{
		"", "https://substrate-actor.local/worker-for-actor/a/b",
		"spiffe://other.local/worker-for-actor/a/b",
		"spiffe://substrate-actor.local/actor/a/b",
		"spiffe://substrate-actor.local/worker-for-actor/a",
		"spiffe://substrate-actor.local/worker-for-actor/a/b/c",
		"spiffe://substrate-actor.local/worker-for-actor/a/%2e%2e",
		"spiffe://substrate-actor.local/worker-for-actor/a/b?x=1",
		"spiffe://substrate-actor.local/worker-for-actor/-a/b",
	} {
		if _, err := ParseActorSPIFFE(bad, ""); !errors.Is(err, ErrNoIdentity) {
			t.Errorf("%q: got %v", bad, err)
		}
	}
}
