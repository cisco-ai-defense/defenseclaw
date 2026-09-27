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

package manager

import (
	"context"
	"slices"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/ocsf"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

type fakeProxy struct {
	mu      sync.Mutex
	decider *egress.Decider
	sets    int
	counter *egress.Counter
}

func (p *fakeProxy) SetDecider(d *egress.Decider) error {
	p.mu.Lock()
	defer p.mu.Unlock()
	p.decider, p.sets = d, p.sets+1
	return nil
}

func (p *fakeProxy) Counter() *egress.Counter { return p.counter }

func (p *fakeProxy) current() *egress.Decider {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.decider
}

func principalOf(t *testing.T, e *harnessEnv, name string) egress.Principal {
	t.Helper()
	b, _ := e.store.Lookup(name)
	p, ok := e.m.creds.Lookup(b.ID)
	if !ok {
		t.Fatalf("no principal for %s", name)
	}
	if p.Decider == nil {
		t.Fatalf("the principal of %s has no decider of its own", name)
	}
	return p
}

// decide is the proxy's verdict for the sandbox's current principal, which
// carries the sandbox's own decider.
func decide(t *testing.T, e *harnessEnv, name, host string, port int) egress.Decision {
	t.Helper()
	p := principalOf(t, e, name)
	return p.Decider.Decide(p, host, port)
}

func TestDeciderAndUnblocks(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.OpenShell.Egress.Block = []string{"blocked.example.com"} })
	proxy := &fakeProxy{counter: egress.NewCounter(egress.CounterOptions{})}
	e.m.AttachProxy(proxy)
	e.create(sandboxapi.CreateRequest{Name: "egbox"})
	e.create(sandboxapi.CreateRequest{Name: "otherbox"})
	if proxy.current() == nil {
		t.Fatal("no default decider set")
	}
	for host, allowed := range map[string]bool{"example.org": true, "webhook.site": false, "blocked.example.com": false} {
		if got := decide(t, e, "egbox", host, 443).Allowed; got != allowed {
			t.Fatalf("%s allowed = %v, want %v", host, got, allowed)
		}
	}

	// A sandbox-scoped unblock opens the feed entry for that sandbox only.
	resp, err := e.m.Unblock(context.Background(), sandboxapi.UnblockRequest{Host: "WebHook.site", Sandbox: "egbox"})
	if err != nil || resp.Scope != "sandbox" || resp.Host != "webhook.site" || !resp.Persisted {
		t.Fatalf("unblock = %+v, %v", resp, err)
	}
	if !decide(t, e, "egbox", "webhook.site", 443).Allowed || decide(t, e, "otherbox", "webhook.site", 443).Allowed {
		t.Fatal("sandbox unblock scope is wrong")
	}
	// The operator blocklist and guard blocks are never unblocked.
	if _, err := e.m.Unblock(context.Background(), sandboxapi.UnblockRequest{Host: "blocked.example.com", Sandbox: "egbox"}); !sandboxapi.IsCode(err, sandboxapi.CodePolicyViolation) {
		t.Fatalf("operator block unblocked: %v", err)
	}
	if _, err := e.m.Unblock(context.Background(), sandboxapi.UnblockRequest{Host: "10.1.2.3", Sandbox: "egbox"}); err == nil {
		t.Fatal("private address unblocked")
	}
	if _, err := e.m.Unblock(context.Background(), sandboxapi.UnblockRequest{Host: "webhook.site"}); !sandboxapi.IsCode(err, sandboxapi.CodeInvalid) {
		t.Fatalf("unscoped unblock: %v", err)
	}
	// Always persists and opens it for everyone.
	resp, err = e.m.Unblock(context.Background(), sandboxapi.UnblockRequest{Host: "pastebin.com", Always: true})
	if err != nil || resp.Scope != "always" || !slices.Equal(e.persist.allow, []string{"pastebin.com"}) {
		t.Fatalf("always = %+v, %v (persisted %v)", resp, err, e.persist.allow)
	}
	if !decide(t, e, "otherbox", "pastebin.com", 443).Allowed {
		t.Fatal("always unblock not effective")
	}
	var unblocks int
	for _, pe := range e.tel.policy {
		if pe.Operation == audit.SandboxEgressUnblock {
			unblocks++
		}
	}
	if unblocks != 2 {
		t.Fatalf("unblock policy records = %d", unblocks)
	}
}

func TestUnblockAdminDenied(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.OpenShell.Admin.AllowUnblock = boolPtr(false)
		c.OpenShell.Admin.EgressBlock = []string{"*.corp-blocked.example"}
	})
	e.create(sandboxapi.CreateRequest{Name: "admbox"})
	for _, req := range []sandboxapi.UnblockRequest{
		{Host: "webhook.site", Sandbox: "admbox"},
		{Host: "webhook.site", Always: true},
	} {
		_, err := e.m.Unblock(context.Background(), req)
		apiErr := wantCode(t, err, sandboxapi.CodeAdminViolation)
		if !strings.Contains(apiErr.Message, sandboxapi.AdminMessage) {
			t.Fatalf("message = %q", apiErr.Message)
		}
	}
	if len(e.persist.allow) != 0 {
		t.Fatal("persisted a refused unblock")
	}
}

func TestAdminAllowOnlyForcesAllowlist(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.OpenShell.Admin.EgressAllowOnly = []string{"*.corp.example"} })
	proxy := &fakeProxy{}
	e.m.AttachProxy(proxy)
	e.create(sandboxapi.CreateRequest{Name: "aobox"})
	if mode := principalOf(t, e, "aobox").Decider.Mode(); mode != egress.ModeAllowlist {
		t.Fatalf("mode = %s", mode)
	}
	if !decide(t, e, "aobox", "git.corp.example", 443).Allowed || decide(t, e, "aobox", "example.org", 443).Allowed {
		t.Fatal("allow-only not enforced")
	}
}

func TestConfigChangeRebuildsDecider(t *testing.T) {
	e := newEnv(t, nil)
	proxy := &fakeProxy{}
	e.m.AttachProxy(proxy)
	e.run()
	e.create(sandboxapi.CreateRequest{Name: "cfgbox"})
	if !decide(t, e, "cfgbox", "late.example.com", 443).Allowed {
		t.Fatal("precondition")
	}
	proxy.mu.Lock()
	sets := proxy.sets
	proxy.mu.Unlock()
	e.setConfig(func(c *config.Config) { c.OpenShell.Egress.Block = []string{"late.example.com"} })
	eventually(t, "decider rebuild", func() bool { return !decide(t, e, "cfgbox", "late.example.com", 443).Allowed })
	// The default decider is swapped too, retiring pooled upstream
	// connections.
	eventually(t, "default decider swap", func() bool {
		proxy.mu.Lock()
		defer proxy.mu.Unlock()
		return proxy.sets > sets
	})
}

func TestEgressSinkMapping(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "sinkbox"})
	b, _ := e.store.Lookup(sb.Name)
	now := time.Now()
	sink := e.m.EgressSink()
	sink.EgressEvent(egress.Event{Kind: egress.EventAllowed, Time: now, BindingID: b.ID, SandboxName: sb.Name, Method: "CONNECT",
		Host: "registry.npmjs.org", Port: 443, RemoteAddr: "104.16.0.1:443", Source: egress.SourceDefault, FirstSeen: true})
	sink.EgressEvent(egress.Event{Kind: egress.EventAllowed, Time: now, BindingID: b.ID, SandboxName: sb.Name, Method: "CONNECT",
		Host: "registry.npmjs.org", Port: 443, Source: egress.SourceDefault})
	sink.EgressEvent(egress.Event{Kind: egress.EventBlocked, Time: now, BindingID: b.ID, SandboxName: sb.Name, Method: "CONNECT",
		Host: "webhook.site", Port: 443, Category: "webhook_catcher", Source: egress.SourceFeed, Entry: "webhook.site", Reason: "exfil destination",
		Unblockable: true})
	sink.EgressEvent(egress.Event{Kind: egress.EventLargeUpload, Time: now, BindingID: b.ID, SandboxName: sb.Name,
		Host: "files.example.net", BytesUp: 30 << 20, Terminated: true})
	sink.EgressEvent(egress.Event{Kind: egress.EventAllowed, SandboxName: "unknown-box", Host: "x.example"})

	eventually(t, "egress telemetry", func() bool {
		e.tel.mu.Lock()
		defer e.tel.mu.Unlock()
		return len(e.tel.egress) == 3 && len(e.tel.findings) == 1
	})
	// The sink publishes the large upload to the feed after recording its
	// finding.
	eventually(t, "the large upload in the feed", func() bool {
		for _, ev := range e.m.ActivitySince(0, sb.Name) {
			if ev.Kind == sandboxapi.ActivityEgressLargeUpload {
				return true
			}
		}
		return false
	})
	e.tel.mu.Lock()
	allowed, blocked := e.tel.egress[0], e.tel.egress[2]
	finding := e.tel.findings[0]
	e.tel.mu.Unlock()
	if allowed.Source != audit.SandboxEgressSourceProxy || allowed.Blocked || allowed.Scheme != "https" || allowed.ResolvedIP != "104.16.0.1" ||
		allowed.DecisionCode != "SANDBOX_EGRESS_ALLOWED" || allowed.Sandbox.Name != sb.Name {
		t.Fatalf("allowed = %+v", allowed)
	}
	if !blocked.Blocked || blocked.DecisionCode != "SANDBOX_EGRESS_WEBHOOK_CATCHER" || !strings.Contains(blocked.PolicyOutcome, "feed") {
		t.Fatalf("blocked = %+v", blocked)
	}
	if finding.Kind != audit.SandboxFindingLargeUpload || finding.Severity != "HIGH" || finding.TargetRef != "files.example.net" {
		t.Fatalf("finding = %+v", finding)
	}
	// The feed shows first contact and blocks, not every tunnel.
	var egressEvents []sandboxapi.ActivityEvent
	for _, ev := range e.m.ActivitySince(0, sb.Name) {
		if strings.HasPrefix(ev.Kind, "egress.") {
			egressEvents = append(egressEvents, ev)
		}
	}
	if len(egressEvents) != 3 || egressEvents[0].Kind != sandboxapi.ActivityEgressAllowed ||
		egressEvents[1].Kind != sandboxapi.ActivityEgressBlocked || !egressEvents[1].Unblockable ||
		egressEvents[2].Kind != sandboxapi.ActivityEgressLargeUpload {
		t.Fatalf("feed = %+v", egressEvents)
	}
	if !strings.Contains(egressEvents[1].Message, "webhook.site") {
		t.Fatalf("block message = %q", egressEvents[1].Message)
	}
}

func TestOCSFMapping(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "ocsfbox"})
	e.watch.waitStarted(t, sb.Name)
	push := func(line string) {
		rec, err := ocsf.Parse(line)
		if err != nil {
			t.Fatalf("parse %q: %v", line, err)
		}
		e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindLog, Time: time.Now(), Log: &stream.Log{Level: "OCSF", Target: "ocsf", Message: line, OCSF: &rec}})
	}
	push("NET:OPEN [MED] DENIED /usr/bin/python3(42) -> evil.example.com:443/tcp [policy:- engine:opa] [reason:transparent_tcp_policy_denied]")
	push("NET:OPEN [INFO] ALLOWED /opt/defenseclaw-harness/claudecode/bin/claude(7) -> api.anthropic.com:443/tcp [policy:_provider_x engine:opa]")
	push("NET:OPEN [INFO] ALLOWED /usr/bin/curl(9) -> host.openshell.internal:18972/tcp [policy:defenseclaw_egress engine:opa]")
	push("FINDING:BLOCKED [HIGH] \"Binary drift detected\" [confidence:0.9]")

	e.tel.mu.Lock()
	egressRecs, findings := append([]audit.SandboxEgressEvent(nil), e.tel.egress...), append([]audit.SandboxFindingEvent(nil), e.tel.findings...)
	e.tel.mu.Unlock()
	if len(egressRecs) != 2 {
		t.Fatalf("egress = %+v", egressRecs)
	}
	if !egressRecs[0].Blocked || egressRecs[0].Host != "evil.example.com" || egressRecs[0].Source != audit.SandboxEgressSourceOpenShell ||
		egressRecs[0].DecisionCode != "SANDBOX_EGRESS_OPENSHELL_DENIED" {
		t.Fatalf("denied = %+v", egressRecs[0])
	}
	if egressRecs[1].Blocked || egressRecs[1].Host != "api.anthropic.com" {
		t.Fatalf("allowed = %+v", egressRecs[1])
	}
	if len(findings) != 1 || findings[0].Kind != audit.SandboxFindingOCSF || findings[0].Severity != "HIGH" {
		t.Fatalf("findings = %+v", findings)
	}
	got, _ := e.m.Get(context.Background(), sb.Name)
	if got.Egress.Blocked != 1 {
		t.Fatalf("blocked count = %d", got.Egress.Blocked)
	}
}

func TestHookCoverageAndSilence(t *testing.T) {
	e := newEnv(t, nil)
	var nowMu sync.Mutex
	now := time.Now()
	clock := func() time.Time { nowMu.Lock(); defer nowMu.Unlock(); return now }
	advance := func(d time.Duration) { nowMu.Lock(); now = now.Add(d); nowMu.Unlock() }
	e.m.opts.Now, e.m.now = clock, clock
	sb := e.create(sandboxapi.CreateRequest{Name: "hookbox"})
	binding, _ := e.store.Lookup(sb.Name)

	e.m.ObserveIngress(binding, sandboxauth.RouteHook)
	e.m.ObserveHookDecision(HookDecision{BindingID: binding.ID, SandboxName: sb.Name, Event: "PreToolUse", Tool: "Bash", Action: "allow"})
	e.m.ObserveHookDecision(HookDecision{BindingID: binding.ID, SandboxName: sb.Name, Event: "PreToolUse", Tool: "Bash", Action: "block",
		Reason: "DCBLOCK rule matched", Severity: "HIGH"})
	e.m.ObserveHookDecision(HookDecision{BindingID: binding.ID, SandboxName: sb.Name, Event: "PostToolUse", Action: "allow"})
	e.m.ObserveHookDecision(HookDecision{BindingID: "sb_other", SandboxName: sb.Name, Event: "PreToolUse", Action: "block"})
	got, _ := e.m.Get(context.Background(), sb.Name)
	if got.Hooks.HookRequests != 1 || got.Hooks.ToolCalls != 2 || got.Hooks.ToolBlocked != 1 || got.Hooks.LastBlocked != "DCBLOCK rule matched" {
		t.Fatalf("hooks = %+v", got.Hooks)
	}
	var toolBlocked bool
	for _, ev := range e.m.ActivitySince(0, sb.Name) {
		toolBlocked = toolBlocked || (ev.Kind == sandboxapi.ActivityToolBlocked && ev.Tool == "Bash")
	}
	if !toolBlocked {
		t.Fatal("tool block not on the feed")
	}

	// Activity well after the last hook raises one finding.
	advance(15 * time.Minute)
	e.m.markActive(e.m.boxes[sb.Name], clock())
	e.m.checkHookSilence(context.Background())
	e.m.checkHookSilence(context.Background())
	var silence int
	for _, f := range e.tel.findings {
		if f.Kind == audit.SandboxFindingHookSilence {
			silence++
		}
	}
	if silence != 1 {
		t.Fatalf("hook silence findings = %d", silence)
	}
	got, _ = e.m.Get(context.Background(), sb.Name)
	if !got.Hooks.Silent {
		t.Fatal("not marked silent")
	}
	e.m.ObserveIngress(binding, sandboxauth.RouteHook)
	got, _ = e.m.Get(context.Background(), sb.Name)
	if got.Hooks.Silent {
		t.Fatal("a hook did not clear the silence")
	}
	// Idle harness: no finding.
	advance(time.Hour)
	e.m.checkHookSilence(context.Background())
	silence = 0
	for _, f := range e.tel.findings {
		if f.Kind == audit.SandboxFindingHookSilence {
			silence++
		}
	}
	if silence != 1 {
		t.Fatalf("idle harness raised a finding: %d", silence)
	}
}

func TestRecoverCredential(t *testing.T) {
	sb := &openshell.Sandbox{Spec: openshell.SandboxSpec{Environment: map[string]string{
		"HTTPS_PROXY": "http://dcx-abc:secret@host.openshell.internal:18972",
	}}}
	if c, ok := recoverCredential(sb, "dcx-abc"); !ok || c.Password != "secret" {
		t.Fatalf("recover = %+v %v", c, ok)
	}
	if _, ok := recoverCredential(sb, "dcx-other"); ok {
		t.Fatal("recovered a credential for another user")
	}
	if _, ok := recoverCredential(&openshell.Sandbox{}, ""); ok {
		t.Fatal("recovered from nothing")
	}
}

// TestAlwaysDecisionsAreUnblocks pins that saved "always" decisions
// (openshell.egress.unblocked) reach the proxy as unblocks, which lift the
// blocklist and allowlist but never open the private addresses a name
// resolves to, and that they stop counting once unblocking is forbidden.
func TestAlwaysDecisionsAreUnblocks(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.OpenShell.Profile = config.OpenShellProfileBalanced
		c.OpenShell.Egress.Unblocked = []string{"cdn.example.org", "webhook.site"}
	})
	proxy := &fakeProxy{counter: egress.NewCounter(egress.CounterOptions{})}
	e.m.AttachProxy(proxy)
	e.create(sandboxapi.CreateRequest{Name: "alwaysbox"})
	for _, host := range []string{"cdn.example.org", "webhook.site"} {
		if dec := decide(t, e, "alwaysbox", host, 443); !dec.Allowed || dec.Source != egress.SourceUnblock {
			t.Fatalf("%s = %+v, want allowed by an unblock (not an operator allow)", host, dec)
		}
	}
	if dec := decide(t, e, "alwaysbox", "other.example.org", 443); dec.Allowed {
		t.Fatalf("unlisted host allowed in allowlist mode: %+v", dec)
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.AllowUnblock = boolPtr(false) })
	e.m.refreshEgress()
	if dec := decide(t, e, "alwaysbox", "cdn.example.org", 443); dec.Allowed || dec.Unblockable {
		t.Fatalf("saved unblock applied after allow_unblock=false: %+v", dec)
	}
}

// TestStrictProfileRevokesTheProxyCredential pins that a sandbox whose
// policy becomes strict (an administrator raising min_profile) loses the
// egress proxy instead of keeping open egress through it.
func TestStrictProfileRevokesTheProxyCredential(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "strictbox"})
	b, _ := e.store.Lookup("strictbox")
	if _, ok := e.m.creds.Lookup(b.ID); !ok {
		t.Fatal("no proxy credential")
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.MinProfile = config.OpenShellProfileStrict })
	e.m.refreshEgress()
	if p, ok := e.m.creds.Lookup(b.ID); ok {
		t.Fatalf("proxy credential still registered under strict: %+v", p)
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.MinProfile = "" })
	e.m.refreshEgress()
	if _, ok := e.m.creds.Lookup(b.ID); !ok {
		t.Fatal("proxy credential not restored when the profile relaxed")
	}
}
