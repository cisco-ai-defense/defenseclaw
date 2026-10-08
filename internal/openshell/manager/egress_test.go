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

package manager

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/profiles"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
	"github.com/defenseclaw/defenseclaw/internal/openshell/triage"
	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// The policy layer, a real egress proxy, REST unblock and triage agree on
// the same inputs: a destination is allowed by both layers or neither, an
// unblock is accepted exactly for what the proxy allows or can lift (and takes
// effect), and triage never approves a direct rule the proxy refuses.
func TestEgressSemanticsAgree(t *testing.T) {
	packDir := writeTeamPack(t)
	type want struct {
		allowed, unblockable bool
		category             egress.Category
		unblockCode          string // "" when the REST unblock is accepted
		triage, afterTriage  triage.Verdict
		// policyAllowed is the policy layer's verdict where it differs from the
		// proxy's: it sees the host as named, the proxy what it resolves to.
		policyAllowed *bool
	}
	yes := true
	block := func(o *config.OpenShellConfig, hosts ...string) { o.Egress.Block = hosts }
	allow := func(hosts ...string) func(*config.OpenShellConfig) {
		return func(o *config.OpenShellConfig) { o.Egress.Allow = hosts }
	}
	allowOnly := func(hosts ...string) func(*config.OpenShellConfig) {
		return func(o *config.OpenShellConfig) { o.Admin.EgressAllowOnly = hosts }
	}
	noUnblock := func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }
	team, balanced := sandboxapi.CreateRequest{Pack: "team"}, sandboxapi.CreateRequest{Profile: "balanced"}
	for _, tc := range []struct {
		name string
		edit func(*config.OpenShellConfig)
		req  sandboxapi.CreateRequest
		host string
		port int
		want want
	}{
		{"open web", nil, sandboxapi.CreateRequest{}, "example.org", 443, want{allowed: true, triage: triage.Approve}},
		{"feed entry is unblockable", nil, sandboxapi.CreateRequest{}, "webhook.site", 443,
			want{category: egress.CategoryWebhookCatcher, unblockable: true, triage: triage.Reject, afterTriage: triage.Approve}},
		{"open-mode IP literal is blocked until unblocked", nil, sandboxapi.CreateRequest{}, "93.184.216.34", 443,
			want{category: egress.CategoryIPLiteral, unblockable: true, triage: triage.Reject, afterTriage: triage.Approve}},
		{"user block list is not one-click unblockable", func(o *config.OpenShellConfig) { block(o, "drop.example.org") },
			sandboxapi.CreateRequest{}, "drop.example.org", 443,
			want{category: egress.CategoryOperatorBlock, unblockCode: sandboxapi.CodePolicyViolation, triage: triage.Reject}},
		{"pack block list is not unblockable", nil, team, "a.paste.example", 443,
			want{category: egress.CategoryOperatorBlock, unblockCode: sandboxapi.CodePolicyViolation, triage: triage.Reject}},
		{"pack allow list lifts the feed", nil, team, "webhook.site", 443, want{allowed: true, triage: triage.Approve}},
		{"pack ports", nil, team, "example.org", 8443, want{allowed: true, triage: triage.Approve}},
		{"admin block is never unblockable", func(o *config.OpenShellConfig) { o.Admin.EgressBlock = []string{"*.ngrok.io"} },
			sandboxapi.CreateRequest{}, "a.ngrok.io", 443,
			want{category: egress.CategoryAdminBlock, unblockCode: sandboxapi.CodeAdminViolation, triage: triage.Reject}},
		{"outside admin allow-only", allowOnly("*.corp.example"), sandboxapi.CreateRequest{}, "pypi.org", 443,
			want{category: egress.CategoryAdminAllowOnly, unblockCode: sandboxapi.CodeAdminViolation, triage: triage.Reject}},
		{"inside admin allow-only", allowOnly("*.corp.example"), sandboxapi.CreateRequest{}, "git.corp.example", 443, want{allowed: true, triage: triage.Approve}},
		{"feed inside admin allow-only", allowOnly("*.pastebin.com"), sandboxapi.CreateRequest{}, "x.pastebin.com", 443,
			want{category: egress.CategoryPasteSite, unblockable: true, triage: triage.Reject, afterTriage: triage.Approve}},
		{"user allow lifts the feed", allow("webhook.site"), sandboxapi.CreateRequest{}, "webhook.site", 443, want{allowed: true, triage: triage.Approve}},
		{"no unblocking: the feed is final", noUnblock, sandboxapi.CreateRequest{}, "webhook.site", 443,
			want{category: egress.CategoryWebhookCatcher, unblockCode: sandboxapi.CodeAdminViolation, triage: triage.Reject}},
		{"no unblocking: a required pack's allow entry does not lift the feed", func(o *config.OpenShellConfig) {
			noUnblock(o)
			o.Admin.RequiredPack = "team"
		}, sandboxapi.CreateRequest{}, "webhook.site", 443,
			want{category: egress.CategoryWebhookCatcher, unblockCode: sandboxapi.CodeAdminViolation, triage: triage.Reject}},
		{"balanced: not allowlisted", nil, balanced, "example.org", 443,
			want{category: egress.CategoryNotAllowlisted, unblockable: true, triage: triage.Ask, afterTriage: triage.Approve}},
		{"balanced: curated allowlist", nil, balanced, "pypi.org", 443, want{allowed: true, triage: triage.Approve}},
		{"private address", nil, sandboxapi.CreateRequest{}, "10.1.2.3", 443,
			want{category: egress.CategoryPrivateNetwork, unblockCode: sandboxapi.CodePolicyViolation, triage: triage.Ask}},
		{"intranet name", nil, sandboxapi.CreateRequest{}, "wiki.corp", 443,
			want{category: egress.CategoryPrivateNetwork, unblockCode: sandboxapi.CodePolicyViolation, triage: triage.Ask}},
		{"an allow entry opens an intranet name", allow("wiki.corp"), sandboxapi.CreateRequest{}, "wiki.corp", 443, want{allowed: true, triage: triage.Approve}},
		{"this machine", nil, sandboxapi.CreateRequest{}, "localhost", 443,
			want{category: egress.CategoryHostInternal, unblockCode: sandboxapi.CodePolicyViolation, triage: triage.Ask}},
		{"metadata", nil, sandboxapi.CreateRequest{}, "169.254.169.254", 443,
			want{category: egress.CategoryHostInternal, unblockCode: sandboxapi.CodePolicyViolation, triage: triage.Reject}},
		// An unblock of a name that resolves to this machine is harmless: it never opens it.
		{"a name that resolves to this machine", nil, sandboxapi.CreateRequest{}, "rebind.example.org", 443,
			want{category: egress.CategoryHostInternal, triage: triage.Reject, afterTriage: triage.Reject, policyAllowed: &yes}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, func(c *config.Config) {
				c.OpenShell.PackDir = packDir
				if tc.edit != nil {
					tc.edit(&c.OpenShell)
				}
			})
			e.dns.set("rebind.example.org", "127.0.0.1")
			proxy := startLiveProxy(t, e)
			tc.req.Name = "sem"
			e.create(tc.req)
			b, err := e.m.box("sem")
			must(t, err)
			eff, err := e.m.resolveBox(b)
			must(t, err)
			target := net.JoinHostPort(tc.host, strconv.Itoa(tc.port))

			policyAllowed := tc.want.allowed
			if tc.want.policyAllowed != nil {
				policyAllowed = *tc.want.policyAllowed
			}
			if pol := eff.DecideEgress(tc.host, tc.port); pol.Allowed != policyAllowed || (!pol.Allowed && pol.Unblockable != tc.want.unblockable) {
				t.Fatalf("policy layer = %+v, want allowed=%v unblockable=%v", pol, policyAllowed, tc.want.unblockable)
			}
			status, body := proxy.connect(t, "sem", target)
			if (status == http.StatusOK) != tc.want.allowed || (!tc.want.allowed && (body.Category != tc.want.category || body.Unblockable != tc.want.unblockable)) {
				t.Fatalf("proxy CONNECT %s = %d %+v, want allowed=%v %s unblockable=%v", target, status, body, tc.want.allowed, tc.want.category, tc.want.unblockable)
			}
			proposal := triage.Proposal{Sandbox: "sem", ChunkID: "c", RuleName: "allow_semantics_" + strconv.Itoa(tc.port),
				Endpoints: []triage.Endpoint{{Host: tc.host, Port: tc.port}}}
			if got := triage.Classify(t.Context(), proposal, e.m.triagePolicy(b, eff)); got.Verdict != tc.want.triage {
				t.Fatalf("triage = %+v, want %s", got, tc.want.triage)
			}
			if !tc.want.allowed && tc.want.triage == triage.Approve {
				t.Fatal("triage approved what the proxy refuses")
			}
			_, err = e.m.Unblock(t.Context(), sandboxapi.UnblockRequest{Host: tc.host, Sandbox: "sem"})
			if (tc.want.unblockCode == "" && err != nil) || (tc.want.unblockCode != "" && !sandboxapi.IsCode(err, tc.want.unblockCode)) {
				t.Fatalf("unblock = %v, want %q", err, tc.want.unblockCode)
			}
			if tc.want.policyAllowed == nil && (err == nil) != (tc.want.allowed || tc.want.unblockable) {
				t.Fatalf("unblock accepted=%v, but the proxy allowed=%v unblockable=%v", err == nil, tc.want.allowed, tc.want.unblockable)
			}
			if err != nil || tc.want.allowed {
				return
			}
			status, body = proxy.connect(t, "sem", target)
			if (status == http.StatusOK) != (tc.want.afterTriage == triage.Approve) {
				t.Fatalf("proxy after the unblock = %d %+v, want allowed=%v", status, body, tc.want.afterTriage == triage.Approve)
			}
			if got := triage.Classify(t.Context(), proposal, e.m.triagePolicy(b, eff)); got.Verdict != tc.want.afterTriage {
				t.Fatalf("triage after the unblock = %+v, want %s", got, tc.want.afterTriage)
			}
		})
	}
}

// The strict profile runs without the proxy, and every layer says so.
func TestStrictSandboxHasNoProxy(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "strictsem", Profile: "strict"})
	b, _ := e.m.box("strictsem")
	eff, err := e.m.resolveBox(b)
	must(t, err)
	if dec := eff.DecideEgress("pypi.org", 443); dec.Allowed || dec.Unblockable {
		t.Fatalf("policy layer = %+v", dec)
	}
	if _, ok := e.m.creds.Lookup(e.binding("strictsem").ID); ok {
		t.Fatal("a strict sandbox has a proxy credential")
	}
	if _, err := e.m.Unblock(t.Context(), sandboxapi.UnblockRequest{Host: "webhook.site", Sandbox: "strictsem"}); !sandboxapi.IsCode(err, sandboxapi.CodePolicyViolation) {
		t.Fatalf("unblock under strict = %v", err)
	}
	p := triage.Proposal{Sandbox: "strictsem", ChunkID: "c", RuleName: ruleFor("pypi.org"), Endpoints: []triage.Endpoint{{Host: "pypi.org", Port: 443}}}
	if got := triage.Classify(t.Context(), p, e.m.triagePolicy(b, eff)); got.Verdict != triage.Ask || got.Reason != triage.ReasonManual {
		t.Fatalf("triage under strict = %+v", got)
	}
}

// Every sandbox is decided by its own pack and admin resolution: one
// sandbox's block list, ports, mode and unblocks never reach another.
func TestPerSandboxDeciders(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.OpenShell.PackDir = writeTeamPack(t) })
	proxy := startLiveProxy(t, e)
	e.create(sandboxapi.CreateRequest{Name: "teambox", Pack: "team"})
	e.create(sandboxapi.CreateRequest{Name: "openbox", Project: e.otherProject("open")})
	e.create(sandboxapi.CreateRequest{Name: "balbox", Profile: "balanced", Project: e.otherProject("bal")})
	for _, tc := range []struct {
		sandbox, target string
		allowed         bool
	}{
		{"teambox", "a.paste.example:443", false}, {"openbox", "a.paste.example:443", true}, {"balbox", "a.paste.example:443", false},
		{"teambox", "example.org:8443", true}, {"openbox", "example.org:8443", false},
		{"teambox", "webhook.site:443", true}, {"openbox", "webhook.site:443", false},
		{"openbox", "example.org:443", true}, {"balbox", "example.org:443", false}, {"balbox", "pypi.org:443", true},
	} {
		if status, body := proxy.connect(t, tc.sandbox, tc.target); (status == http.StatusOK) != tc.allowed {
			t.Errorf("%s CONNECT %s = %d %+v, want allowed=%v", tc.sandbox, tc.target, status, body, tc.allowed)
		}
	}
	_, err := e.m.Unblock(t.Context(), sandboxapi.UnblockRequest{Host: "example.org", Sandbox: "balbox"})
	must(t, err)
	if status, _ := proxy.connect(t, "balbox", "example.org:443"); status != http.StatusOK {
		t.Fatalf("balbox after its unblock = %d", status)
	}
	e.create(sandboxapi.CreateRequest{Name: "balbox2", Profile: "balanced", Project: e.otherProject("bal2")})
	if status, _ := proxy.connect(t, "balbox2", "example.org:443"); status != http.StatusForbidden {
		t.Fatalf("another sandbox got balbox's unblock: %d", status)
	}
}

// GAP-0173: `sandbox policy block HOST` then at once `sandbox unblock HOST`
// is decided against config.yaml as written, not the snapshot from before
// the write that the reload watcher has not replaced yet: the unblock is
// refused with the block list's remedy instead of reported done.
func TestUnblockLoadsTheBlockListJustWritten(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "balbox", Profile: "balanced"})
	e.m.opts.SyncConfig = func(context.Context) error {
		e.setConfig(func(c *config.Config) { c.OpenShell.Egress.Block = []string{"example.org"} })
		return nil
	}
	resp, err := e.m.Unblock(t.Context(), sandboxapi.UnblockRequest{Host: "example.org", Sandbox: "balbox"})
	var se *sandboxapi.Error
	if !errors.As(err, &se) || se.Code != sandboxapi.CodePolicyViolation || !strings.Contains(se.Detail, "policy block --remove example.org") {
		t.Fatalf("unblock right after the block = %+v, %v; want the block list's refusal", resp, err)
	}
}

// A sandbox whose policy stops resolving (its pack deleted) keeps no decider
// of its last good policy: the proxy refuses it with the reason, triage leaves
// it alone and its direct rules answer to the organization's policy alone.
func TestUnresolvablePolicyFailsClosed(t *testing.T) {
	packDir := writeTeamPack(t)
	e := newEnv(t, func(c *config.Config) { c.OpenShell.PackDir = packDir })
	e.run()
	proxy := startLiveProxy(t, e)
	e.live(sandboxapi.CreateRequest{Name: "teambox", Pack: "team"})
	e.create(sandboxapi.CreateRequest{Name: "openbox", Project: e.otherProject("open")})
	blocked, kept := e.propose("teambox", "example.org"), e.propose("teambox", "keep.example.net")
	e.draft("teambox")
	e.waitChunk("teambox", blocked, "approved")
	e.waitChunk("teambox", kept, "approved")

	packFile := filepath.Join(packDir, "team", "pack.yaml")
	must(t, os.Remove(packFile))
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.EgressBlock = []string{"example.org"} })
	e.m.refreshEgress()
	if status, body := proxy.connect(t, "openbox", "example.org:443"); status != http.StatusForbidden || body.Category != egress.CategoryAdminBlock {
		t.Fatalf("openbox CONNECT example.org = %d %+v, want the admin block", status, body)
	}
	for _, target := range []string{"example.org:443", "keep.example.net:443"} {
		if status, body := proxy.connect(t, "teambox", target); status != http.StatusForbidden ||
			body.Category != egress.CategoryEgressOff || !strings.Contains(body.Reason, "cannot be resolved") {
			t.Fatalf("teambox CONNECT %s with an unresolvable policy = %d %+v, want it refused with the reason", target, status, body)
		}
	}
	if len(e.events("teambox", sandboxapi.ActivityEgressBlocked, policyUnresolvedReason)) == 0 {
		t.Fatal("no feed event for the unresolvable policy")
	}
	if len(where(&e.tel.mu, &e.tel.health, func(h audit.SandboxHealthEvent) bool {
		return h.Sandbox.Name == "teambox" && h.ErrorCode == "openshell_pack_invalid"
	})) == 0 {
		t.Fatal("no degraded health record for the unresolvable policy")
	}
	e.m.enforceAll(t.Context())
	if e.hasRule("teambox", ruleFor("example.org")) || !e.hasRule("teambox", ruleFor("keep.example.net")) {
		t.Fatal("want the admin-blocked direct rule removed and the one the organization allows kept")
	}
	waiting := e.propose("teambox", "new.example.net")
	e.m.triageSandbox(t.Context(), e.boxOf("teambox"))
	if e.chunkStatus("teambox", waiting) != "pending" {
		t.Fatalf("proposal under an unresolvable policy = %s, want pending", e.chunkStatus("teambox", waiting))
	}

	// The pack comes back: the sandbox is served again, under the current administrator's list.
	writeFile(t, packFile, teamPack)
	e.m.refreshEgress()
	if status, body := proxy.connect(t, "teambox", "example.org:443"); status != http.StatusForbidden || body.Category != egress.CategoryAdminBlock {
		t.Fatalf("teambox CONNECT example.org after the pack returned = %d %+v, want the admin block", status, body)
	}
	if status, _ := proxy.connect(t, "teambox", "keep.example.net:443"); status != http.StatusOK {
		t.Fatalf("teambox CONNECT keep.example.net after the pack returned = %d", status)
	}
	e.m.triageSandbox(t.Context(), e.boxOf("teambox"))
	e.waitChunk("teambox", waiting, "approved")
}

// TestUnresolvablePolicyRecordSaysWhatToDo (GAP-0160): the degraded record
// of a sandbox whose pack is gone says what to do, and is an alert (HIGH)
// only while the sandbox runs: a stopped one sends nothing under the
// policy, and its start refuses with the reason.
func TestUnresolvablePolicyRecordSaysWhatToDo(t *testing.T) {
	packDir := writeTeamPack(t)
	e := newEnv(t, func(c *config.Config) { c.OpenShell.PackDir = packDir })
	e.create(sandboxapi.CreateRequest{Name: "runbox", Pack: "team"})
	e.create(sandboxapi.CreateRequest{Name: "idlebox", Pack: "team", Project: e.otherProject("idle")})
	run, idle := e.boxOf("runbox"), e.boxOf("idlebox")
	e.m.mu.Lock()
	run.phase, idle.phase, idle.rec.Phase = audit.SandboxPhaseReady, audit.SandboxPhaseStopped, string(audit.SandboxPhaseStopped)
	e.m.mu.Unlock()
	must(t, os.Remove(filepath.Join(packDir, "team", "pack.yaml")))
	e.m.refreshEgress()
	record := func(name string) audit.SandboxHealthEvent {
		got := where(&e.tel.mu, &e.tel.health, func(h audit.SandboxHealthEvent) bool {
			return h.Sandbox.Name == name && h.ErrorCode == "openshell_pack_invalid"
		})
		if len(got) != 1 || !strings.Contains(got[0].ErrorSummary, "or delete the sandbox: defenseclaw sandbox delete "+name) {
			t.Fatalf("%s health = %+v", name, got)
		}
		return got[0]
	}
	if r, i := record("runbox"), record("idlebox"); r.Severity != "" || i.Severity != "MEDIUM" {
		t.Fatalf("severities: running %q (want the default HIGH), stopped %q (want MEDIUM)", r.Severity, i.Severity)
	}
}

// TestRestartSuspendsAnUnresolvableSandboxsCredential (GAP-0180): a daemon
// that restarts while a running sandbox's pack is gone still takes its proxy
// credential back from the sandbox, and suspends it: the proxy refuses the
// sandbox with the reason instead of as an unknown credential, whose
// refusals raised a second alert about a stale or revoked credential.
func TestRestartSuspendsAnUnresolvableSandboxsCredential(t *testing.T) {
	packDir := writeTeamPack(t)
	e := newEnv(t, func(c *config.Config) { c.OpenShell.PackDir = packDir })
	e.live(sandboxapi.CreateRequest{Name: "teambox", Pack: "team"})
	e.stop()
	must(t, os.Remove(filepath.Join(packDir, "team", "pack.yaml")))
	e.restartDaemon()
	proxy := startLiveProxy(t, e)
	if status, body := proxy.connect(t, "teambox", "example.org:443"); status != http.StatusForbidden ||
		body.Category != egress.CategoryEgressOff || !strings.Contains(body.Reason, "cannot be resolved") {
		t.Fatalf("CONNECT after the restart = %d %+v, want the sandbox refused with the reason", status, body)
	}
}

// Every change to a sandbox's proxy credential reaches its open tunnels:
// block lists end exactly the ones they now refuse, and an unresolvable
// policy or the deny network mode ends all of the sandbox's.
func TestOpenTunnelsFollowPolicyChanges(t *testing.T) {
	packDir := writeTeamPack(t)
	e := newEnv(t, func(c *config.Config) { c.OpenShell.PackDir = packDir })
	proxy := startLiveProxy(t, e)
	e.create(sandboxapi.CreateRequest{Name: "openbox"})
	e.create(sandboxapi.CreateRequest{Name: "teambox", Pack: "team", Project: e.otherProject("team")})
	open := func(sandbox, target string) func() bool {
		conn, br := proxy.open(t, sandbox, target)
		return func() bool { return tunnelOpen(conn, br) }
	}
	userBlocked, adminBlocked := open("openbox", "drop.example.org:443"), open("openbox", "example.org:443")
	kept, team := open("openbox", "keep.example.net:443"), open("teambox", "keep.example.net:443")
	if !userBlocked() || !adminBlocked() || !kept() || !team() {
		t.Fatal("a tunnel did not stay open")
	}
	e.setConfig(func(c *config.Config) {
		c.OpenShell.Egress.Block = []string{"drop.example.org"}
		c.OpenShell.Admin.EgressBlock = []string{"example.org"}
	})
	e.m.refreshEgress()
	if userBlocked() || adminBlocked() || !kept() || !team() {
		t.Fatal("want exactly the tunnels to the newly blocked destinations ended")
	}
	// The pack goes away; the next resolution fails the sandbox closed, without a configuration change.
	must(t, os.Remove(filepath.Join(packDir, "team", "pack.yaml")))
	if _, err := e.m.resolveBox(e.boxOf("teambox")); err == nil {
		t.Fatal("teambox's policy still resolves without its pack")
	}
	if team() || !kept() {
		t.Fatal("want the tunnel of the sandbox whose policy cannot be resolved ended, and only that one")
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.MinProfile = config.OpenShellProfileStrict })
	e.m.refreshEgress()
	if kept() {
		t.Fatal("an open tunnel of a sandbox moved to the deny network mode survived")
	}
}

func TestDeciderAndUnblocks(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.OpenShell.Egress.Block = []string{"blocked.example.com"} })
	proxy := &fakeProxy{counter: egress.NewCounter(egress.CounterOptions{})}
	e.m.AttachProxy(proxy)
	e.run()
	e.create(sandboxapi.CreateRequest{Name: "egbox"})
	e.create(sandboxapi.CreateRequest{Name: "otherbox", Project: e.otherProject("other")})
	if proxy.swaps() == 0 {
		t.Fatal("no default decider set")
	}
	for host, allowed := range map[string]bool{"example.org": true, "webhook.site": false, "blocked.example.com": false} {
		if got := e.decideEgress("egbox", host).Allowed; got != allowed {
			t.Fatalf("%s allowed = %v, want %v", host, got, allowed)
		}
	}
	// A sandbox-scoped unblock opens the feed entry for that sandbox only.
	resp, err := e.m.Unblock(t.Context(), sandboxapi.UnblockRequest{Host: "WebHook.site", Sandbox: "egbox"})
	if err != nil || resp.Scope != "sandbox" || resp.Host != "webhook.site" || !resp.Persisted {
		t.Fatalf("unblock = %+v, %v", resp, err)
	}
	if !e.decideEgress("egbox", "webhook.site").Allowed || e.decideEgress("otherbox", "webhook.site").Allowed {
		t.Fatal("sandbox unblock scope is wrong")
	}
	// The operator blocklist and guard blocks are never unblocked; an unblock names its scope.
	for req, code := range map[sandboxapi.UnblockRequest]string{
		{Host: "blocked.example.com", Sandbox: "egbox"}: sandboxapi.CodePolicyViolation,
		{Host: "10.1.2.3", Sandbox: "egbox"}:            sandboxapi.CodePolicyViolation,
		{Host: "webhook.site"}:                          sandboxapi.CodeInvalid,
	} {
		if _, err := e.m.Unblock(t.Context(), req); !sandboxapi.IsCode(err, code) {
			t.Fatalf("unblock %+v = %v, want %s", req, err, code)
		}
	}
	// Always persists and opens it for everyone, from the configuration only.
	resp, err = e.m.Unblock(t.Context(), sandboxapi.UnblockRequest{Host: "pastebin.com", Always: true})
	if err != nil || resp.Scope != "always" || !slices.Equal(e.persist.allowed(), []string{"pastebin.com"}) || !e.decideEgress("otherbox", "pastebin.com").Allowed {
		t.Fatalf("always = %+v, %v (persisted %v)", resp, err, e.persist.allowed())
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Egress.Unblocked = nil })
	e.m.refreshEgress()
	if e.decideEgress("otherbox", "pastebin.com").Allowed {
		t.Fatal("the always unblock outlived its removal from the configuration")
	}
	if n := len(where(&e.tel.mu, &e.tel.policy, func(p audit.SandboxPolicyEvent) bool { return p.Operation == audit.SandboxEgressUnblock })); n != 2 {
		t.Fatalf("unblock policy records = %d", n)
	}
	// A configuration change rebuilds the deciders on its own, and swaps the
	// default one too, retiring pooled upstream connections.
	sets := proxy.swaps()
	e.setConfig(func(c *config.Config) { c.OpenShell.Egress.Block = []string{"late.example.com"} })
	eventually(t, "the deciders rebuilt", func() bool { return !e.decideEgress("egbox", "late.example.com").Allowed && proxy.swaps() > sets })
}

// #954: EgressUnblock reports a host the sandbox's proxy reaches because of
// an unblock, with the unblock's scope, and nothing else: not a host the
// proxy allows anyway, a subdomain of the unblocked host, another
// sandbox's unblock, another binding, or an unblock the policy no longer
// honors.
func TestEgressUnblockFollowsTheProxy(t *testing.T) {
	e := newEnv(t, nil)
	proxy := &fakeProxy{counter: egress.NewCounter(egress.CounterOptions{})}
	e.m.AttachProxy(proxy)
	e.run()
	e.create(sandboxapi.CreateRequest{Name: "egbox"})
	e.create(sandboxapi.CreateRequest{Name: "otherbox", Project: e.otherProject("other")})
	eg, other := e.binding("egbox"), e.binding("otherbox")
	unblocked := func(b sandboxauth.Binding, host string) string {
		t.Helper()
		scope, ok := e.m.EgressUnblock(b.ID, b.SandboxName, host)
		if !ok {
			return "-"
		}
		return scope
	}
	if got := unblocked(eg, "webhook.site"); got != "-" {
		t.Fatalf("webhook.site before any unblock = %s", got)
	}
	_, err := e.m.Unblock(t.Context(), sandboxapi.UnblockRequest{Host: "webhook.site", Sandbox: "egbox"})
	must(t, err)
	for _, tc := range []struct {
		b          sandboxauth.Binding
		host, want string
	}{
		{eg, "webhook.site", "sandbox"},
		{eg, "WebHook.Site.", "sandbox"},
		{eg, "x.webhook.site", "-"},
		{eg, "example.org", "-"},
		{other, "webhook.site", "-"},
		{sandboxauth.Binding{ID: other.ID, SandboxName: "egbox"}, "webhook.site", "-"},
		{sandboxauth.Binding{ID: "sb_unknown", SandboxName: "egbox"}, "webhook.site", "-"},
	} {
		if got := unblocked(tc.b, tc.host); got != tc.want {
			t.Errorf("EgressUnblock(%s, %s) = %s, want %s", tc.b.SandboxName, tc.host, got, tc.want)
		}
	}
	_, err = e.m.Unblock(t.Context(), sandboxapi.UnblockRequest{Host: "pastebin.com", Always: true})
	must(t, err)
	if got, gotOther := unblocked(eg, "pastebin.com"), unblocked(other, "pastebin.com"); got != "always" || gotOther != "always" {
		t.Fatalf("always unblock = %s and %s, want always for both", got, gotOther)
	}
	// An unblock the policy no longer honors lifts nothing.
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.AllowUnblock = boolPtr(false) })
	e.m.refreshEgress()
	if got := unblocked(eg, "webhook.site"); got != "-" {
		t.Fatalf("webhook.site under allow_unblock: false = %s", got)
	}
}

// With unblocking off each refusal gives its own reason (the organization's
// block list, a host not blocked, a strict sandbox's approvals; allow_unblock
// only for what it forbids), recorded as no-change policy records.
func TestUnblockRefusals(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.OpenShell.Admin.AllowUnblock = boolPtr(false)
		c.OpenShell.Admin.EgressBlock = []string{"example.com"}
	})
	e.create(sandboxapi.CreateRequest{Name: "openbox"})
	e.create(sandboxapi.CreateRequest{Name: "strictbox", Pack: "strict", Project: e.otherProject("strict")})
	unblock := func(req sandboxapi.UnblockRequest) *sandboxapi.Error {
		t.Helper()
		_, err := e.m.Unblock(t.Context(), req)
		var apiErr *sandboxapi.Error
		if !errors.As(err, &apiErr) {
			t.Fatalf("unblock %+v = %v, want a refusal", req, err)
		}
		return apiErr
	}
	if got := unblock(sandboxapi.UnblockRequest{Host: "example.com", Sandbox: "openbox"}); got.Violation == nil ||
		got.Violation.Constraint != "openshell.admin.egress_block" || !strings.Contains(got.Detail, "blocklist") {
		t.Fatalf("admin-blocked host = %+v", got)
	}
	// #946: the organization's domain covers its subdomains.
	for _, req := range []sandboxapi.UnblockRequest{{Host: "www.example.com", Sandbox: "openbox"}, {Host: "api.www.example.com", Always: true}} {
		if got := unblock(req); got.Violation == nil || got.Violation.Constraint != "openshell.admin.egress_block" ||
			!strings.Contains(got.Detail, "matches *.example.com on your organization's blocklist") {
			t.Fatalf("subdomain of an admin-blocked domain %+v = %+v", req, got)
		}
	}
	if got := unblock(sandboxapi.UnblockRequest{Host: "www.example.org", Always: true}); got.Code != sandboxapi.CodeInvalid ||
		!strings.Contains(got.Message, "www.example.org is not blocked") {
		t.Fatalf("host that is not blocked = %+v", got)
	}
	// The large-upload block refuses hosts the policy itself allows, which
	// only an unblock lifts: with it on, such a host is not "not blocked".
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.BlockLargeUploads = true })
	if got := unblock(sandboxapi.UnblockRequest{Host: "files.example.net", Sandbox: "openbox"}); got.Code != sandboxapi.CodeAdminViolation ||
		got.Violation == nil || got.Violation.Constraint != "openshell.admin.allow_unblock" || strings.Contains(got.Message, "is not blocked") {
		t.Fatalf("host under the large-upload block = %+v", got)
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.BlockLargeUploads = false })
	if got := unblock(sandboxapi.UnblockRequest{Host: "www.example.net", Sandbox: "strictbox"}); got.Violation == nil ||
		got.Violation.Constraint == "openshell.admin.allow_unblock" || !strings.Contains(got.Violation.Detail, "defenseclaw sandbox approvals") {
		t.Fatalf("strict sandbox = %+v", got)
	}
	for _, req := range []sandboxapi.UnblockRequest{{Host: "webhook.site", Sandbox: "openbox"}, {Host: "webhook.site", Always: true}} {
		if got := unblock(req); got.Code != sandboxapi.CodeAdminViolation || !strings.Contains(got.Message, sandboxapi.AdminMessage) ||
			got.Violation == nil || got.Violation.Constraint != "openshell.admin.allow_unblock" {
			t.Fatalf("blocklisted host with unblocks off = %+v", got)
		}
	}
	if len(e.persist.allowed()) != 0 {
		t.Fatal("persisted a refused unblock")
	}
	var scopes []string
	for _, p := range where(&e.tel.mu, &e.tel.policy, func(p audit.SandboxPolicyEvent) bool {
		return p.Operation == audit.SandboxEgressUnblock && p.NoChange && p.Reason == policyReasonAdminRefused && p.Target == "webhook.site"
	}) {
		scopes = append(scopes, p.Sandbox.Name)
	}
	slices.Sort(scopes)
	if !slices.Equal(scopes, []string{"all", "openbox"}) {
		t.Fatalf("refused unblock records for %v, want the sandbox's and every sandbox's", scopes)
	}
}

// Saved "always" decisions (openshell.egress.unblocked) reach the proxy as
// unblocks, which lift the blocklist and allowlist but never open private
// addresses, and stop counting once unblocking is forbidden.
func TestAlwaysDecisionsAreUnblocks(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.OpenShell.Profile = config.OpenShellProfileBalanced
		c.OpenShell.Egress.Unblocked = []string{"cdn.example.org", "webhook.site"}
	})
	e.m.AttachProxy(&fakeProxy{counter: egress.NewCounter(egress.CounterOptions{})})
	e.create(sandboxapi.CreateRequest{Name: "alwaysbox"})
	for _, host := range []string{"cdn.example.org", "webhook.site"} {
		if dec := e.decideEgress("alwaysbox", host); !dec.Allowed || dec.Source != egress.SourceUnblock {
			t.Fatalf("%s = %+v, want allowed by an unblock (not an operator allow)", host, dec)
		}
	}
	if dec := e.decideEgress("alwaysbox", "other.example.org"); dec.Allowed {
		t.Fatalf("unlisted host allowed in allowlist mode: %+v", dec)
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.AllowUnblock = boolPtr(false) })
	e.m.refreshEgress()
	if e.decideEgress("alwaysbox", "cdn.example.org").Allowed || e.decideEgress("alwaysbox", "cdn.example.org").Unblockable {
		t.Fatal("saved unblock applied after allow_unblock=false")
	}
}

// A sandbox whose policy becomes strict loses its proxy credential instead of
// keeping open egress through it, and gets it back once the profile relaxes.
func TestStrictProfileRevokesTheProxyCredential(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "strictbox"})
	id := e.binding("strictbox").ID
	for _, profile := range []string{config.OpenShellProfileStrict, ""} {
		e.setConfig(func(c *config.Config) { c.OpenShell.Admin.MinProfile = profile })
		e.m.refreshEgress()
		if _, ok := e.m.creds.Lookup(id); ok != (profile == "") {
			t.Fatalf("min_profile %q: proxy credential registered = %v", profile, ok)
		}
	}
}

// Each sandbox's proxy credential carries its own pack's large-upload
// threshold, and follows a configuration change.
func TestSandboxLargeUploadThresholdIsItsOwn(t *testing.T) {
	dir := t.TempDir()
	pack := strings.Replace(strings.Replace(teamPack, "name: team", "name: small", 1), "ports: [443, 8443]", "ports: [443, 8443]\n  large_upload_mb: 7", 1)
	writeFile(t, filepath.Join(dir, "small", "pack.yaml"), pack)
	e := newEnv(t, func(c *config.Config) { c.OpenShell.PackDir = dir })
	e.create(sandboxapi.CreateRequest{Name: "smallbox", Pack: "small"})
	e.create(sandboxapi.CreateRequest{Name: "defaultbox", Project: e.otherProject("default")})
	threshold := func(name string) int64 {
		p, ok := e.m.creds.Lookup(e.binding(name).ID)
		if !ok {
			t.Fatalf("%s has no proxy credential", name)
		}
		return p.LargeUploadBytes
	}
	if got, base := threshold("smallbox"), threshold("defaultbox"); got != 7<<20 || base <= 0 || base == 7<<20 {
		t.Fatalf("thresholds = %d and %d, want the small pack's 7 MiB and the default pack's", got, base)
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Egress.LargeUploadMB = 3 })
	e.m.refreshEgress()
	if threshold("defaultbox") != 3<<20 {
		t.Fatalf("defaultbox threshold after the change = %d, want 3 MiB", threshold("defaultbox"))
	}
}

// Each sandbox's proxy credential carries its policy's large-upload block,
// which follows a configuration change; the running sandbox's feed says
// that its uploads are now blocked.
func TestSandboxLargeUploadBlockFollowsConfig(t *testing.T) {
	e := newEnv(t, nil)
	e.live(sandboxapi.CreateRequest{Name: "upbox"})
	blocks := func() bool {
		p, ok := e.m.creds.Lookup(e.binding("upbox").ID)
		if !ok {
			t.Fatal("upbox has no proxy credential")
		}
		return p.BlockLargeUploads
	}
	if blocks() {
		t.Fatal("the open pack blocks large uploads")
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Egress.BlockLargeUploads = true })
	e.m.refreshEgress()
	if !blocks() {
		t.Fatal("openshell.egress.block_large_uploads did not reach the sandbox's credential")
	}
	if moved := e.events("upbox", sandboxapi.ActivityLifecycle, sandboxapi.ReasonPolicyChanged); len(moved) != 1 ||
		!strings.Contains(moved[0].Message, "the sandbox policy changed: large uploads to first-seen hosts reported → blocked") {
		t.Fatalf("policy-change feed = %+v", moved)
	}
	e.setConfig(func(c *config.Config) {
		c.OpenShell.Egress.BlockLargeUploads = false
		c.OpenShell.Admin.BlockLargeUploads = true
	})
	e.m.refreshEgress()
	if !blocks() {
		t.Fatal("openshell.admin.block_large_uploads did not reach the sandbox's credential")
	}
	if moved := e.events("upbox", sandboxapi.ActivityLifecycle, sandboxapi.ReasonPolicyChanged); len(moved) != 1 {
		t.Fatalf("an unchanged block was announced again: %+v", moved)
	}
}

// With the block on, the upload that crosses the threshold is cut: the feed
// shows a ✗ that names the threshold and offers the unblock, a HIGH finding
// and a blocked egress record are written, later tunnels to the host are
// refused, and an unblock of the host lifts the block.
func TestLargeUploadBlockCutsAndRefuses(t *testing.T) {
	e := newEnv(t, func(c *config.Config) {
		c.OpenShell.Egress.LargeUploadMB = 1
		c.OpenShell.Egress.BlockLargeUploads = true
	})
	e.run()
	proxy := startLiveProxyWith(t, e, func(o *egress.Options) { o.Sink = e.m.EgressSink() })
	e.live(sandboxapi.CreateRequest{Name: "upbox"})
	conn, br := proxy.open(t, "upbox", "example.org:80")
	const size = 2 << 20
	_, err := fmt.Fprintf(conn, "POST /upload HTTP/1.1\r\nHost: example.org\r\nContent-Length: %d\r\n\r\n", size)
	must(t, err)
	chunk := bytes.Repeat([]byte("u"), 32<<10)
	for sent := 0; sent < size; sent += len(chunk) {
		if _, err := conn.Write(chunk); err != nil {
			break // the proxy cut the tunnel
		}
	}
	_, _ = io.Copy(io.Discard, br)

	var ev sandboxapi.ActivityEvent
	eventually(t, "the cut in the feed", func() bool {
		for _, got := range e.events("upbox", sandboxapi.ActivityEgressBlocked, "") {
			if got.Category == string(egress.CategoryLargeUpload) {
				ev = got
				return true
			}
		}
		return false
	})
	if ev.Host != "example.org" || !ev.Unblockable || ev.Severity != "HIGH" || ev.BytesUp > 1<<20 ||
		ev.Message != "✗ example.org:80 (large upload blocked: this sandbox tried to send more than 1 MiB to a destination it had not contacted before)" {
		t.Fatalf("feed event = %+v", ev)
	}
	if n := len(e.events("upbox", sandboxapi.ActivityEgressLargeUpload, "")); n != 0 {
		t.Fatalf("the cut was also reported as %d unblocked large uploads", n)
	}
	eventually(t, "the finding and the blocked record", func() bool {
		return len(e.tel.findingsOf(audit.SandboxFindingLargeUpload)) == 1 &&
			egressRecords(e, "upbox", func(r audit.SandboxEgressEvent) bool { return r.Blocked }) == 1
	})
	finding := e.tel.findingsOf(audit.SandboxFindingLargeUpload)[0]
	if finding.Severity != "HIGH" || !strings.Contains(finding.Title, "blocked") || !strings.Contains(finding.Description, "more than 1 MiB") ||
		!strings.Contains(finding.Remediation, "defenseclaw sandbox unblock example.org --sandbox upbox") {
		t.Fatalf("finding = %+v", finding)
	}
	rec := where(&e.tel.mu, &e.tel.egress, func(r audit.SandboxEgressEvent) bool { return r.Blocked })[0]
	if rec.DecisionCode != "SANDBOX_EGRESS_LARGE_UPLOAD" || rec.Severity != "HIGH" || rec.Host != "example.org" ||
		!strings.Contains(rec.Reason, "tried to send more than 1 MiB") {
		t.Fatalf("egress record = %+v", rec)
	}

	status, body := proxy.connect(t, "upbox", "example.org:443")
	if status != http.StatusForbidden || body.Category != egress.CategoryLargeUpload || !body.Unblockable {
		t.Fatalf("CONNECT after the cut = %d %+v", status, body)
	}
	// The refusal says why the host is blocked: the CONNECT sent nothing.
	// It went to port 443, the cut to port 80: the port tells the two
	// lines apart (PR 1022 live retest N3).
	eventually(t, "the refusal in the feed", func() bool {
		for _, got := range e.events("upbox", sandboxapi.ActivityEgressBlocked, "") {
			if got.Category == string(egress.CategoryLargeUpload) && got.Severity == "" && got.BytesUp == 0 &&
				got.Message == "✗ example.org (large upload blocked: this destination is blocked since this sandbox tried to send more than 1 MiB "+
					"to it, a destination it had not contacted before)" {
				return true
			}
		}
		return false
	})
	if _, err := e.m.Unblock(t.Context(), sandboxapi.UnblockRequest{Host: "example.org", Sandbox: "upbox"}); err != nil {
		t.Fatalf("Unblock: %v", err)
	}
	if status, body := proxy.connect(t, "upbox", "example.org:443"); status != http.StatusOK {
		t.Fatalf("CONNECT after the unblock = %d %+v", status, body)
	}
}

// An upload of more than the threshold to a host an allow entry exempts is
// only reported, with or without the block. With the block off the finding
// points to it; with it on it says the host is exempt, not to turn on a
// block that is on already.
func TestLargeUploadToAnExemptHost(t *testing.T) {
	for _, block := range []bool{false, true} {
		t.Run(fmt.Sprintf("block %v", block), func(t *testing.T) {
			e := newEnv(t, func(c *config.Config) {
				c.OpenShell.Egress.LargeUploadMB = 1
				c.OpenShell.Egress.BlockLargeUploads = block
				c.OpenShell.Egress.Allow = []string{"files.example.net"}
			})
			e.run()
			proxy := startLiveProxyWith(t, e, func(o *egress.Options) { o.Sink = e.m.EgressSink() })
			e.live(sandboxapi.CreateRequest{Name: "upbox"})
			conn, _ := proxy.open(t, "upbox", "files.example.net:80")
			const size = 2 << 20
			_, err := fmt.Fprintf(conn, "POST /upload HTTP/1.1\r\nHost: files.example.net\r\nContent-Length: %d\r\n\r\n", size)
			must(t, err)
			chunk := bytes.Repeat([]byte("u"), 32<<10)
			for sent := 0; sent < size; sent += len(chunk) {
				_, err := conn.Write(chunk)
				must(t, err)
			}
			eventually(t, "the large-upload finding", func() bool { return len(e.tel.findingsOf(audit.SandboxFindingLargeUpload)) == 1 })
			_ = conn.Close()
			f := e.tel.findingsOf(audit.SandboxFindingLargeUpload)[0]
			advises := strings.Contains(f.Remediation, "openshell.egress.block_large_uploads: true cuts such uploads")
			if f.Severity != "MEDIUM" || advises == block || (block && !strings.Contains(f.Remediation, "exempt")) {
				t.Fatalf("finding = %+v", f)
			}
		})
	}
}

func TestEgressSinkMapping(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "sinkbox"})
	id, now, sink := e.binding(sb.Name).ID, time.Now(), e.m.EgressSink()
	mk := func(kind egress.EventKind, host string) egress.Event {
		return egress.Event{Kind: kind, Time: now, BindingID: id, SandboxName: sb.Name, Method: "CONNECT", Host: host, Port: 443}
	}
	first := mk(egress.EventAllowed, "registry.npmjs.org")
	first.RemoteAddr, first.Source, first.FirstSeen = "104.16.0.1:443", egress.SourceDefault, true
	again := mk(egress.EventAllowed, "registry.npmjs.org")
	again.Source = egress.SourceDefault
	blocked := mk(egress.EventBlocked, "webhook.site")
	blocked.Category, blocked.Source, blocked.Entry, blocked.Reason, blocked.Unblockable = "webhook_catcher", egress.SourceFeed, "webhook.site", "exfil destination", true
	upload := mk(egress.EventLargeUpload, "files.example.net")
	upload.BytesUp, upload.Threshold = 25<<20+4096, 25<<20
	for _, ev := range []egress.Event{first, again, blocked, upload, {Kind: egress.EventAllowed, SandboxName: "unknown-box", Host: "x.example"}} {
		sink.EgressEvent(ev)
	}
	// The sink publishes the large upload to the feed after recording its finding.
	eventually(t, "egress telemetry and the large upload in the feed", func() bool {
		return len(where(&e.tel.mu, &e.tel.egress, nil)) == 3 && len(e.tel.findingsOf(audit.SandboxFindingLargeUpload)) == 1 &&
			len(e.events(sb.Name, sandboxapi.ActivityEgressLargeUpload, "")) == 1
	})
	recs, finding := where(&e.tel.mu, &e.tel.egress, nil), e.tel.findingsOf(audit.SandboxFindingLargeUpload)[0]
	if a := recs[0]; a.Source != audit.SandboxEgressSourceProxy || a.Blocked || a.Scheme != "https" || a.ResolvedIP != "104.16.0.1" ||
		a.DecisionCode != "SANDBOX_EGRESS_ALLOWED" || a.Sandbox.Name != sb.Name {
		t.Fatalf("allowed = %+v", a)
	}
	if b := recs[2]; !b.Blocked || b.DecisionCode != "SANDBOX_EGRESS_WEBHOOK_CATCHER" || !strings.Contains(b.PolicyOutcome, "feed") {
		t.Fatalf("blocked = %+v", b)
	}
	// Reported as it crossed the threshold, before it ended: "more than"
	// the threshold, not the bytes sent then (RT U4).
	if finding.Severity != "MEDIUM" || finding.TargetRef != "files.example.net" ||
		finding.Description != "sinkbox sent more than 25 MiB to files.example.net, which it had not contacted before (26218496 bytes as it crossed the threshold)." {
		t.Fatalf("finding = %+v", finding)
	}
	// The feed shows first contact and blocks, not every tunnel.
	var feed []sandboxapi.ActivityEvent
	for _, ev := range e.m.ActivitySince(0, sb.Name) {
		if strings.HasPrefix(ev.Kind, "egress.") {
			feed = append(feed, ev)
		}
	}
	if len(feed) != 3 || feed[0].Kind != sandboxapi.ActivityEgressAllowed || feed[1].Kind != sandboxapi.ActivityEgressBlocked ||
		!feed[1].Unblockable || !strings.Contains(feed[1].Message, "webhook.site") || feed[2].Kind != sandboxapi.ActivityEgressLargeUpload ||
		feed[2].Threshold != 25<<20 || feed[2].BytesUp != 25<<20+4096 || feed[2].Message != "⚠ large upload to first-seen files.example.net (more than 25 MiB)" {
		t.Fatalf("feed = %+v", feed)
	}
}

func TestOCSFMapping(t *testing.T) {
	e := liveEnv(t, "ocsfbox", nil)
	for _, line := range []string{
		"NET:OPEN [MED] DENIED /usr/bin/python3(42) -> evil.example.com:443/tcp [policy:- engine:opa] [reason:transparent_tcp_policy_denied]",
		"NET:OPEN [INFO] ALLOWED /opt/defenseclaw-harness/claudecode/bin/claude(7) -> api.anthropic.com:443/tcp [policy:_provider_x engine:opa]",
		"NET:OPEN [INFO] ALLOWED /usr/bin/curl(9) -> host.openshell.internal:18972/tcp [policy:defenseclaw_egress engine:opa]",
		"FINDING:BLOCKED [HIGH] \"Binary drift detected\" [confidence:0.9]",
	} {
		e.watch.push(t, "ocsfbox", stream.Event{Kind: stream.KindLog, Time: time.Now(), Log: &stream.Log{Level: "OCSF", Target: "ocsf", Message: line, OCSF: parseOCSF(t, line)}})
	}
	recs, findings := where(&e.tel.mu, &e.tel.egress, nil), where(&e.tel.mu, &e.tel.findings, nil)
	if len(recs) != 2 || !recs[0].Blocked || recs[0].Host != "evil.example.com" || recs[0].Source != audit.SandboxEgressSourceOpenShell ||
		recs[0].DecisionCode != "SANDBOX_EGRESS_OPENSHELL_DENIED" || recs[1].Blocked || recs[1].Host != "api.anthropic.com" {
		t.Fatalf("egress = %+v", recs)
	}
	if len(findings) != 1 || findings[0].Kind != audit.SandboxFindingOCSF || findings[0].Severity != "HIGH" || e.get("ocsfbox").Egress.Blocked != 1 {
		t.Fatalf("findings = %+v, blocked %d", findings, e.get("ocsfbox").Egress.Blocked)
	}
}

func TestRecoverCredential(t *testing.T) {
	sb := &openshell.Sandbox{Spec: openshell.SandboxSpec{Environment: map[string]string{"HTTPS_PROXY": "http://dcx-abc:secret@host.openshell.internal:18972"}}}
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

// fastFlush shortens the refusal fold and the flush for a test.
func fastFlush(t *testing.T) {
	window, lines, interval, held := blockCoalesceWindow, feedFoldWindow, sinkFlushInterval, heldBackInterval
	blockCoalesceWindow, feedFoldWindow, sinkFlushInterval, heldBackInterval = 100*time.Millisecond, 100*time.Millisecond, 20*time.Millisecond, 50*time.Millisecond
	t.Cleanup(func() {
		blockCoalesceWindow, feedFoldWindow, sinkFlushInterval, heldBackInterval = window, lines, interval, held
	})
}

func egressRecords(e *harnessEnv, sandbox string, match func(audit.SandboxEgressEvent) bool) int {
	return len(where(&e.tel.mu, &e.tel.egress, func(r audit.SandboxEgressEvent) bool {
		return r.Sandbox.Name == sandbox && (match == nil || match(r))
	}))
}

func blockedEvent(sandbox, host string) egress.Event {
	return egress.Event{Kind: egress.EventBlocked, Time: time.Now(), SandboxName: sandbox, Method: "CONNECT",
		Host: host, Port: 443, Category: "webhook_catcher", Source: egress.SourceFeed, Reason: "exfil destination"}
}

// One sandbox refused the same request thousands of times puts one record
// into the shared queue and one for the repeats, naming their count; its
// large-upload finding and another sandbox's refusal still get through.
func TestRepeatedRefusalsAreFolded(t *testing.T) {
	fastFlush(t)
	e := newEnv(t, nil)
	e.run()
	a := e.create(sandboxapi.CreateRequest{Name: "floodbox"})
	b := e.create(sandboxapi.CreateRequest{Name: "quietbox", Project: e.otherProject("quietbox")})
	sink := e.m.EgressSink()
	for range 10000 {
		sink.EgressEvent(blockedEvent(a.Name, "flood.example"))
	}
	sink.EgressEvent(egress.Event{Kind: egress.EventLargeUpload, Time: time.Now(), SandboxName: a.Name, Host: "files.example.net", BytesUp: 30 << 20})
	sink.EgressEvent(blockedEvent(b.Name, "other.example"))
	// The folded refusal is recorded before it is published to the feed.
	eventually(t, "the other sandbox's refusal, the finding and the folded repeats", func() bool {
		return len(where(&e.tel.mu, &e.tel.findings, nil)) == 1 && egressRecords(e, b.Name, nil) == 1 &&
			egressRecords(e, a.Name, func(r audit.SandboxEgressEvent) bool { return strings.Contains(r.Reason, "9998 more like it") }) == 1 &&
			len(e.events(a.Name, sandboxapi.ActivityEgressBlocked, "")) >= 2
	})
	if n, feed := egressRecords(e, a.Name, nil), len(e.events(a.Name, sandboxapi.ActivityEgressBlocked, "")); n != 2 || feed != 2 {
		t.Fatalf("%d egress records and %d feed events for 10000 identical refusals, want 2 each", n, feed)
	}
}

// GAP-0329: a retry loop's refusals of one destination fold under several
// keys (its DNS refusals and its connections', or two programs'), whose
// folded lines read the same: the feed shows one, counting them all.
func TestFoldedRefusalsOfOneDestinationAreOneLine(t *testing.T) {
	fastFlush(t)
	e := liveEnv(t, "pairbox", nil)
	now := time.Now()
	for range 3 {
		e.ocsf("pairbox", "NET:REFUSE [MED] DENIED registry.npmjs.org [reason:policy_dns_ineligible]", now)
		e.ocsf("pairbox", "NET:OPEN [MED] DENIED /usr/bin/node(42) -> registry.npmjs.org:443/tcp [policy:- engine:opa] [reason:transparent_tcp_policy_denied]", now)
		e.ocsf("pairbox", "NET:OPEN [MED] DENIED /usr/bin/npm(43) -> registry.npmjs.org:443/tcp [policy:- engine:opa] [reason:transparent_tcp_policy_denied]", now)
	}
	first := len(e.events("pairbox", sandboxapi.ActivityEgressBlocked, ""))
	eventually(t, "the folded lines", func() bool {
		e.m.sink.flushOpenShell(t.Context(), time.Now())
		return len(e.events("pairbox", sandboxapi.ActivityEgressBlocked, "")) > first
	})
	time.Sleep(50 * time.Millisecond)
	e.m.sink.flushOpenShell(t.Context(), time.Now())
	feed := e.events("pairbox", sandboxapi.ActivityEgressBlocked, "")
	var msgs []string
	for _, l := range feed {
		msgs = append(msgs, l.Message)
	}
	if n := len(feed) - first; n != 1 || feed[len(feed)-1].Repeats < 1 {
		t.Fatalf("first %d lines, then %d folded: %q", first, n, msgs)
	}
}

// GAP-0329 (round 3): a strict session's npm retry loop, refused at 0 s,
// 10 s and 11 s, then twice at once a minute later, printed identical lines
// in pairs and no count. The repeats of a minute are one line with their
// count, and a single repeat adds no line.
func TestARetryLoopsRefusalsAreOneLineAMinute(t *testing.T) {
	e := newEnv(t, nil)
	_, advance := e.fakeClock(time.Now())
	e.live(sandboxapi.CreateRequest{Name: "loopbox"})
	refuse := func() {
		e.ocsf("loopbox", "NET:OPEN [MED] DENIED /usr/bin/node(42) -> registry.npmjs.org:443/tcp [policy:- engine:opa] [reason:transparent_tcp_policy_denied]", time.Now())
	}
	refuse()
	advance(10 * time.Second)
	refuse()
	advance(time.Second)
	refuse()
	advance(50 * time.Second)
	e.m.sink.flushOpenShell(t.Context(), e.m.now())
	refuse()
	refuse()
	advance(time.Minute)
	e.m.sink.flushOpenShell(t.Context(), e.m.now())
	var msgs []string
	for _, l := range e.events("loopbox", sandboxapi.ActivityEgressBlocked, "") {
		msgs = append(msgs, l.Message)
	}
	const line = "✗ registry.npmjs.org (no OpenShell rule allows it)"
	if want := []string{line, line + " (and 1 more like it)", line}; !slices.Equal(msgs, want) {
		t.Fatalf("feed %q, want %q", msgs, want)
	}
}

// GAP-0199: a pip retry loop OpenShell refused seven times in seven seconds
// made seven MEDIUM alerts and seven feed lines. Repeats of one refusal (the
// destination and the program) fold into the first record, and one more
// names their count; another program's refusal is its own record. The feed
// line names no program, so its repeats fold by the line (GAP-0329).
func TestRepeatedOpenShellRefusalsAreFolded(t *testing.T) {
	fastFlush(t)
	e := liveEnv(t, "retrybox", nil)
	now := time.Now()
	for range 7 {
		e.ocsf("retrybox", "NET:OPEN [MED] DENIED /usr/bin/python3(42) -> pypi.org:443/tcp [policy:- engine:opa] [reason:transparent_tcp_policy_denied]", now)
	}
	e.ocsf("retrybox", "NET:OPEN [MED] DENIED /usr/bin/curl(43) -> pypi.org:443/tcp [policy:- engine:opa] [reason:transparent_tcp_policy_denied]", now)
	refused := func(match func(audit.SandboxEgressEvent) bool) int {
		return egressRecords(e, "retrybox", func(r audit.SandboxEgressEvent) bool {
			return r.Blocked && r.Host == "pypi.org" && (match == nil || match(r))
		})
	}
	if n, feed := refused(nil), len(e.events("retrybox", sandboxapi.ActivityEgressBlocked, "")); n != 2 || feed != 1 {
		t.Fatalf("%d records and %d feed lines for 7 repeats and one other program, want 2 and 1", n, feed)
	}
	// The folded repeats are recorded before they are published to the feed.
	eventually(t, "the folded repeats", func() bool {
		e.m.sink.flushOpenShell(t.Context(), time.Now())
		return refused(func(r audit.SandboxEgressEvent) bool { return strings.Contains(r.Reason, "(and 5 more like it)") }) == 1 &&
			len(e.events("retrybox", sandboxapi.ActivityEgressBlocked, "")) == 2
	})
	// The folded line says how many it stands for, in the words of the
	// first (GAP-0309).
	if n, feed := refused(nil), e.events("retrybox", sandboxapi.ActivityEgressBlocked, ""); n != 3 || len(feed) != 2 ||
		feed[1].Message != "✗ pypi.org (no OpenShell rule allows it) (and 6 more like it)" || feed[1].Repeats != 6 ||
		feed[0].Message != "✗ pypi.org (no OpenShell rule allows it)" || feed[0].Repeats != 0 {
		t.Fatalf("%d records, feed %+v", n, feed)
	}
	if got := destinationKinds(t, e, "retrybox")["pypi.org"]; got.Refused != 8 {
		t.Fatalf("destination = %+v, want each refusal counted", got)
	}
}

// A sandbox refused for thousands of distinct destinations is paced on its
// own: another sandbox's refusal is recorded and shown, and the feed tells
// how many of the flood it held back.
func TestDistinctRefusalsArePacedPerSandbox(t *testing.T) {
	fastFlush(t)
	e := newEnv(t, nil)
	e.run()
	a := e.create(sandboxapi.CreateRequest{Name: "manyhosts"})
	b := e.create(sandboxapi.CreateRequest{Name: "onehost", Project: e.otherProject("onehost")})
	sink := e.m.EgressSink()
	for i := range 5000 {
		sink.EgressEvent(blockedEvent(a.Name, fmt.Sprintf("h%d.flood.example", i)))
	}
	sink.EgressEvent(blockedEvent(b.Name, "other.example"))
	eventually(t, "the other sandbox's refusal and the held-back count on the feed", func() bool {
		other := e.events(b.Name, sandboxapi.ActivityEgressBlocked, "")
		return len(other) == 1 && other[0].Host == "other.example" && len(e.events(a.Name, "", "flood")) >= 1
	})
	if n := egressRecords(e, a.Name, nil); n > 2*blockedBurst {
		t.Fatalf("%d egress records for 5000 refusals in a burst, want the sandbox paced", n)
	}
	shown := slices.DeleteFunc(e.events(a.Name, "", ""), func(ev sandboxapi.ActivityEvent) bool { return ev.Host == "" })
	if len(shown) > 2*feedBurst {
		t.Fatalf("%d feed events for 5000 refusals in a burst, want the sandbox paced", len(shown))
	}
}

// A large-upload finding the full queue cannot take is kept, and recorded
// once the queue drains.
func TestLargeUploadSurvivesAFullQueue(t *testing.T) {
	fastFlush(t)
	e := newEnv(t, nil)
	sb := e.create(sandboxapi.CreateRequest{Name: "fullq"})
	sink := e.m.EgressSink()
	for range egressSinkBuffer + 10 {
		sink.EgressEvent(egress.Event{Kind: egress.EventClosed, Time: time.Now(), SandboxName: sb.Name, Host: "a.example", Port: 443})
	}
	sink.EgressEvent(egress.Event{Kind: egress.EventLargeUpload, Time: time.Now(), SandboxName: sb.Name, Host: "files.example.net", BytesUp: 30 << 20})
	e.run()
	eventually(t, "the finding", func() bool { return len(where(&e.tel.mu, &e.tel.findings, nil)) == 1 })
}

// A required strict pack turns a running sandbox's egress off with a 403
// naming the pack (live it was a 407 that sent the agent debugging its
// credentials), and the feed says so once, with what moved.
func TestRequiredStrictPackTurnsRunningEgressOff(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	proxy := startLiveProxy(t, e)
	e.live(sandboxapi.CreateRequest{Name: "basebox"})
	if status, _ := proxy.connect(t, "basebox", "example.org:443"); status != http.StatusOK {
		t.Fatalf("CONNECT under the open pack = %d", status)
	}
	moved := func() []sandboxapi.ActivityEvent {
		return e.events("basebox", sandboxapi.ActivityLifecycle, sandboxapi.ReasonPolicyChanged)
	}
	off := func() []sandboxapi.ActivityEvent {
		return e.events("basebox", sandboxapi.ActivityLifecycle, sandboxapi.ReasonEgressOff)
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.RequiredPack = "strict" })
	e.m.refreshEgress()
	status, body := proxy.connect(t, "basebox", "example.org:443")
	if status != http.StatusForbidden || body.Category != egress.CategoryEgressOff ||
		!strings.Contains(body.Reason, "required sandbox pack (strict)") || !strings.Contains(body.Reason, "openshell.admin.required_pack") {
		t.Fatalf("CONNECT under the required strict pack = %d %+v", status, body)
	}
	if o := off(); len(o) != 1 || !strings.Contains(o[0].Message, "all web egress: your organization's required sandbox pack (strict)") {
		t.Fatalf("egress-off feed = %+v", o)
	}
	if m := moved(); len(m) != 1 || !strings.Contains(m[0].Message, "your organization's sandbox policy changed: ") ||
		!strings.Contains(m[0].Message, "pack open → strict") || !strings.Contains(m[0].Message, "(web egress off)") {
		t.Fatalf("policy-change feed = %+v", m)
	}
	if got := e.get("basebox"); got.NetworkMode != "deny" || got.Pack != "strict" {
		t.Fatalf("status = pack %s, network %s", got.Pack, got.NetworkMode)
	}
	// The same configuration again moves nothing; relaxed again, the egress comes back.
	e.m.refreshEgress()
	if len(off()) != 1 || len(moved()) != 1 {
		t.Fatalf("a repeated configuration said %d egress-off and %d policy-change lines", len(off()), len(moved()))
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.RequiredPack = "" })
	e.m.refreshEgress()
	if status, _ := proxy.connect(t, "basebox", "example.org:443"); status != http.StatusOK {
		t.Fatalf("CONNECT after the relax = %d", status)
	}
	if m := moved(); len(m) != 2 || !strings.Contains(m[1].Message, "pack strict → open") {
		t.Fatalf("policy-change feed after the relax = %+v", m)
	}
}

// An administrator's change of the egress lists reaches every running
// sandbox's feed as one line naming what changed; a stopped sandbox gets none.
func TestAdminEgressChangeIsAnnouncedPerSandbox(t *testing.T) {
	e := newEnv(t, nil)
	e.live(sandboxapi.CreateRequest{Name: "onebox"})
	e.live(sandboxapi.CreateRequest{Name: "twobox", Project: e.otherProject("two")})
	e.create(sandboxapi.CreateRequest{Name: "idlebox", Project: e.otherProject("idle")})
	e.stopBox("idlebox")
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.EgressBlock = []string{"example.com", "*.example.org"} })
	e.m.refreshEgress()
	for _, name := range []string{"onebox", "twobox"} {
		if moved := e.events(name, sandboxapi.ActivityLifecycle, sandboxapi.ReasonPolicyChanged); len(moved) != 1 ||
			!strings.Contains(moved[0].Message, "egress_block now includes example.com, *.example.com, *.example.org") || !strings.HasSuffix(moved[0].Message, "applied to "+name) {
			t.Fatalf("%s: policy-change feed = %+v", name, moved)
		}
	}
	if moved := e.events("idlebox", sandboxapi.ActivityLifecycle, sandboxapi.ReasonPolicyChanged); len(moved) != 0 {
		t.Fatalf("a stopped sandbox was told: %+v", moved)
	}
}

// Launch.Yolo is the next launch's skip-permissions mode (it follows the
// policy), SessionYolo the running session's, which is warned about.
func TestStatusReportsTheSessionsSkipPermissions(t *testing.T) {
	e := liveEnv(t, "yolobox", nil)
	if got := e.get("yolobox"); !got.Launch.Yolo || !got.SessionYolo {
		t.Fatalf("before = launch %v, session %v", got.Launch.Yolo, got.SessionYolo)
	}
	warned := func(sb *sandboxapi.Sandbox) bool {
		return slices.ContainsFunc(sb.Warnings, func(w string) bool {
			return strings.Contains(w, "skip-permissions stays on in the session running now") && strings.Contains(w, "openshell.admin.allow_yolo")
		})
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.AllowYolo = boolPtr(false) })
	e.m.refreshEgress()
	if got := e.get("yolobox"); got.Launch.Yolo || got.Yolo || !got.SessionYolo || !warned(got) {
		t.Fatalf("after allow_yolo false = launch %v, yolo %v, session %v, warnings %q", got.Launch.Yolo, got.Yolo, got.SessionYolo, got.Warnings)
	}
	e.stopBox("yolobox")
	if e.get("yolobox").SessionYolo {
		t.Fatal("a stopped sandbox reports a session in skip-permissions mode")
	}
	e.startBox("yolobox", sandboxapi.StartRequest{})
	if got := e.get("yolobox"); got.SessionYolo || got.Launch.Yolo || warned(got) {
		t.Fatalf("new session = launch %v, session %v, warnings %q", got.Launch.Yolo, got.SessionYolo, got.Warnings)
	}
}

// A sandbox's create-time clamps stayed on status after the administrator
// dropped the constraint behind them; the view reports the ones the
// configuration applies now.
func TestViolationsFollowThePolicy(t *testing.T) {
	e := newEnv(t, func(c *config.Config) { c.OpenShell.Admin.RequiredPack = "strict" })
	e.live(sandboxapi.CreateRequest{Name: "clampbox", Pack: "open"})
	pack := func() bool {
		return slices.ContainsFunc(e.get("clampbox").Violations, func(v sandboxapi.Violation) bool { return v.Key == "pack" })
	}
	if !pack() {
		t.Fatalf("violations under the required pack = %+v", e.get("clampbox").Violations)
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.RequiredPack = "" })
	e.m.refreshEgress()
	if got := e.get("clampbox"); pack() || got.Pack != "open" || got.Approvals == "manual" {
		t.Fatalf("after the constraint went: violations %+v, pack %s, approvals %s", got.Violations, got.Pack, got.Approvals)
	}
}

// A --credential binding, whose provider rule opens its endpoint around the
// egress proxy, is judged again once the policy changes: a running sandbox's
// provider is detached (recorded, on the feed) and the next start refused.
func TestCredentialEndpointsFollowThePolicy(t *testing.T) {
	for _, tc := range []struct {
		name         string
		edit         func(c *config.Config)
		code, reason string
	}{
		{"admin block", func(c *config.Config) { c.OpenShell.Admin.EgressBlock = []string{"api.stripe.com"} }, sandboxapi.CodeAdminViolation, policyReasonAdmin},
		{"admin allow-only", func(c *config.Config) { c.OpenShell.Admin.EgressAllowOnly = []string{"registry.example.org"} }, sandboxapi.CodeAdminViolation, policyReasonAdmin},
		{"block list", func(c *config.Config) { c.OpenShell.Egress.Block = []string{"api.stripe.com"} }, sandboxapi.CodePolicyViolation, policyReasonBlocklist},
	} {
		t.Run(tc.name, func(t *testing.T) {
			e := newEnv(t, nil)
			e.create(sandboxapi.CreateRequest{Name: "credbox", Credentials: stripeCred})
			provider := providerName("credbox", roleCredential, 0)
			e.setConfig(tc.edit)
			if !e.m.enforceAll(t.Context()) {
				t.Fatal("enforcement did not reach the gateway")
			}
			if got, err := e.client.GetSandbox(t.Context(), "credbox"); err != nil || slices.Contains(got.Spec.Providers, provider) {
				t.Fatalf("providers after enforcement = %v, %v; want %s detached", got.Spec.Providers, err, provider)
			}
			if !e.tel.removed(provider, tc.reason) || len(e.events("credbox", sandboxapi.ActivityEgressBlocked, tc.reason)) == 0 {
				t.Fatal("the detach is not recorded or not on the feed")
			}
			e.stopBox("credbox")
			_, err := e.m.Start(t.Context(), "credbox", sandboxapi.StartRequest{})
			wantCode(t, err, tc.code)
		})
	}
}

// The endpoints of the --llm credential's provider, which its rule opens
// around the proxy, answer to the organization's egress_allow_only and
// egress_block at create and on every later start.
func TestModelProviderEndpointsFollowTheAdminLists(t *testing.T) {
	llm := &sandboxapi.LLMCredential{Profile: profiles.AnthropicID, Credentials: map[string]string{"ANTHROPIC_API_KEY": "sk-test"}}
	e := newEnv(t, func(c *config.Config) { c.OpenShell.Admin.EgressAllowOnly = []string{"registry.example.org"} })
	_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "llmbox", LLM: llm})
	if apiErr := wantCode(t, err, sandboxapi.CodeAdminViolation); apiErr.Violation == nil || apiErr.Violation.Key != "llm" ||
		apiErr.Violation.Attempted != "api.anthropic.com" {
		t.Fatalf("violation = %+v", apiErr.Violation)
	}
	assertNothingLeft(t, e)
	e = newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "llmbox", LLM: llm})
	e.stopBox("llmbox")
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.EgressBlock = []string{"api.anthropic.com"} })
	_, err = e.m.Start(t.Context(), "llmbox", sandboxapi.StartRequest{})
	wantCode(t, err, sandboxapi.CodeAdminViolation)
}

// GAP-0361: in a strict session one connection to the model host outside
// its provider rule was refused, and the feed and the session summary read
// "x bedrock-mantle... (no OpenShell rule allows this port)", as if strict
// had cut the model off. The refusal says it was another connection.
func TestARefusalOnTheModelHostSaysTheModelChannelStaysOpen(t *testing.T) {
	llm := &sandboxapi.LLMCredential{Profile: profiles.AnthropicID, Credentials: map[string]string{"ANTHROPIC_API_KEY": "sk-test"}}
	e := newEnv(t, nil)
	e.live(sandboxapi.CreateRequest{Name: "mhbox", LLM: llm})
	e.ocsf("mhbox", "NET:OPEN [MED] DENIED /usr/bin/node(42) -> api.anthropic.com:443/tcp [policy:- engine:opa] [reason:transparent_tcp_mapping_denied]", time.Now())
	feed := e.events("mhbox", sandboxapi.ActivityEgressBlocked, "")
	const want = "✗ api.anthropic.com (a connection outside the model channel, which stays open; no OpenShell rule allows it)"
	if len(feed) != 1 || feed[0].Message != want || feed[0].Reason != sandboxapi.ReasonModelHostSide {
		t.Fatalf("feed = %+v, want %q", feed, want)
	}
	if n := egressRecords(e, "mhbox", func(r audit.SandboxEgressEvent) bool {
		return r.Blocked && strings.HasPrefix(r.Reason, "a connection outside the model channel") && strings.HasSuffix(r.Reason, "(transparent_tcp_mapping_denied)")
	}); n != 1 {
		t.Fatalf("%d records say the model channel stays open, want 1", n)
	}
}

// GAP-0354 with GAP-0361: OpenShell refuses a model request whose body
// carries a credential placeholder on the sandbox's own model host. That is
// the model channel refusing this conversation, not a connection outside
// it: the line and the record name the placeholder.
func TestAPlaceholderRefusalOnTheModelHostNamesThePlaceholder(t *testing.T) {
	llm := &sandboxapi.LLMCredential{Profile: profiles.AnthropicID, Credentials: map[string]string{"ANTHROPIC_API_KEY": "sk-test"}}
	e := newEnv(t, nil)
	e.live(sandboxapi.CreateRequest{Name: "phbox", LLM: llm})
	e.ocsf("phbox", "NET:TRAFFIC [HIGH] DENIED api.anthropic.com:443 [reason:POST request body credential traffic denied for api.anthropic.com:443]", time.Now())
	feed := e.events("phbox", sandboxapi.ActivityEgressBlocked, "")
	const want = "✗ api.anthropic.com (OpenShell forwards no request whose body carries a sandbox credential placeholder)"
	if len(feed) != 1 || feed[0].Message != want || feed[0].Reason == sandboxapi.ReasonModelHostSide {
		t.Fatalf("feed = %+v, want %q", feed, want)
	}
	if n := egressRecords(e, "phbox", func(r audit.SandboxEgressEvent) bool {
		return strings.HasPrefix(r.Reason, "a connection outside the model channel")
	}); n != 0 {
		t.Fatalf("%d records call the placeholder refusal a connection outside the model channel", n)
	}
}

// privatePack is a custom pack whose allow list opens a private address.
const privatePack = `version: 1
name: lanpack
network: {mode: open}
approvals: {mode: triage}
egress:
  allow: [10.0.0.9]
workspace: {mode: mount}
harness: {yolo: true}
mcp: {import: true, host_ports: false}
hooks: {fail_mode: closed}
`

// A live-mounted sandbox never reads its policy from inside its own project:
// the agent writes the project as the host user, who owns the pack, and could
// open private networks on the next resolution. A copy may carry its pack.
func TestPackInsideTheMountIsRefused(t *testing.T) {
	e := newEnv(t, nil)
	inside := writeFile(t, filepath.Join(e.project, ".defenseclaw", "lanpack", "pack.yaml"), privatePack)
	_, err := e.tryCreate(sandboxapi.CreateRequest{Name: "selfpack", Pack: inside})
	if apiErr := wantCode(t, err, sandboxapi.CodePackInvalid); !strings.Contains(apiErr.Message, "inside the project") || len(e.ws.planned) != 0 {
		t.Fatalf("refusal = %+v, planned %v", apiErr, e.ws.planned)
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.PackDir = filepath.Join(e.project, ".defenseclaw") })
	_, err = e.tryCreate(sandboxapi.CreateRequest{Name: "selfpack", Pack: "lanpack"})
	wantCode(t, err, sandboxapi.CodePackInvalid)
	if sb := e.create(sandboxapi.CreateRequest{Name: "copypack", Pack: inside, Copy: true}); sb.WorkdirMode != config.OpenShellWorkdirCopy {
		t.Fatalf("workdir mode = %s", sb.WorkdirMode)
	}
}

// The mount plan and the snapshot protect every file the sandbox policy is
// read from, so the workspace refuses a share that holds one.
func TestMountProtectsPolicySources(t *testing.T) {
	packDir := filepath.Join(t.TempDir(), "packs")
	file := writeFile(t, filepath.Join(packDir, "lanpack", "pack.yaml"), privatePack)
	e := newEnv(t, func(c *config.Config) { c.OpenShell.PackDir = packDir })
	e.create(sandboxapi.CreateRequest{Name: "mountbox", Pack: "lanpack"})
	if p := e.ws.lastMount.Protected; !slices.Contains(p, packDir) || !slices.Contains(p, file) || !slices.Contains(e.ws.lastSnapshot.Protected, file) {
		t.Fatalf("mount protected = %v, snapshot protected = %v; want %s and %s", p, e.ws.lastSnapshot.Protected, packDir, file)
	}
}

// A running sandbox whose pack is now read from inside its mounted project
// (the agent could rewrite it) fails closed until it is read from outside.
func TestPolicyMovedIntoTheMountFailsClosed(t *testing.T) {
	outside := filepath.Join(t.TempDir(), "packs")
	writeFile(t, filepath.Join(outside, "lanpack", "pack.yaml"), strings.Replace(privatePack, "allow: [10.0.0.9]", "allow: []", 1))
	e := newEnv(t, func(c *config.Config) { c.OpenShell.PackDir = outside })
	e.live(sandboxapi.CreateRequest{Name: "movebox", Pack: "lanpack"})
	id := e.binding("movebox").ID
	registered := func() bool { _, ok := e.m.creds.Lookup(id); return ok }
	inside := filepath.Join(e.project, ".defenseclaw")
	writeFile(t, filepath.Join(inside, "lanpack", "pack.yaml"), privatePack) // the agent opened a private address
	e.setConfig(func(c *config.Config) { c.OpenShell.PackDir = inside })
	e.m.refreshEgress()
	if registered() {
		t.Fatal("the proxy credential survived a pack the sandbox can write")
	}
	chunkID := e.addChunk("movebox", chunk("allow_10_0_0_9_443", "10.0.0.9", 443))
	e.m.triageSandbox(t.Context(), e.boxOf("movebox"))
	if asks, _ := e.m.Approvals(t.Context(), "movebox"); e.chunkStatus("movebox", chunkID) != "pending" || len(asks) != 0 {
		t.Fatalf("private proposal = %s, asks %+v; want it left alone while the policy is refused", e.chunkStatus("movebox", chunkID), asks)
	}
	// Back to the pack outside the project: triage asks about the private address.
	e.setConfig(func(c *config.Config) { c.OpenShell.PackDir = outside })
	e.m.refreshEgress()
	if !registered() {
		t.Fatal("the proxy credential was not restored")
	}
	e.draft("movebox")
	if ask := e.waitAsks("movebox", 1)[0]; ask.Host != "10.0.0.9" || !ask.Risky || !strings.Contains(ask.Reason, "private network") ||
		e.chunkStatus("movebox", chunkID) != "pending" {
		t.Fatalf("ask = %+v", ask)
	}
}

// A connection OpenShell closes because the policy changed under it (every
// reload does that) showed as a block, twice per reload; it stays in the
// audit record only, as the end of an allowed connection, not a block: it
// raised MEDIUM alerts and counted on the dashboards' blocked egress
// (GAP-0138). A real denial still counts.
func TestPolicyReloadCutsAreNoBlocks(t *testing.T) {
	e := liveEnv(t, "portsbox", nil)
	cut := "NET:OPEN [MED] DENIED " + testClaudeBin + "(0) -> bedrock-mantle.us-east-1.api.aws:443 [reason:L7 tunnel closed before inspection " +
		"because policy changed: policy generation is stale [captured_generation:2 current_generation:3]]"
	e.ocsf("portsbox", cut, time.Now())
	e.ocsf("portsbox", cut, time.Now())
	audited := where(&e.tel.mu, &e.tel.egress, func(ev audit.SandboxEgressEvent) bool {
		return ev.Host == "bedrock-mantle.us-east-1.api.aws" && !ev.Blocked && ev.End == audit.SandboxEgressFailed && ev.Terminated &&
			ev.DecisionCode == "SANDBOX_EGRESS_TERMINATED"
	})
	if got := e.events("portsbox", sandboxapi.ActivityEgressBlocked, ""); len(got) != 0 || e.get("portsbox").Egress.Blocked != 0 || len(audited) != 2 {
		t.Fatalf("feed = %+v, blocked %d, audited %d; want the reload's cuts audited only", got, e.get("portsbox").Egress.Blocked, len(audited))
	}
	e.ocsf("portsbox", "NET:OPEN [MED] DENIED /usr/bin/curl(0) -> webhook.example.net:443 [reason:transparent_tcp_policy_denied]", time.Now())
	if got := e.events("portsbox", sandboxapi.ActivityEgressBlocked, ""); len(got) != 1 || e.get("portsbox").Egress.Blocked != 1 {
		t.Fatalf("feed = %+v", got)
	}
}

// A settings reload, or a global provider profile import (another
// sandbox's), drops the transparent mappings of the names a running sandbox
// looked up: its harness's next model connection was denied
// (transparent_tcp_mapping_denied) and read as DefenseClaw blocking the
// model host, a site blocked in the session's summary, while the call was
// retried and worked (GAP-0379). It is audited as the end of a connection
// the client makes again; past the reload's window the denial is a block.
func TestAMappingDenialAfterAReloadIsNoBlock(t *testing.T) {
	r := newReachEnv(t)
	denied := "NET:OPEN [MED] DENIED " + testClaudeBin + "(0) -> bedrock-mantle.us-east-1.api.aws:443 [reason:transparent_tcp_mapping_denied]"
	blocks := func() (int, int) {
		return len(r.events(r.name, sandboxapi.ActivityEgressBlocked, "")), r.get(r.name).Egress.Blocked
	}
	r.line("CONFIG:DETECTED [INFO] Settings poll: config change detected [old_revision:7 new_revision:7 policy_changed:false provider_env_changed:true]")
	r.advance(10 * time.Second)
	r.line(denied)
	cut := where(&r.tel.mu, &r.tel.egress, func(ev audit.SandboxEgressEvent) bool {
		return !ev.Blocked && ev.Terminated && ev.DecisionCode == "SANDBOX_EGRESS_TERMINATED" && strings.Contains(ev.Reason, "mapped the sandbox's names again")
	})
	if lines, n := blocks(); lines != 0 || n != 0 || len(cut) != 1 {
		t.Fatalf("after a reload: feed %d, blocked %d, audited cuts %d; want the denial audited only", lines, n, len(cut))
	}
	r.advance(reloadMappingWindow)
	r.line(denied)
	if lines, n := blocks(); lines != 1 || n != 1 {
		t.Fatalf("past the reload's window: feed %d, blocked %d; want a block", lines, n)
	}
	r.m.beforeGlobalImport(t.Context(), "defenseclaw-test-profile")
	r.advance(time.Second)
	r.line(denied)
	if lines, n := blocks(); lines != 1 || n != 1 {
		t.Fatalf("after a global profile import: feed %d, blocked %d; want no new block", lines, n)
	}
}

// Denials of this install's own ports are no blocked sites, also without
// the mapping record, which after a restart comes from the sandbox record.
func TestOwnPortDenialsAreNoBlocks(t *testing.T) {
	e := liveEnv(t, "portsbox", nil)
	ingress, egressPort := strconv.Itoa(testIngressPort), strconv.Itoa(testEgressPort)
	quiet := func(what string) {
		t.Helper()
		if got := e.events("portsbox", sandboxapi.ActivityEgressBlocked, ""); len(got) != 0 || e.get("portsbox").Egress.Blocked != 0 {
			t.Fatalf("%s: feed = %+v, blocked %d; DefenseClaw's own ports counted", what, got, e.get("portsbox").Egress.Blocked)
		}
	}
	e.ocsf("portsbox", "NET:OPEN [MED] DENIED "+testClaudeBin+"(0) -> 198.18.0.2:"+ingress+" [reason:transparent_tcp_mapping_denied]", time.Now())
	e.ocsf("portsbox", "NET:OPEN [MED] DENIED "+testClaudeBin+"(0) -> 198.18.0.2:"+egressPort+" [reason:transparent_tcp_mapping_denied]", time.Now())
	quiet("no mapping record seen")
	e.ocsf("portsbox", "CONFIG:PUBLISHED [INFO] Policy DNS mapped host.openshell.internal resolved=127.0.0.1 synthetic=198.18.0.3 ports="+
		egressPort+","+ingress+",38821 mapping_id=m1", time.Now())
	e.stop()
	if recs, errs := newRecordStore(e.dataDir).loadAll(); len(errs) != 0 || len(recs) != 1 || recs[0].HostAlias == nil ||
		recs[0].HostAlias.Addr != "198.18.0.3" || len(recs[0].HostAlias.Ports) != 3 {
		t.Fatalf("records = %+v, %v; want the host alias mapping kept", recs, errs)
	}
	e.restartDaemon()
	eventually(t, "the adopted sandbox is ready", func() bool {
		sb, err := e.m.Get(t.Context(), "portsbox")
		return err == nil && sb.Phase == "ready"
	})
	// A credential port the mapping covers reaches nothing new; the ingress's is DefenseClaw's own.
	e.ocsf("portsbox", "NET:OPEN [MED] DENIED "+testClaudeBin+"(0) -> 198.18.0.3:38821 [reason:transparent_tcp_mapping_denied]", time.Now())
	e.ocsf("portsbox", "NET:OPEN [MED] DENIED "+testClaudeBin+"(0) -> 198.18.0.3:"+ingress+" [reason:transparent_tcp_mapping_denied]", time.Now())
	quiet("after the restart")
	e.ocsf("portsbox", "NET:OPEN [MED] DENIED /usr/bin/curl(0) -> 198.18.0.3:38590 [reason:transparent_tcp_mapping_denied]", time.Now())
	if got := e.events("portsbox", sandboxapi.ActivityEgressBlocked, ""); len(got) != 1 || got[0].Host != openshellHostAlias || got[0].Port != 38590 ||
		e.get("portsbox").Egress.Blocked != 1 {
		t.Fatalf("feed = %+v; want another port of the host alias named a closed host port", got)
	}
}
