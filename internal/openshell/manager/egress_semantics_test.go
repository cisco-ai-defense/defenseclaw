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
	"bufio"
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
	"github.com/defenseclaw/defenseclaw/internal/openshell/stream"
	"github.com/defenseclaw/defenseclaw/internal/openshell/triage"
)

// teamPack is a custom pack with its own block and allow lists and an
// extra port.
const teamPack = `version: 1
name: team
network: {mode: open}
approvals: {mode: auto}
egress:
  block: ["*.paste.example"]
  allow: [webhook.site]
  ports: [443, 8443]
workspace: {mode: mount}
harness: {yolo: true}
mcp: {import: true, host_ports: false}
hooks: {fail_mode: closed}
`

func writeTeamPack(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "team"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "team", "pack.yaml"), []byte(teamPack), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// liveProxy is a real egress proxy serving the manager's sandbox
// credentials. Every allowed dial goes to a local listener that holds the
// connection.
type liveProxy struct {
	addr string
}

func startLiveProxy(t *testing.T, e *harnessEnv) *liveProxy {
	t.Helper()
	upstream, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = upstream.Close() })
	go func() {
		for {
			c, err := upstream.Accept()
			if err != nil {
				return
			}
			go func() { _, _ = io.Copy(io.Discard, c); _ = c.Close() }()
		}
	}()
	d, err := e.m.Decider()
	if err != nil {
		t.Fatal(err)
	}
	var dialer net.Dialer
	p, err := egress.New(egress.Options{
		Auth: e.m.EgressAuthenticator(), Decider: d, Resolver: e.dns,
		Dialer: dialerFunc(func(ctx context.Context, _, _ string) (net.Conn, error) {
			return dialer.DialContext(ctx, "tcp", upstream.Addr().String())
		}),
	})
	if err != nil {
		t.Fatal(err)
	}
	e.m.AttachProxy(p)
	ln, err := egress.Listen("127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = p.Serve(ln) }()
	t.Cleanup(func() { _ = p.Close() })
	return &liveProxy{addr: ln.Addr().String()}
}

type dialerFunc func(ctx context.Context, network, address string) (net.Conn, error)

func (f dialerFunc) DialContext(ctx context.Context, network, address string) (net.Conn, error) {
	return f(ctx, network, address)
}

// send sends a CONNECT for sandbox's credential and returns the
// connection, its reader and the response head. The caller closes the
// connection.
func (lp *liveProxy) send(t *testing.T, e *harnessEnv, sandbox, target string) (net.Conn, *bufio.Reader, *http.Response) {
	t.Helper()
	e.m.mu.Lock()
	cred := e.m.boxes[sandbox].cred
	e.m.mu.Unlock()
	conn, err := net.DialTimeout("tcp", lp.addr, 5*time.Second)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = conn.Close() })
	_ = conn.SetDeadline(time.Now().Add(10 * time.Second))
	auth := base64.StdEncoding.EncodeToString([]byte(cred.Username + ":" + cred.Password))
	if _, err := io.WriteString(conn, "CONNECT "+target+" HTTP/1.1\r\nHost: "+target+"\r\nProxy-Authorization: Basic "+auth+"\r\n\r\n"); err != nil {
		t.Fatal(err)
	}
	br := bufio.NewReader(conn)
	resp, err := http.ReadResponse(br, &http.Request{Method: http.MethodConnect})
	if err != nil {
		t.Fatalf("CONNECT %s: %v", target, err)
	}
	return conn, br, resp
}

// open establishes a CONNECT tunnel for sandbox's credential.
func (lp *liveProxy) open(t *testing.T, e *harnessEnv, sandbox, target string) (net.Conn, *bufio.Reader) {
	t.Helper()
	conn, br, resp := lp.send(t, e, sandbox, target)
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("%s CONNECT %s = %d", sandbox, target, resp.StatusCode)
	}
	return conn, br
}

// tunnelOpen reports whether the proxy still holds a tunnel open: a read
// waits for bytes instead of ending.
func tunnelOpen(conn net.Conn, br *bufio.Reader) bool {
	_ = conn.SetReadDeadline(time.Now().Add(200 * time.Millisecond))
	_, err := br.ReadByte()
	return errors.Is(err, os.ErrDeadlineExceeded)
}

// connect sends a CONNECT for sandbox's credential and returns the status
// and, for a refusal, the block body.
func (lp *liveProxy) connect(t *testing.T, e *harnessEnv, sandbox, target string) (int, egress.BlockResponse) {
	t.Helper()
	conn, _, resp := lp.send(t, e, sandbox, target)
	defer conn.Close()
	defer resp.Body.Close()
	var body egress.BlockResponse
	if resp.StatusCode == http.StatusForbidden {
		if err := json.NewDecoder(resp.Body).Decode(&body); err != nil {
			t.Fatalf("CONNECT %s: block body: %v", target, err)
		}
	}
	return resp.StatusCode, body
}

// TestEgressSemanticsAgree drives the policy layer (packs DecideEgress),
// the egress proxy (a real proxy serving the sandbox's own credential and
// decider), REST unblock and triage with the same inputs, and pins that
// they agree: a destination is allowed by both layers or by neither, an
// unblock is accepted exactly for what the proxy allows or reports
// unblockable, an accepted unblock takes effect in the proxy and in triage,
// and triage never approves a direct rule to what the proxy refuses.
func TestEgressSemanticsAgree(t *testing.T) {
	packDir := writeTeamPack(t)
	type want struct {
		allowed     bool
		unblockable bool
		category    egress.Category
		// unblockCode is the REST unblock's error code, "" when accepted.
		unblockCode string
		triage      triage.Verdict
		// afterTriage is triage's verdict once the unblock is in.
		afterTriage triage.Verdict
		// policyAllowed is the policy layer's verdict when it differs from
		// the proxy's: the policy sees the host as named, the proxy also
		// checks what it resolves to.
		policyAllowed *bool
	}
	yes := true
	for _, tc := range []struct {
		name string
		edit func(*config.OpenShellConfig)
		req  sandboxapi.CreateRequest
		host string
		port int
		want want
	}{
		{"open web", nil, sandboxapi.CreateRequest{}, "example.org", 443,
			want{allowed: true, triage: triage.Approve}},
		{"feed entry is unblockable", nil, sandboxapi.CreateRequest{}, "webhook.site", 443,
			want{category: egress.CategoryWebhookCatcher, unblockable: true, triage: triage.Reject, afterTriage: triage.Approve}},
		{"open-mode IP literal is blocked until unblocked", nil, sandboxapi.CreateRequest{}, "93.184.216.34", 443,
			want{category: egress.CategoryIPLiteral, unblockable: true, triage: triage.Reject, afterTriage: triage.Approve}},
		{"user block list is not one-click unblockable", func(o *config.OpenShellConfig) { o.Egress.Block = []string{"drop.example.org"} },
			sandboxapi.CreateRequest{}, "drop.example.org", 443,
			want{category: egress.CategoryOperatorBlock, unblockCode: sandboxapi.CodePolicyViolation, triage: triage.Reject}},
		{"pack block list is not unblockable", nil, sandboxapi.CreateRequest{Pack: "team"}, "a.paste.example", 443,
			want{category: egress.CategoryOperatorBlock, unblockCode: sandboxapi.CodePolicyViolation, triage: triage.Reject}},
		{"pack allow list lifts the feed", nil, sandboxapi.CreateRequest{Pack: "team"}, "webhook.site", 443,
			want{allowed: true, triage: triage.Approve}},
		{"pack ports", nil, sandboxapi.CreateRequest{Pack: "team"}, "example.org", 8443,
			want{allowed: true, triage: triage.Approve}},
		{"admin block is never unblockable", func(o *config.OpenShellConfig) { o.Admin.EgressBlock = []string{"*.ngrok.io"} },
			sandboxapi.CreateRequest{}, "a.ngrok.io", 443,
			want{category: egress.CategoryAdminBlock, unblockCode: sandboxapi.CodeAdminViolation, triage: triage.Reject}},
		{"outside admin allow-only", func(o *config.OpenShellConfig) { o.Admin.EgressAllowOnly = []string{"*.corp.example"} },
			sandboxapi.CreateRequest{}, "pypi.org", 443,
			want{category: egress.CategoryAdminAllowOnly, unblockCode: sandboxapi.CodeAdminViolation, triage: triage.Reject}},
		{"inside admin allow-only", func(o *config.OpenShellConfig) { o.Admin.EgressAllowOnly = []string{"*.corp.example"} },
			sandboxapi.CreateRequest{}, "git.corp.example", 443, want{allowed: true, triage: triage.Approve}},
		{"feed inside admin allow-only", func(o *config.OpenShellConfig) { o.Admin.EgressAllowOnly = []string{"*.pastebin.com"} },
			sandboxapi.CreateRequest{}, "x.pastebin.com", 443,
			want{category: egress.CategoryPasteSite, unblockable: true, triage: triage.Reject, afterTriage: triage.Approve}},
		{"user allow lifts the feed", func(o *config.OpenShellConfig) { o.Egress.Allow = []string{"webhook.site"} },
			sandboxapi.CreateRequest{}, "webhook.site", 443, want{allowed: true, triage: triage.Approve}},
		{"no unblocking: the feed is final", func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) },
			sandboxapi.CreateRequest{}, "webhook.site", 443,
			want{category: egress.CategoryWebhookCatcher, unblockCode: sandboxapi.CodeAdminViolation, triage: triage.Reject}},
		{"no unblocking: a required pack's allow entry does not lift the feed", func(o *config.OpenShellConfig) {
			o.Admin.AllowUnblock, o.Admin.RequiredPack = boolPtr(false), "team"
		}, sandboxapi.CreateRequest{}, "webhook.site", 443,
			want{category: egress.CategoryWebhookCatcher, unblockCode: sandboxapi.CodeAdminViolation, triage: triage.Reject}},
		{"balanced: not allowlisted", nil, sandboxapi.CreateRequest{Profile: "balanced"}, "example.org", 443,
			want{category: egress.CategoryNotAllowlisted, unblockable: true, triage: triage.Ask, afterTriage: triage.Approve}},
		{"balanced: curated allowlist", nil, sandboxapi.CreateRequest{Profile: "balanced"}, "pypi.org", 443,
			want{allowed: true, triage: triage.Approve}},
		{"private address", nil, sandboxapi.CreateRequest{}, "10.1.2.3", 443,
			want{category: egress.CategoryPrivateNetwork, unblockCode: sandboxapi.CodePolicyViolation, triage: triage.Ask}},
		{"intranet name", nil, sandboxapi.CreateRequest{}, "wiki.corp", 443,
			want{category: egress.CategoryPrivateNetwork, unblockCode: sandboxapi.CodePolicyViolation, triage: triage.Ask}},
		{"an allow entry opens an intranet name", func(o *config.OpenShellConfig) { o.Egress.Allow = []string{"wiki.corp"} },
			sandboxapi.CreateRequest{}, "wiki.corp", 443, want{allowed: true, triage: triage.Approve}},
		{"this machine", nil, sandboxapi.CreateRequest{}, "localhost", 443,
			want{category: egress.CategoryHostInternal, unblockCode: sandboxapi.CodePolicyViolation, triage: triage.Ask}},
		{"metadata", nil, sandboxapi.CreateRequest{}, "169.254.169.254", 443,
			want{category: egress.CategoryHostInternal, unblockCode: sandboxapi.CodePolicyViolation, triage: triage.Reject}},
		// The policy sees the name; the proxy and triage see where it
		// resolves. An unblock is harmless: it never opens this machine.
		{"a name that resolves to this machine", nil, sandboxapi.CreateRequest{}, "rebind.example.org", 443,
			want{category: egress.CategoryHostInternal, triage: triage.Reject, afterTriage: triage.Reject, policyAllowed: &yes}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			ctx := context.Background()
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
			if err != nil {
				t.Fatal(err)
			}
			eff, err := e.m.resolveBox(b)
			if err != nil {
				t.Fatal(err)
			}
			target := net.JoinHostPort(tc.host, strconv.Itoa(tc.port))

			// The two layers agree.
			pol := eff.DecideEgress(tc.host, tc.port)
			policyAllowed := tc.want.allowed
			if tc.want.policyAllowed != nil {
				policyAllowed = *tc.want.policyAllowed
			}
			if pol.Allowed != policyAllowed {
				t.Fatalf("policy layer = %+v, want allowed=%v", pol, policyAllowed)
			}
			if !pol.Allowed && pol.Unblockable != tc.want.unblockable {
				t.Fatalf("policy layer = %+v, want unblockable=%v", pol, tc.want.unblockable)
			}
			status, body := proxy.connect(t, e, "sem", target)
			if (status == http.StatusOK) != tc.want.allowed {
				t.Fatalf("proxy CONNECT %s = %d %+v, want allowed=%v", target, status, body, tc.want.allowed)
			}
			if !tc.want.allowed && (body.Category != tc.want.category || body.Unblockable != tc.want.unblockable) {
				t.Fatalf("proxy refusal = %+v, want %s unblockable=%v", body, tc.want.category, tc.want.unblockable)
			}

			// Triage holds a direct rule to the same verdict.
			proposal := triage.Proposal{Sandbox: "sem", ChunkID: "c", RuleName: "allow_semantics_" + strconv.Itoa(tc.port),
				Endpoints: []triage.Endpoint{{Host: tc.host, Port: tc.port}}}
			if got := triage.Classify(ctx, proposal, e.m.triagePolicy(b, eff)); got.Verdict != tc.want.triage {
				t.Fatalf("triage = %+v, want %s", got, tc.want.triage)
			}
			if !tc.want.allowed && tc.want.triage == triage.Approve {
				t.Fatal("triage approved what the proxy refuses")
			}

			// REST unblock accepts exactly what the proxy allows or can
			// lift.
			_, err = e.m.Unblock(ctx, sandboxapi.UnblockRequest{Host: tc.host, Sandbox: "sem"})
			switch {
			case tc.want.unblockCode == "" && err != nil:
				t.Fatalf("unblock = %v, want accepted", err)
			case tc.want.unblockCode != "" && !sandboxapi.IsCode(err, tc.want.unblockCode):
				t.Fatalf("unblock = %v, want %s", err, tc.want.unblockCode)
			}
			if tc.want.policyAllowed == nil && (err == nil) != (tc.want.allowed || tc.want.unblockable) {
				t.Fatalf("unblock accepted=%v, but the proxy allowed=%v unblockable=%v", err == nil, tc.want.allowed, tc.want.unblockable)
			}
			if err != nil || tc.want.allowed {
				return
			}
			status, body = proxy.connect(t, e, "sem", target)
			if afterAllowed := tc.want.afterTriage == triage.Approve; (status == http.StatusOK) != afterAllowed {
				t.Fatalf("proxy after the unblock = %d %+v, want allowed=%v", status, body, afterAllowed)
			}
			if got := triage.Classify(ctx, proposal, e.m.triagePolicy(b, eff)); got.Verdict != tc.want.afterTriage {
				t.Fatalf("triage after the unblock = %+v, want %s", got, tc.want.afterTriage)
			}
		})
	}
}

// TestStrictSandboxHasNoProxy: the strict profile runs without the proxy,
// and every layer says so.
func TestStrictSandboxHasNoProxy(t *testing.T) {
	e := newEnv(t, nil)
	e.create(sandboxapi.CreateRequest{Name: "strictsem", Profile: "strict"})
	b, _ := e.m.box("strictsem")
	eff, err := e.m.resolveBox(b)
	if err != nil {
		t.Fatal(err)
	}
	if dec := eff.DecideEgress("pypi.org", 443); dec.Allowed || dec.Unblockable {
		t.Fatalf("policy layer = %+v", dec)
	}
	binding, _ := e.store.Lookup("strictsem")
	if _, ok := e.m.creds.Lookup(binding.ID); ok {
		t.Fatal("a strict sandbox has a proxy credential")
	}
	if _, err := e.m.Unblock(context.Background(), sandboxapi.UnblockRequest{Host: "webhook.site", Sandbox: "strictsem"}); !sandboxapi.IsCode(err, sandboxapi.CodePolicyViolation) {
		t.Fatalf("unblock under strict = %v", err)
	}
	p := triage.Proposal{Sandbox: "strictsem", ChunkID: "c", RuleName: "allow_pypi_org_443", Endpoints: []triage.Endpoint{{Host: "pypi.org", Port: 443}}}
	if got := triage.Classify(context.Background(), p, e.m.triagePolicy(b, eff)); got.Verdict != triage.Ask || got.Reason != triage.ReasonManual {
		t.Fatalf("triage under strict = %+v", got)
	}
}

// TestPerSandboxDeciders: every sandbox is decided by its own pack and
// admin resolution; one sandbox's block list, ports and mode never reach
// another (the old single decider merged every pack's block list and ports).
func TestPerSandboxDeciders(t *testing.T) {
	packDir := writeTeamPack(t)
	e := newEnv(t, func(c *config.Config) { c.OpenShell.PackDir = packDir })
	proxy := startLiveProxy(t, e)
	e.create(sandboxapi.CreateRequest{Name: "teambox", Pack: "team"})
	e.create(sandboxapi.CreateRequest{Name: "openbox", Project: e.otherProject("open")})
	e.create(sandboxapi.CreateRequest{Name: "balbox", Profile: "balanced", Project: e.otherProject("bal")})
	for _, tc := range []struct {
		sandbox, target string
		allowed         bool
	}{
		{"teambox", "a.paste.example:443", false},
		{"openbox", "a.paste.example:443", true},
		{"balbox", "a.paste.example:443", false},
		{"teambox", "example.org:8443", true},
		{"openbox", "example.org:8443", false},
		{"teambox", "webhook.site:443", true},
		{"openbox", "webhook.site:443", false},
		{"openbox", "example.org:443", true},
		{"balbox", "example.org:443", false},
		{"balbox", "pypi.org:443", true},
	} {
		status, body := proxy.connect(t, e, tc.sandbox, tc.target)
		if (status == http.StatusOK) != tc.allowed {
			t.Errorf("%s CONNECT %s = %d %+v, want allowed=%v", tc.sandbox, tc.target, status, body, tc.allowed)
		}
	}
	// One sandbox's unblock stays its own.
	if _, err := e.m.Unblock(context.Background(), sandboxapi.UnblockRequest{Host: "example.org", Sandbox: "balbox"}); err != nil {
		t.Fatal(err)
	}
	if status, _ := proxy.connect(t, e, "balbox", "example.org:443"); status != http.StatusOK {
		t.Fatalf("balbox after its unblock = %d", status)
	}
	e.create(sandboxapi.CreateRequest{Name: "balbox2", Profile: "balanced", Project: e.otherProject("bal2")})
	if status, _ := proxy.connect(t, e, "balbox2", "example.org:443"); status != http.StatusForbidden {
		t.Fatalf("another sandbox got balbox's unblock: %d", status)
	}
}

// TestUnresolvablePolicyFailsClosed: a sandbox whose policy no longer
// resolves (its custom pack was deleted while it runs) must not keep the
// decider of its last good policy, which carries the administrator's lists
// of that time. Its proxy credential is revoked until the policy resolves
// again, triage leaves its proposals alone, and its approved OpenShell
// rules are judged by the organization's policy alone.
func TestUnresolvablePolicyFailsClosed(t *testing.T) {
	packDir := writeTeamPack(t)
	e := newEnv(t, func(c *config.Config) { c.OpenShell.PackDir = packDir })
	e.run()
	proxy := startLiveProxy(t, e)
	e.create(sandboxapi.CreateRequest{Name: "teambox", Pack: "team"})
	e.create(sandboxapi.CreateRequest{Name: "openbox", Project: e.otherProject("open")})
	e.watch.waitStarted(t, "teambox")
	blocked := addChunk(e, "teambox", chunk("allow_example_org_443", "example.org", 443))
	kept := addChunk(e, "teambox", chunk("allow_keep_example_net_443", "keep.example.net", 443))
	e.watch.push(t, "teambox", stream.Event{Kind: stream.KindDraft})
	eventually(t, "approvals applied", func() bool {
		return chunkStatus(e, "teambox", blocked) == "approved" && chunkStatus(e, "teambox", kept) == "approved"
	})

	// The pack goes away, then the administrator blocks example.org.
	packFile := filepath.Join(packDir, "team", "pack.yaml")
	if err := os.Remove(packFile); err != nil {
		t.Fatal(err)
	}
	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.EgressBlock = []string{"example.org"} })
	e.m.refreshEgress()
	if status, body := proxy.connect(t, e, "openbox", "example.org:443"); status != http.StatusForbidden || body.Category != egress.CategoryAdminBlock {
		t.Fatalf("openbox CONNECT example.org = %d %+v, want the admin block", status, body)
	}
	for _, target := range []string{"example.org:443", "keep.example.net:443"} {
		// Refused with the reason, not as a credential the proxy does not know.
		if status, body := proxy.connect(t, e, "teambox", target); status != http.StatusForbidden ||
			body.Category != egress.CategoryEgressOff || !strings.Contains(body.Reason, "cannot be resolved") {
			t.Fatalf("teambox CONNECT %s with an unresolvable policy = %d %+v, want it refused with the reason", target, status, body)
		}
	}
	var fed bool
	for _, ev := range e.m.ActivitySince(0, "teambox") {
		fed = fed || (ev.Kind == sandboxapi.ActivityEgressBlocked && ev.Reason == policyUnresolvedReason)
	}
	if !fed {
		t.Fatal("no feed event for the unresolvable policy")
	}
	var degraded bool
	e.tel.mu.Lock()
	for _, h := range e.tel.health {
		degraded = degraded || (h.Sandbox.Name == "teambox" && h.ErrorCode == "openshell_pack_invalid")
	}
	e.tel.mu.Unlock()
	if !degraded {
		t.Fatal("no degraded health record for the unresolvable policy")
	}

	// The approved direct rules answer to the organization's policy.
	e.m.enforceAll(context.Background())
	policy, _ := e.fake.SandboxPolicy(openshell.DefaultWorkspace, "teambox")
	if _, ok := policy.NetworkPolicies["allow_example_org_443"]; ok {
		t.Fatal("the admin-blocked direct rule survived the unresolvable policy")
	}
	if _, ok := policy.NetworkPolicies["allow_keep_example_net_443"]; !ok {
		t.Fatal("a direct rule the organization allows was removed")
	}

	// Triage does not decide proposals under the policy it no longer has.
	e.m.mu.Lock()
	b := e.m.boxes["teambox"]
	e.m.mu.Unlock()
	waiting := addChunk(e, "teambox", chunk("allow_new_example_net_443", "new.example.net", 443))
	e.m.triageSandbox(context.Background(), b)
	if s := chunkStatus(e, "teambox", waiting); s != "pending" {
		t.Fatalf("proposal under an unresolvable policy = %s, want pending", s)
	}

	// The pack comes back: the sandbox is served again, under the current
	// administrator's list.
	if err := os.WriteFile(packFile, []byte(teamPack), 0o644); err != nil {
		t.Fatal(err)
	}
	e.m.refreshEgress()
	if status, body := proxy.connect(t, e, "teambox", "example.org:443"); status != http.StatusForbidden || body.Category != egress.CategoryAdminBlock {
		t.Fatalf("teambox CONNECT example.org after the pack returned = %d %+v, want the admin block", status, body)
	}
	if status, _ := proxy.connect(t, e, "teambox", "keep.example.net:443"); status != http.StatusOK {
		t.Fatalf("teambox CONNECT keep.example.net after the pack returned = %d", status)
	}
	e.m.triageSandbox(context.Background(), b)
	eventually(t, "the waiting proposal approved", func() bool { return chunkStatus(e, "teambox", waiting) == "approved" })
}

// TestOpenTunnelsFollowPolicyChanges: the proxy decides a tunnel when it
// opens, and traffic keeps it open, so every change the manager makes to a
// sandbox's proxy credential reaches the tunnels already open. An
// administrator's block list ends the ones it now refuses (and only those),
// a policy that no longer resolves ends all of the sandbox's, and so does
// the deny network mode an administrator's min_profile moves it to.
func TestOpenTunnelsFollowPolicyChanges(t *testing.T) {
	packDir := writeTeamPack(t)
	e := newEnv(t, func(c *config.Config) { c.OpenShell.PackDir = packDir })
	proxy := startLiveProxy(t, e)
	e.create(sandboxapi.CreateRequest{Name: "openbox"})
	e.create(sandboxapi.CreateRequest{Name: "teambox", Pack: "team", Project: e.otherProject("team")})
	blockedConn, blockedBr := proxy.open(t, e, "openbox", "example.org:443")
	keptConn, keptBr := proxy.open(t, e, "openbox", "keep.example.net:443")
	teamConn, teamBr := proxy.open(t, e, "teambox", "keep.example.net:443")
	for name, open := range map[string]bool{
		"openbox example.org": tunnelOpen(blockedConn, blockedBr), "openbox keep.example.net": tunnelOpen(keptConn, keptBr),
		"teambox keep.example.net": tunnelOpen(teamConn, teamBr),
	} {
		if !open {
			t.Fatalf("the %s tunnel did not stay open", name)
		}
	}

	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.EgressBlock = []string{"example.org"} })
	e.m.refreshEgress()
	if tunnelOpen(blockedConn, blockedBr) {
		t.Fatal("an open tunnel to a destination the administrator blocked survived")
	}
	if !tunnelOpen(keptConn, keptBr) || !tunnelOpen(teamConn, teamBr) {
		t.Fatal("the administrator's block list ended tunnels it does not refuse")
	}

	// The pack goes away; the next resolution (triage, an approval, a
	// hook) fails the sandbox closed, without a configuration change.
	if err := os.Remove(filepath.Join(packDir, "team", "pack.yaml")); err != nil {
		t.Fatal(err)
	}
	teambox, err := e.m.box("teambox")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := e.m.resolveBox(teambox); err == nil {
		t.Fatal("teambox's policy still resolves without its pack")
	}
	if tunnelOpen(teamConn, teamBr) {
		t.Fatal("an open tunnel of a sandbox whose policy cannot be resolved survived")
	}
	if !tunnelOpen(keptConn, keptBr) {
		t.Fatal("another sandbox's policy failure ended openbox's tunnel")
	}

	e.setConfig(func(c *config.Config) { c.OpenShell.Admin.MinProfile = config.OpenShellProfileStrict })
	e.m.refreshEgress()
	if tunnelOpen(keptConn, keptBr) {
		t.Fatal("an open tunnel of a sandbox moved to the deny network mode survived")
	}
}

// TestNoPolicyRemovesDirectRules: when not even the organization's policy
// resolves (the required pack is gone), nothing can vouch for a sandbox's
// approved OpenShell rules, which bypass the proxy: every triaged rule is
// removed, and DefenseClaw's own rules stay.
func TestNoPolicyRemovesDirectRules(t *testing.T) {
	e := newEnv(t, nil)
	e.run()
	sb := e.create(sandboxapi.CreateRequest{Name: "orphanbox"})
	e.watch.waitStarted(t, sb.Name)
	id := addChunk(e, sb.Name, chunk("allow_keep_example_net_443", "keep.example.net", 443))
	e.watch.push(t, sb.Name, stream.Event{Kind: stream.KindDraft})
	eventually(t, "approval applied", func() bool { return chunkStatus(e, sb.Name, id) == "approved" })
	e.setConfig(func(c *config.Config) {
		c.OpenShell.Admin.RequiredPack = filepath.Join(t.TempDir(), "gone", "pack.yaml")
	})
	e.m.enforceAll(context.Background())
	policy, _ := e.fake.SandboxPolicy(openshell.DefaultWorkspace, sb.Name)
	if _, ok := policy.NetworkPolicies["allow_keep_example_net_443"]; ok {
		t.Fatal("a direct rule survived without any policy")
	}
	if _, ok := policy.NetworkPolicies["defenseclaw_egress"]; !ok {
		t.Fatalf("DefenseClaw's own rule was removed: %v", policy.NetworkPolicies)
	}
	var recorded bool
	e.tel.mu.Lock()
	for _, p := range e.tel.policy {
		recorded = recorded || (p.Operation == audit.SandboxPolicyRuleRemove && p.Target == "allow_keep_example_net_443" && p.Reason == "policy_unresolved")
	}
	e.tel.mu.Unlock()
	if !recorded {
		t.Fatal("no rule_remove record for the unbound rule")
	}
}
