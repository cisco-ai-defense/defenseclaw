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

package triage

import (
	"context"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"testing"
	"unicode/utf8"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
)

// This machine's interface addresses as the package's tests see them: the
// egress guard refuses ranges and literals that hold them, so verdicts must
// not depend on the machine the tests run on. testOwnV4 and testOwnV6 are
// public, so their subnets (/24 and /64) are the local network.
const (
	testOwnV4 = "185.199.9.9"
	testOwnV6 = "2a00:1450:9::fe"
)

func testInterfaceAddrs() ([]net.Addr, error) {
	return []net.Addr{
		&net.IPNet{IP: net.ParseIP("127.0.0.1"), Mask: net.CIDRMask(8, 32)},
		&net.IPNet{IP: net.ParseIP("::1"), Mask: net.CIDRMask(128, 128)},
		&net.IPNet{IP: net.ParseIP(testOwnV4), Mask: net.CIDRMask(24, 32)},
		&net.IPNet{IP: net.ParseIP(testOwnV6), Mask: net.CIDRMask(64, 128)},
	}, nil
}

// Policies most tests judge proposals under, resolved once.
var (
	effOpen, effBalanced, effStrict *packs.Effective
	effNoUnblock                    *packs.Effective // openshell.admin.allow_unblock: false
)

func TestMain(m *testing.M) {
	restore := egress.OverrideInterfaceAddrsForTest(testInterfaceAddrs)
	var err error
	resolve := func(edit func(*config.OpenShellConfig), flags packs.Flags) *packs.Effective {
		eff, e := resolveEffective(edit, flags)
		if e != nil {
			err = e
		}
		return eff
	}
	effOpen, effBalanced = resolve(nil, packs.Flags{}), resolve(nil, packs.Flags{Profile: "balanced"})
	effStrict = resolve(nil, packs.Flags{Profile: "strict"})
	effNoUnblock = resolve(func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, packs.Flags{})
	code := 1
	if err != nil {
		fmt.Fprintln(os.Stderr, "resolve the test policies:", err)
	} else {
		code = m.Run()
	}
	restore()
	os.Exit(code)
}

func boolPtr(v bool) *bool { return &v }

// fakeResolver answers the names a test sets and a public address for
// every other name, so no test depends on real DNS.
type fakeResolver struct {
	mu      sync.Mutex
	answers map[string][]string
	lookups []string
}

func newResolver() *fakeResolver { return &fakeResolver{answers: map[string][]string{}} }

func (r *fakeResolver) set(host string, addrs ...string) *fakeResolver {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.answers[host+"."] = addrs
	return r
}

func (r *fakeResolver) LookupIPAddr(_ context.Context, name string) ([]net.IPAddr, error) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.lookups = append(r.lookups, name)
	addrs, ok := r.answers[name]
	if !ok {
		addrs = []string{"93.184.216.34"}
	}
	if len(addrs) == 0 {
		return nil, &net.DNSError{Err: "no such host", Name: name, IsNotFound: true}
	}
	out := make([]net.IPAddr, 0, len(addrs))
	for _, a := range addrs {
		out = append(out, net.IPAddr{IP: net.ParseIP(a)})
	}
	return out, nil
}

type resolverFunc func(ctx context.Context, name string) ([]net.IPAddr, error)

func (f resolverFunc) LookupIPAddr(ctx context.Context, name string) ([]net.IPAddr, error) {
	return f(ctx, name)
}

// testResolver answers every test that does not bring its own.
var testResolver = newResolver()

func testPolicy(eff *packs.Effective) Policy {
	return Policy{Effective: eff, Resolver: testResolver, AgentProposals: true}
}

func resolveEffective(edit func(*config.OpenShellConfig), flags packs.Flags) (*packs.Effective, error) {
	cfg := &config.Config{}
	cfg.Gateway.APIPort = 18970
	cfg.Guardrail.Port = 4000
	if edit != nil {
		edit(&cfg.OpenShell)
	}
	eff, _, err := packs.Resolve(cfg, flags)
	return eff, err
}

func effective(t *testing.T, edit func(*config.OpenShellConfig), flags packs.Flags) *packs.Effective {
	t.Helper()
	eff, err := resolveEffective(edit, flags)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	return eff
}

// ruleName is the name OpenShell drafts for a denied connection, as
// measured on 0.1.1 (allow_www_example_net_443).
func ruleName(host string, port int) string {
	var b strings.Builder
	for _, r := range strings.ToLower(host) {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') {
			b.WriteRune(r)
		} else {
			b.WriteByte('_')
		}
	}
	n := strings.Trim(b.String(), "_")
	if n == "" {
		n = "x"
	}
	return "allow_" + n + "_" + strconv.Itoa(port)
}

func proposal(host string, port int, more ...Endpoint) Proposal {
	return Proposal{Sandbox: "dc-claude-app-1a2b", ChunkID: "c1", ReviewToken: "rt", RuleName: ruleName(host, port),
		Endpoints: append([]Endpoint{{Host: host, Port: port}}, more...)}
}

// liveChunk is a draft chunk in the shape OpenShell 0.1.1 drafts for a
// denied direct connection (captured on the host).
func liveChunk(host string, port uint32) openshell.PolicyChunk {
	return openshell.PolicyChunk{
		ID: "09ae94a5-80da-4bd8-b6c3-161aa5a05baa", Status: "pending", RuleName: ruleName(host, int(port)), Binary: "/usr/bin/curl",
		ReviewToken: "20223bc770f1",
		ProposedRule: &v1.NetworkPolicyRule{
			Name:      ruleName(host, int(port)),
			Endpoints: []v1.PolicyNetworkEndpoint{{Host: host, Port: port, Ports: []uint32{port}, AdvisorProposed: true}},
			Binaries:  []v1.PolicyNetworkBinary{{Path: "/usr/bin/curl"}},
		},
		CurrentEffectivePolicy: &v1.SandboxPolicy{NetworkPolicies: map[string]v1.NetworkPolicyRule{"defenseclaw_egress": {}}},
	}
}

func TestClassify(t *testing.T) {
	withAllow := effective(t, func(o *config.OpenShellConfig) { o.Egress.Allow = []string{"api.internal-tools.example"} }, packs.Flags{Profile: "balanced"})
	adminBlock := effective(t, func(o *config.OpenShellConfig) { o.Admin.EgressBlock = []string{"*.corp-blocked.example"} }, packs.Flags{})
	adminDomain := effective(t, func(o *config.OpenShellConfig) { o.Admin.EgressBlock = []string{"corp-blocked.example"} }, packs.Flags{})
	noHostPorts := effective(t, func(o *config.OpenShellConfig) { o.Admin.AllowHostPorts = boolPtr(false) }, packs.Flags{})
	blocked := effective(t, func(o *config.OpenShellConfig) { o.Egress.Block = []string{"drop.example.org"} }, packs.Flags{})
	nr, hp := KindNetworkRule, KindHostPort
	for _, tc := range []struct {
		eff     *packs.Effective
		verdict Verdict
		reason  Reason
		kind    string
		risky   bool
		// unblockable: a rejection says an unblock lifts it exactly as the
		// proxy does, so the feed offers unblocking only where it works.
		unblockable bool
		targets     []string // host:port
	}{
		{effOpen, Approve, ReasonAutoMode, nr, false, false, []string{"registry.example.org:443", "docs.example.org:80"}},
		{effOpen, Reject, ReasonBlocklisted, nr, false, true, []string{"webhook.site:443", "x.pastebin.com:443"}},
		{adminBlock, Reject, ReasonAdmin, nr, false, false, []string{"a.corp-blocked.example:443"}},
		{adminDomain, Reject, ReasonAdmin, nr, false, false, []string{"corp-blocked.example:443", "www.corp-blocked.example:443"}},
		{blocked, Reject, ReasonPolicy, nr, false, false, []string{"drop.example.org:443"}},
		{effOpen, Reject, ReasonPolicy, nr, false, false, []string{"169.254.169.254:80", "169.254.169.254:443", "metadata.google.internal:80"}},
		{effOpen, Reject, ReasonIPLiteral, nr, true, true, []string{"93.184.216.34:443"}},
		{effOpen, Reject, ReasonPortNotAllowed, nr, false, false, []string{"db.example.org:5432", "github.com:22"}},
		{effOpen, Reject, ReasonWildcard, nr, false, false, []string{"*.example.org:443"}},
		{effOpen, Reject, ReasonInvalid, nr, false, false, []string{":443"}},
		// Host ports ask, except DefenseClaw's own (ingress, main API) and
		// the OpenShell gateway's.
		{effOpen, Ask, ReasonHostLocal, hp, true, false, []string{"host.openshell.internal:5432", "127.0.0.1:3000"}},
		{effOpen, Reject, ReasonPolicy, hp, true, false, []string{"host.openshell.internal:18971", "host.openshell.internal:18970", "host.openshell.internal:17670"}},
		{effOpen, Reject, ReasonInvalid, hp, true, false, []string{"host.openshell.internal:0"}},
		{noHostPorts, Reject, ReasonAdmin, hp, true, false, []string{"host.openshell.internal:5432"}},
		{effOpen, Ask, ReasonPrivateNetwork, nr, true, false, []string{"10.1.2.3:443", "100.64.1.1:443"}},
		// Without allow_unblock nothing is unblockable.
		{effNoUnblock, Reject, ReasonAdmin, nr, false, false, []string{"10.1.2.3:443", "webhook.site:443"}},
		{effNoUnblock, Reject, ReasonIPLiteral, nr, true, false, []string{"93.184.216.34:443"}},
		{effBalanced, Ask, ReasonNotAllowlisted, nr, false, false, []string{"unknown.example.org:443"}},
		{withAllow, Approve, ReasonAllowed, nr, false, false, []string{"api.internal-tools.example:443"}},
		{effStrict, Ask, ReasonManual, nr, false, false, []string{"unknown.example.org:443"}},
	} {
		for _, target := range tc.targets {
			h, portText, _ := strings.Cut(target, ":")
			port, _ := strconv.Atoi(portText)
			got := Classify(context.Background(), proposal(h, port), testPolicy(tc.eff))
			if got.Verdict != tc.verdict || got.Reason != tc.reason || got.Kind != tc.kind || got.Risky != tc.risky ||
				(tc.verdict == Reject && got.Unblockable != tc.unblockable) || got.Message == "" {
				t.Errorf("%s (%s): Classify = %+v, want verdict %s reason %s kind %s risky %v unblockable %v and a message",
					target, tc.eff.Profile, got, tc.verdict, tc.reason, tc.kind, tc.risky, tc.unblockable)
			}
		}
	}
	// Without endpoints, without a policy, or with agent proposals off,
	// nothing is approved.
	for name, tc := range map[string]struct {
		p      Proposal
		pol    Policy
		reason Reason
	}{
		"no endpoints":  {Proposal{Sandbox: "s", ChunkID: "c"}, testPolicy(effOpen), ReasonNoEndpoints},
		"no policy":     {proposal("ok.example.org", 443), Policy{AgentProposals: true}, ""},
		"proposals off": {proposal("ok.example.org", 443), Policy{Effective: effOpen, Resolver: testResolver}, ReasonAgentProposalOff},
	} {
		if got := Classify(context.Background(), tc.p, tc.pol); got.Verdict != Reject || (tc.reason != "" && got.Reason != tc.reason) {
			t.Errorf("%s: Classify = %+v", name, got)
		}
	}
}

// Triage checks a proposal's port against the ports the sandbox's proxy
// relays. A deny-mode pack that lists no ports, run under a profile that
// turns the proxy on, relays the default ports, so triage must not refuse
// every proposal on them.
func TestClassifyDenyPackWithoutPortsUnderOpenProfile(t *testing.T) {
	dir := t.TempDir()
	pack := "version: 1\nname: noports\nnetwork: {mode: deny}\napprovals: {mode: auto}\negress: {ports: []}\n" +
		"workspace: {mode: mount}\nharness: {yolo: true}\nmcp: {import: true, host_ports: false}\nhooks: {fail_mode: closed}\n"
	if err := os.MkdirAll(filepath.Join(dir, "noports"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "noports", packs.PackFileName), []byte(pack), 0o644); err != nil {
		t.Fatal(err)
	}
	pol := testPolicy(effective(t, func(o *config.OpenShellConfig) { o.PackDir = dir }, packs.Flags{Pack: "noports", Profile: "open"}))
	if got := Classify(context.Background(), proposal("registry.example.org", 443), pol); got.Verdict != Approve {
		t.Fatalf("Classify(registry.example.org:443) = %+v, want approved on a port the proxy relays", got)
	}
	if got := Classify(context.Background(), proposal("db.example.org", 5432), pol); got.Reason != ReasonPortNotAllowed {
		t.Fatalf("Classify(db.example.org:5432) = %+v, want the port refused", got)
	}
}

// The worst endpoint decides a proposal, and one naming more than one
// destination host is rejected: approving opens every endpoint of it, but
// an ask shows the user one destination.
func TestClassifyWorstEndpointWins(t *testing.T) {
	ctx, host := context.Background(), "host.openshell.internal"
	p := proposal(host, 8080, Endpoint{Host: host, Port: 5432}, Endpoint{Host: host, Port: 18971})
	if got := Classify(ctx, p, testPolicy(effOpen)); got.Verdict != Reject || got.Port != 18971 {
		t.Fatalf("mixed proposal = %+v, want the reserved port to reject it", got)
	}
	p.Endpoints = p.Endpoints[:2]
	// The ask shows one destination; it names every port approving opens.
	if got := Classify(ctx, p, testPolicy(effOpen)); got.Verdict != Ask || got.Kind != KindHostPort || got.Port != 8080 ||
		!strings.Contains(got.Message, "approving opens ports 8080, 5432") {
		t.Fatalf("mixed proposal = %+v, want the host port to ask with every port", got)
	}

	for _, eff := range []*packs.Effective{effOpen, effBalanced} {
		got := Classify(ctx, proposal("docs.example.org", 443, Endpoint{Host: "Hidden.Example.NET.", Port: 443}), testPolicy(eff))
		if got.Verdict != Reject || got.Reason != ReasonMultipleHosts || got.Host != "docs.example.org" || !strings.Contains(got.Message, "hidden.example.net") {
			t.Fatalf("two-host proposal (%s) = %+v", eff.Profile, got)
		}
	}
	// The same host twice (another port, another spelling) is one host.
	if got := Classify(ctx, proposal("docs.example.org", 443, Endpoint{Host: "DOCS.example.org.", Port: 80}), testPolicy(effOpen)); got.Verdict != Approve {
		t.Fatalf("one-host proposal = %+v", got)
	}
}

func TestClassifySecurityNotesAsk(t *testing.T) {
	p := proposal("cdn.example.org", 443)
	p.SecurityNotes = "binary downloads executables"
	if got := Classify(context.Background(), p, testPolicy(effOpen)); got.Verdict != Ask || got.Reason != ReasonSecurityFlagged {
		t.Fatalf("flagged proposal = %+v, want an ask", got)
	}
	// Long notes are cut on a character boundary: the 300-byte limit falls
	// inside the two-byte é.
	p.SecurityNotes = strings.Repeat("a", 299) + "é and more"
	if got := Classify(context.Background(), p, testPolicy(effOpen)); !strings.HasSuffix(got.Message, ": "+strings.Repeat("a", 299)+"…") ||
		!utf8.ValidString(got.Message) {
		t.Fatalf("flagged proposal message = %q, want the notes cut before the é", got.Message)
	}
}

// TestClassifyRejectsHarnessFetches pins that a request the sandbox's
// harness binary makes around the proxy for something it does without
// (Codex's startup tip download, measured live: an open-network sandbox
// approved a direct rule for it at every first start, and the reload cut
// the session's open connections) is rejected, while the same destination
// from another binary, or a proposal that adds another endpoint, is judged
// as usual.
func TestClassifyRejectsHarnessFetches(t *testing.T) {
	const root = "/opt/defenseclaw-harness/codex"
	codex := root + "/lib/node_modules/@openai/codex/node_modules/@openai/codex-linux-arm64/vendor/aarch64-unknown-linux-musl/bin/codex"
	pol := testPolicy(effOpen)
	pol.HarnessFetches = []HarnessFetch{{BinaryRoot: root, Host: "raw.githubusercontent.com", Port: 443, What: "Codex's startup tip download"}}
	chunk := liveChunk("raw.githubusercontent.com", 443)
	chunk.Binary = codex
	chunk.ProposedRule.Binaries = []v1.PolicyNetworkBinary{{Path: codex}}
	fetch := func(edit func(*Proposal)) Proposal {
		p := FromChunk("fx-codex", chunk)
		edit(&p)
		return p
	}

	got := Classify(context.Background(), fetch(func(*Proposal) {}), pol)
	if got.Verdict != Reject || got.Reason != ReasonHarnessFetch || got.Host != "raw.githubusercontent.com" || got.Port != 443 ||
		!strings.Contains(got.Message, "Codex's startup tip download") || !strings.Contains(got.Message, "no direct rule") {
		t.Fatalf("harness fetch = %+v", got)
	}
	// Host spelling does not matter; without the declaration the open
	// network approves it.
	if got := Classify(context.Background(), fetch(func(p *Proposal) { p.Endpoints[0].Host = "RAW.githubusercontent.com." }), pol); got.Reason != ReasonHarnessFetch {
		t.Fatalf("spelling variant = %+v", got)
	}
	if got := Classify(context.Background(), fetch(func(*Proposal) {}), testPolicy(effOpen)); got.Verdict != Approve {
		t.Fatalf("undeclared = %+v, want the open network to approve it", got)
	}
	for name, edit := range map[string]func(*Proposal){
		"another binary":      func(p *Proposal) { p.Binary, p.Binaries = "/usr/bin/curl", []string{"/usr/bin/curl"} },
		"a rule binary too":   func(p *Proposal) { p.Binaries = append(p.Binaries, "/usr/bin/curl") },
		"a path escape":       func(p *Proposal) { p.Binary = root + "/../../usr/bin/curl"; p.Binaries = []string{p.Binary} },
		"no binary":           func(p *Proposal) { p.Binary, p.Binaries = "", nil },
		"another port":        func(p *Proposal) { p.Endpoints[0].Port = 8443 },
		"another endpoint":    func(p *Proposal) { p.Endpoints = append(p.Endpoints, Endpoint{Host: "ok.example.org", Port: 443}) },
		"a lookalike host":    func(p *Proposal) { p.Endpoints[0].Host = "raw.githubusercontent.com.example.org" },
		"the root's neighbor": func(p *Proposal) { p.Binary = root + "-evil/bin/codex"; p.Binaries = []string{p.Binary} },
	} {
		if got := Classify(context.Background(), fetch(edit), pol); got.Reason == ReasonHarnessFetch {
			t.Errorf("%s: rejected as a harness fetch: %+v", name, got)
		}
	}
}

func TestClassifyAllowedIPs(t *testing.T) {
	for _, tc := range []struct {
		eff     *packs.Effective
		verdict Verdict
		reason  Reason
		entries []string
	}{
		// A wide range that contains loopback or metadata is refused even
		// though its base address is public (100.64.0.0/10 holds
		// 100.100.100.200).
		{effOpen, Reject, ReasonPolicy, []string{"169.254.169.254/32", "127.0.0.0/8", "0.0.0.0/0", "198.18.0.2", "64.0.0.0/2",
			"100.64.0.0/10", "::/0", "fd00:ec2::254"}},
		{effOpen, Reject, ReasonInvalid, []string{"not-an-ip"}},
		// Private, CGNAT and ULA ranges, and ranges holding them, ask; so do
		// the rest of this machine's public subnets, the user's network.
		{effOpen, Ask, ReasonPrivateNetwork, []string{"10.0.0.0/8", "10.0.5.20", "8.0.0.0/5", "100.64.0.0/16", "fc00::/8",
			"::ffff:192.168.0.0/112", "185.199.9.200", "185.199.9.128/25", "2a00:1450:9::1"}},
		// Without allow_unblock the administrator refuses them.
		{effNoUnblock, Reject, ReasonAdmin, []string{"10.0.0.0/8", "185.199.9.200"}},
		{effOpen, Approve, ReasonAutoMode, []string{"93.184.216.0/24", "185.199.10.0/24"}},
		{effNoUnblock, Approve, ReasonAutoMode, []string{"93.184.216.0/24"}},
		// This machine's own addresses (testInterfaceAddrs) are never
		// opened, even in a public range. With allowed_ips set OpenShell
		// skips its own private-address check, so a name that rebinds to
		// one of them later would reach the host.
		{effOpen, Reject, ReasonResolvesToHost, []string{testOwnV4, "::ffff:" + testOwnV4, "185.199.0.0/16", "184.0.0.0/7", testOwnV6, "2a00:1450::/32"}},
	} {
		for _, entry := range tc.entries {
			p := proposal("my-cdn.attacker.example", 443)
			p.AllowedIPs = []string{entry}
			got := Classify(context.Background(), p, testPolicy(tc.eff))
			if got.Verdict != tc.verdict || got.Reason != tc.reason ||
				(tc.verdict == Ask && (!got.Risky || !strings.Contains(got.Message, entry) || got.Host != "my-cdn.attacker.example")) {
				t.Errorf("allowed_ips %s (%s) = %+v, want %s %s", entry, tc.eff.Profile, got, tc.verdict, tc.reason)
			}
			// The operator's decision runs the same checks.
			if err := CheckProposal(tc.eff, p, false); (err != nil) != (tc.verdict == Reject) {
				t.Errorf("CheckProposal(%s) = %v", entry, err)
			}
		}
	}
}

func TestClassifyRuleShape(t *testing.T) {
	pol := testPolicy(effOpen)
	if got := Classify(context.Background(), FromChunk("box", liveChunk("www.example.net", 443)), pol); got.Verdict != Approve || got.Reason != ReasonAutoMode {
		t.Fatalf("OpenShell's own proposal = %+v, want an automatic approval (the open pack uses approvals: auto)", got)
	}
	otherHost := ruleName("wiki.intranet.example", 443)
	for name, edit := range map[string]func(c *openshell.PolicyChunk){
		"defenseclaw rule": func(c *openshell.PolicyChunk) { c.RuleName = "defenseclaw_egress" },
		"provider rule":    func(c *openshell.PolicyChunk) { c.RuleName = "_provider_anthropic" },
		"custom rule name": func(c *openshell.PolicyChunk) { c.RuleName = "github" },
		"rule name case":   func(c *openshell.PolicyChunk) { c.RuleName = "Allow_www_example_net_443" },
		"rest protocol":    func(c *openshell.PolicyChunk) { c.ProposedRule.Endpoints[0].Protocol = "rest" },
		"layer-7 rules": func(c *openshell.PolicyChunk) {
			c.ProposedRule.Endpoints[0].Rules = []v1.L7Rule{{Allow: &v1.L7Allow{Method: "GET"}}}
		},
		"access preset": func(c *openshell.PolicyChunk) { c.ProposedRule.Endpoints[0].Access = v1.NetworkAccessPresetFull },
		"tls mode":      func(c *openshell.PolicyChunk) { c.ProposedRule.Endpoints[0].TLS = v1.NetworkTLSModeTerminate },
		"credential": func(c *openshell.PolicyChunk) {
			c.ProposedRule.Endpoints[0].CredentialBinding = &types.NetworkCredentialBinding{Provider: "llm"}
		},
		"credential rewrite": func(c *openshell.PolicyChunk) { c.ProposedRule.Endpoints[0].RequestBodyCredentialRewrite = true },
		"merge into a credentialed rule": func(c *openshell.PolicyChunk) {
			c.CurrentEffectivePolicy.NetworkPolicies[c.RuleName] = v1.NetworkPolicyRule{Endpoints: []v1.PolicyNetworkEndpoint{
				{Host: "api.anthropic.com", Port: 443, Protocol: "rest", ProviderCredentialed: true}}}
		},
		// A rule name is only a map key: an agent can name the rule the
		// user approved for another host, and the merged rule would carry
		// the user's approval to this one.
		"merge into another host's rule": func(c *openshell.PolicyChunk) {
			c.RuleName, c.ProposedRule.Name = otherHost, otherHost
			c.CurrentEffectivePolicy.NetworkPolicies[otherHost] = v1.NetworkPolicyRule{Endpoints: []v1.PolicyNetworkEndpoint{
				{Host: "wiki.intranet.example", Port: 443}}}
		},
		"candidate merges another host": func(c *openshell.PolicyChunk) {
			c.RuleName, c.ProposedRule.Name = otherHost, otherHost
			c.CandidateEffectivePolicy = &v1.SandboxPolicy{NetworkPolicies: map[string]v1.NetworkPolicyRule{otherHost: {
				Endpoints: []v1.PolicyNetworkEndpoint{{Host: "wiki.intranet.example", Port: 443}, {Host: "www.example.net", Port: 443}}}}}
		},
	} {
		c := liveChunk("www.example.net", 443)
		edit(&c)
		if got := Classify(context.Background(), FromChunk("box", c), pol); got.Verdict != Reject || got.Reason != ReasonRuleShape {
			t.Errorf("%s: Classify = %+v, want an unsupported-rule rejection", name, got)
		}
	}
	// Merging into an earlier plain approval of the same rule, for the same
	// host, is fine; the candidate shows the merged rule.
	c := liveChunk("www.example.net", 443)
	c.CurrentEffectivePolicy.NetworkPolicies[c.RuleName] = v1.NetworkPolicyRule{Endpoints: []v1.PolicyNetworkEndpoint{{Host: "WWW.example.net.", Port: 80}}}
	c.CandidateEffectivePolicy = &v1.SandboxPolicy{NetworkPolicies: map[string]v1.NetworkPolicyRule{c.RuleName: {
		Endpoints: []v1.PolicyNetworkEndpoint{{Host: "www.example.net", Port: 80}, {Host: "www.example.net", Port: 443}}}}}
	if got := Classify(context.Background(), FromChunk("box", c), pol); got.Verdict != Approve {
		t.Fatalf("merge into a plain rule = %+v", got)
	}
}

// TestClassifyUnblocked: triage asks the sandbox's own proxy decider, so
// the sandbox's unblocks lift what they lift in the proxy (the feed, the
// allowlist, open-mode IP literals) for that sandbox only, and never the
// administrator's lists, the block list or the private-network checks.
func TestClassifyUnblocked(t *testing.T) {
	adminBlock := effective(t, func(o *config.OpenShellConfig) { o.Admin.EgressBlock = []string{"webhook.site"} }, packs.Flags{})
	userBlock := effective(t, func(o *config.OpenShellConfig) { o.Egress.Block = []string{"webhook.site"} }, packs.Flags{})
	unblocks, err := egress.NewMemoryUnblocks(
		egress.Unblock{Pattern: "api.internal-tools.example"}, egress.Unblock{Pattern: "webhook.site"},
		egress.Unblock{Pattern: "10.1.2.3"}, egress.Unblock{Pattern: "93.184.216.34", SandboxID: "sb-a"},
	)
	if err != nil {
		t.Fatal(err)
	}
	withUnblocks := func(eff *packs.Effective, sandboxID string) Policy {
		d, err := eff.EgressDecider(unblocks)
		if err != nil {
			t.Fatal(err)
		}
		pol := testPolicy(eff)
		pol.Decider, pol.Principal = d, egress.Principal{BindingID: "b-" + sandboxID, SandboxID: sandboxID}
		return pol
	}
	for _, tc := range []struct {
		name    string
		pol     Policy
		host    string
		verdict Verdict
		reason  Reason // empty: any, but marked risky
	}{
		{"unblocked host", withUnblocks(effBalanced, "sb-a"), "api.internal-tools.example", Approve, ReasonAllowed},
		// An unblock lifts the blocklist feed, as in the proxy.
		{"unblocked feed host", withUnblocks(effBalanced, "sb-a"), "webhook.site", Approve, ReasonAllowed},
		// A sandbox's own unblock of an IP literal opens it for that sandbox only.
		{"unblocked IP literal", withUnblocks(effOpen, "sb-a"), "93.184.216.34", Approve, ""},
		{"another sandbox's unblock", withUnblocks(effOpen, "sb-b"), "93.184.216.34", Reject, ReasonIPLiteral},
		// Without the sandbox's decider, only the policy decides.
		{"feed host without unblocks", testPolicy(effBalanced), "webhook.site", Reject, ReasonBlocklisted},
		// It never lifts the administrator's blocklist, the block list or the
		// private checks.
		{"admin-blocked unblocked host", withUnblocks(adminBlock, "sb-a"), "webhook.site", Reject, ReasonAdmin},
		{"user-blocked unblocked host", withUnblocks(userBlock, "sb-a"), "webhook.site", Reject, ReasonPolicy},
		{"unblocked private address", withUnblocks(adminBlock, "sb-a"), "10.1.2.3", Ask, ReasonPrivateNetwork},
	} {
		if got := Classify(context.Background(), proposal(tc.host, 443), tc.pol); got.Verdict != tc.verdict ||
			(tc.reason != "" && got.Reason != tc.reason) || (tc.reason == "" && !got.Risky) {
			t.Errorf("%s: Classify(%s) = %+v, want %s %s", tc.name, tc.host, got, tc.verdict, tc.reason)
		}
	}
}

// TestApprovesAutomatically pins the check a rule DefenseClaw approved on
// its own must keep passing: what the policy approves without asking, judged
// as named (no lookup), so a stricter approvals or network mode, a
// destination off the allow list or a closed port takes the approval away.
func TestApprovesAutomatically(t *testing.T) {
	requiredStrict := effective(t, func(o *config.OpenShellConfig) { o.Admin.RequiredPack = "strict" }, packs.Flags{})
	for _, tc := range []struct {
		name string
		eff  *packs.Effective
		p    Proposal
		want bool
	}{
		{"open network", effOpen, proposal("registry.example.org", 443), true},
		{"balanced, curated allowlist", effBalanced, proposal("pypi.org", 443), true},
		{"balanced, not allowlisted", effBalanced, proposal("registry.example.org", 443), false},
		{"strict profile", effStrict, proposal("registry.example.org", 443), false},
		{"required strict pack", requiredStrict, proposal("registry.example.org", 443), false},
		{"a port the policy no longer relays", effStrict, proposal("pypi.org", 80), false},
		{"a host port always asks", effOpen, proposal("host.openshell.internal", 5432), false},
		{"a private network asks", effOpen, proposal("10.1.2.3", 443), false},
		{"blocklisted", effOpen, proposal("webhook.site", 443), false},
		{"no endpoints", effOpen, Proposal{RuleName: "allow_x_443"}, false},
	} {
		res := newResolver()
		pol := testPolicy(tc.eff)
		pol.Resolver = res
		if got := ApprovesAutomatically(context.Background(), tc.p, pol); got != tc.want || len(res.lookups) > 0 {
			t.Errorf("%s: ApprovesAutomatically = %v, want %v; looked up %v (the check judges names as named)", tc.name, got, tc.want, res.lookups)
		}
	}
	if ApprovesAutomatically(context.Background(), proposal("registry.example.org", 443), Policy{}) {
		t.Fatal("approved without a policy")
	}
}

// TestClassifyResolvesNames: a direct rule reaches whatever its name
// resolves to without the proxy's guard, so triage resolves every name and
// holds the answers to the proxy's dial-time rules. Approved rules are
// re-checked the same way (RecheckResolved): every dial-time refusal counts,
// a private answer included, which only the user may approve; a name that
// does not resolve now, or one judged as named, does not.
func TestClassifyResolvesNames(t *testing.T) {
	ctx := context.Background()
	r := newResolver().
		set("rebind.example.org", "127.0.0.1").
		set("meta.example.org", "169.254.169.254").
		set("mixed.example.org", "93.184.216.34", "::1").
		set("lan.example.org", "10.0.0.5").
		set("db.corp-tools.example", "10.0.0.6").
		set("feedaddr.example.org", "93.184.216.35").
		set("registry.npmjs.org", "10.0.0.9").
		set("gone.example.org")
	allowed := effective(t, func(o *config.OpenShellConfig) { o.Egress.Allow = []string{"db.corp-tools.example"} }, packs.Flags{})
	blockedAddr := effective(t, func(o *config.OpenShellConfig) { o.Egress.Block = []string{"93.184.216.35"} }, packs.Flags{})
	adminAddr := effective(t, func(o *config.OpenShellConfig) { o.Admin.EgressBlock = []string{"93.184.216.0/24"} }, packs.Flags{})
	for _, tc := range []struct {
		eff     *packs.Effective
		host    string
		verdict Verdict
		reason  Reason
		recheck Reason
	}{
		{effOpen, "cdn.example.org", Approve, ReasonAutoMode, ""},
		{effOpen, "rebind.example.org", Reject, ReasonResolvesToHost, ReasonResolvesToHost},
		{effOpen, "meta.example.org", Reject, ReasonResolvesToHost, ReasonResolvesToHost},
		// One bad answer among good ones.
		{effOpen, "mixed.example.org", Reject, ReasonResolvesToHost, ReasonResolvesToHost},
		{effOpen, "lan.example.org", Ask, ReasonPrivateNetwork, ReasonPrivateNetwork},
		{effNoUnblock, "lan.example.org", Reject, ReasonAdmin, ReasonAdmin},
		// A private answer an exact allow entry opens.
		{allowed, "db.corp-tools.example", Approve, ReasonAllowed, ""},
		{effBalanced, "rebind.example.org", Reject, ReasonResolvesToHost, ReasonResolvesToHost},
		// The curated allowlist admits the name, not its private answers.
		{effBalanced, "registry.npmjs.org", Ask, ReasonPrivateNetwork, ReasonPrivateNetwork},
		{blockedAddr, "feedaddr.example.org", Reject, ReasonBlocklisted, ReasonBlocklisted},
		{adminAddr, "feedaddr.example.org", Reject, ReasonAdmin, ReasonAdmin},
		{effOpen, "gone.example.org", Reject, ReasonUnresolved, ""},
		// Intranet names ask without a lookup.
		{effOpen, "wiki.corp", Ask, ReasonPrivateNetwork, ""},
		{effOpen, "host.openshell.internal", Ask, ReasonHostLocal, ""},
		{effOpen, "93.184.216.34", Reject, ReasonIPLiteral, ""},
	} {
		pol := testPolicy(tc.eff)
		pol.Resolver = r
		r.mu.Lock()
		before := len(r.lookups)
		r.mu.Unlock()
		got := Classify(ctx, proposal(tc.host, 443), pol)
		if got.Verdict != tc.verdict || got.Reason != tc.reason || (tc.verdict != Approve && !got.Risky) {
			t.Errorf("Classify(%s) = %+v, want %s %s, marked risky", tc.host, got, tc.verdict, tc.reason)
		}
		r.mu.Lock()
		asked := strings.Join(r.lookups[before:], " ")
		r.mu.Unlock()
		if strings.Contains(asked, "wiki.corp") || (tc.host == "cdn.example.org" && !strings.Contains(asked, "cdn.example.org.")) {
			t.Errorf("Classify(%s) looked up %q: an intranet name, or a name not fully qualified", tc.host, asked)
		}
		if got := RecheckResolved(ctx, proposal(tc.host, 443), pol); got != tc.recheck {
			t.Errorf("RecheckResolved(%s) = %q, want %q", tc.host, got, tc.recheck)
		}
	}
}

// TestClassifyDefersTransientLookups pins that only a name that does not
// exist or has no address is rejected as unresolved: a timeout, a temporary
// DNS failure or a canceled context defers the proposal (it stays pending
// and is decided later), and a deferral never hides a rejection or turns
// into an approval or an ask.
func TestClassifyDefersTransientLookups(t *testing.T) {
	ctx := context.Background()
	fail := map[string]error{
		"nx.example.org.":       &net.DNSError{Err: "no such host", Name: "nx.example.org", IsNotFound: true},
		"servfail.example.org.": &net.DNSError{Err: "server misbehaving", Name: "servfail.example.org", IsTemporary: true},
		"timeout.example.org.":  &net.DNSError{Err: "i/o timeout", Name: "timeout.example.org", IsTimeout: true},
		"refused.example.org.":  &net.DNSError{Err: "connection refused", Name: "refused.example.org"},
		"deadline.example.org.": context.DeadlineExceeded,
	}
	pol := testPolicy(effOpen)
	pol.Resolver = resolverFunc(func(ctx context.Context, name string) ([]net.IPAddr, error) {
		if err, ok := fail[name]; ok {
			return nil, err
		}
		if name == "empty.example.org." {
			return []net.IPAddr{}, nil
		}
		return testResolver.LookupIPAddr(ctx, name)
	})
	for host, want := range map[string]Reason{
		"nx.example.org": ReasonUnresolved, "empty.example.org": ReasonUnresolved,
		"servfail.example.org": ReasonLookupFailed, "timeout.example.org": ReasonLookupFailed,
		"refused.example.org": ReasonLookupFailed, "deadline.example.org": ReasonLookupFailed,
	} {
		verdict := Defer
		if want == ReasonUnresolved {
			verdict = Reject
		}
		if got := Classify(ctx, proposal(host, 443), pol); got.Verdict != verdict || got.Reason != want {
			t.Errorf("Classify(%s) = %+v, want %s %s", host, got, verdict, want)
		}
	}
	// Endpoint order: a rejection anywhere wins over a deferral, and a
	// deferral wins over an ask or an approval. Classify refuses proposals
	// naming several hosts first, so the order is pinned on the endpoint
	// judgement itself, and across the ports of one host.
	decider, err := pol.decider()
	if err != nil {
		t.Fatal(err)
	}
	timeout := Endpoint{Host: "timeout.example.org", Port: 443}
	for _, tc := range []struct {
		p    Proposal
		want Verdict
	}{
		{proposal("webhook.site", 443, timeout), Reject},
		{proposal("ok.example.org", 443, timeout), Defer},
		{proposal("wiki.corp", 443, timeout), Defer},
	} {
		if got := classifyEndpoints(ctx, tc.p, pol, decider); got.Verdict != tc.want {
			t.Errorf("classifyEndpoints(%v) = %+v, want %s", tc.p.Endpoints, got, tc.want)
		}
	}
	if got := Classify(ctx, proposal("ok.example.org", 443, timeout), pol); got.Verdict != Reject || got.Reason != ReasonMultipleHosts {
		t.Fatalf("two-host proposal = %+v, want a rejection", got)
	}
	if got := Classify(ctx, proposal("timeout.example.org", 443, Endpoint{Host: "timeout.example.org", Port: 22}), pol); got.Verdict != Reject ||
		got.Reason != ReasonPortNotAllowed {
		t.Fatalf("deferred port + refused port = %+v, want a rejection", got)
	}
	// A canceled context never approves: the proposal waits.
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	pol.Resolver = resolverFunc(func(ctx context.Context, _ string) ([]net.IPAddr, error) { return nil, ctx.Err() })
	if got := Classify(canceled, proposal("cdn.example.org", 443), pol); got.Verdict != Defer || got.Reason != ReasonLookupFailed {
		t.Fatalf("Classify without DNS = %+v", got)
	}
}

// A proposal for this machine's own address (live: the host's LAN IP on a
// dev-server port) is rejected with a reason that says how to reach the
// service instead, so the feed line gives the user the way on; a name that
// resolves to this machine gets the same way on.
func TestOwnAddressRejectionNamesHostPort(t *testing.T) {
	pol := testPolicy(effOpen)
	pol.Resolver = newResolver().set("dev.example.org", testOwnV4)
	d := Classify(context.Background(), proposal(testOwnV4, 38590), pol)
	if d.Verdict != Reject || !strings.Contains(d.Message, "belongs to this machine") ||
		!strings.Contains(d.Message, "--host-port 38590") || !strings.Contains(d.Message, "host.openshell.internal:38590") {
		t.Fatalf("decision = %+v", d)
	}
	if d = Classify(context.Background(), proposal("dev.example.org", 443), pol); d.Verdict != Reject || d.Reason != ReasonResolvesToHost ||
		!strings.Contains(d.Message, "--host-port 443") {
		t.Fatalf("decision for a name = %+v", d)
	}
}

func TestContentDigest(t *testing.T) {
	a := liveChunk("www.example.net", 443)
	b := liveChunk("www.example.net", 443)
	b.ID, b.ReviewToken, b.HitCount = "other", "other-token", 7
	b.ProposedRule.Endpoints[0].Rules = []v1.L7Rule{}
	b.CurrentEffectivePolicy = nil
	if ContentDigest(a) != ContentDigest(b) || RuleDigest(a) != RuleDigest(b) {
		t.Fatal("the same proposal hashed differently")
	}
	b.SecurityNotes = "downloads executables"
	if ContentDigest(a) == ContentDigest(b) || RuleDigest(a) != RuleDigest(b) {
		t.Fatal("security notes must change the content digest only")
	}
	for name, edit := range map[string]func(*openshell.PolicyChunk){
		"an added port":      func(c *openshell.PolicyChunk) { c.ProposedRule.Endpoints[0].Ports = []uint32{443, 22} },
		"a different binary": func(c *openshell.PolicyChunk) { c.ProposedRule.Binaries = []v1.PolicyNetworkBinary{{Path: "/bin/sh"}} },
	} {
		c := liveChunk("www.example.net", 443)
		if edit(&c); RuleDigest(a) == RuleDigest(c) {
			t.Errorf("%s did not change the digest", name)
		}
	}
}

func TestFromChunk(t *testing.T) {
	p := FromChunk("box", openshell.PolicyChunk{
		ID: "chunk-1", ReviewToken: "rt", RuleName: "allow_pypi", Binary: "/usr/bin/python3", HitCount: 3, SecurityNotes: "  ",
		ProposedRule: &v1.NetworkPolicyRule{Endpoints: []v1.PolicyNetworkEndpoint{
			{Host: "pypi.org", Port: 443, Ports: []uint32{443, 80}, Protocol: "rest"},
			{Host: "files.pythonhosted.org"},
		}},
	})
	if p.ChunkID != "chunk-1" || p.Binary != "/usr/bin/python3" || p.HitCount != 3 || p.SecurityNotes != "" || p.RuleName != "allow_pypi" ||
		len(p.Unsupported) != 1 || !strings.Contains(p.Unsupported[0], "rest") {
		t.Fatalf("proposal = %+v", p)
	}
	if want := []Endpoint{{"pypi.org", 443, "rest"}, {"pypi.org", 80, "rest"}, {"files.pythonhosted.org", 0, ""}}; fmt.Sprint(p.Endpoints) != fmt.Sprint(want) {
		t.Fatalf("endpoints = %+v, want %+v", p.Endpoints, want)
	}
}

func TestCheckApprovalAndUnblock(t *testing.T) {
	if err := CheckApproval(effNoUnblock, "ok.example.org", 443, true); err == nil {
		t.Fatal("approve-always allowed without allow_unblock")
	}
	if err := CheckApproval(effNoUnblock, "ok.example.org", 443, false); err != nil {
		t.Fatalf("approve once refused: %v", err)
	}
	if err := CheckUnblock(effNoUnblock, "webhook.site"); err == nil {
		t.Fatal("unblock allowed without allow_unblock")
	}
	if err := CheckUnblock(effOpen, "webhook.site"); err != nil {
		t.Fatalf("unblock refused: %v", err)
	}
	// #946: an administrator's domain covers its subdomains, for approvals
	// and unblocks alike, and the refusal names the organization's list.
	domain := effective(t, func(o *config.OpenShellConfig) { o.Admin.EgressBlock = []string{"example.net"} }, packs.Flags{})
	for _, host := range []string{"example.net", "www.example.net", "a.b.example.net"} {
		for _, always := range []bool{false, true} {
			if err := CheckApproval(domain, host, 443, always); err == nil || !strings.Contains(err.Error(), "on your organization's blocklist") {
				t.Errorf("CheckApproval(%s, always=%t) = %v, want the organization's blocklist", host, always, err)
			}
		}
		if err := CheckUnblock(domain, host); err == nil || !strings.Contains(err.Error(), "on your organization's blocklist") {
			t.Errorf("CheckUnblock(%s) = %v, want the organization's blocklist", host, err)
		}
	}
	if err := CheckApproval(domain, "myexample.net", 443, false); err != nil {
		t.Errorf("a name that only ends like the domain was refused: %v", err)
	}
	for host, want := range map[string]bool{
		"host.openshell.internal": true, "HOST.OpenShell.Internal.": true, "localhost": true, "app.localhost": true,
		"127.0.0.1": true, "[::1]": true, "0.0.0.0": true, "example.org": false, "10.0.0.1": false,
	} {
		if got := IsHostLocal(host); got != want {
			t.Errorf("IsHostLocal(%q) = %v, want %v", host, got, want)
		}
	}
}
