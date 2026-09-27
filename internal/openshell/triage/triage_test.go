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
	"net"
	"strconv"
	"strings"
	"sync"
	"testing"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"
	"github.com/NVIDIA/OpenShell/sdk/go/openshell/v1/types"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
)

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

// testResolver answers every test that does not bring its own.
var testResolver = newResolver()

func testPolicy(eff *packs.Effective) Policy {
	return Policy{Effective: eff, Resolver: testResolver, AgentProposals: true}
}

func effective(t *testing.T, edit func(*config.OpenShellConfig), flags packs.Flags) *packs.Effective {
	t.Helper()
	cfg := &config.Config{}
	cfg.Gateway.APIPort = 18970
	cfg.Guardrail.Port = 4000
	if edit != nil {
		edit(&cfg.OpenShell)
	}
	eff, _, err := packs.Resolve(cfg, flags)
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

func proposal(host string, port int) Proposal {
	return Proposal{Sandbox: "dc-claude-app-1a2b", ChunkID: "c1", ReviewToken: "rt", RuleName: ruleName(host, port),
		Endpoints: []Endpoint{{Host: host, Port: port}}}
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
	open := effective(t, nil, packs.Flags{})
	balanced := effective(t, nil, packs.Flags{Profile: "balanced"})
	strict := effective(t, nil, packs.Flags{Profile: "strict"})
	withAllow := effective(t, func(o *config.OpenShellConfig) { o.Egress.Allow = []string{"api.internal-tools.example"} }, packs.Flags{Profile: "balanced"})
	noUnblock := effective(t, func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, packs.Flags{})
	adminBlock := effective(t, func(o *config.OpenShellConfig) { o.Admin.EgressBlock = []string{"*.corp-blocked.example"} }, packs.Flags{})
	noHostPorts := effective(t, func(o *config.OpenShellConfig) { o.Admin.AllowHostPorts = boolPtr(false) }, packs.Flags{})

	for _, tc := range []struct {
		name    string
		eff     *packs.Effective
		p       Proposal
		verdict Verdict
		reason  Reason
		kind    string
		risky   bool
	}{
		{"open network approves a public name", open, proposal("registry.example.org", 443), Approve, ReasonAutoMode, KindNetworkRule, false},
		{"open network approves port 80", open, proposal("docs.example.org", 80), Approve, ReasonAutoMode, KindNetworkRule, false},
		{"blocklisted host is rejected", open, proposal("webhook.site", 443), Reject, ReasonBlocklisted, KindNetworkRule, false},
		{"feed subdomain is rejected", open, proposal("x.pastebin.com", 443), Reject, ReasonBlocklisted, KindNetworkRule, false},
		{"admin blocklist is rejected", adminBlock, proposal("a.corp-blocked.example", 443), Reject, ReasonAdmin, KindNetworkRule, false},
		{"metadata address is rejected", open, proposal("169.254.169.254", 80), Reject, ReasonPolicy, KindNetworkRule, false},
		{"metadata name is rejected", open, proposal("metadata.google.internal", 80), Reject, ReasonPolicy, KindNetworkRule, false},
		{"public IP literal is rejected", open, proposal("93.184.216.34", 443), Reject, ReasonIPLiteral, KindNetworkRule, true},
		{"high port is rejected", open, proposal("db.example.org", 5432), Reject, ReasonPortNotAllowed, KindNetworkRule, false},
		{"ssh port is rejected", open, proposal("github.com", 22), Reject, ReasonPortNotAllowed, KindNetworkRule, false},
		{"wildcard is rejected", open, proposal("*.example.org", 443), Reject, ReasonWildcard, KindNetworkRule, false},
		{"empty host is rejected", open, proposal("", 443), Reject, ReasonInvalid, KindNetworkRule, false},
		{"no endpoints is rejected", open, Proposal{Sandbox: "s", ChunkID: "c"}, Reject, ReasonNoEndpoints, KindNetworkRule, false},
		{"host port asks", open, proposal("host.openshell.internal", 5432), Ask, ReasonHostLocal, KindHostPort, true},
		{"localhost asks", open, proposal("127.0.0.1", 3000), Ask, ReasonHostLocal, KindHostPort, true},
		{"ingress port is rejected", open, proposal("host.openshell.internal", 18971), Reject, ReasonPolicy, KindHostPort, true},
		{"main API port is rejected", open, proposal("host.openshell.internal", 18970), Reject, ReasonPolicy, KindHostPort, true},
		{"openshell gateway port is rejected", open, proposal("host.openshell.internal", 17670), Reject, ReasonPolicy, KindHostPort, true},
		{"host port without a port is rejected", open, proposal("host.openshell.internal", 0), Reject, ReasonInvalid, KindHostPort, true},
		{"admin disallows host ports", noHostPorts, proposal("host.openshell.internal", 5432), Reject, ReasonAdmin, KindHostPort, true},
		{"private address asks", open, proposal("10.1.2.3", 443), Ask, ReasonPrivateNetwork, KindNetworkRule, true},
		{"cgnat address asks", open, proposal("100.64.1.1", 443), Ask, ReasonPrivateNetwork, KindNetworkRule, true},
		{"private refused without unblock", noUnblock, proposal("10.1.2.3", 443), Reject, ReasonAdmin, KindNetworkRule, false},
		{"feed refused without unblock", noUnblock, proposal("webhook.site", 443), Reject, ReasonAdmin, KindNetworkRule, false},
		{"balanced asks unknown hosts", balanced, proposal("unknown.example.org", 443), Ask, ReasonNotAllowlisted, KindNetworkRule, false},
		{"balanced approves allowed hosts", withAllow, proposal("api.internal-tools.example", 443), Approve, ReasonAllowed, KindNetworkRule, false},
		{"strict asks", strict, proposal("unknown.example.org", 443), Ask, ReasonManual, KindNetworkRule, false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			got := Classify(context.Background(), tc.p, testPolicy(tc.eff))
			if got.Verdict != tc.verdict || got.Reason != tc.reason || got.Kind != tc.kind || got.Risky != tc.risky {
				t.Fatalf("Classify = %+v, want verdict %s reason %s kind %s risky %v", got, tc.verdict, tc.reason, tc.kind, tc.risky)
			}
			if got.Message == "" {
				t.Fatal("decision without a message")
			}
		})
	}
}

func TestClassifyWorstEndpointWins(t *testing.T) {
	open := effective(t, nil, packs.Flags{})
	p := Proposal{Sandbox: "s", ChunkID: "c", RuleName: "allow_multi", Endpoints: []Endpoint{
		{Host: "ok.example.org", Port: 443}, {Host: "host.openshell.internal", Port: 8080}, {Host: "webhook.site", Port: 443},
	}}
	if got := Classify(context.Background(), p, testPolicy(open)); got.Verdict != Reject || got.Host != "webhook.site" {
		t.Fatalf("mixed proposal = %+v, want the blocklisted endpoint to reject it", got)
	}
	p.Endpoints = p.Endpoints[:2]
	if got := Classify(context.Background(), p, testPolicy(open)); got.Verdict != Ask || got.Kind != KindHostPort {
		t.Fatalf("mixed proposal = %+v, want the host port to ask", got)
	}
}

func TestClassifySecurityNotesAsk(t *testing.T) {
	open := effective(t, nil, packs.Flags{})
	p := proposal("cdn.example.org", 443)
	p.SecurityNotes = "binary downloads executables"
	got := Classify(context.Background(), p, testPolicy(open))
	if got.Verdict != Ask || got.Reason != ReasonSecurityFlagged {
		t.Fatalf("flagged proposal = %+v, want an ask", got)
	}
}

func TestClassifyAgentProposalsOff(t *testing.T) {
	open := effective(t, nil, packs.Flags{})
	got := Classify(context.Background(), proposal("ok.example.org", 443), Policy{Effective: open, Resolver: testResolver})
	if got.Verdict != Reject || got.Reason != ReasonAgentProposalOff {
		t.Fatalf("proposals off = %+v", got)
	}
}

func TestClassifyAllowedIPs(t *testing.T) {
	open := effective(t, nil, packs.Flags{})
	noUnblock := effective(t, func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, packs.Flags{})
	for _, tc := range []struct {
		entry   string
		eff     *packs.Effective
		verdict Verdict
		reason  Reason
	}{
		{"169.254.169.254/32", open, Reject, ReasonPolicy},
		{"127.0.0.0/8", open, Reject, ReasonPolicy},
		{"0.0.0.0/0", open, Reject, ReasonPolicy},
		{"198.18.0.2", open, Reject, ReasonPolicy},
		{"not-an-ip", open, Reject, ReasonInvalid},
		// A wide range that contains loopback or metadata is refused even
		// though its base address is public.
		{"64.0.0.0/2", open, Reject, ReasonPolicy},
		{"100.64.0.0/10", open, Reject, ReasonPolicy}, // holds 100.100.100.200
		{"::/0", open, Reject, ReasonPolicy},
		{"fd00:ec2::254", open, Reject, ReasonPolicy},
		// Private, CGNAT and ULA ranges, and ranges holding them, ask.
		{"10.0.0.0/8", open, Ask, ReasonPrivateNetwork},
		{"10.0.5.20", open, Ask, ReasonPrivateNetwork},
		{"8.0.0.0/5", open, Ask, ReasonPrivateNetwork},
		{"100.64.0.0/16", open, Ask, ReasonPrivateNetwork},
		{"fc00::/8", open, Ask, ReasonPrivateNetwork},
		{"::ffff:192.168.0.0/112", open, Ask, ReasonPrivateNetwork},
		// Without allow_unblock the administrator refuses private ranges.
		{"10.0.0.0/8", noUnblock, Reject, ReasonAdmin},
		{"93.184.216.0/24", open, Approve, ReasonAutoMode},
		{"93.184.216.0/24", noUnblock, Approve, ReasonAutoMode},
		// This machine's own addresses (see hostaddrs_test.go) are never
		// opened, even in a public range; the rest of its public subnets
		// is the user's network. With allowed_ips set OpenShell skips its
		// own private-address check, so a name that rebinds to one of them
		// later would reach the host.
		{testOwnV4, open, Reject, ReasonResolvesToHost},
		{"::ffff:" + testOwnV4, open, Reject, ReasonResolvesToHost},
		{"185.199.0.0/16", open, Reject, ReasonResolvesToHost},
		{"184.0.0.0/7", open, Reject, ReasonResolvesToHost},
		{testOwnV6, open, Reject, ReasonResolvesToHost},
		{"2a00:1450::/32", open, Reject, ReasonResolvesToHost},
		{"185.199.9.200", open, Ask, ReasonPrivateNetwork},
		{"185.199.9.128/25", open, Ask, ReasonPrivateNetwork},
		{"2a00:1450:9::1", open, Ask, ReasonPrivateNetwork},
		{"185.199.9.200", noUnblock, Reject, ReasonAdmin},
		{"185.199.10.0/24", open, Approve, ReasonAutoMode},
	} {
		t.Run(tc.entry, func(t *testing.T) {
			p := proposal("my-cdn.attacker.example", 443)
			p.AllowedIPs = []string{tc.entry}
			got := Classify(context.Background(), p, testPolicy(tc.eff))
			if got.Verdict != tc.verdict || got.Reason != tc.reason {
				t.Fatalf("allowed_ips %s = %+v, want %s %s", tc.entry, got, tc.verdict, tc.reason)
			}
			if tc.verdict == Ask && (!got.Risky || !strings.Contains(got.Message, tc.entry) || got.Host != "my-cdn.attacker.example") {
				t.Fatalf("private allowed_ips ask = %+v", got)
			}
			// The operator's decision runs the same checks.
			if err := CheckProposal(tc.eff, p, false); (err != nil) != (tc.verdict == Reject) {
				t.Fatalf("CheckProposal(%s) = %v", tc.entry, err)
			}
		})
	}
}

func TestClassifyRuleShape(t *testing.T) {
	open := effective(t, nil, packs.Flags{})
	pol := testPolicy(open)
	if got := Classify(context.Background(), FromChunk("box", liveChunk("www.example.net", 443)), pol); got.Verdict != Approve || got.Reason != ReasonAutoMode {
		t.Fatalf("OpenShell's own proposal = %+v, want an automatic approval (the open pack uses approvals: auto)", got)
	}
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
	} {
		t.Run(name, func(t *testing.T) {
			c := liveChunk("www.example.net", 443)
			edit(&c)
			got := Classify(context.Background(), FromChunk("box", c), pol)
			if got.Verdict != Reject || got.Reason != ReasonRuleShape {
				t.Fatalf("Classify = %+v, want an unsupported-rule rejection", got)
			}
		})
	}
	// Merging into an earlier plain approval of the same rule is fine.
	c := liveChunk("www.example.net", 443)
	c.CurrentEffectivePolicy.NetworkPolicies[c.RuleName] = v1.NetworkPolicyRule{Endpoints: []v1.PolicyNetworkEndpoint{{Host: "www.example.net", Port: 443}}}
	if got := Classify(context.Background(), FromChunk("box", c), pol); got.Verdict != Approve {
		t.Fatalf("merge into a plain rule = %+v", got)
	}
}

// TestClassifyUnblocked: triage asks the sandbox's own proxy decider, so
// the sandbox's unblocks lift what they lift in the proxy (the feed, the
// allowlist, open-mode IP literals) for that sandbox only, and never the
// administrator's lists, the block list or the private-network checks.
func TestClassifyUnblocked(t *testing.T) {
	ctx := context.Background()
	balanced := effective(t, nil, packs.Flags{Profile: "balanced"})
	open := effective(t, nil, packs.Flags{})
	adminBlock := effective(t, func(o *config.OpenShellConfig) { o.Admin.EgressBlock = []string{"webhook.site"} }, packs.Flags{})
	userBlock := effective(t, func(o *config.OpenShellConfig) { o.Egress.Block = []string{"webhook.site"} }, packs.Flags{})
	unblocks, err := egress.NewMemoryUnblocks(
		egress.Unblock{Pattern: "api.internal-tools.example"},
		egress.Unblock{Pattern: "webhook.site"},
		egress.Unblock{Pattern: "10.1.2.3"},
		egress.Unblock{Pattern: "93.184.216.34", SandboxID: "sb-a"},
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
	pol := withUnblocks(balanced, "sb-a")
	if got := Classify(ctx, proposal("api.internal-tools.example", 443), pol); got.Verdict != Approve || got.Reason != ReasonAllowed {
		t.Fatalf("unblocked host = %+v", got)
	}
	// An unblock lifts the blocklist feed, as in the proxy.
	if got := Classify(ctx, proposal("webhook.site", 443), pol); got.Verdict != Approve || got.Reason != ReasonAllowed {
		t.Fatalf("unblocked feed host = %+v", got)
	}
	// A sandbox's own unblock of an IP literal opens it for that sandbox only.
	if got := Classify(ctx, proposal("93.184.216.34", 443), withUnblocks(open, "sb-a")); got.Verdict != Approve || !got.Risky {
		t.Fatalf("unblocked IP literal = %+v", got)
	}
	if got := Classify(ctx, proposal("93.184.216.34", 443), withUnblocks(open, "sb-b")); got.Verdict != Reject || got.Reason != ReasonIPLiteral {
		t.Fatalf("another sandbox's unblock applied: %+v", got)
	}
	// Without the sandbox's decider, only the policy decides.
	if got := Classify(ctx, proposal("webhook.site", 443), testPolicy(balanced)); got.Verdict != Reject || got.Reason != ReasonBlocklisted {
		t.Fatalf("feed host without unblocks = %+v", got)
	}
	// It never lifts the administrator's blocklist, the block list or the
	// private checks.
	if got := Classify(ctx, proposal("webhook.site", 443), withUnblocks(adminBlock, "sb-a")); got.Verdict != Reject || got.Reason != ReasonAdmin {
		t.Fatalf("admin-blocked unblocked host = %+v", got)
	}
	if got := Classify(ctx, proposal("webhook.site", 443), withUnblocks(userBlock, "sb-a")); got.Verdict != Reject || got.Reason != ReasonPolicy {
		t.Fatalf("user-blocked unblocked host = %+v", got)
	}
	if got := Classify(ctx, proposal("10.1.2.3", 443), withUnblocks(adminBlock, "sb-a")); got.Verdict != Ask || got.Reason != ReasonPrivateNetwork {
		t.Fatalf("unblocked private address = %+v", got)
	}
}

// TestClassifyUnblockable: a rejection says whether an unblock would lift
// it exactly as the proxy does, so the feed offers unblocking only where
// it works.
func TestClassifyUnblockable(t *testing.T) {
	ctx := context.Background()
	open := effective(t, nil, packs.Flags{})
	noUnblock := effective(t, func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, packs.Flags{})
	blocked := effective(t, func(o *config.OpenShellConfig) { o.Egress.Block = []string{"drop.example.org"} }, packs.Flags{})
	for _, tc := range []struct {
		name        string
		eff         *packs.Effective
		host        string
		unblockable bool
	}{
		{"feed", open, "webhook.site", true},
		{"IP literal", open, "93.184.216.34", true},
		{"block list", blocked, "drop.example.org", false},
		{"feed without unblocking", noUnblock, "webhook.site", false},
		{"IP literal without unblocking", noUnblock, "93.184.216.34", false},
		{"metadata", open, "169.254.169.254", false},
	} {
		got := Classify(ctx, proposal(tc.host, 443), testPolicy(tc.eff))
		if got.Verdict != Reject || got.Unblockable != tc.unblockable {
			t.Errorf("%s: Classify(%s) = %+v, want a rejection with unblockable=%v", tc.name, tc.host, got, tc.unblockable)
		}
	}
}

// TestClassifyResolvesNames: a direct rule reaches whatever its name
// resolves to without the proxy's guard, so triage resolves every name and
// holds the answers to the proxy's dial-time rules.
func TestClassifyResolvesNames(t *testing.T) {
	ctx := context.Background()
	r := newResolver().
		set("rebind.example.org", "127.0.0.1").
		set("meta.example.org", "169.254.169.254").
		set("mixed.example.org", "93.184.216.34", "::1").
		set("lan.example.org", "10.0.0.5").
		set("db.corp-tools.example", "10.0.0.6").
		set("feedaddr.example.org", "93.184.216.35").
		set("gone.example.org")
	open := effective(t, nil, packs.Flags{})
	noUnblock := effective(t, func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, packs.Flags{})
	allowed := effective(t, func(o *config.OpenShellConfig) { o.Egress.Allow = []string{"db.corp-tools.example"} }, packs.Flags{})
	blockedAddr := effective(t, func(o *config.OpenShellConfig) { o.Egress.Block = []string{"93.184.216.35"} }, packs.Flags{})
	adminAddr := effective(t, func(o *config.OpenShellConfig) { o.Admin.EgressBlock = []string{"93.184.216.0/24"} }, packs.Flags{})
	balanced := effective(t, nil, packs.Flags{Profile: "balanced"})
	for _, tc := range []struct {
		name    string
		eff     *packs.Effective
		host    string
		verdict Verdict
		reason  Reason
	}{
		{"public answer", open, "cdn.example.org", Approve, ReasonAutoMode},
		{"loopback answer", open, "rebind.example.org", Reject, ReasonResolvesToHost},
		{"metadata answer", open, "meta.example.org", Reject, ReasonResolvesToHost},
		{"one bad answer among good ones", open, "mixed.example.org", Reject, ReasonResolvesToHost},
		{"private answer asks", open, "lan.example.org", Ask, ReasonPrivateNetwork},
		{"private answer when unblock is off", noUnblock, "lan.example.org", Reject, ReasonAdmin},
		{"private answer an exact allow entry opens", allowed, "db.corp-tools.example", Approve, ReasonAllowed},
		{"not-allowlisted name with a loopback answer", balanced, "rebind.example.org", Reject, ReasonResolvesToHost},
		{"blocked address answer", blockedAddr, "feedaddr.example.org", Reject, ReasonBlocklisted},
		{"admin-blocked address answer", adminAddr, "feedaddr.example.org", Reject, ReasonAdmin},
		{"no answer", open, "gone.example.org", Reject, ReasonUnresolved},
		{"intranet name asks without a lookup", open, "wiki.corp", Ask, ReasonPrivateNetwork},
	} {
		t.Run(tc.name, func(t *testing.T) {
			pol := testPolicy(tc.eff)
			pol.Resolver = r
			got := Classify(ctx, proposal(tc.host, 443), pol)
			if got.Verdict != tc.verdict || got.Reason != tc.reason {
				t.Fatalf("Classify(%s) = %+v, want %s %s", tc.host, got, tc.verdict, tc.reason)
			}
			if tc.verdict != Approve && !got.Risky {
				t.Fatalf("Classify(%s) = %+v, want it marked risky", tc.host, got)
			}
		})
	}
	r.mu.Lock()
	lookups := strings.Join(r.lookups, " ")
	r.mu.Unlock()
	if strings.Contains(lookups, "wiki.corp") {
		t.Fatalf("an intranet name was looked up: %s", lookups)
	}
	if !strings.Contains(lookups, "cdn.example.org.") {
		t.Fatalf("names are not looked up fully qualified: %s", lookups)
	}

	// Approved rules are re-checked the same way.
	pol := testPolicy(open)
	pol.Resolver = r
	if !ResolvesToHost(ctx, proposal("rebind.example.org", 443), pol) || ResolvesToHost(ctx, proposal("lan.example.org", 443), pol) ||
		ResolvesToHost(ctx, proposal("gone.example.org", 443), pol) || ResolvesToHost(ctx, proposal("host.openshell.internal", 5432), pol) {
		t.Fatal("ResolvesToHost misjudged an approved rule")
	}
	// A canceled context never approves: the proposal waits.
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	pol.Resolver = resolverFunc(func(ctx context.Context, _ string) ([]net.IPAddr, error) { return nil, ctx.Err() })
	if got := Classify(canceled, proposal("cdn.example.org", 443), pol); got.Verdict != Defer || got.Reason != ReasonLookupFailed {
		t.Fatalf("Classify without DNS = %+v", got)
	}
}

// TestClassifyDefersTransientLookups pins that only a name that does not
// exist or has no address is rejected as unresolved: a timeout or a
// temporary DNS failure defers the proposal (it stays pending and is
// decided later), and a deferral never hides a rejection or turns into an
// approval or an ask.
func TestClassifyDefersTransientLookups(t *testing.T) {
	ctx := context.Background()
	fail := map[string]error{
		"nx.example.org.":       &net.DNSError{Err: "no such host", Name: "nx.example.org", IsNotFound: true},
		"servfail.example.org.": &net.DNSError{Err: "server misbehaving", Name: "servfail.example.org", IsTemporary: true},
		"timeout.example.org.":  &net.DNSError{Err: "i/o timeout", Name: "timeout.example.org", IsTimeout: true},
		"refused.example.org.":  &net.DNSError{Err: "connection refused", Name: "refused.example.org"},
		"deadline.example.org.": context.DeadlineExceeded,
	}
	pol := testPolicy(effective(t, nil, packs.Flags{}))
	pol.Resolver = resolverFunc(func(ctx context.Context, name string) ([]net.IPAddr, error) {
		if err, ok := fail[name]; ok {
			return nil, err
		}
		if name == "empty.example.org." {
			return []net.IPAddr{}, nil
		}
		return testResolver.LookupIPAddr(ctx, name)
	})
	for _, tc := range []struct {
		host    string
		verdict Verdict
		reason  Reason
	}{
		{"nx.example.org", Reject, ReasonUnresolved},
		{"empty.example.org", Reject, ReasonUnresolved},
		{"servfail.example.org", Defer, ReasonLookupFailed},
		{"timeout.example.org", Defer, ReasonLookupFailed},
		{"refused.example.org", Defer, ReasonLookupFailed},
		{"deadline.example.org", Defer, ReasonLookupFailed},
	} {
		t.Run(tc.host, func(t *testing.T) {
			got := Classify(ctx, proposal(tc.host, 443), pol)
			if got.Verdict != tc.verdict || got.Reason != tc.reason {
				t.Fatalf("Classify(%s) = %+v, want %s %s", tc.host, got, tc.verdict, tc.reason)
			}
		})
	}
	// Endpoint order: a rejection anywhere wins over a deferral, and a
	// deferral wins over an ask or an approval.
	multi := func(hosts ...string) Proposal {
		p := proposal(hosts[0], 443)
		for _, h := range hosts[1:] {
			p.Endpoints = append(p.Endpoints, Endpoint{Host: h, Port: 443})
		}
		return p
	}
	if got := Classify(ctx, multi("timeout.example.org", "webhook.site"), pol); got.Verdict != Reject {
		t.Fatalf("deferred + blocklisted = %+v, want a rejection", got)
	}
	if got := Classify(ctx, multi("ok.example.org", "timeout.example.org"), pol); got.Verdict != Defer {
		t.Fatalf("approved + deferred = %+v, want a deferral", got)
	}
	if got := Classify(ctx, multi("wiki.corp", "timeout.example.org"), pol); got.Verdict != Defer {
		t.Fatalf("ask + deferred = %+v, want a deferral", got)
	}
}

type resolverFunc func(ctx context.Context, name string) ([]net.IPAddr, error)

func (f resolverFunc) LookupIPAddr(ctx context.Context, name string) ([]net.IPAddr, error) {
	return f(ctx, name)
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
	c := liveChunk("www.example.net", 443)
	c.ProposedRule.Endpoints[0].Ports = []uint32{443, 22}
	if RuleDigest(a) == RuleDigest(c) {
		t.Fatal("an added port did not change the digest")
	}
	d := liveChunk("www.example.net", 443)
	d.ProposedRule.Binaries = []v1.PolicyNetworkBinary{{Path: "/bin/sh"}}
	if RuleDigest(a) == RuleDigest(d) {
		t.Fatal("a different binary did not change the digest")
	}
}

func TestClassifyNilPolicy(t *testing.T) {
	if got := Classify(context.Background(), proposal("a.example", 443), Policy{AgentProposals: true}); got.Verdict != Reject {
		t.Fatalf("nil effective = %+v", got)
	}
}

func TestFromChunk(t *testing.T) {
	chunk := openshell.PolicyChunk{
		ID: "chunk-1", ReviewToken: "rt", RuleName: "allow_pypi", Binary: "/usr/bin/python3", HitCount: 3,
		SecurityNotes: "  ",
		ProposedRule: &v1.NetworkPolicyRule{
			Endpoints: []v1.PolicyNetworkEndpoint{
				{Host: "pypi.org", Port: 443, Ports: []uint32{443, 80}, Protocol: "rest"},
				{Host: "files.pythonhosted.org"},
			},
		},
	}
	p := FromChunk("box", chunk)
	if p.ChunkID != "chunk-1" || p.Binary != "/usr/bin/python3" || p.HitCount != 3 || p.SecurityNotes != "" {
		t.Fatalf("proposal = %+v", p)
	}
	want := []Endpoint{{"pypi.org", 443, "rest"}, {"pypi.org", 80, "rest"}, {"files.pythonhosted.org", 0, ""}}
	if p.RuleName != "allow_pypi" || len(p.Unsupported) != 1 || !strings.Contains(p.Unsupported[0], "rest") {
		t.Fatalf("rule name %q, unsupported %v", p.RuleName, p.Unsupported)
	}
	if len(p.Endpoints) != len(want) {
		t.Fatalf("endpoints = %+v", p.Endpoints)
	}
	for i := range want {
		if p.Endpoints[i] != want[i] {
			t.Fatalf("endpoint %d = %+v, want %+v", i, p.Endpoints[i], want[i])
		}
	}
}

func TestCheckApprovalAndUnblock(t *testing.T) {
	noUnblock := effective(t, func(o *config.OpenShellConfig) { o.Admin.AllowUnblock = boolPtr(false) }, packs.Flags{})
	if err := CheckApproval(noUnblock, "ok.example.org", 443, true); err == nil {
		t.Fatal("approve-always allowed without allow_unblock")
	}
	if err := CheckApproval(noUnblock, "ok.example.org", 443, false); err != nil {
		t.Fatalf("approve once refused: %v", err)
	}
	if err := CheckUnblock(noUnblock, "webhook.site"); err == nil {
		t.Fatal("unblock allowed without allow_unblock")
	}
	open := effective(t, nil, packs.Flags{})
	if err := CheckUnblock(open, "webhook.site"); err != nil {
		t.Fatalf("unblock refused: %v", err)
	}
}

func TestHostHelpers(t *testing.T) {
	for host, want := range map[string]bool{
		"host.openshell.internal": true, "HOST.OpenShell.Internal.": true, "localhost": true, "app.localhost": true,
		"127.0.0.1": true, "[::1]": true, "0.0.0.0": true, "example.org": false, "10.0.0.1": false,
	} {
		if got := IsHostLocal(host); got != want {
			t.Errorf("IsHostLocal(%q) = %v, want %v", host, got, want)
		}
	}
}
