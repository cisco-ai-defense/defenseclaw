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
	"strings"
	"testing"

	v1 "github.com/NVIDIA/OpenShell/sdk/go/openshell/v1"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell"
	"github.com/defenseclaw/defenseclaw/internal/openshell/packs"
)

func boolPtr(v bool) *bool { return &v }

// testFeed blocks the hosts the builtin feed would, for the test's purposes.
func testFeed(feeds []string, host string) (string, bool) {
	for _, f := range feeds {
		if f == packs.FeedBuiltin && (host == "webhook.site" || strings.HasSuffix(host, ".pastebin.com")) {
			return "exfil:" + host, true
		}
	}
	return "", false
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

func proposal(host string, port int) Proposal {
	return Proposal{Sandbox: "dc-claude-app-1a2b", ChunkID: "c1", ReviewToken: "rt", Endpoints: []Endpoint{{Host: host, Port: port, Protocol: "rest"}}}
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
		{"open network approves a public name", open, proposal("registry.example.org", 443), Approve, ReasonOpenNetwork, KindNetworkRule, false},
		{"open network approves port 80", open, proposal("docs.example.org", 80), Approve, ReasonOpenNetwork, KindNetworkRule, false},
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
			got := Classify(tc.p, Policy{Effective: tc.eff, Feed: testFeed, AgentProposals: true})
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
	p := Proposal{Sandbox: "s", ChunkID: "c", Endpoints: []Endpoint{
		{Host: "ok.example.org", Port: 443}, {Host: "host.openshell.internal", Port: 8080}, {Host: "webhook.site", Port: 443},
	}}
	if got := Classify(p, Policy{Effective: open, Feed: testFeed, AgentProposals: true}); got.Verdict != Reject || got.Host != "webhook.site" {
		t.Fatalf("mixed proposal = %+v, want the blocklisted endpoint to reject it", got)
	}
	p.Endpoints = p.Endpoints[:2]
	if got := Classify(p, Policy{Effective: open, Feed: testFeed, AgentProposals: true}); got.Verdict != Ask || got.Kind != KindHostPort {
		t.Fatalf("mixed proposal = %+v, want the host port to ask", got)
	}
}

func TestClassifySecurityNotesAsk(t *testing.T) {
	open := effective(t, nil, packs.Flags{})
	p := proposal("cdn.example.org", 443)
	p.SecurityNotes = "binary downloads executables"
	got := Classify(p, Policy{Effective: open, Feed: testFeed, AgentProposals: true})
	if got.Verdict != Ask || got.Reason != ReasonSecurityFlagged {
		t.Fatalf("flagged proposal = %+v, want an ask", got)
	}
}

func TestClassifyAgentProposalsOff(t *testing.T) {
	open := effective(t, nil, packs.Flags{})
	got := Classify(proposal("ok.example.org", 443), Policy{Effective: open, Feed: testFeed})
	if got.Verdict != Reject || got.Reason != ReasonAgentProposalOff {
		t.Fatalf("proposals off = %+v", got)
	}
}

func TestClassifyAllowedIPs(t *testing.T) {
	open := effective(t, nil, packs.Flags{})
	for _, entry := range []string{"169.254.169.254/32", "127.0.0.0/8", "0.0.0.0/0", "198.18.0.2", "not-an-ip"} {
		p := proposal("ok.example.org", 443)
		p.AllowedIPs = []string{entry}
		if got := Classify(p, Policy{Effective: open, Feed: testFeed, AgentProposals: true}); got.Verdict != Reject {
			t.Fatalf("allowed_ips %s = %+v, want a rejection", entry, got)
		}
	}
	p := proposal("ok.example.org", 443)
	p.AllowedIPs = []string{"203.0.113.0/24"}
	if got := Classify(p, Policy{Effective: open, Feed: testFeed, AgentProposals: true}); got.Verdict != Approve {
		t.Fatalf("public allowed_ips = %+v, want approval", got)
	}
}

func TestClassifyNilPolicy(t *testing.T) {
	if got := Classify(proposal("a.example", 443), Policy{AgentProposals: true}); got.Verdict != Reject {
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
	if err := CheckApproval(noUnblock, "ok.example.org", 443, true, testFeed); err == nil {
		t.Fatal("approve-always allowed without allow_unblock")
	}
	if err := CheckApproval(noUnblock, "ok.example.org", 443, false, testFeed); err != nil {
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
