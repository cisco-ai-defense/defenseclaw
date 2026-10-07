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

package packs

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/openshell/egress"
)

// CheckEgress is the egress decider's verdict (the proxy's), with the
// setting behind it named.
func TestCheckEgressMatchesTheDecider(t *testing.T) {
	root := t.TempDir()
	writePack(t, root, "team", "version: 1\nname: team\nextends: balanced\negress: {allow: [artifacts.example.com], block: [bad.example.com]}\n")
	cfg := testConfig(func(o *config.OpenShellConfig) {
		o.PackDir = root
		o.Egress.Block = []string{"mine.example.org"}
		o.Admin.EgressBlock = []string{"corp-banned.example"}
	})
	rp := mustRepoPolicy(t, "version: 1\negress: {block: [repo-banned.example.com]}\n")
	for _, tc := range []struct {
		pack, host string
		port       int
		allowed    bool
		rule       EgressRule
		source     string
	}{
		{"team", "artifacts.example.com", 443, true, RuleAllow, "pack team"},
		{"team", "registry.npmjs.org", 443, true, RuleAllow, "DefenseClaw's curated allowlist"},
		{"team", "bad.example.com", 443, false, RuleBlock, "pack team"},
		{"team", "mine.example.org", 443, false, RuleBlock, "openshell.egress.block"},
		{"team", "repo-banned.example.com", 443, false, RuleBlock, RepoPolicyConstraint},
		{"team", "www.corp-banned.example", 443, false, RuleAdminBlock, "openshell.admin.egress_block"},
		{"team", "unlisted.example.com", 443, false, RuleNetworkAllowlist, "network.mode allowlist (profile balanced)"},
		{"team", "artifacts.example.com", 8080, false, RulePort, "egress.ports 80, 443 (pack team)"},
		{"team", "127.0.0.1", 443, false, RuleHostInternal, "defenseclaw guard"},
		{"open", "pastebin.com", 443, false, RuleFeed, "blocklist feed (entry Pastebin)"},
		{"open", "unlisted.example.com", 0, true, RuleNetworkOpen, "network.mode open"},
		{"strict", "registry.npmjs.org", 443, false, RuleNetworkDeny, "network.mode deny"},
	} {
		eff, _ := mustResolve(t, cfg, Flags{Pack: tc.pack, RepoPolicy: rp})
		got := eff.CheckEgress(nil, policyProbe, tc.host, tc.port)
		if got.Allowed != tc.allowed || got.Rule != tc.rule || !strings.Contains(got.Source, tc.source) {
			t.Fatalf("%s %s:%d = %+v, want allowed=%v rule %s source %q", tc.pack, tc.host, tc.port, got, tc.allowed, tc.rule, tc.source)
		}
		// One implementation: the policy check, the proxy's decider and the
		// fixture's expectation agree.
		if dec := eff.DecideEgress(tc.host, tc.port); dec != got.EgressDecision {
			t.Fatalf("%s: DecideEgress %+v, CheckEgress %+v", tc.host, dec, got.EgressDecision)
		}
		d, err := eff.EgressDecider(nil)
		if err != nil {
			t.Fatal(err)
		}
		if raw := d.Decide(policyProbe, tc.host, max(tc.port, 443)); eff.NetworkMode != NetworkDeny && tc.port != 0 && raw.Allowed != got.Allowed {
			t.Fatalf("%s: decider %+v, check %+v", tc.host, raw, got)
		}
	}

	// A sandbox's own decider carries its unblocks.
	eff, _ := mustResolve(t, cfg, Flags{Pack: "open"})
	unblocks, err := egress.NewMemoryUnblocks(egress.Unblock{Pattern: "pastebin.com", SandboxID: "sb-1"})
	if err != nil {
		t.Fatal(err)
	}
	d, err := eff.EgressDecider(unblocks)
	if err != nil {
		t.Fatal(err)
	}
	if got := eff.CheckEgress(d, egress.Principal{BindingID: "b", SandboxID: "sb-1"}, "pastebin.com", 443); !got.Allowed || got.Rule != RuleUnblock {
		t.Fatalf("unblocked = %+v", got)
	}
	if got := eff.CheckEgress(d, egress.Principal{BindingID: "b", SandboxID: "sb-2"}, "pastebin.com", 443); got.Allowed {
		t.Fatalf("another sandbox's unblock applied: %+v", got)
	}
}

func TestParseEgressFixture(t *testing.T) {
	cases, err := ParseEgressFixture([]byte(`
- {host: registry.npmjs.org, port: 443, binary: /usr/bin/node, expect: allow}
- {host: pastebin.com, expect: block, rule: feed}
`), "fixture.yaml")
	if err != nil || len(cases) != 2 || cases[0].Binary != "/usr/bin/node" || cases[1].Port != 0 || cases[1].Rule != "feed" {
		t.Fatalf("cases %+v, %v", cases, err)
	}
	if !cases[1].Matches(EgressDecision{Rule: RuleFeed}) || cases[1].Matches(EgressDecision{Rule: RuleBlock}) ||
		cases[0].Matches(EgressDecision{Rule: RuleAllow}) || !cases[0].Matches(EgressDecision{Allowed: true, Rule: RuleNetworkOpen}) {
		t.Fatal("Matches")
	}
	json, err := ParseEgressFixture([]byte(`[{"host": "example.org", "port": 80, "expect": "block"}]`), "fixture.json")
	if err != nil || len(json) != 1 || json[0].Port != 80 {
		t.Fatalf("json fixture %+v, %v", json, err)
	}
	for doc, code := range map[string]string{
		"[]":                               "invalid_value",
		"- {host: a.example}":              "missing_field",
		"- {host: a.example, expect: yes}": "invalid_value",
		"- {host: a.example, expect: allow, rule: maybe}":                         "invalid_value",
		"- {host: a.example, expect: allow, port: 70000}":                         "invalid_value",
		"- {host: a.example, expect: allow, color: blue}":                         "unknown_field",
		"- {host: a.example, expect: allow, port: \"443\"}":                       "yaml_type",
		"{host: a.example, expect: allow}":                                        "yaml_type",
		"- " + strings.Repeat("x", MaxFixtureBytes):                               "too_large",
		strings.Repeat("- {host: a.example, expect: allow}\n", MaxFixtureCases+1): "invalid_value",
	} {
		_, err := ParseEgressFixture([]byte(doc), "f")
		wantPackError(t, err, code, "")
		if !strings.HasPrefix(err.Error(), "egress fixture f") {
			t.Errorf("%q: the error does not name the fixture: %v", doc, err)
		}
	}
}
