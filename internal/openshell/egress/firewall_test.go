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

package egress

import (
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/firewall"
)

func TestFirewallBlockPatterns(t *testing.T) {
	cfg := &firewall.FirewallConfig{Rules: []firewall.Rule{
		{Name: "metadata", Direction: "outbound", Protocol: "tcp", Destination: "169.254.169.254", Action: "deny"},
		{Name: "host", Destination: "Exfil.Example.com", Action: "DENY"},
		{Name: "wildcard", Protocol: "any", Destination: "*.bad.example.net", Action: "deny"},
		{Name: "cidr", Destination: "8.8.4.0/24", Action: "deny"},
		{Name: "dup", Destination: "exfil.example.com", Action: "deny"},
		{Name: "allow rule", Destination: "ok.example.com", Action: "allow"},
		{Name: "udp only", Protocol: "udp", Destination: "dns.example.com", Action: "deny"},
		{Name: "inbound", Direction: "inbound", Destination: "in.example.com", Action: "deny"},
		{Name: "no destination", Port: 22, Action: "deny"},
		{Name: "ssh only", Destination: "ssh.example.com", Port: 22, Action: "deny"},
		{Name: "https", Destination: "tls.example.com", Port: 443, Action: "deny"},
		{Name: "range", Destination: "range.example.com", PortRange: "400-500", Action: "deny"},
		{Name: "colon range", Destination: "colon.example.com", PortRange: "1:79", Action: "deny"},
		{Name: "bad range", Destination: "odd.example.com", PortRange: "web", Action: "deny"},
		{Name: "bad destination", Destination: "a.*.example.com", Action: "deny"},
	}}
	got := FirewallBlockPatterns(cfg, nil)
	want := []string{"169.254.169.254", "exfil.example.com", "*.bad.example.net", "8.8.4.0/24", "tls.example.com", "range.example.com", "odd.example.com"}
	if !slices.Equal(got, want) {
		t.Errorf("FirewallBlockPatterns = %v\nwant %v", got, want)
	}
	if got := FirewallBlockPatterns(cfg, []int{22}); !slices.Contains(got, "ssh.example.com") || slices.Contains(got, "tls.example.com") {
		t.Errorf("port-scoped rules with ports [22] = %v", got)
	}
	if FirewallBlockPatterns(nil, nil) != nil {
		t.Error("nil config produced patterns")
	}

	// The output is always accepted by the Decider.
	d := mustDecider(t, DeciderOptions{Block: got})
	checkDecision(t, d, testPrincipal, "x.bad.example.net", 443, decisionWant{category: CategoryOperatorBlock, source: SourceOperator})

	// The shipped default firewall config converts cleanly. It denies by
	// default and allowlists DefenseClaw's own endpoints; neither the
	// default action nor the allowlist carries over to sandboxes.
	def := firewall.DefaultFirewallConfig()
	got = FirewallBlockPatterns(def, nil)
	if !slices.Contains(got, "169.254.169.254") {
		t.Errorf("default firewall config = %v", got)
	}
	for _, host := range slices.Concat(def.Allowlist.Domains, def.Allowlist.IPs) {
		if slices.Contains(got, host) {
			t.Errorf("allowlisted %s became a sandbox block pattern", host)
		}
	}
	denyAll := &firewall.FirewallConfig{DefaultAction: "deny", Allowlist: firewall.AllowlistConfig{Domains: []string{"api.github.com"}}}
	if got := FirewallBlockPatterns(denyAll, nil); len(got) != 0 {
		t.Errorf("default_action deny with an allowlist = %v, want no patterns", got)
	}
}

func TestParsePortRange(t *testing.T) {
	for in, want := range map[string][2]int{"443": {443, 443}, "1000-2000": {1000, 2000}, " 80 : 90 ": {80, 90}} {
		lo, hi, ok := parsePortRange(in)
		if !ok || lo != want[0] || hi != want[1] {
			t.Errorf("parsePortRange(%q) = %d, %d, %v", in, lo, hi, ok)
		}
	}
	for _, in := range []string{"", "x", "0-10", "10-5", "1-70000", "a-b"} {
		if _, _, ok := parsePortRange(in); ok {
			t.Errorf("parsePortRange(%q) accepted", in)
		}
	}
}
