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

package iptables

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/firewall"
)

// TestCompile_F2907_EmitsIPv6Section is a regression test for avarice
// F-2907. The compiler must emit an `# v6:` divider followed by an
// ip6tables ruleset so dual-stack hosts apply default-deny to IPv6
// traffic, not just IPv4.
func TestCompile_F2907_EmitsIPv6Section(t *testing.T) {
	c := New()
	cfg := &firewall.FirewallConfig{
		Version:       "1",
		DefaultAction: "deny",
		Logging: firewall.LoggingConfig{
			Enabled:   true,
			RateLimit: "10/min",
			Prefix:    "DC-FW",
		},
	}
	rules, err := c.Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	joined := strings.Join(rules, "\n")
	if !strings.Contains(joined, "# v6:") {
		t.Fatalf("expected IPv6 divider `# v6:` in output, got:\n%s", joined)
	}
	idx := strings.Index(joined, "# v6:")
	v4Section := joined[:idx]
	v6Section := joined[idx:]
	if !strings.Contains(v4Section, "*filter") || !strings.Contains(v4Section, "COMMIT") {
		t.Fatalf("v4 section missing *filter/COMMIT: %s", v4Section)
	}
	if !strings.Contains(v6Section, "*filter") {
		t.Fatalf("v6 section missing *filter table header: %s", v6Section)
	}
	if !strings.Contains(v6Section, "ipv6-icmp") {
		t.Fatalf("v6 section missing ICMPv6 allow rule: %s", v6Section)
	}
	if !strings.Contains(v6Section, "-A OUTPUT -j DROP") {
		t.Fatalf("v6 section missing default-deny: %s", v6Section)
	}
}

// TestCompile_F2907_IPv6Allowlist verifies that allowlisted IPv6 IPs
// land in the v6 section while IPv4 IPs stay in the v4 section.
func TestCompile_F2907_IPv6Allowlist(t *testing.T) {
	c := New()
	cfg := &firewall.FirewallConfig{
		Version:       "1",
		DefaultAction: "deny",
		Allowlist: firewall.AllowlistConfig{
			IPs: []string{"203.0.113.5", "2001:db8::1"},
		},
	}
	rules, err := c.Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	joined := strings.Join(rules, "\n")
	idx := strings.Index(joined, "# v6:")
	if idx < 0 {
		t.Fatalf("missing v6 divider")
	}
	v4Section := joined[:idx]
	v6Section := joined[idx:]
	if !strings.Contains(v4Section, "203.0.113.5") {
		t.Fatalf("expected IPv4 allowlist entry in v4 section")
	}
	if strings.Contains(v4Section, "2001:db8::1") {
		t.Fatalf("IPv6 allowlist leaked into v4 section")
	}
	if !strings.Contains(v6Section, "2001:db8::1") {
		t.Fatalf("expected IPv6 allowlist entry in v6 section")
	}
}

// TestApplyCommand_F2907_SkipsMissingIp6tables verifies the apply
// command gracefully skips ip6tables-restore when not present so
// IPv4-only hosts still apply the default-deny.
func TestApplyCommand_F2907_SkipsMissingIp6tables(t *testing.T) {
	c := New()
	cmd := c.ApplyCommand("/tmp/rules.txt")
	if !strings.Contains(cmd, "command -v ip6tables-restore") {
		t.Fatalf("ApplyCommand should guard the ip6tables-restore call: %s", cmd)
	}
	if !strings.Contains(cmd, "iptables-restore") {
		t.Fatalf("ApplyCommand must always call iptables-restore: %s", cmd)
	}
}

// TestRemoveCommand_F2907_FlushesIPv6 verifies the teardown also
// resets the ip6tables OUTPUT chain when the binary is present.
func TestRemoveCommand_F2907_FlushesIPv6(t *testing.T) {
	c := New()
	cmd := c.RemoveCommand()
	if !strings.Contains(cmd, "ip6tables -F OUTPUT") {
		t.Fatalf("RemoveCommand must flush ip6tables OUTPUT: %s", cmd)
	}
	if !strings.Contains(cmd, "command -v ip6tables") {
		t.Fatalf("RemoveCommand should guard ip6tables call: %s", cmd)
	}
}
