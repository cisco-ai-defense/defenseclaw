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

package pfctl

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/firewall"
)

// TestCompile_F2908_NoBlanketUDPPass is a regression test for avarice
// F-2908. The compiled ruleset must NOT contain a blanket
// `pass out quick inet proto udp keep state` rule before the default
// deny — that rule made all outbound UDP/QUIC bypass the firewall.
func TestCompile_F2908_NoBlanketUDPPass(t *testing.T) {
	c := New()
	cfg := &firewall.FirewallConfig{
		Version:       "1",
		DefaultAction: "deny",
	}
	rules, err := c.Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	for _, r := range rules {
		trimmed := strings.TrimSpace(r)
		if trimmed == "pass out quick inet proto udp keep state" {
			t.Fatalf("F-2908 regression: blanket UDP pass rule re-introduced")
		}
		// Also reject any UDP pass rule without a `to` clause.
		if strings.HasPrefix(trimmed, "pass out quick inet proto udp ") &&
			!strings.Contains(trimmed, " to ") {
			t.Fatalf("F-2908 regression: UDP pass rule without destination: %q", trimmed)
		}
	}
}

// TestCompile_F2908_KeepsDNSUDP verifies that legitimate UDP DNS
// traffic is still allowed via the explicit port 53 rule.
func TestCompile_F2908_KeepsDNSUDP(t *testing.T) {
	c := New()
	cfg := &firewall.FirewallConfig{
		Version:       "1",
		DefaultAction: "deny",
	}
	rules, err := c.Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	joined := strings.Join(rules, "\n")
	if !strings.Contains(joined, "pass out quick inet proto udp to any port 53") {
		t.Fatalf("expected DNS-over-UDP rule, got:\n%s", joined)
	}
}

// TestCompile_F2908_TCPEstablishedHasKeepState verifies the TCP
// established rule is stateful so reply traffic continues to flow.
func TestCompile_F2908_TCPEstablishedHasKeepState(t *testing.T) {
	c := New()
	cfg := &firewall.FirewallConfig{
		Version:       "1",
		DefaultAction: "deny",
	}
	rules, err := c.Compile(cfg)
	if err != nil {
		t.Fatalf("Compile: %v", err)
	}
	joined := strings.Join(rules, "\n")
	if !strings.Contains(joined, "pass out quick inet proto tcp flags A/A keep state") {
		t.Fatalf("expected stateful TCP established rule, got:\n%s", joined)
	}
}
