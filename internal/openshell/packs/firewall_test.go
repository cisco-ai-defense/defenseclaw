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
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
)

const hostFirewallYAML = `version: "1.0"
default_action: deny
rules:
  - name: exfil-drop
    direction: outbound
    protocol: tcp
    destination: drop.exfil-test.example
    action: deny
  - name: exfil-range
    destination: 198.51.99.0/24
    action: deny
  - name: ssh-only
    destination: ssh.exfil-test.example
    port: 22
    action: deny
  - name: dns-udp
    protocol: udp
    destination: udp.exfil-test.example
    action: deny
  - name: allowed
    destination: allowed.exfil-test.example
    action: allow
allowlist:
  domains: [api.anthropic.com]
`

// TestHostFirewallDenyRulesBlockSandboxes pins that the deny rules of the
// host egress firewall (firewall.config_file) carry over to sandbox egress:
// outbound TCP rules that cover the proxy's ports join the block list, so the
// proxy refuses the destination, and neither an unblock nor an approval (a
// direct rule) lifts it. The host firewall's allow rules and allowlist do
// not apply to sandboxes.
func TestHostFirewallDenyRulesBlockSandboxes(t *testing.T) {
	path := filepath.Join(t.TempDir(), "firewall.yaml")
	if err := os.WriteFile(path, []byte(hostFirewallYAML), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := testConfig(nil)
	cfg.Firewall.ConfigFile = path
	eff, _ := mustResolve(t, cfg, Flags{})
	for _, want := range []string{"drop.exfil-test.example", "198.51.99.0/24"} {
		if !slices.Contains(eff.Egress.Block, want) {
			t.Fatalf("egress.block = %v, want %s from the host firewall", eff.Egress.Block, want)
		}
	}
	for _, not := range []string{"ssh.exfil-test.example", "udp.exfil-test.example", "allowed.exfil-test.example", "api.anthropic.com"} {
		if slices.Contains(eff.Egress.Block, not) || slices.Contains(eff.Egress.Allow, not) {
			t.Fatalf("egress = %+v, want nothing for %s", eff.Egress, not)
		}
	}
	setting, _ := eff.Setting("egress.block")
	if !strings.Contains(setting.Origin, path) {
		t.Fatalf("egress.block origin = %q, want the firewall configuration named", setting.Origin)
	}
	for _, host := range []string{"drop.exfil-test.example", "198.51.99.7"} {
		if d := eff.DecideEgress(host, 443); d.Allowed || d.Rule != RuleBlock {
			t.Fatalf("DecideEgress(%s) = %+v, want the block list", host, d)
		}
		for _, kind := range []ActionKind{ActionUnblock, ActionApprove} {
			err := eff.Allow(Action{Kind: kind, Host: host, Port: 443})
			var v *Violation
			if !errors.As(err, &v) || v.Constraint != "firewall.config_file" {
				t.Fatalf("Allow(%s %s) = %v, want a host firewall violation", kind, host, err)
			}
		}
	}
	if d := eff.DecideEgress("ssh.exfil-test.example", 443); !d.Allowed {
		t.Fatalf("a rule for port 22 only refused %+v", d)
	}

	// No file means no host firewall.
	cfg.Firewall.ConfigFile = filepath.Join(t.TempDir(), "missing.yaml")
	if eff, _ := mustResolve(t, cfg, Flags{}); len(eff.Egress.Block) != 0 {
		t.Fatalf("egress.block without a firewall configuration = %v", eff.Egress.Block)
	}
	// One that cannot be parsed fails the policy instead of dropping the
	// operator's denials.
	if err := os.WriteFile(path, []byte("rules: [unterminated"), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg.Firewall.ConfigFile = path
	if _, _, err := Resolve(cfg, Flags{}); err == nil || !strings.Contains(err.Error(), "host egress firewall") {
		t.Fatalf("Resolve with a malformed firewall configuration = %v", err)
	}
}
