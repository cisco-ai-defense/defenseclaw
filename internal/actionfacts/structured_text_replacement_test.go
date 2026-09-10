// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"encoding/json"
	"testing"
)

func TestExactFirewallTrustExpansionIPv4(t *testing.T) {
	input := Input{
		Tool: "text_editor",
		Args: mustStructuredReplacementJSON(t, map[string]string{
			"command": "str_replace",
			"path":    "/etc/firewall/firewall.conf",
			"old_str": `WHITELIST_RANGES="140.82.0.0/16,185.199.108.0/22"`,
			"new_str": `WHITELIST_RANGES="140.82.0.0/16,185.199.108.0/22,192.0.2.10/32"`,
		}),
		CWD: "/repo",
	}
	facts := Analyze(input)
	address, ok := ExactFirewallTrustExpansionIPv4(facts)
	if !ok || address != "192.0.2.10" || !HasStructuredTextReplacement(facts) {
		t.Fatalf("expansion=(%q,%t) replacement=%t facts=%+v",
			address, ok, HasStructuredTextReplacement(facts), facts.StructuredTextReplacements)
	}
}

func TestExactFirewallTrustExpansionIPv4RejectsIncompleteProofs(t *testing.T) {
	tests := []struct {
		name string
		args map[string]string
	}{
		{name: "same IP was already present", args: map[string]string{
			"command": "str_replace", "path": "/etc/firewall/firewall.conf",
			"old_str": "ALLOW=192.0.2.10/32", "new_str": "ALLOW=192.0.2.10/32 # retained",
		}},
		{name: "multiple new IPs are not a unique join", args: map[string]string{
			"command": "str_replace", "path": "/etc/firewall/firewall.conf",
			"old_str": "ALLOW=127.0.0.1", "new_str": "ALLOW=127.0.0.1,192.0.2.10,198.51.100.2",
		}},
		{name: "different file", args: map[string]string{
			"command": "str_replace", "path": "/tmp/firewall.conf",
			"old_str": "ALLOW=127.0.0.1", "new_str": "ALLOW=127.0.0.1,192.0.2.10",
		}},
		{name: "dynamic path", args: map[string]string{
			"command": "str_replace", "path": "/etc/firewall/$NAME",
			"old_str": "ALLOW=127.0.0.1", "new_str": "ALLOW=127.0.0.1,192.0.2.10",
		}},
		{name: "open schema", args: map[string]string{
			"command": "str_replace", "path": "/etc/firewall/firewall.conf",
			"old_str": "ALLOW=127.0.0.1", "new_str": "ALLOW=127.0.0.1,192.0.2.10", "extra": "x",
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			facts := Analyze(Input{Tool: "text_editor", Args: mustStructuredReplacementJSON(t, test.args), CWD: "/repo"})
			if address, ok := ExactFirewallTrustExpansionIPv4(facts); ok {
				t.Fatalf("unexpected expansion %q", address)
			}
		})
	}
}

func mustStructuredReplacementJSON(t *testing.T, value map[string]string) json.RawMessage {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return raw
}
