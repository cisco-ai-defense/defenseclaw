// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// SPDX-License-Identifier: Apache-2.0

package firewall

import (
	"slices"
	"testing"
)

func TestAIDefenseAllowlistHost(t *testing.T) {
	for name, test := range map[string]struct {
		endpoint string
		want     string
	}{
		"unset falls back to the client's own default": {
			endpoint: "",
			want:     "us.api.inspect.aidefense.security.cisco.com",
		},
		"blank falls back": {
			endpoint: "   ",
			want:     "us.api.inspect.aidefense.security.cisco.com",
		},
		"preview tenant": {
			endpoint: "https://preview.api.inspect.aidefense.aiteam.cisco.com",
			want:     "preview.api.inspect.aidefense.aiteam.cisco.com",
		},
		"another region": {
			endpoint: "https://eu.api.inspect.aidefense.security.cisco.com",
			want:     "eu.api.inspect.aidefense.security.cisco.com",
		},
		"trailing path is not part of the host": {
			endpoint: "https://preview.api.inspect.aidefense.aiteam.cisco.com/api/v1/",
			want:     "preview.api.inspect.aidefense.aiteam.cisco.com",
		},
		"port is not part of the host": {
			endpoint: "https://inspect.example.com:8443",
			want:     "inspect.example.com",
		},
		"scheme-less value still names a host": {
			endpoint: "preview.api.inspect.aidefense.aiteam.cisco.com",
			want:     "preview.api.inspect.aidefense.aiteam.cisco.com",
		},
	} {
		t.Run(name, func(t *testing.T) {
			if got := AIDefenseAllowlistHost(test.endpoint); got != test.want {
				t.Fatalf("AIDefenseAllowlistHost(%q) = %q, want %q", test.endpoint, got, test.want)
			}
		})
	}
}

func TestDefaultFirewallConfigCarriesTheDefaultInspectionHost(t *testing.T) {
	domains := DefaultFirewallConfig().Allowlist.Domains
	if !slices.Contains(domains, "us.api.inspect.aidefense.security.cisco.com") {
		t.Fatalf("default allowlist lost the default inspection host: %v", domains)
	}
}

func TestMergeAIDefenseEndpointFollowsTheConfiguredTenant(t *testing.T) {
	cfg := DefaultFirewallConfig().
		MergeAIDefenseEndpoint("https://preview.api.inspect.aidefense.aiteam.cisco.com")
	if !slices.Contains(cfg.Allowlist.Domains, "preview.api.inspect.aidefense.aiteam.cisco.com") {
		t.Fatalf("preview host was not allowed: %v", cfg.Allowlist.Domains)
	}

	// Merging the default twice must not duplicate the entry.
	base := DefaultFirewallConfig()
	before := len(base.Allowlist.Domains)
	if after := len(base.MergeAIDefenseEndpoint("").Allowlist.Domains); after != before {
		t.Fatalf("allowlist grew from %d to %d merging the default host", before, after)
	}
}
