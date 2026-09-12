// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func validACPConfig() ACPConfig {
	return ACPConfig{
		Enabled: true, Mode: "action", DefaultProfile: "kiro-only",
		Clients: map[string]ACPBinding{"zed": {Enabled: true, Profile: "kiro-only"}},
		Agents:  map[string]ACPBinding{"kiro": {Enabled: true, Profile: "kiro-only"}},
		Profiles: map[string]ACPProfile{"kiro-only": {
			Mode: "action", FailMode: "closed", AllowedClients: []string{"zed"},
			AllowedAgents: []string{"kiro"}, DeniedMethods: []string{"fs/write_text_file"},
		}},
	}
}

func TestACPConfigValidate(t *testing.T) {
	cfg := validACPConfig()
	if err := cfg.Validate(); err != nil {
		t.Fatalf("valid ACP config: %v", err)
	}
}

func TestACPConfigValidateRejectsMissingProfileReferences(t *testing.T) {
	tests := map[string]func(*ACPConfig){
		"default": func(c *ACPConfig) { c.DefaultProfile = "missing" },
		"client":  func(c *ACPConfig) { c.Clients["zed"] = ACPBinding{Enabled: true, Profile: "missing"} },
		"agent":   func(c *ACPConfig) { c.Agents["kiro"] = ACPBinding{Enabled: true, Profile: "missing"} },
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := validACPConfig()
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}

func TestACPConfigValidateRejectsAmbiguousPolicyValues(t *testing.T) {
	tests := map[string]func(*ACPConfig){
		"mode":      func(c *ACPConfig) { c.Mode = "enforce" },
		"fail mode": func(c *ACPConfig) { p := c.Profiles["kiro-only"]; p.FailMode = "maybe"; c.Profiles["kiro-only"] = p },
		"action fail open": func(c *ACPConfig) {
			p := c.Profiles["kiro-only"]
			p.FailMode = "open"
			c.Profiles["kiro-only"] = p
		},
		"observe fail closed": func(c *ACPConfig) {
			c.Mode = "observe"
			p := c.Profiles["kiro-only"]
			p.Mode = "observe"
			p.FailMode = "closed"
			c.Profiles["kiro-only"] = p
		},
		"duplicate allow": func(c *ACPConfig) {
			p := c.Profiles["kiro-only"]
			p.AllowedAgents = []string{"kiro", "kiro"}
			c.Profiles["kiro-only"] = p
		},
		"invalid method": func(c *ACPConfig) {
			p := c.Profiles["kiro-only"]
			p.DeniedMethods = []string{"bad\nmethod"}
			c.Profiles["kiro-only"] = p
		},
		"duplicate method": func(c *ACPConfig) {
			p := c.Profiles["kiro-only"]
			p.DeniedMethods = []string{"x/y", "x/y"}
			c.Profiles["kiro-only"] = p
		},
		"noncanonical binding name": func(c *ACPConfig) {
			c.Clients = map[string]ACPBinding{"Zed": {Enabled: true, Profile: "kiro-only"}}
		},
		"oversized allowlist": func(c *ACPConfig) {
			p := c.Profiles["kiro-only"]
			p.AllowedAgents = make([]string, maxACPBindings+1)
			c.Profiles["kiro-only"] = p
		},
		"oversized denied methods": func(c *ACPConfig) {
			p := c.Profiles["kiro-only"]
			p.DeniedMethods = make([]string, maxACPDeniedMethods+1)
			c.Profiles["kiro-only"] = p
		},
	}
	for name, mutate := range tests {
		t.Run(name, func(t *testing.T) {
			cfg := validACPConfig()
			mutate(&cfg)
			if err := cfg.Validate(); err == nil {
				t.Fatal("expected validation error")
			}
		})
	}
}
