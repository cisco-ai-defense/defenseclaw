// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestACPProfileJSONUsesDocumentedKeys(t *testing.T) {
	body, err := json.Marshal(ACPProfile{
		Mode: "action", FailMode: "closed", AllowedClients: []string{"zed"},
		AllowedAgents: []string{"kiro"}, DeniedMethods: []string{"terminal/create"},
	})
	if err != nil {
		t.Fatal(err)
	}
	value := string(body)
	for _, key := range []string{"mode", "fail_mode", "allowed_clients", "allowed_agents", "denied_methods"} {
		if !strings.Contains(value, `"`+key+`"`) {
			t.Fatalf("ACP profile JSON omits %q: %s", key, value)
		}
	}
}

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

// Per-pair bindings have to survive the real loader, not just the struct.
// Go validation used to require a profile on every client and agent pin,
// which would have rejected every configuration the CLI writes once it
// started recording policy per pair -- the CLI would write a file the
// gateway refused to load.
func TestACPPerPairBindingsLoadFromFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte(`config_version: 8
acp:
  enabled: true
  mode: action
  default_profile: locked
  clients:
    zed:
      enabled: true
  agents:
    kiro:
      enabled: true
    devin:
      enabled: true
  bindings:
    zed/kiro:
      enabled: true
      profile: locked
    zed/devin:
      enabled: true
      profile: watch
  profiles:
    locked:
      mode: action
      allowed_clients: [zed]
      allowed_agents: [kiro]
    watch:
      mode: observe
      allowed_clients: [zed]
      allowed_agents: [devin]
`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg, err := LoadFromFile(path)
	if err != nil {
		t.Fatalf("LoadFromFile: %v", err)
	}
	if len(cfg.ACP.Bindings) != 2 {
		t.Fatalf("bindings = %#v, want two entries", cfg.ACP.Bindings)
	}
	if got := cfg.ACP.ACPProfileForPair("zed", "kiro"); got != "locked" {
		t.Errorf("zed/kiro resolved %q, want locked", got)
	}
	if got := cfg.ACP.ACPProfileForPair("zed", "devin"); got != "watch" {
		t.Errorf("zed/devin resolved %q, want watch", got)
	}
}

func TestACPPairBindingValidation(t *testing.T) {
	base := func() *ACPConfig {
		return &ACPConfig{
			Enabled: true, Mode: "action", DefaultProfile: "locked",
			Clients:  map[string]ACPBinding{"zed": {Enabled: true}},
			Agents:   map[string]ACPBinding{"kiro": {Enabled: true}},
			Bindings: map[string]ACPBinding{"zed/kiro": {Enabled: true, Profile: "locked"}},
			Profiles: map[string]ACPProfile{"locked": {Mode: "action"}},
		}
	}
	if err := base().Validate(); err != nil {
		t.Fatalf("baseline per-pair config rejected: %v", err)
	}

	// A pin still needs a profile when there are no pair bindings, so the
	// pre-per-pair contract is unchanged for configurations that predate it.
	legacy := base()
	legacy.Bindings = nil
	if err := legacy.Validate(); err == nil {
		t.Error("a pin with no profile and no pair bindings should still be rejected")
	}

	for name, mutate := range map[string]func(*ACPConfig){
		"unknown profile":   func(c *ACPConfig) { c.Bindings["zed/kiro"] = ACPBinding{Enabled: true, Profile: "nope"} },
		"unknown client":    func(c *ACPConfig) { c.Bindings["other/kiro"] = ACPBinding{Enabled: true} },
		"unknown agent":     func(c *ACPConfig) { c.Bindings["zed/other"] = ACPBinding{Enabled: true} },
		"missing separator": func(c *ACPConfig) { c.Bindings["zedkiro"] = ACPBinding{Enabled: true} },
		"uppercase half":    func(c *ACPConfig) { c.Bindings["Zed/kiro"] = ACPBinding{Enabled: true} },
	} {
		cfg := base()
		mutate(cfg)
		if err := cfg.Validate(); err == nil {
			t.Errorf("%s should be rejected", name)
		}
	}
}
