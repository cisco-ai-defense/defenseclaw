// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// The one outage decision (owner decision 2026-10-23): config mode, policy
// tier and managed state in, open or closed out. A per-user (OSS) install
// fails open for an outage in the default and permissive tiers and closed in
// strict; every managed or enterprise install keeps its administrator's mode
// (closed by default), whatever the tier, and Secure Client keeps its open
// default. A per-user configured hook_fail_mode, open or closed, and the
// guardrail mode change nothing.
func TestHookOutageFailModeDecision(t *testing.T) {
	standalone := func(c *Config) {
		c.DeploymentMode = managed.DeploymentModeManagedEnterprise
		c.Enterprise.Profile = managed.ProfileStandalone
	}
	for _, tc := range []struct {
		name  string
		setup func(*Config)
		want  string
	}{
		{"OSS default", func(*Config) {}, "open"},
		{"OSS default, explicit default pack", func(c *Config) { c.Guardrail.RulePack = "default" }, "open"},
		{"OSS permissive", func(c *Config) { c.Guardrail.RulePack = "permissive" }, "open"},
		{"OSS strict", func(c *Config) { c.Guardrail.RulePack = "strict" }, "closed"},
		{"OSS strict, connector pack", func(c *Config) {
			c.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{"codex": {RulePack: "strict"}}
		}, "closed"},
		{"OSS strict global, permissive connector", func(c *Config) {
			c.Guardrail.RulePack = "strict"
			c.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{"codex": {RulePack: "permissive"}}
		}, "open"},
		{"OSS default, saved closed", func(c *Config) { c.Guardrail.HookFailMode = "closed" }, "closed"},
		{"OSS strict, saved open", func(c *Config) {
			c.Guardrail.RulePack = "strict"
			c.Guardrail.HookFailMode = "open"
			c.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{"codex": {HookFailMode: "open"}}
		}, "open"},
		{"OSS default, action mode", func(c *Config) { c.Guardrail.Mode = "action" }, "open"},
		{"OSS strict, observe mode", func(c *Config) { c.Guardrail.Mode = "observe"; c.Guardrail.RulePack = "strict" }, "closed"},
		{"managed default", standalone, "closed"},
		{"managed permissive", func(c *Config) { standalone(c); c.Guardrail.RulePack = "permissive" }, "closed"},
		{"managed strict", func(c *Config) { standalone(c); c.Guardrail.RulePack = "strict" }, "closed"},
		{"managed, administrator open", func(c *Config) { standalone(c); c.Guardrail.HookFailMode = "open" }, "open"},
		{"managed strict, administrator open", func(c *Config) {
			standalone(c)
			c.Guardrail.RulePack = "strict"
			c.Guardrail.HookFailMode = "open"
		}, "open"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			tc.setup(cfg)
			if got := cfg.EffectiveHookOutageFailModeForConnector("codex"); got != tc.want {
				t.Fatalf("outage mode = %q, want %q (tier %q)", got, tc.want, cfg.HookPolicyTierForConnector("codex"))
			}
			// Every failure that is not an outage keeps its own resolver:
			// closed on a per-user install in every tier.
			if !managed.IsManagedEnterprise(cfg.DeploymentMode) {
				if got := cfg.EffectiveHookFailModeForConnector("codex"); got != "closed" {
					t.Fatalf("non-outage failure mode = %q, want closed", got)
				}
			}
		})
	}
	if got := (*Config)(nil).EffectiveHookOutageFailModeForConnector("codex"); got != "closed" {
		t.Fatalf("nil config outage mode = %q, want closed", got)
	}
	for _, tc := range []struct {
		managedInstall bool
		managedMode    string
		tier           string
		want           string
	}{
		{false, "", "default", "open"}, {false, "", "permissive", "open"}, {false, "", "strict", "closed"},
		{false, "", "", "open"}, {false, "", "STRICT", "closed"}, {false, "closed", "default", "closed"},
		{false, "open", "strict", "open"},
		{true, "", "default", "closed"}, {true, "closed", "permissive", "closed"}, {true, "open", "strict", "open"},
		{true, "OPEN", "default", "open"}, {true, "bogus", "default", "closed"},
	} {
		if got := HookOutageFailMode(tc.managedInstall, tc.managedMode, tc.tier); got != tc.want {
			t.Errorf("HookOutageFailMode(%v, %q, %q) = %q, want %q", tc.managedInstall, tc.managedMode, tc.tier, got, tc.want)
		}
	}
}

// A custom pack's tier is its manifest posture, else its folder name, as the
// gateway reads it (packPosture): a strict custom pack closes the outage.
func TestHookPolicyTierOfACustomPack(t *testing.T) {
	root := t.TempDir()
	manifest := filepath.Join(root, "team-pack")
	folder := filepath.Join(root, "strict")
	plain := filepath.Join(root, "mine")
	for _, dir := range []string{manifest, folder, plain} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(manifest, "defenseclaw-pack.json"), []byte(`{"posture":"strict"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		dir, tier, outage string
	}{
		{manifest, "strict", "closed"},
		{folder, "strict", "closed"},
		{plain, "default", "open"},
	} {
		cfg := &Config{}
		cfg.Guardrail.RulePack = "custom"
		cfg.Guardrail.CustomPacks = map[string]CustomRulePack{"custom": {Path: tc.dir}}
		if got := cfg.HookPolicyTierForConnector("claudecode"); got != tc.tier {
			t.Errorf("%s: tier = %q, want %q", tc.dir, got, tc.tier)
		}
		if got := cfg.EffectiveHookOutageFailModeForConnector("claudecode"); got != tc.outage {
			t.Errorf("%s: outage mode = %q, want %q", tc.dir, got, tc.outage)
		}
	}
}
