// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// An outage must never turn an ordinary per-user tool call into an
// allow, even when a saved setting or the selected pack says permissive.
func TestPerUserOutageRemainsClosedAcrossConnectorsAndTiers(t *testing.T) {
	for _, connector := range []string{"amp", "antigravity", "claudecode", "codex", "copilot", "cursor", "devin", "hermes", "kiro", "opencode"} {
		for _, tier := range []string{"default", "permissive", "strict"} {
			for _, mode := range []string{"observe", "action"} {
				cfg := &Config{}
				cfg.Guardrail.Mode = mode
				cfg.Guardrail.RulePack = tier
				cfg.Guardrail.HookFailMode = "open" // A saved older value must not reopen it.
				cfg.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{
					connector: {HookFailMode: "open"},
				}
				if got := cfg.EffectiveHookOutageFailModeForConnector(connector); got != "closed" {
					t.Errorf("%s/%s/%s outage mode = %q, want closed", connector, tier, mode, got)
				}
			}
		}
	}
}

// Per-user outages close in every tier and mode. Managed and enterprise
// installs keep the administrator's mode (closed by default), and Secure
// Client keeps its open default.
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
		{"OSS default", func(*Config) {}, "closed"},
		{"OSS default, explicit default pack", func(c *Config) { c.Guardrail.RulePack = "default" }, "closed"},
		{"OSS permissive", func(c *Config) { c.Guardrail.RulePack = "permissive" }, "closed"},
		{"OSS strict", func(c *Config) { c.Guardrail.RulePack = "strict" }, "closed"},
		{"OSS strict, connector pack", func(c *Config) {
			c.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{"codex": {RulePack: "strict"}}
		}, "closed"},
		{"OSS strict global, permissive connector", func(c *Config) {
			c.Guardrail.RulePack = "strict"
			c.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{"codex": {RulePack: "permissive"}}
		}, "closed"},
		{"OSS default, saved closed", func(c *Config) { c.Guardrail.HookFailMode = "closed" }, "closed"},
		{"OSS strict, saved open", func(c *Config) {
			c.Guardrail.RulePack = "strict"
			c.Guardrail.HookFailMode = "open"
			c.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{"codex": {HookFailMode: "open"}}
		}, "closed"},
		{"OSS default, action mode", func(c *Config) { c.Guardrail.Mode = "action" }, "closed"},
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
		{"Secure Client default", func(c *Config) {
			c.DeploymentMode = managed.DeploymentModeManagedEnterprise
			c.Enterprise.Profile = managed.ProfileSecureClient
		}, "open"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{}
			tc.setup(cfg)
			if got := cfg.EffectiveHookOutageFailModeForConnector("codex"); got != tc.want {
				t.Fatalf("outage mode = %q, want %q", got, tc.want)
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
		want           string
	}{
		{false, "", "closed"}, {false, "open", "closed"}, {false, "closed", "closed"},
		{true, "", "closed"}, {true, "closed", "closed"}, {true, "open", "open"},
		{true, "OPEN", "open"}, {true, "bogus", "closed"},
	} {
		if got := HookOutageFailMode(tc.managedInstall, tc.managedMode); got != tc.want {
			t.Errorf("HookOutageFailMode(%v, %q) = %q, want %q", tc.managedInstall, tc.managedMode, got, tc.want)
		}
	}
}

// Migration still reads a custom pack's posture from its manifest or folder.
func TestPackPostureForMigration(t *testing.T) {
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
		dir, tier string
	}{
		{manifest, "strict"},
		{folder, "strict"},
		{plain, "default"},
	} {
		got := packManifestPosture(tc.dir)
		if got == "" {
			got = packFolderPosture(tc.dir)
		}
		if got != tc.tier {
			t.Errorf("%s: tier = %q, want %q", tc.dir, got, tc.tier)
		}
	}
}
