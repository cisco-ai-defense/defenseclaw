// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func openShellReloadConfig(edit func(*config.Config)) *config.Config {
	cfg := &config.Config{}
	cfg.Gateway.APIPort = 18970
	cfg.OpenShell.Enabled = true
	if edit != nil {
		edit(cfg)
	}
	return cfg
}

// Only the sandbox listeners are tied to the API server's lifecycle; every
// other openshell key is read per sandbox launch and must hot-reload.
func TestAPINeedsRestartForOpenShellListenersOnly(t *testing.T) {
	base := openShellReloadConfig(nil)
	for _, tc := range []struct {
		name    string
		oldCfg  *config.Config
		newCfg  *config.Config
		restart bool
	}{
		{"enable", openShellReloadConfig(func(c *config.Config) { c.OpenShell.Enabled = false }), base, true},
		{"disable", base, openShellReloadConfig(func(c *config.Config) { c.OpenShell.Enabled = false }), true},
		{"ingress port", base, openShellReloadConfig(func(c *config.Config) { c.OpenShell.IngressPort = 19971 }), true},
		{"egress port", base, openShellReloadConfig(func(c *config.Config) { c.OpenShell.EgressPort = 19972 }), true},
		{"explicit port equal to derived", base, openShellReloadConfig(func(c *config.Config) { c.OpenShell.IngressPort = 18971 }), false},
		{"disabled port move", openShellReloadConfig(func(c *config.Config) { c.OpenShell.Enabled = false }),
			openShellReloadConfig(func(c *config.Config) { c.OpenShell.Enabled = false; c.OpenShell.EgressPort = 19972 }), false},
		{"profile", base, openShellReloadConfig(func(c *config.Config) { c.OpenShell.Profile = "strict" }), false},
		{"pack", base, openShellReloadConfig(func(c *config.Config) { c.OpenShell.Pack = "balanced" }), false},
		{"admin", base, openShellReloadConfig(func(c *config.Config) { c.OpenShell.Admin.MinProfile = "strict" }), false},
		{"egress lists", base, openShellReloadConfig(func(c *config.Config) { c.OpenShell.Egress.Block = []string{"paste.example"} }), false},
		{"harnesses", base, openShellReloadConfig(func(c *config.Config) { c.OpenShell.Harnesses = []string{"codex"} }), false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := apiNeedsRestart(tc.oldCfg, tc.newCfg); got != tc.restart {
				t.Fatalf("apiNeedsRestart() = %v, want %v", got, tc.restart)
			}
		})
	}
}

func TestDiffConfigsTreatsOpenShellSectionAsHot(t *testing.T) {
	oldCfg := openShellReloadConfig(nil)
	newCfg := openShellReloadConfig(func(c *config.Config) {
		c.OpenShell.Enabled = false
		c.OpenShell.Profile = "balanced"
		c.OpenShell.Admin.AllowedHarnesses = []string{"codex"}
	})
	diff := diffConfigs(oldCfg, newCfg)
	if !slices.Contains(diff.Changed, "openshell") || len(diff.RestartRequired) != 0 {
		t.Fatalf("openshell change: changed=%v restart=%v, want a hot reload", diff.Changed, diff.RestartRequired)
	}
}
