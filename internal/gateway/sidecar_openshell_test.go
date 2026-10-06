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

// Every API listener, hook/plugin address, and health probe must agree on one
// address, or an upgrade health check dials one host while the API listens on
// another and rolls back. guardrail.host never moves the API (the retired
// standalone sandbox's veth address, 10.200.0.1, is reset by the
// config_version 9 migration).
func TestAPIListenAddrIsAPIBindOrLoopback(t *testing.T) {
	for _, tc := range []struct {
		name string
		cfg  *config.Config
		want string
	}{
		{"default", openShellReloadConfig(nil), "127.0.0.1:18970"},
		{"guardrail host", openShellReloadConfig(func(c *config.Config) { c.Guardrail.Host = "10.200.0.1" }), "127.0.0.1:18970"},
		{"explicit api_bind", openShellReloadConfig(func(c *config.Config) { c.Gateway.APIBind = "192.168.65.2" }), "192.168.65.2:18970"},
	} {
		if got := apiListenAddr(tc.cfg); got != tc.want {
			t.Errorf("%s listener = %q, want %q", tc.name, got, tc.want)
		}
	}
}

// Only the sandbox listeners are tied to the API server's lifecycle; every
// other openshell key is read per sandbox launch and must hot-reload.
func TestAPINeedsRestartForOpenShellListenersOnly(t *testing.T) {
	base := openShellReloadConfig(nil)
	disabled := func(c *config.Config) { c.OpenShell.Enabled = false }
	for _, tc := range []struct {
		name    string
		oldCfg  *config.Config
		newCfg  *config.Config
		restart bool
	}{
		{"enable", openShellReloadConfig(disabled), base, true},
		{"disable", base, openShellReloadConfig(disabled), true},
		{"ingress port", base, openShellReloadConfig(func(c *config.Config) { c.OpenShell.IngressPort = 19971 }), true},
		{"egress port", base, openShellReloadConfig(func(c *config.Config) { c.OpenShell.EgressPort = 19972 }), true},
		{"explicit port equal to derived", base, openShellReloadConfig(func(c *config.Config) { c.OpenShell.IngressPort = 18971 }), false},
		{"disabled port move", openShellReloadConfig(disabled),
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

// The openshell section hot-reloads.
func TestDiffConfigsTreatsOpenShellSectionAsHot(t *testing.T) {
	diff := diffConfigs(openShellReloadConfig(nil), openShellReloadConfig(func(c *config.Config) {
		c.OpenShell.Enabled = false
		c.OpenShell.Profile = "balanced"
		c.OpenShell.Admin.AllowedHarnesses = []string{"codex"}
	}))
	if !slices.Contains(diff.Changed, "openshell") || len(diff.RestartRequired) != 0 {
		t.Errorf("changed=%v restart=%v, want a hot reload", diff.Changed, diff.RestartRequired)
	}
}
