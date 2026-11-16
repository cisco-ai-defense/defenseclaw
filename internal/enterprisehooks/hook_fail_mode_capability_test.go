// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// managedConfigForProfile returns a managed-enterprise config on profile, and
// pins this process to the same profile: on Windows the renderer reads the
// process's protected profile pin (windowsEnterpriseStandaloneProcess), not
// the config. A config with no profile resolves to Secure Client.
func managedConfigForProfile(t *testing.T, profile string) *config.Config {
	t.Helper()
	pin := ""
	if profile == managed.ProfileStandalone {
		pin = profile
	}
	t.Setenv(managed.EnterpriseProfileEnv, pin)
	cfg := &config.Config{DeploymentMode: managed.DeploymentModeManagedEnterprise}
	cfg.Enterprise.Profile = profile
	return cfg
}

// ManagedHookFailMode is the value the renderer writes. Outside Secure Client
// every connector's managed hooks block through the native deny, so no
// connector is lowered: status says closed for a connector without its own
// value and the administrator's open for one that sets it (owner decision
// 2026-10-20).
func TestManagedHookFailModeIsTheRenderedValue(t *testing.T) {
	cfg := managedConfigForProfile(t, managed.ProfileStandalone)
	closed := config.PerConnectorGuardrailConfig{HookFailMode: "closed"}
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"hermes": closed, "copilot": closed, "opencode": closed, "amp": {HookFailMode: "open"},
	}
	for _, name := range []string{"hermes", "copilot"} {
		if got := cfg.EffectiveHookFailModeForConnector(name); got != "closed" {
			t.Fatalf("%s: the config resolves %q; the test needs closed", name, got)
		}
	}
	want := map[string]string{
		"hermes": "closed", "copilot": "closed",
		"codex": "closed", "claudecode": "closed", "opencode": "closed",
		"amp": "open", // the administrator's explicit open
	}
	for name, mode := range want {
		if got := ManagedHookFailMode(cfg, name); got != mode {
			t.Errorf("%s: ManagedHookFailMode = %q, the renderer writes %q", name, got, mode)
		}
	}
	if got := renderedHookFailModeFor(cfg, "not-a-connector", "closed"); got != "closed" {
		t.Errorf("unknown connector = %q", got)
	}
}

// Under Secure Client (#1163) an unset hook fail mode resolves open for every
// connector, Codex and Claude Code included, an explicit closed stays closed
// except for an agent that cannot fail closed (Hermes, Copilot: status must
// not say closed, GAP-0001), and an explicit open stays open.
func TestSecureClientManagedHookFailModeFollowsTheConfig(t *testing.T) {
	useSecureClientHookDelivery(t)
	cfg := managedConfigForProfile(t, managed.ProfileSecureClient)
	if !cfg.SecureClientIntegration() {
		t.Fatal("test config does not resolve to Secure Client")
	}
	closed := config.PerConnectorGuardrailConfig{HookFailMode: "closed"}
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"claudecode": closed, "hermes": closed, "copilot": closed, "amp": {HookFailMode: "open"},
	}
	want := map[string]string{
		"codex":      "open",   // unset
		"opencode":   "open",   // unset
		"claudecode": "closed", // explicit closed is kept
		"hermes":     "open",   // explicit closed, but the agent cannot fail closed
		"copilot":    "open",   // explicit closed, but the agent cannot fail closed
		"amp":        "open",   // explicit open
	}
	for name, mode := range want {
		if got := ManagedHookFailMode(cfg, name); got != mode {
			t.Errorf("%s: ManagedHookFailMode = %q, want %q", name, got, mode)
		}
	}
	if got := renderedHookFailModeFor(cfg, "not-a-connector", "closed"); got != "closed" {
		t.Errorf("unknown connector = %q", got)
	}
}

// Status reports the mode a managed standalone hook operates in: the managed
// Amp plugin, and OpenCode or Copilot on the per-user route, block every
// gateway outage whatever hook_fail_mode says, so an administrator's open
// reads closed for them; on vendor machine policy the administrator's mode
// applies (GAP-0465).
func TestManagedStatusHookFailModeIsTheOutageModeOnThePerUserRoute(t *testing.T) {
	cfg := managedConfigForProfile(t, managed.ProfileStandalone)
	cfg.Guardrail.HookFailMode = "open"
	cfg.Guardrail.Connectors = map[string]config.PerConnectorGuardrailConfig{
		"amp": {}, "opencode": {}, "copilot": {}, "codex": {}, "claudecode": {}, "cursor": {},
	}
	for _, tc := range []struct {
		name, goos string
		machine    bool
		want       string
	}{
		{"amp", "linux", false, "closed"},
		{"amp", "darwin", false, "closed"},
		{"amp", "windows", false, "closed"},
		{"opencode", "linux", false, "closed"},
		{"opencode", "linux", true, "open"},
		{"opencode", "windows", false, "closed"},
		{"copilot", "darwin", false, "closed"},
		{"copilot", "linux", true, "open"},
		{"copilot", "windows", false, "open"},
		{"codex", "linux", false, "open"},
		{"claudecode", "darwin", true, "open"},
		{"cursor", "windows", false, "open"},
	} {
		if got := ManagedHookFailMode(cfg, tc.name); got != "open" {
			t.Fatalf("%s: ManagedHookFailMode = %q; the test needs the administrator's open", tc.name, got)
		}
		if got := ManagedStatusHookFailMode(cfg, tc.name, tc.goos, tc.machine); got != tc.want {
			t.Errorf("%s on %s (machine policy %v): status reports %q, the hook operates %q", tc.name, tc.goos, tc.machine, got, tc.want)
		}
	}
	cfg.Guardrail.HookFailMode = "closed"
	for _, name := range []string{"amp", "opencode", "codex"} {
		if got := ManagedStatusHookFailMode(cfg, name, "linux", false); got != "closed" {
			t.Errorf("%s: closed reports %q", name, got)
		}
	}
}
