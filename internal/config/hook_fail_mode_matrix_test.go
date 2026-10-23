// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// TestEveryConnectorHookFailModeMatrix pins the owner decisions of
// 2026-10-14 and 2026-10-20 ("the customer can choose open or closed based
// on policy, and the default is closed; it should not ignore stuff") for
// every connector, per-user, managed standalone and Secure Client, in
// observe and action mode, with the fail mode unset, explicit open or
// explicit closed, set globally, per connector or through the automatic
// protection overlay:
//
//   - per-user and managed standalone: unset closed, open open, closed
//     closed (a managed computer's config is the administrator's);
//   - Secure Client: unset open (#1163), open open, closed closed;
//   - per-user Cursor follows its guardrail mode (observe open, action
//     closed) whatever is configured.
//
// Anything but "open" (any case) is closed, a typo included.
func TestEveryConnectorHookFailModeMatrix(t *testing.T) {
	names := []string{"amp", "antigravity", "claudecode", "codex", "copilot", "cursor", "devin", "hermes", "kiro", "opencode"}
	deployments := []struct {
		name, mode, profile string
		unset               string
	}{
		{"per-user", "", "", "closed"},
		{"unmanaged", "unmanaged_byod", "", "closed"},
		{"managed standalone", "managed_enterprise", "standalone", "closed"},
		{"Secure Client", "managed_enterprise", "secure_client", "open"},
	}
	type setting struct {
		name                     string
		global, perCon, protects string
		want                     string // "" = the deployment's unset default
	}
	settings := []setting{
		{name: "unset"},
		{name: "empty", global: " "},
		{name: "global open", global: "open", want: "open"},
		{name: "global Open", global: " Open ", want: "open"},
		{name: "connector open", perCon: "open", want: "open"},
		{name: "protection open", protects: "open", want: "open"},
		{name: "global closed", global: "closed", want: "closed"},
		{name: "connector closed", perCon: "closed", want: "closed"},
		{name: "protection closed", protects: "closed", want: "closed"},
		{name: "connector closed over global open", global: "open", perCon: "closed", want: "closed"},
		{name: "connector open over global closed", global: "closed", perCon: "open", want: "open"},
		{name: "global typo", global: "opne", want: "closed"},
	}
	for _, name := range names {
		for _, d := range deployments {
			for _, mode := range []string{"observe", "action"} {
				for _, s := range settings {
					cfg := &Config{DeploymentMode: d.mode}
					cfg.Enterprise.Profile = d.profile
					cfg.Guardrail.Mode = mode
					cfg.Guardrail.HookFailMode = s.global
					if s.perCon != "" {
						cfg.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{name: {HookFailMode: s.perCon}}
					}
					if s.protects != "" {
						// The automatic-protection overlay of a connector
						// setup does not configure by hand.
						cfg.ApplicationProtection.Enabled = true
						cfg.ApplicationProtection.Connectors = map[string]ApplicationProtectionConnectorConfig{
							name: {Guardrail: PerConnectorGuardrailConfig{Mode: mode, HookFailMode: s.protects}},
						}
					}
					want := s.want
					if want == "" {
						want = d.unset
					}
					action := want
					if name == "cursor" && d.mode != "managed_enterprise" {
						want, action = "open", "closed"
						if mode == "action" {
							want = "closed"
						}
					}
					what := name + " " + d.name + " " + mode + " " + s.name
					if got := cfg.EffectiveHookFailModeForConnector(name); got != want {
						t.Errorf("%s: fail mode = %q, want %q", what, got, want)
					}
					if got := cfg.EffectiveActionHookFailModeForConnector(name); got != action {
						t.Errorf("%s: action fail mode = %q, want %q", what, got, action)
					}
				}
			}
		}
	}
}
