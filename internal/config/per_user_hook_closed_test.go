// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

// A per-user config is writable by that user, so it cannot grant an outage
// exception. The exception belongs to the administrator of a managed host.
func TestPerUserHookFailureCannotBeOpenedByConfiguration(t *testing.T) {
	for _, deployment := range []string{"", "unmanaged_byod"} {
		for _, connector := range []string{"codex", "claudecode", "cursor", "opencode", "amp"} {
			for _, mode := range []string{"observe", "action"} {
				cfg := &Config{DeploymentMode: deployment}
				cfg.Guardrail.Mode = mode
				cfg.Guardrail.HookFailMode = "open"
				cfg.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{connector: {HookFailMode: "open"}}
				cfg.ApplicationProtection.Enabled = true
				cfg.ApplicationProtection.Connectors = map[string]ApplicationProtectionConnectorConfig{
					connector: {Guardrail: PerConnectorGuardrailConfig{HookFailMode: "open"}},
				}
				if got := cfg.EffectiveHookFailModeForConnector(connector); got != "closed" {
					t.Errorf("%s/%s/%s: hook failure = %q, want closed", deployment, connector, mode, got)
				}
				if got := cfg.EffectiveActionHookFailModeForConnector(connector); got != "closed" {
					t.Errorf("%s/%s/%s: action failure = %q, want closed", deployment, connector, mode, got)
				}
			}
		}
	}
}
