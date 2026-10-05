// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"strings"
	"testing"
)

func TestValidateGuardrailProfiles(t *testing.T) {
	enabled := true
	valid := func() GuardrailConfig {
		return GuardrailConfig{
			Profiles: map[string]GuardrailProfile{
				"contractors": {Mode: "action", BlockAt: "medium", Connectors: map[string]PerConnectorGuardrailConfig{"codex": {Mode: "observe"}}},
			},
			ProfileAssignments: []ProfileAssignment{
				{Profile: "contractors", Match: ProfileMatch{Groups: []string{`CORP\Contractors`}}},
			},
			DefaultProfile: "contractors",
		}
	}
	cases := []struct {
		name   string
		mutate func(*Config)
		want   string
	}{
		{name: "valid", mutate: func(*Config) {}},
		{name: "unknown assignment profile", mutate: func(c *Config) { c.Guardrail.ProfileAssignments[0].Profile = "ml-team" }, want: `unknown profile "ml-team"`},
		{name: "unknown default profile", mutate: func(c *Config) { c.Guardrail.DefaultProfile = "ml-team" }, want: `default_profile: unknown profile`},
		{name: "enabled in profile", mutate: func(c *Config) {
			p := c.Guardrail.Profiles["contractors"]
			p.Enabled = &enabled
			c.Guardrail.Profiles["contractors"] = p
		}, want: "enabled is not allowed in a guardrail profile"},
		{name: "hook_fail_mode in profile connector", mutate: func(c *Config) {
			c.Guardrail.Profiles["contractors"].Connectors["codex"] = PerConnectorGuardrailConfig{HookFailMode: "open"}
		}, want: `connectors["codex"]: hook_fail_mode is not allowed`},
		{name: "secure client", mutate: func(c *Config) {
			c.DeploymentMode = "managed_enterprise"
			c.Enterprise.Profile = "secure_client"
		}, want: "not supported with the Secure Client integration"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			cfg := &Config{Guardrail: valid()}
			tc.mutate(cfg)
			err := cfg.ValidateGuardrailProfiles()
			if tc.want == "" {
				if err != nil {
					t.Fatalf("ValidateGuardrailProfiles() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Fatalf("ValidateGuardrailProfiles() = %v, want error containing %q", err, tc.want)
			}
		})
	}
}
