// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import "testing"

func TestNormalizeHookMode(t *testing.T) {
	for in, want := range map[string]string{
		"action": "action", " Enforce ": "action", "observe": "observe", "warn": "observe", "": "observe",
	} {
		if got := NormalizeHookMode(in); got != want {
			t.Errorf("NormalizeHookMode(%q) = %q, want %q", in, got, want)
		}
	}
}

// The legacy per-connector hook mode wins over the guardrail chain, both
// ways; "inherit" or unset falls through to it.
func TestHookModeForConnectorLegacyPrecedence(t *testing.T) {
	c := &Config{}
	c.Guardrail.Mode = "observe"
	c.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{
		"claudecode": {Mode: "observe"},
		"codex":      {Mode: "action"},
		"opencode":   {},
		"amp":        {},
	}
	c.ClaudeCode.Mode = "action"
	c.Codex.Mode = "observe"
	c.ConnectorHooks = map[string]AgentHookConfig{"opencode": {Mode: "enforce"}, "amp": {Mode: "inherit"}}
	for name, want := range map[string]string{
		"claudecode": "action", "codex": "observe", "opencode": "action", "amp": "observe", "cursor": "observe",
	} {
		if got := c.HookModeForConnector(name); got != want {
			t.Errorf("HookModeForConnector(%q) = %q, want %q", name, got, want)
		}
	}
	var none *Config
	if got := none.HookModeForConnector("claudecode"); got != "observe" {
		t.Errorf("nil config hook mode = %q, want observe", got)
	}
}

// The preview resolves the base and every profile with the hook path's
// resolvers: a legacy claude_code.mode keeps Claude Code in action mode for
// accounts on no profile and on profiles that set no mode for it; a profile
// mode (profile-wide or for the connector) replaces it; a profile HILT block
// replaces the candidate one.
func TestPreviewConnectorHILTFollowsHookResolvers(t *testing.T) {
	c := &Config{}
	c.Guardrail.Mode = "observe"
	c.Guardrail.HILT = HILTConfig{Enabled: false, MinSeverity: "HIGH"}
	c.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{"Claude-Code": {}, "codex": {}}
	c.ClaudeCode.Mode = "action"
	own := HILTConfig{Enabled: false, MinSeverity: "CRITICAL"}
	c.Guardrail.Profiles = map[string]GuardrailProfile{
		"plain":      {BlockAt: "HIGH"},
		"audit":      {Mode: "observe"},
		"quiet":      {Connectors: map[string]PerConnectorGuardrailConfig{"claude_code": {Mode: "observe"}}},
		"codex-only": {Connectors: map[string]PerConnectorGuardrailConfig{"codex": {Mode: "observe"}}},
		"own":        {HILT: &own},
		"own-conn":   {Connectors: map[string]PerConnectorGuardrailConfig{"claudecode": {HILT: &own}}},
	}
	candidate := HILTConfig{Enabled: true, MinSeverity: "MEDIUM"}
	preview, err := c.PreviewConnectorHILT("claude-code", candidate)
	if err != nil {
		t.Fatal(err)
	}
	if preview.Connector != "claudecode" || preview.Base.Mode != "action" || preview.Base.HILT != candidate ||
		!preview.Base.FollowsConnectorHILT {
		t.Fatalf("base = %+v (connector %q), want action with the candidate HILT", preview.Base, preview.Connector)
	}
	want := map[string]HILTPreviewScope{
		"audit":      {Profile: "audit", Mode: "observe", HILT: candidate, FollowsConnectorHILT: true},
		"codex-only": {Profile: "codex-only", Mode: "action", HILT: candidate, FollowsConnectorHILT: true},
		"own":        {Profile: "own", Mode: "action", HILT: own},
		"own-conn":   {Profile: "own-conn", Mode: "action", HILT: own},
		"plain":      {Profile: "plain", Mode: "action", HILT: candidate, FollowsConnectorHILT: true},
		"quiet":      {Profile: "quiet", Mode: "observe", HILT: candidate, FollowsConnectorHILT: true},
	}
	if len(preview.Profiles) != len(want) {
		t.Fatalf("profiles = %+v", preview.Profiles)
	}
	for i, got := range preview.Profiles {
		if i > 0 && preview.Profiles[i-1].Profile >= got.Profile {
			t.Fatalf("profiles not sorted: %+v", preview.Profiles)
		}
		if got != want[got.Profile] {
			t.Errorf("profile %s = %+v, want %+v", got.Profile, got, want[got.Profile])
		}
	}
	same, err := c.PreviewConnectorHILT("claudecode", own)
	if err != nil {
		t.Fatal(err)
	}
	for _, got := range same.Profiles {
		if (got.Profile == "own" || got.Profile == "own-conn") && (got.FollowsConnectorHILT || got.HILT != own) {
			t.Errorf("profile %s with the same HILT as the saved one = %+v, want its own block", got.Profile, got)
		}
	}
	if c.Guardrail.Connectors["Claude-Code"].HILT != nil || c.ClaudeCode.Mode != "action" {
		t.Fatalf("preview changed the configuration: %+v", c.Guardrail.Connectors)
	}
}
