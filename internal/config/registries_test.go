// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"os"
	"path/filepath"
	"testing"
)

// TestLoadRegistriesFromYAML verifies the gateway can read a config
// produced by the Python CLI's `defenseclaw registry add`. The two
// sides serialise the same RegistrySource shape (mapstructure tags on
// Go, dataclass field order on Python); a regression here is a sign
// the lockstep contract has drifted.
func TestLoadRegistriesFromYAML(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", tmpDir)

	configFile := filepath.Join(tmpDir, DefaultConfigName)
	data := []byte(`registries:
  sources:
    - id: corp-skills
      kind: http_yaml
      url: https://catalog.example.com/skills.yaml
      content: skill
      auth_env: DEFENSECLAW_REGISTRY_TOKEN
      enabled: true
      sync_interval_hours: 12
    - id: smithery-public
      kind: smithery
      content: mcp
      enabled: false
`)
	if err := os.WriteFile(configFile, data, 0o600); err != nil {
		t.Fatalf("WriteFile: %v", err)
	}

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if got := len(cfg.Registries.Sources); got != 2 {
		t.Fatalf("len(Registries.Sources) = %d, want 2", got)
	}

	first := cfg.Registries.Sources[0]
	if first.ID != "corp-skills" {
		t.Errorf("Sources[0].ID = %q, want corp-skills", first.ID)
	}
	if first.Kind != "http_yaml" {
		t.Errorf("Sources[0].Kind = %q, want http_yaml", first.Kind)
	}
	if first.URL != "https://catalog.example.com/skills.yaml" {
		t.Errorf("Sources[0].URL = %q", first.URL)
	}
	if first.Content != "skill" {
		t.Errorf("Sources[0].Content = %q", first.Content)
	}
	if first.AuthEnv != "DEFENSECLAW_REGISTRY_TOKEN" {
		t.Errorf("Sources[0].AuthEnv = %q", first.AuthEnv)
	}
	if !first.Enabled {
		t.Error("Sources[0].Enabled should be true")
	}
	if first.SyncIntervalHours != 12 {
		t.Errorf("Sources[0].SyncIntervalHours = %d, want 12", first.SyncIntervalHours)
	}

	second := cfg.Registries.Sources[1]
	if second.ID != "smithery-public" {
		t.Errorf("Sources[1].ID = %q", second.ID)
	}
	if second.Kind != "smithery" {
		t.Errorf("Sources[1].Kind = %q", second.Kind)
	}
	if second.Enabled {
		t.Error("Sources[1].Enabled should be false")
	}
}

// TestLoadEmptyRegistriesIsZeroValue exercises the back-compat path —
// older configs without a `registries:` block must still load with an
// empty sources slice (not a parse error, not a panic).
func TestLoadEmptyRegistriesIsZeroValue(t *testing.T) {
	tmpDir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", tmpDir)

	cfg, err := Load()
	if err != nil {
		t.Fatalf("Load: %v", err)
	}
	if cfg.Registries.Sources == nil {
		// Sources is allowed to be nil OR an empty slice — both are
		// "no registries configured". Just assert len.
	}
	if got := len(cfg.Registries.Sources); got != 0 {
		t.Fatalf("expected zero registry sources, got %d", got)
	}
}

func TestIsKnownRegistryKind(t *testing.T) {
	cases := []struct {
		kind string
		want bool
	}{
		{"clawhub", true},
		{"  http_yaml  ", true}, // trim+lowercase tolerated
		{"HTTP_JSON", true},
		{"git", true},
		{"file", true},
		{"smithery", true},
		{"npm", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.kind, func(t *testing.T) {
			if got := IsKnownRegistryKind(tc.kind); got != tc.want {
				t.Errorf("IsKnownRegistryKind(%q) = %v, want %v",
					tc.kind, got, tc.want)
			}
		})
	}
}

func TestIsKnownRegistryContent(t *testing.T) {
	cases := []struct {
		content string
		want    bool
	}{
		{"skill", true},
		{"mcp", true},
		{"both", true},
		{"BOTH", true},
		{"plugin", false},
		{"", false},
	}
	for _, tc := range cases {
		t.Run(tc.content, func(t *testing.T) {
			if got := IsKnownRegistryContent(tc.content); got != tc.want {
				t.Errorf("IsKnownRegistryContent(%q) = %v, want %v",
					tc.content, got, tc.want)
			}
		})
	}
}

// TestPromotedRulesAttributedToRegistry asserts the asset-policy
// admission engine attributes a registry-promoted rule back to its
// source via AssetPolicyDecision.RegistrySource. Without this,
// the TUI cross-link badge and the gateway audit event have no way
// to point an operator at the source that promoted the asset.
func TestPromotedRulesAttributedToRegistry(t *testing.T) {
	cfg := &Config{AssetPolicy: DefaultAssetPolicy()}
	cfg.AssetPolicy.Enabled = true
	cfg.AssetPolicy.Mode = AssetPolicyModeAction
	cfg.AssetPolicy.Skill.Default = "deny"
	cfg.AssetPolicy.Skill.Registry = []AssetPolicyRule{{
		Name:   "demo-skill",
		Reason: "registry:corp-skills",
	}}

	decision := cfg.EvaluateAssetPolicy(AssetPolicyInput{
		TargetType: "skill",
		Name:       "demo-skill",
	})
	if decision.Action != "allow" {
		t.Fatalf("expected allow, got %q (raw=%q)",
			decision.Action, decision.RawAction)
	}
	if decision.Source != "registry" {
		t.Fatalf("Source = %q, want registry", decision.Source)
	}
	if decision.RegistrySource != "corp-skills" {
		t.Fatalf("RegistrySource = %q, want corp-skills", decision.RegistrySource)
	}
}

func TestParseRegistrySourceID(t *testing.T) {
	cases := []struct {
		in, want string
	}{
		{"registry:corp-skills", "corp-skills"},
		{"  registry:corp  ", "corp"},
		{"REGISTRY:corp", ""}, // case-sensitive prefix
		{"admin: trust me", ""},
		{"", ""},
	}
	for _, tc := range cases {
		t.Run(tc.in, func(t *testing.T) {
			if got := ParseRegistrySourceID(tc.in); got != tc.want {
				t.Errorf("ParseRegistrySourceID(%q) = %q, want %q",
					tc.in, got, tc.want)
			}
		})
	}
}
