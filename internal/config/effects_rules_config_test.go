// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestEffectsRulesDefaultIsShadow proves an upgraded config that never names
// guardrail.effects_rules loads with the shipped "shadow" default, so the
// effect-model lane computes verdicts beside today's without changing the
// answer until the lead flips it.
func TestEffectsRulesDefaultIsShadow(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.Guardrail.EffectsRules != "shadow" {
		t.Fatalf("default EffectsRules = %q, want shadow", cfg.Guardrail.EffectsRules)
	}
}

// TestEffectsRulesSchemaEnum accepts the three lane values and refuses any
// other, so a typo cannot silently disable or enable the lane.
func TestEffectsRulesSchemaEnum(t *testing.T) {
	for _, value := range []string{"off", "shadow", "on"} {
		raw := []byte("config_version: 9\nguardrail:\n  effects_rules: " + value + "\n")
		if err := ValidateCandidate(filepath.Join(t.TempDir(), DefaultConfigName), raw); err != nil {
			t.Fatalf("effects_rules %s: ValidateCandidate() error = %v, want accept", value, err)
		}
	}
	for _, value := range []string{"enabled", "true", "Shadow"} {
		raw := []byte("config_version: 9\nguardrail:\n  effects_rules: " + value + "\n")
		if err := ValidateCandidate(filepath.Join(t.TempDir(), DefaultConfigName), raw); err == nil ||
			!strings.Contains(err.Error(), "effects_rules") {
			t.Fatalf("effects_rules %s: ValidateCandidate() error = %v, want an effects_rules refusal", value, err)
		}
	}
}

// TestEffectsRulesTierDefaultAndEnum proves the tier ships restricted and the
// schema accepts only restricted|full.
func TestEffectsRulesTierDefaultAndEnum(t *testing.T) {
	if cfg := DefaultConfig(); cfg.Guardrail.EffectsRulesTier != "restricted" {
		t.Fatalf("default EffectsRulesTier = %q, want restricted", cfg.Guardrail.EffectsRulesTier)
	}
	for _, value := range []string{"restricted", "full"} {
		raw := []byte("config_version: 9\nguardrail:\n  effects_rules_tier: " + value + "\n")
		if err := ValidateCandidate(filepath.Join(t.TempDir(), DefaultConfigName), raw); err != nil {
			t.Fatalf("effects_rules_tier %s: ValidateCandidate() = %v, want accept", value, err)
		}
	}
	for _, value := range []string{"both", "Restricted", "none"} {
		raw := []byte("config_version: 9\nguardrail:\n  effects_rules_tier: " + value + "\n")
		if err := ValidateCandidate(filepath.Join(t.TempDir(), DefaultConfigName), raw); err == nil ||
			!strings.Contains(err.Error(), "effects_rules_tier") {
			t.Fatalf("effects_rules_tier %s: ValidateCandidate() = %v, want refusal", value, err)
		}
	}
}
