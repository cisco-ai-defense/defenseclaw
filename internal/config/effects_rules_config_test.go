// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"strings"
	"testing"
)

// TestCascadeLanesDefaultIsShadow proves a config that never names
// guardrail.cascade.lanes loads with both lanes shipped as "shadow": the
// effect-model and secret-flow lanes compute and record beside today's rules
// without changing the answer.
func TestCascadeLanesDefaultIsShadow(t *testing.T) {
	cfg := DefaultConfig()
	if got := cfg.Guardrail.Cascade.Lanes.EffectsMode(); got != "shadow" {
		t.Fatalf("default effects lane = %q, want shadow", got)
	}
	if got := cfg.Guardrail.Cascade.Lanes.SecretFlowMode(); got != "shadow" {
		t.Fatalf("default secret_flow lane = %q, want shadow", got)
	}
	var empty CascadeLaneValues
	if empty.EffectsMode() != "shadow" || empty.SecretFlowMode() != "shadow" {
		t.Fatalf("an unset lane must read as its shipped default, got %q / %q", empty.EffectsMode(), empty.SecretFlowMode())
	}
}

// TestCascadeLanesSchemaEnum accepts the values a shadow-only lane takes in
// 1.0.10 (off, shadow), refuses "on" with the not-available message, and
// refuses any other value, so a typo cannot silently disable or enable a lane.
func TestCascadeLanesSchemaEnum(t *testing.T) {
	for _, lane := range []string{CascadeLaneEffects, CascadeLaneSecretFlow} {
		for _, value := range CascadeLaneAllowed(lane) {
			raw := []byte("config_version: 9\nguardrail:\n  cascade:\n    lanes:\n      " + lane + ": " + value + "\n")
			if err := ValidateCandidate(filepath.Join(t.TempDir(), DefaultConfigName), raw); err != nil {
				t.Fatalf("cascade.lanes.%s %s: ValidateCandidate() error = %v, want accept", lane, value, err)
			}
		}
		for _, value := range []string{"enabled", "true", "Shadow", "on"} {
			raw := []byte("config_version: 9\nguardrail:\n  cascade:\n    lanes:\n      " + lane + ": " + value + "\n")
			if err := ValidateCandidate(filepath.Join(t.TempDir(), DefaultConfigName), raw); err == nil ||
				!strings.Contains(err.Error(), lane) {
				t.Fatalf("cascade.lanes.%s %s: ValidateCandidate() error = %v, want a refusal naming the lane", lane, value, err)
			}
		}
	}
}

// TestCascadeLaneOnIsNotAvailable: a shadow-only lane refuses "on" with the
// message that names the release and the open gaps (decision D4).
func TestCascadeLaneOnIsNotAvailable(t *testing.T) {
	validate := func(lanes CascadeLaneValues) error {
		cfg := &Config{}
		cfg.Guardrail.Cascade.Lanes = lanes
		return cfg.ValidateCascade(false)
	}
	for _, lanes := range []CascadeLaneValues{{"effects": "on"}, {"secret_flow": "on"}} {
		err := validate(lanes)
		if err == nil || !strings.Contains(err.Error(), "not available in 1.0.10") || !strings.Contains(err.Error(), "GAP-0191") {
			t.Fatalf("ValidateCascade(%v) = %v, want a not-available-in-1.0.10 refusal naming the gaps", lanes, err)
		}
	}
	if err := validate(CascadeLaneValues{"effects": "maybe"}); err == nil {
		t.Fatalf("ValidateCascade accepted an unknown lane value")
	}
	if err := validate(CascadeLaneValues{"effects": "off", "secret_flow": "shadow"}); err != nil {
		t.Fatalf("ValidateCascade rejected off/shadow: %v", err)
	}
	// Process-wide lanes are top level only.
	cfg := &Config{}
	cfg.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{"codex": {Cascade: &CascadeScope{Lanes: CascadeLaneValues{"effects": "off"}}}}
	if err := cfg.ValidateCascade(false); err == nil || !strings.Contains(err.Error(), "process-wide") {
		t.Fatalf("a connector scope set the effects lane: %v", err)
	}
}

// TestOldLaneKeysAreGone: the unreleased guardrail.effects_rules and
// guardrail.secret_flow.mode keys moved under cascade.lanes and have no
// upgrade path (they never shipped), so the schema refuses them.
func TestOldLaneKeysAreGone(t *testing.T) {
	for _, body := range []string{"  effects_rules: shadow\n", "  secret_flow:\n    mode: shadow\n", "  secret_flow:\n    sink_action:\n      managed: block\n"} {
		raw := []byte("config_version: 9\nguardrail:\n" + body)
		if err := ValidateCandidate(filepath.Join(t.TempDir(), DefaultConfigName), raw); err == nil {
			t.Fatalf("ValidateCandidate accepted the removed key in %q", body)
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
