// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"path/filepath"
	"slices"
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
	var empty CascadeLanes
	if empty.EffectsMode() != "shadow" || empty.SecretFlowMode() != "shadow" {
		t.Fatalf("an unset lane must read as its shipped default, got %q / %q", empty.EffectsMode(), empty.SecretFlowMode())
	}
}

// TestCascadeLanesSchemaEnum accepts the values each lane takes in 1.0.10 (a
// shadow-only lane: off, shadow; nonshell: off, shadow, on), in any case and
// trimmed, refuses "on" for a shadow-only lane, and refuses any other value,
// so a typo cannot silently disable or enable a lane.
func TestCascadeLanesSchemaEnum(t *testing.T) {
	for _, lane := range CascadeLaneNames() {
		allowed := CascadeLaneAllowed(lane)
		for _, value := range allowed {
			for _, spelling := range []string{value, strings.ToUpper(value), "' " + value + " '"} {
				raw := []byte("config_version: 9\nguardrail:\n  cascade:\n    lanes:\n      " + lane + ": " + spelling + "\n")
				if err := ValidateCandidate(filepath.Join(t.TempDir(), DefaultConfigName), raw); err != nil {
					t.Fatalf("cascade.lanes.%s %s: ValidateCandidate() error = %v, want accept", lane, spelling, err)
				}
			}
		}
		refused := []string{"enabled", "true", "onn", "''"}
		if !slices.Contains(allowed, "on") {
			refused = append(refused, "on", "ON")
		}
		for _, value := range refused {
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
	for _, c := range []CascadeConfig{
		{Lanes: CascadeLanes{Effects: "on"}},
		{Lanes: CascadeLanes{SecretFlow: "on"}},
	} {
		err := c.Validate()
		if err == nil || !strings.Contains(err.Error(), "not available in 1.0.10") || !strings.Contains(err.Error(), "GAP-0191") {
			t.Fatalf("Validate(%+v) = %v, want a not-available-in-1.0.10 refusal naming the gaps", c, err)
		}
	}
	if err := (CascadeConfig{Lanes: CascadeLanes{Effects: "maybe"}}).Validate(); err == nil {
		t.Fatalf("Validate accepted an unknown lane value")
	}
	if err := (CascadeConfig{Lanes: CascadeLanes{Effects: "off", SecretFlow: "shadow"}}).Validate(); err != nil {
		t.Fatalf("Validate rejected off/shadow: %v", err)
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
