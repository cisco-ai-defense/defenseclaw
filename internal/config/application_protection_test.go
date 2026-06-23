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
	"strings"
	"testing"
)

func appFloatPtr(v float64) *float64 { return &v }
func appBoolPtr(v bool) *bool        { return &v }

func TestDefaultConfigApplicationProtection(t *testing.T) {
	cfg := DefaultConfig()
	if !cfg.ApplicationProtection.Enabled {
		t.Fatal("DefaultConfig().ApplicationProtection.Enabled = false, want true")
	}
	if cfg.ApplicationProtection.MinConfidence != DefaultApplicationProtectionMinConfidence {
		t.Errorf("MinConfidence = %v, want %v", cfg.ApplicationProtection.MinConfidence, DefaultApplicationProtectionMinConfidence)
	}
	if cfg.ApplicationProtection.RemoveWhenGone {
		t.Error("RemoveWhenGone = true, want false")
	}
	if cfg.ApplicationProtection.GoneAfterMin != DefaultApplicationProtectionGoneAfterMin {
		t.Errorf("GoneAfterMin = %d, want %d", cfg.ApplicationProtection.GoneAfterMin, DefaultApplicationProtectionGoneAfterMin)
	}
}

func TestApplicationProtectionPolicyOverlay(t *testing.T) {
	cfg := &Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.HookFailMode = "closed"
	cfg.Guardrail.BlockMessage = "global block"
	cfg.Guardrail.RulePackDir = "/global/default"
	cfg.Guardrail.HILT = HILTConfig{Enabled: false, MinSeverity: "HIGH"}
	cfg.AssetPolicy.Mode = AssetPolicyModeObserve
	cfg.ApplicationProtection = DefaultApplicationProtectionConfig()
	cfg.ApplicationProtection.Connectors = map[string]ApplicationProtectionConnectorConfig{
		"codex": {
			MinConfidence: appFloatPtr(0.91),
			Guardrail: PerConnectorGuardrailConfig{
				Mode:         "action",
				HookFailMode: "open",
				BlockMessage: "auto block",
				RulePackDir:  "/profiles/strict",
				HILT:         &HILTConfig{Enabled: true, MinSeverity: "LOW"},
			},
			AssetPolicy: ApplicationProtectionAssetPolicyConfig{Mode: AssetPolicyModeAction},
		},
	}

	if got := cfg.ApplicationProtection.EffectiveMinConfidence("codex"); got != 0.91 {
		t.Errorf("EffectiveMinConfidence(codex) = %v, want 0.91", got)
	}
	if got := cfg.EffectiveGuardrailModeForConnector("codex"); got != "action" {
		t.Errorf("EffectiveGuardrailModeForConnector(codex) = %q, want action", got)
	}
	if got := cfg.EffectiveHookFailModeForConnector("codex"); got != "open" {
		t.Errorf("EffectiveHookFailModeForConnector(codex) = %q, want open", got)
	}
	if got := cfg.EffectiveBlockMessageForConnector("codex"); got != "auto block" {
		t.Errorf("EffectiveBlockMessageForConnector(codex) = %q, want auto block", got)
	}
	if got := cfg.EffectiveRulePackDirForConnector("codex"); got != "/profiles/strict" {
		t.Errorf("EffectiveRulePackDirForConnector(codex) = %q, want /profiles/strict", got)
	}
	if got := cfg.EffectiveHILTForConnector("codex"); !got.Enabled || got.MinSeverity != "LOW" {
		t.Errorf("EffectiveHILTForConnector(codex) = %+v, want enabled LOW", got)
	}
	if got := cfg.EffectiveAssetPolicyModeForConnector("codex"); got != AssetPolicyModeAction {
		t.Errorf("EffectiveAssetPolicyModeForConnector(codex) = %q, want action", got)
	}
}

func TestApplicationProtectionEffectiveMinConfidenceHonorsExplicitZero(t *testing.T) {
	cfg := DefaultApplicationProtectionConfig()
	cfg.MinConfidence = 0

	if got := cfg.EffectiveMinConfidence("codex"); got != 0 {
		t.Errorf("EffectiveMinConfidence(codex) = %v, want explicit zero", got)
	}
}

func TestApplicationProtectionManualGuardrailPrecedence(t *testing.T) {
	cfg := &Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{
		"codex": {
			Mode:         "observe",
			HookFailMode: "closed",
			BlockMessage: "manual block",
			RulePackDir:  "/manual",
		},
	}
	cfg.ApplicationProtection = DefaultApplicationProtectionConfig()
	cfg.ApplicationProtection.Connectors = map[string]ApplicationProtectionConnectorConfig{
		"codex": {
			Guardrail: PerConnectorGuardrailConfig{
				Mode:         "action",
				HookFailMode: "open",
				BlockMessage: "auto block",
				RulePackDir:  "/auto",
			},
		},
	}

	if !cfg.ManualConnectorConfigured("codex") {
		t.Fatal("ManualConnectorConfigured(codex) = false, want true")
	}
	if got := cfg.EffectiveGuardrailModeForConnector("codex"); got != "observe" {
		t.Errorf("manual mode should win, got %q", got)
	}
	if got := cfg.EffectiveHookFailModeForConnector("codex"); got != "closed" {
		t.Errorf("manual hook fail mode should win, got %q", got)
	}
	if got := cfg.EffectiveBlockMessageForConnector("codex"); got != "manual block" {
		t.Errorf("manual block message should win, got %q", got)
	}
	if got := cfg.EffectiveRulePackDirForConnector("codex"); got != "/manual" {
		t.Errorf("manual rule pack should win, got %q", got)
	}
}

func TestApplicationProtectionValidateRejectsBadValues(t *testing.T) {
	cfg := DefaultApplicationProtectionConfig()
	cfg.MinConfidence = 1.25
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "min_confidence") {
		t.Fatalf("Validate invalid confidence = %v, want min_confidence error", err)
	}

	cfg = DefaultApplicationProtectionConfig()
	cfg.IncludeConnectors = []string{"open-hands", "openhands"}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "same connector") {
		t.Fatalf("Validate duplicate include = %v, want duplicate connector error", err)
	}

	cfg = DefaultApplicationProtectionConfig()
	cfg.Connectors = map[string]ApplicationProtectionConnectorConfig{
		"codex": {AssetPolicy: ApplicationProtectionAssetPolicyConfig{Mode: "block"}},
	}
	if err := cfg.Validate(); err == nil || !strings.Contains(err.Error(), "asset_policy") {
		t.Fatalf("Validate invalid asset mode = %v, want asset_policy error", err)
	}
}

func TestApplicationProtectionEffectiveEnabled(t *testing.T) {
	cfg := DefaultApplicationProtectionConfig()
	cfg.Connectors = map[string]ApplicationProtectionConnectorConfig{
		"codex": {Enabled: appBoolPtr(false)},
	}
	if cfg.EffectiveEnabled("codex") {
		t.Error("EffectiveEnabled(codex) = true, want false")
	}
	if !cfg.EffectiveEnabled("cursor") {
		t.Error("EffectiveEnabled(cursor) = false, want true")
	}
}
