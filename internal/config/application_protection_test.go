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

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func appFloatPtr(v float64) *float64 { return &v }
func appBoolPtr(v bool) *bool        { return &v }

func TestDefaultConfigApplicationProtection(t *testing.T) {
	cfg := DefaultConfig()
	if cfg.ApplicationProtection.Enabled {
		t.Fatal("DefaultConfig().ApplicationProtection.Enabled = true, want opt-in false")
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
	if cfg.ApplicationProtection.Guardrail.Mode != "observe" {
		t.Errorf("ApplicationProtection.Guardrail.Mode = %q, want observe", cfg.ApplicationProtection.Guardrail.Mode)
	}
	if cfg.ApplicationProtection.AssetPolicy.Mode != AssetPolicyModeObserve {
		t.Errorf("ApplicationProtection.AssetPolicy.Mode = %q, want observe", cfg.ApplicationProtection.AssetPolicy.Mode)
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
	cfg.ApplicationProtection.Enabled = true
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
	if got := cfg.EffectiveHookFailModeForConnector("codex"); got != "closed" {
		t.Errorf("EffectiveHookFailModeForConnector(codex) = %q, want closed on a per-user install", got)
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

func TestApplicationProtectionRulesSurviveLoadAndLayer(t *testing.T) {
	raw := []byte(`config_version: 9
guardrail:
  rules: {enable: [GLOBAL-RULE]}
  connectors:
    cursor: {rules: {enable: [MANUAL-RULE]}}
application_protection:
  enabled: true
  guardrail:
    rules: {enable: [AUTO-RULE]}
  connectors:
    codex:
      guardrail:
        rules: {disable: [CODEX-RULE]}
observability: {}
`)
	cfg, err := LoadRuntimeV8CandidateFromBytes("config.yaml", raw)
	if err != nil {
		t.Fatal(err)
	}
	if got := cfg.EffectiveRulesForConnector("codex"); len(got) != 3 ||
		len(got[0].Enable) != 1 || got[0].Enable[0] != "GLOBAL-RULE" ||
		len(got[1].Enable) != 1 || got[1].Enable[0] != "AUTO-RULE" ||
		len(got[2].Disable) != 1 || got[2].Disable[0] != "CODEX-RULE" {
		t.Errorf("automatic codex rules = %+v, want global, auto, connector layers", got)
	}
	if got := cfg.EffectiveRulesForConnector("claudecode"); len(got) != 2 ||
		len(got[1].Enable) != 1 || got[1].Enable[0] != "AUTO-RULE" {
		t.Errorf("automatic claudecode rules = %+v, want global and auto layers", got)
	}
	if got := cfg.EffectiveRulesForConnector("cursor"); len(got) != 2 ||
		len(got[1].Enable) != 1 || got[1].Enable[0] != "MANUAL-RULE" {
		t.Errorf("manual cursor rules = %+v, want global and manual layers", got)
	}
}

// Every managed connector follows the owner rule (2026-10-20): the
// administrator's explicit open wins on the standalone profile too, and
// under Secure Client the native Codex and Claude Code hooks take an
// explicit open like every other connector (#1163); an unmanaged install
// keeps the saved choice but runs its hooks closed.
func TestManagedEnterpriseNativeHookFailModesFollowTheAdministrator(t *testing.T) {
	cfg := &Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "standalone"}}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.HookFailMode = "open"
	cfg.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{
		"codex":      {HookFailMode: "open"},
		"claudecode": {HookFailMode: "open"},
		"cursor":     {HookFailMode: "open"},
	}
	for _, connector := range []string{"codex", "claudecode", "cursor"} {
		if got := cfg.EffectiveHookFailModeForConnector(connector); got != "open" {
			t.Errorf("standalone %s fail mode = %q, want the administrator's open", connector, got)
		}
	}

	cfg.Enterprise.Profile = "secure_client"
	for _, connector := range []string{"codex", "claudecode", "cursor"} {
		if got := cfg.EffectiveHookFailModeForConnector(connector); got != "open" {
			t.Errorf("secure client %s fail mode = %q, want the explicit open", connector, got)
		}
	}

	cfg.DeploymentMode = "unmanaged_byod"
	cfg.Enterprise.Profile = ""
	if got := cfg.EffectiveHookFailModeForConnector("claudecode"); got != "closed" {
		t.Errorf("unmanaged Claude fail mode = %q, want closed", got)
	}
}

func TestApplicationProtectionEffectiveMinConfidenceHonorsExplicitZero(t *testing.T) {
	cfg := DefaultApplicationProtectionConfig()
	cfg.MinConfidence = 0

	if got := cfg.EffectiveMinConfidence("codex"); got != 0 {
		t.Errorf("EffectiveMinConfidence(codex) = %v, want explicit zero", got)
	}
}

func TestApplicationProtectionAutomaticModesDefaultObserve(t *testing.T) {
	cfg := &Config{}
	cfg.Guardrail.Mode = "action"
	cfg.AssetPolicy.Mode = AssetPolicyModeAction
	cfg.ApplicationProtection = DefaultApplicationProtectionConfig()
	cfg.ApplicationProtection.Enabled = true

	if got := cfg.EffectiveGuardrailModeForConnector("codex"); got != "observe" {
		t.Errorf("EffectiveGuardrailModeForConnector(codex) = %q, want observe", got)
	}
	if got := cfg.EffectiveAssetPolicyModeForConnector("codex"); got != AssetPolicyModeObserve {
		t.Errorf("EffectiveAssetPolicyModeForConnector(codex) = %q, want observe", got)
	}
}

func TestApplicationProtectionTopLevelActionOptIn(t *testing.T) {
	cfg := &Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.AssetPolicy.Mode = AssetPolicyModeObserve
	cfg.ApplicationProtection = DefaultApplicationProtectionConfig()
	cfg.ApplicationProtection.Enabled = true
	cfg.ApplicationProtection.Guardrail.Mode = "action"
	cfg.ApplicationProtection.AssetPolicy.Mode = AssetPolicyModeAction

	if got := cfg.EffectiveGuardrailModeForConnector("codex"); got != "action" {
		t.Errorf("EffectiveGuardrailModeForConnector(codex) = %q, want action", got)
	}
	if got := cfg.EffectiveAssetPolicyModeForConnector("codex"); got != AssetPolicyModeAction {
		t.Errorf("EffectiveAssetPolicyModeForConnector(codex) = %q, want action", got)
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
		t.Errorf("manual connector fail mode should remain independent of observe mode, got %q", got)
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
	cfg.IncludeConnectors = []string{"codex", "CoDeX"}
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
	cfg.Enabled = true
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

// Standalone Devin runs the administrator-owned hook with
// --enterprise-managed, which takes its fail mode from the runtime
// descriptor the lifecycle writes from this value (owner decision
// 2026-10-20), so an administrator's hook_fail_mode open for Devin is open
// in the config, the lock, status and the hook alike. A per-user config may
// retain a saved open value but its hook runs closed.
func TestStandaloneDevinHookFailModeFollowsTheConfig(t *testing.T) {
	for _, test := range []struct {
		name, mode, profile, want string
	}{
		{"standalone", managed.DeploymentModeManagedEnterprise, managed.ProfileStandalone, "open"},
		{"secure client", managed.DeploymentModeManagedEnterprise, managed.ProfileSecureClient, "open"},
		{"per-user", "", "", "closed"},
	} {
		t.Run(test.name, func(t *testing.T) {
			cfg := &Config{DeploymentMode: test.mode}
			cfg.Enterprise.Profile = test.profile
			cfg.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{"devin": {HookFailMode: "open"}}
			if got := cfg.EffectiveHookFailModeForConnector("devin"); got != test.want {
				t.Fatalf("devin hook fail mode = %q, want %q", got, test.want)
			}
		})
	}
}

// TestSecureClientHookFailModesHonorPolicy keeps #1163 scoped to Secure
// Client: there an explicit policy wins for every connector (codex,
// claudecode and cursor included) and an unset policy resolves to open.
func TestSecureClientHookFailModesHonorPolicy(t *testing.T) {
	cfg := &Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "secure_client"}}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.HookFailMode = "open"
	cfg.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{
		"codex":      {HookFailMode: "open"},
		"claudecode": {HookFailMode: "open"},
		"cursor":     {HookFailMode: "open"},
	}
	if !cfg.SecureClientIntegration() {
		t.Fatal("test config does not resolve to Secure Client")
	}
	for _, connector := range []string{"codex", "claudecode", "cursor"} {
		if got := cfg.EffectiveHookFailModeForConnector(connector); got != "open" {
			t.Errorf("secure client %s fail mode = %q, want open", connector, got)
		}
		cfg.Guardrail.Connectors[connector] = PerConnectorGuardrailConfig{HookFailMode: "closed"}
		if got := cfg.EffectiveHookFailModeForConnector(connector); got != "closed" {
			t.Errorf("explicit secure client %s fail mode = %q, want closed", connector, got)
		}
		cfg.Guardrail.Connectors[connector] = PerConnectorGuardrailConfig{HookFailMode: "open"}
	}
}

// TestUnsetHookFailModeIsOpenOnlyUnderSecureClient is the owner rule: an
// unset hook fail mode is open under Secure Client and closed for OSS,
// standalone enterprise and every other managed install (Cursor outside
// Secure Client keeps its action->closed / observe->open rule). Explicit
// closed always wins.
func TestUnsetHookFailModeIsOpenOnlyUnderSecureClient(t *testing.T) {
	profiles := []struct {
		name, deploymentMode, profile string
		secureClient                  bool
	}{
		{"oss", "", "", false},
		{"unmanaged", "unmanaged_byod", "", false},
		{"standalone", "managed_enterprise", "standalone", false},
		{"secure_client", "managed_enterprise", "secure_client", true},
	}
	for _, p := range profiles {
		for _, connector := range []string{"codex", "claudecode", "amp", "devin"} {
			cfg := &Config{DeploymentMode: p.deploymentMode, Enterprise: EnterpriseConfig{Profile: p.profile}}
			cfg.Guardrail.Mode = "action"
			want := "closed"
			if p.secureClient {
				want = "open"
			}
			if got := cfg.EffectiveHookFailModeForConnector(connector); got != want {
				t.Errorf("%s/%s unset fail mode = %q, want %q", p.name, connector, got, want)
			}
			cfg.Guardrail.HookFailMode = "closed"
			if got := cfg.EffectiveHookFailModeForConnector(connector); got != "closed" {
				t.Errorf("%s/%s explicit closed fail mode = %q, want closed", p.name, connector, got)
			}
		}
	}

	// Secure Client resolves unset to open in observe mode too, and a
	// case-variant "Open" is open.
	sc := &Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "secure_client"}}
	for _, mode := range []string{"observe", "action"} {
		sc.Guardrail.Mode = mode
		sc.Guardrail.HookFailMode = ""
		if got := sc.EffectiveHookFailModeForConnector("cursor"); got != "open" {
			t.Errorf("secure client %s cursor unset fail mode = %q, want open", mode, got)
		}
		sc.Guardrail.HookFailMode = " Open "
		if got := sc.EffectiveHookFailModeForConnector("codex"); got != "open" {
			t.Errorf("secure client %s codex \"Open\" fail mode = %q, want open", mode, got)
		}
		sc.Guardrail.HookFailMode = "invalid"
		if got := sc.EffectiveHookFailModeForConnector("codex"); got != "closed" {
			t.Errorf("secure client %s codex invalid fail mode = %q, want closed", mode, got)
		}
	}

	// On a per-user install Cursor in action mode is closed even with an
	// explicit open (main's rule); on the standalone profile the
	// administrator's explicit open wins (owner decision 2026-10-20).
	perUser := &Config{}
	perUser.Guardrail.Mode = "action"
	perUser.Guardrail.HookFailMode = "open"
	if got := perUser.EffectiveHookFailModeForConnector("cursor"); got != "closed" {
		t.Errorf("per-user action cursor fail mode = %q, want closed", got)
	}
	standalone := &Config{DeploymentMode: "managed_enterprise", Enterprise: EnterpriseConfig{Profile: "standalone"}}
	standalone.Guardrail.Mode = "action"
	standalone.Guardrail.HookFailMode = "open"
	if got := standalone.EffectiveHookFailModeForConnector("cursor"); got != "open" {
		t.Errorf("standalone action cursor fail mode = %q, want the administrator's open", got)
	}
}
