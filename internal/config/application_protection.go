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
	"fmt"
	"sort"
	"strings"
)

const (
	DefaultApplicationProtectionMinConfidence = 0.80
	DefaultApplicationProtectionGoneAfterMin  = 60
)

// ApplicationProtectionConfig controls automatic hook-native connector
// activation from AI-discovery supported_connector signals. It is an overlay
// on top of the existing manual setup / guardrail / asset-policy control
// plane: manual guardrail.connectors entries remain authoritative, while
// discovered connectors may inherit global policy or opt into a per-connector
// application_protection override.
type ApplicationProtectionConfig struct {
	Enabled           bool                                            `mapstructure:"enabled"            yaml:"enabled"`
	MinConfidence     float64                                         `mapstructure:"min_confidence"     yaml:"min_confidence"`
	RemoveWhenGone    bool                                            `mapstructure:"remove_when_gone"   yaml:"remove_when_gone"`
	GoneAfterMin      int                                             `mapstructure:"gone_after_min"     yaml:"gone_after_min"`
	IncludeConnectors []string                                        `mapstructure:"include_connectors" yaml:"include_connectors,omitempty"`
	ExcludeConnectors []string                                        `mapstructure:"exclude_connectors" yaml:"exclude_connectors,omitempty"`
	Guardrail         PerConnectorGuardrailConfig                     `mapstructure:"guardrail"          yaml:"guardrail,omitempty"`
	AssetPolicy       ApplicationProtectionAssetPolicyConfig          `mapstructure:"asset_policy"       yaml:"asset_policy,omitempty"`
	Connectors        map[string]ApplicationProtectionConnectorConfig `mapstructure:"connectors"         yaml:"connectors,omitempty"`
}

// ApplicationProtectionConnectorConfig is the per-connector automatic
// protection overlay. Empty fields inherit from the global application
// protection block and the existing guardrail / asset_policy blocks.
type ApplicationProtectionConnectorConfig struct {
	Enabled       *bool                                  `mapstructure:"enabled"        yaml:"enabled,omitempty"`
	MinConfidence *float64                               `mapstructure:"min_confidence" yaml:"min_confidence,omitempty"`
	Guardrail     PerConnectorGuardrailConfig            `mapstructure:"guardrail"      yaml:"guardrail,omitempty"`
	AssetPolicy   ApplicationProtectionAssetPolicyConfig `mapstructure:"asset_policy"  yaml:"asset_policy,omitempty"`
}

// ApplicationProtectionAssetPolicyConfig intentionally carries only the mode
// override requested for automatic protection. Full asset allow/deny/registry
// policy remains owned by asset_policy.
type ApplicationProtectionAssetPolicyConfig struct {
	Mode string `mapstructure:"mode" yaml:"mode,omitempty"`
}

// DefaultApplicationProtectionConfig returns the fresh-install defaults used
// by both DefaultConfig() and viper defaults.
func DefaultApplicationProtectionConfig() ApplicationProtectionConfig {
	return ApplicationProtectionConfig{
		// Automatic connector activation mutates third-party agent config. Keep
		// it opt-in so upgrading an unmanaged/OSS install does not start writing
		// hooks merely because AI discovery recognized a local agent.
		Enabled:        false,
		MinConfidence:  DefaultApplicationProtectionMinConfidence,
		RemoveWhenGone: false,
		GoneAfterMin:   DefaultApplicationProtectionGoneAfterMin,
		Guardrail: PerConnectorGuardrailConfig{
			Mode: "observe",
		},
		AssetPolicy: ApplicationProtectionAssetPolicyConfig{
			Mode: AssetPolicyModeObserve,
		},
	}
}

func (a *ApplicationProtectionConfig) connectorOverride(connector string) (ApplicationProtectionConnectorConfig, bool) {
	if a == nil || connector == "" || len(a.Connectors) == 0 {
		return ApplicationProtectionConnectorConfig{}, false
	}
	if pc, ok := a.Connectors[connector]; ok {
		return pc, true
	}
	want := normalizeConnectorKey(connector)
	if want == "" {
		return ApplicationProtectionConnectorConfig{}, false
	}
	for name, pc := range a.Connectors {
		if normalizeConnectorKey(name) == want {
			return pc, true
		}
	}
	return ApplicationProtectionConnectorConfig{}, false
}

// EffectiveMinConfidence resolves the confidence threshold for a connector.
func (a *ApplicationProtectionConfig) EffectiveMinConfidence(connector string) float64 {
	if a == nil {
		return DefaultApplicationProtectionMinConfidence
	}
	if pc, ok := a.connectorOverride(connector); ok && pc.MinConfidence != nil {
		return *pc.MinConfidence
	}
	if a.MinConfidence >= 0 {
		return a.MinConfidence
	}
	return DefaultApplicationProtectionMinConfidence
}

// EffectiveEnabled resolves the per-connector automatic-protection switch.
func (a *ApplicationProtectionConfig) EffectiveEnabled(connector string) bool {
	if a == nil || !a.Enabled {
		return false
	}
	if pc, ok := a.connectorOverride(connector); ok && pc.Enabled != nil {
		return *pc.Enabled
	}
	return true
}

// AllowsConnector applies include/exclude filters. Exclude wins over include;
// an empty include list means "all supported hook-native connectors".
func (a *ApplicationProtectionConfig) AllowsConnector(connector string) bool {
	name := normalizeConnectorKey(connector)
	if name == "" {
		return false
	}
	for _, raw := range a.ExcludeConnectors {
		if normalizeConnectorKey(raw) == name {
			return false
		}
	}
	if len(a.IncludeConnectors) == 0 {
		return true
	}
	for _, raw := range a.IncludeConnectors {
		if normalizeConnectorKey(raw) == name {
			return true
		}
	}
	return false
}

// Validate checks automatic-protection value invariants. It deliberately does
// not validate connector identity against the runtime registry; unknown
// connector names are surfaced by the gateway controller with a skipped reason.
func (a *ApplicationProtectionConfig) Validate() error {
	if a == nil {
		return nil
	}
	if err := validateConfidence("application_protection.min_confidence", a.MinConfidence); err != nil {
		return err
	}
	if a.GoneAfterMin < 0 {
		return fmt.Errorf("application_protection.gone_after_min must be >= 0")
	}
	if err := validateConnectorList("application_protection.include_connectors", a.IncludeConnectors); err != nil {
		return err
	}
	if err := validateConnectorList("application_protection.exclude_connectors", a.ExcludeConnectors); err != nil {
		return err
	}
	if err := validateGuardrailMode(a.Guardrail.Mode); err != nil {
		return fmt.Errorf("application_protection.guardrail: %w", err)
	}
	if err := validateGuardrailHookFailMode(a.Guardrail.HookFailMode); err != nil {
		return fmt.Errorf("application_protection.guardrail: %w", err)
	}
	if a.Guardrail.HILT != nil {
		if err := validateGuardrailMinSeverity(a.Guardrail.HILT.MinSeverity); err != nil {
			return fmt.Errorf("application_protection.guardrail: %w", err)
		}
	}
	if err := validateAssetPolicyMode(a.AssetPolicy.Mode); err != nil {
		return fmt.Errorf("application_protection.asset_policy: %w", err)
	}

	names := make([]string, 0, len(a.Connectors))
	for name := range a.Connectors {
		names = append(names, name)
	}
	sort.Strings(names)
	seen := make(map[string]string, len(names))
	for _, name := range names {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("application_protection.connectors: empty connector name is not allowed")
		}
		norm := normalizeConnectorKey(name)
		if prev, dup := seen[norm]; dup {
			return fmt.Errorf("application_protection.connectors: %q and %q refer to the same connector %q; keep only one", prev, name, norm)
		}
		seen[norm] = name
	}
	for _, name := range names {
		pc := a.Connectors[name]
		if pc.MinConfidence != nil {
			if err := validateConfidence(fmt.Sprintf("application_protection.connectors[%q].min_confidence", name), *pc.MinConfidence); err != nil {
				return err
			}
		}
		if err := validateGuardrailMode(pc.Guardrail.Mode); err != nil {
			return fmt.Errorf("application_protection.connectors[%q].guardrail: %w", name, err)
		}
		if err := validateGuardrailHookFailMode(pc.Guardrail.HookFailMode); err != nil {
			return fmt.Errorf("application_protection.connectors[%q].guardrail: %w", name, err)
		}
		if pc.Guardrail.HILT != nil {
			if err := validateGuardrailMinSeverity(pc.Guardrail.HILT.MinSeverity); err != nil {
				return fmt.Errorf("application_protection.connectors[%q].guardrail: %w", name, err)
			}
		}
		if err := validateAssetPolicyMode(pc.AssetPolicy.Mode); err != nil {
			return fmt.Errorf("application_protection.connectors[%q].asset_policy: %w", name, err)
		}
	}
	return nil
}

func validateConnectorList(path string, names []string) error {
	seen := map[string]string{}
	for _, name := range names {
		if strings.TrimSpace(name) == "" {
			return fmt.Errorf("%s: empty connector name is not allowed", path)
		}
		norm := normalizeConnectorKey(name)
		if prev, dup := seen[norm]; dup {
			return fmt.Errorf("%s: %q and %q refer to the same connector %q; keep only one", path, prev, name, norm)
		}
		seen[norm] = name
	}
	return nil
}

func validateConfidence(path string, v float64) error {
	if v < 0 || v > 1 {
		return fmt.Errorf("%s must be between 0 and 1", path)
	}
	return nil
}

func validateAssetPolicyMode(mode string) error {
	switch strings.TrimSpace(mode) {
	case "", AssetPolicyModeObserve, AssetPolicyModeAction:
		return nil
	default:
		return fmt.Errorf("invalid asset_policy mode %q (want \"observe\" or \"action\")", mode)
	}
}

func (c *Config) manualConnectorConfigured(connector string) bool {
	if c == nil {
		return false
	}
	want := normalizeConnectorKey(connector)
	if want == "" {
		return false
	}
	for _, name := range c.ActiveConnectors() {
		if normalizeConnectorKey(name) == want {
			return true
		}
	}
	return false
}

// ManualConnectorConfigured reports whether a connector is part of the manual
// setup control plane (guardrail.connectors, guardrail.connector, or claw.mode).
func (c *Config) ManualConnectorConfigured(connector string) bool {
	return c.manualConnectorConfigured(connector)
}

func (c *Config) appProtectionGuardrailOverride(connector string) (PerConnectorGuardrailConfig, bool) {
	if c == nil || !c.ApplicationProtection.Enabled || c.manualConnectorConfigured(connector) {
		return PerConnectorGuardrailConfig{}, false
	}
	if pc, ok := c.ApplicationProtection.connectorOverride(connector); ok {
		return pc.Guardrail, true
	}
	return c.ApplicationProtection.Guardrail, true
}

// EffectiveGuardrailModeForConnector resolves manual per-connector guardrail
// config first, then automatic-protection guardrail overrides, then global
// guardrail mode.
func (c *Config) EffectiveGuardrailModeForConnector(connector string) string {
	if c == nil {
		return "observe"
	}
	if pc, ok := c.appProtectionGuardrailOverride(connector); ok {
		if m := strings.TrimSpace(pc.Mode); m != "" {
			return m
		}
		return "observe"
	}
	return c.Guardrail.EffectiveMode(connector)
}

func (c *Config) EffectiveGuardrailEnabledForConnector(connector string) bool {
	if c == nil {
		return true
	}
	if c.manualConnectorConfigured(connector) {
		return c.Guardrail.EffectiveEnabled(connector)
	}
	return c.ApplicationProtection.EffectiveEnabled(connector)
}

func (c *Config) EffectiveHILTForConnector(connector string) HILTConfig {
	if c == nil {
		return HILTConfig{}
	}
	if pc, ok := c.appProtectionGuardrailOverride(connector); ok && pc.HILT != nil {
		return *pc.HILT
	}
	return c.Guardrail.EffectiveHILT(connector)
}

func (c *Config) EffectiveBlockMessageForConnector(connector string) string {
	if c == nil {
		return ""
	}
	if pc, ok := c.appProtectionGuardrailOverride(connector); ok && pc.BlockMessage != "" {
		return pc.BlockMessage
	}
	return c.Guardrail.EffectiveBlockMessage(connector)
}

func (c *Config) EffectiveRulePackDirForConnector(connector string) string {
	if c == nil {
		return ""
	}
	if pc, ok := c.appProtectionGuardrailOverride(connector); ok {
		if strings.TrimSpace(pc.RulePackDir) != "" {
			return pc.RulePackDir
		}
	}
	return c.Guardrail.EffectiveRulePackDir(connector)
}

func (c *Config) EffectiveHookFailModeForConnector(connector string) string {
	if c == nil {
		return "closed"
	}
	if !strings.EqualFold(strings.TrimSpace(c.EffectiveGuardrailModeForConnector(connector)), "action") {
		return "open"
	}
	if pc, ok := c.appProtectionGuardrailOverride(connector); ok {
		if strings.TrimSpace(pc.HookFailMode) != "" {
			if strings.EqualFold(strings.TrimSpace(pc.HookFailMode), "open") {
				return "open"
			}
			return "closed"
		}
	}
	return c.Guardrail.EffectiveHookFailModeFor(connector)
}

// EffectiveAssetPolicyModeForConnector resolves static asset_policy connector
// overrides first, then automatic-protection connector mode, then the global
// asset_policy mode.
func (c *Config) EffectiveAssetPolicyModeForConnector(connector string) string {
	if c == nil {
		return AssetPolicyModeObserve
	}
	if pc, ok := c.AssetPolicy.connectorOverride(connector); ok {
		if m := strings.TrimSpace(pc.Mode); m != "" {
			return m
		}
	}
	if !c.ApplicationProtection.Enabled || c.manualConnectorConfigured(connector) {
		if m := strings.TrimSpace(c.AssetPolicy.Mode); m != "" {
			return m
		}
		return AssetPolicyModeObserve
	}
	if pc, ok := c.ApplicationProtection.connectorOverride(connector); ok {
		if m := strings.TrimSpace(pc.AssetPolicy.Mode); m != "" {
			return m
		}
	}
	if m := strings.TrimSpace(c.ApplicationProtection.AssetPolicy.Mode); m != "" {
		return m
	}
	return AssetPolicyModeObserve
}
