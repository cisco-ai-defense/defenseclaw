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

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

// ManagedEnterpriseDocument reports a config.yaml document whose
// deployment_mode is managed_enterprise, without loading the config.
func ManagedEnterpriseDocument(data []byte) bool {
	var doc struct {
		DeploymentMode string `yaml:"deployment_mode"`
	}
	return yaml.Unmarshal(data, &doc) == nil && managed.IsManagedEnterprise(doc.DeploymentMode)
}

// ConfiguredHookFailModeInDocument is the hook fail mode a config.yaml
// document sets explicitly for a per-user connector, resolved as the loaded
// config resolves it (configuredHookFailModeForConnector): the automatic
// protection overlay for a connector it covers (application_protection
// enabled and the connector not set up by hand), then the connector's
// guardrail.connectors entry, then guardrail.hook_fail_mode. It reads only
// those keys and the guardrail modes, so a native hook can check its sidecar
// against the config without loading it, and the installers' refresh can
// read a 0.8.x config this release does not load yet (0.8.10 resolved the
// overlay the same way). A Cursor open counts outside action mode only:
// action hooks are closed (the v9 migration closes that open too). It is ""
// when the document sets none or does not parse: callers treat "" as closed.
func ConfiguredHookFailModeInDocument(data []byte, connector string) string {
	type guardrailFailMode struct {
		Mode         string `yaml:"mode"`
		HookFailMode string `yaml:"hook_fail_mode"`
	}
	var doc struct {
		Claw struct {
			Mode string `yaml:"mode"`
		} `yaml:"claw"`
		Guardrail struct {
			Mode         string                       `yaml:"mode"`
			HookFailMode string                       `yaml:"hook_fail_mode"`
			Connector    string                       `yaml:"connector"`
			Connectors   map[string]guardrailFailMode `yaml:"connectors"`
		} `yaml:"guardrail"`
		ApplicationProtection struct {
			Enabled    bool              `yaml:"enabled"`
			Guardrail  guardrailFailMode `yaml:"guardrail"`
			Connectors map[string]struct {
				Guardrail guardrailFailMode `yaml:"guardrail"`
			} `yaml:"connectors"`
		} `yaml:"application_protection"`
	}
	if yaml.Unmarshal(data, &doc) != nil {
		return ""
	}
	c := &Config{
		Claw: ClawConfig{Mode: ClawMode(strings.TrimSpace(doc.Claw.Mode))},
		Guardrail: GuardrailConfig{
			Mode:         strings.TrimSpace(doc.Guardrail.Mode),
			HookFailMode: strings.TrimSpace(doc.Guardrail.HookFailMode),
			Connector:    strings.TrimSpace(doc.Guardrail.Connector),
		},
		ApplicationProtection: ApplicationProtectionConfig{
			Enabled: doc.ApplicationProtection.Enabled,
			Guardrail: PerConnectorGuardrailConfig{
				Mode:         doc.ApplicationProtection.Guardrail.Mode,
				HookFailMode: doc.ApplicationProtection.Guardrail.HookFailMode,
			},
		},
	}
	if len(doc.Guardrail.Connectors) > 0 {
		c.Guardrail.Connectors = make(map[string]PerConnectorGuardrailConfig, len(doc.Guardrail.Connectors))
		for name, entry := range doc.Guardrail.Connectors {
			c.Guardrail.Connectors[name] = PerConnectorGuardrailConfig{Mode: entry.Mode, HookFailMode: entry.HookFailMode}
		}
	}
	if len(doc.ApplicationProtection.Connectors) > 0 {
		c.ApplicationProtection.Connectors = make(map[string]ApplicationProtectionConnectorConfig, len(doc.ApplicationProtection.Connectors))
		for name, entry := range doc.ApplicationProtection.Connectors {
			c.ApplicationProtection.Connectors[name] = ApplicationProtectionConnectorConfig{Guardrail: PerConnectorGuardrailConfig{
				Mode: entry.Guardrail.Mode, HookFailMode: entry.Guardrail.HookFailMode,
			}}
		}
	}
	mode := c.configuredHookFailModeForConnector(connector)
	if mode == "open" && normalizeConnectorKey(connector) == "cursor" && cursorActionMode(c.EffectiveGuardrailModeForConnector(connector)) {
		return "closed"
	}
	return mode
}

// cursorActionMode reports a guardrail mode whose Cursor hooks block
// (action, or its legacy name enforce), as the hook renderer reads it.
func cursorActionMode(mode string) bool {
	mode = strings.TrimSpace(mode)
	return strings.EqualFold(mode, "action") || strings.EqualFold(mode, "enforce")
}
