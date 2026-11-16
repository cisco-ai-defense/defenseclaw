// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"sort"
	"strings"
)

// NormalizeHookMode maps a configured mode to the two hook modes: "action"
// (or its alias "enforce") is action, everything else observe.
func NormalizeHookMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "action", "enforce":
		return "action"
	default:
		return "observe"
	}
}

// HookModeForConnector is the hook mode the gateway gives connector's calls
// in c: the legacy per-connector hook mode (claude_code.mode, codex.mode,
// connector_hooks.<c>.mode) when set, else the guardrail chain
// (EffectiveGuardrailModeForConnector). On a configuration derived for a
// guardrail profile that sets a mode, the profile cleared the legacy hook
// mode, so the profile's mode decides (applyGuardrailProfile).
func (c *Config) HookModeForConnector(name string) string {
	if c == nil {
		return "observe"
	}
	mode := strings.TrimSpace(c.ConnectorHookConfig(name).Mode)
	if mode == "" || strings.EqualFold(mode, "inherit") {
		mode = c.EffectiveGuardrailModeForConnector(name)
	}
	return NormalizeHookMode(mode)
}

// HILTPreviewScope is the hook mode and HILT block one set of accounts gets
// for a connector: the accounts no guardrail profile matches (Profile "")
// or the accounts of one profile. FollowsConnectorHILT is false when the
// profile's own HILT block replaces the connector's, so saving the
// connector's does not change what its accounts get.
type HILTPreviewScope struct {
	Profile              string
	Mode                 string
	HILT                 HILTConfig
	FollowsConnectorHILT bool
}

// ConnectorHILTPreview is what saving hilt as connector's own HILT block
// does: the scope of the accounts no profile matches, then one scope per
// guardrail profile, sorted by name.
type ConnectorHILTPreview struct {
	Connector string
	Base      HILTPreviewScope
	Profiles  []HILTPreviewScope
}

// PreviewConnectorHILT resolves, without changing c, the hook mode and HILT
// the gateway would give connector's calls once hilt is saved as
// guardrail.connectors[connector].hilt. It uses the resolvers the hook path
// uses (HookModeForConnector, EffectiveHILTForConnector) on c and on the
// configuration derived for each guardrail profile. Whether a scope follows
// the connector's block is resolved the same way: with the opposite enabled
// value saved instead, a scope whose HILT does not change has its own.
func (c *Config) PreviewConnectorHILT(connector string, hilt HILTConfig) (ConnectorHILTPreview, error) {
	key := normalizeConnectorKey(connector)
	preview := ConnectorHILTPreview{Connector: key, Profiles: []HILTPreviewScope{}}
	if c == nil {
		return preview, nil
	}
	base, err := withConnectorHILT(c, key, hilt)
	if err != nil {
		return preview, err
	}
	probe := hilt
	probe.Enabled = !hilt.Enabled
	alt, err := withConnectorHILT(c, key, probe)
	if err != nil {
		return preview, err
	}
	scope := func(profile string, cfg, altCfg *Config) HILTPreviewScope {
		resolved := cfg.EffectiveHILTForConnector(key)
		return HILTPreviewScope{
			Profile:              profile,
			Mode:                 cfg.HookModeForConnector(key),
			HILT:                 resolved,
			FollowsConnectorHILT: resolved != altCfg.EffectiveHILTForConnector(key),
		}
	}
	preview.Base = scope("", base, alt)
	names := make([]string, 0, len(base.Guardrail.Profiles))
	for name := range base.Guardrail.Profiles {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		profile := base.Guardrail.Profiles[name]
		preview.Profiles = append(preview.Profiles,
			scope(name, deriveProfileFrom(base, profile), deriveProfileFrom(alt, profile)))
	}
	return preview, nil
}

// withConnectorHILT is a private copy of c with hilt saved as connector's
// own HILT block (the entry whose name normalizes to connector, else a new
// one).
func withConnectorHILT(c *Config, connector string, hilt HILTConfig) (*Config, error) {
	out, err := copyConfigSharingProfiles(c)
	if err != nil {
		return nil, err
	}
	entryKey := connector
	for name := range out.Guardrail.Connectors {
		if normalizeConnectorKey(name) == connector {
			entryKey = name
			break
		}
	}
	if out.Guardrail.Connectors == nil {
		out.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{}
	}
	entry := out.Guardrail.Connectors[entryKey]
	entry.HILT = &hilt
	out.Guardrail.Connectors[entryKey] = entry
	return out, nil
}
