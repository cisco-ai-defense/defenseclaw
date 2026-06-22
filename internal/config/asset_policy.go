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
	"path/filepath"
	"strings"
)

const (
	AssetPolicyModeObserve = "observe"
	AssetPolicyModeAction  = "action"
)

// AssetPolicyConfig is the operator-controlled allow/deny/registry gate for
// install-time and runtime assets. The global per-type policies share the same
// decision ordering across MCP servers, skills, and plugins; per-connector
// scalar overrides (mode + default / registry_required / registry_empty_action)
// live in Connectors so a multi-connector install can, e.g., enforce on codex
// while only observing on hermes.
type AssetPolicyConfig struct {
	Enabled bool            `mapstructure:"enabled" yaml:"enabled"`
	Mode    string          `mapstructure:"mode"    yaml:"mode"`
	MCP     AssetTypePolicy `mapstructure:"mcp"     yaml:"mcp"`
	Skill   AssetTypePolicy `mapstructure:"skill"   yaml:"skill"`
	Plugin  AssetTypePolicy `mapstructure:"plugin"  yaml:"plugin"`
	// Connectors holds per-connector asset_policy overrides keyed by
	// connector name (OTHER-7). An empty/absent map preserves the legacy
	// global-only behavior. Only the scalar settings are per-connector;
	// the rule lists (registry/allowed/denied) and runtime_detection stay
	// on the global per-type policy and are filtered by AssetPolicyRule.Connector
	// at match time. Resolution goes through EffectiveMode / EffectiveAssetTypePolicy,
	// never by reading the map directly. Mirrors AssetPolicyConfig.connectors in
	// cli/defenseclaw/config.py and the guardrail.connectors pattern.
	Connectors map[string]PerConnectorAssetPolicy `mapstructure:"connectors" yaml:"connectors,omitempty"`
}

// PerConnectorAssetPolicy carries the subset of asset_policy that an operator
// may override on a single connector. Every field is optional: an empty Mode
// inherits the global AssetPolicyConfig.Mode, and a nil per-type block inherits
// the global per-type policy entirely. Resolution goes through the Effective*
// methods. Mirrors PerConnectorAssetPolicy in cli/defenseclaw/config.py.
type PerConnectorAssetPolicy struct {
	Mode   string                       `mapstructure:"mode"   yaml:"mode,omitempty"`
	MCP    *PerConnectorAssetTypePolicy `mapstructure:"mcp"    yaml:"mcp,omitempty"`
	Skill  *PerConnectorAssetTypePolicy `mapstructure:"skill"  yaml:"skill,omitempty"`
	Plugin *PerConnectorAssetTypePolicy `mapstructure:"plugin" yaml:"plugin,omitempty"`
}

// PerConnectorAssetTypePolicy holds the per-connector scalar overrides for one
// asset type. Scalars only: an empty Default / RegistryEmptyAction or a nil
// RegistryRequired pointer inherits the global AssetTypePolicy value (the
// pointer mirrors guardrail's *bool inherit-on-nil semantics). Rule lists and
// runtime_detection are never per-connector.
type PerConnectorAssetTypePolicy struct {
	Default             string `mapstructure:"default"               yaml:"default,omitempty"`
	RegistryRequired    *bool  `mapstructure:"registry_required"     yaml:"registry_required,omitempty"`
	RegistryEmptyAction string `mapstructure:"registry_empty_action" yaml:"registry_empty_action,omitempty"`
}

type AssetTypePolicy struct {
	Default          string `mapstructure:"default"           yaml:"default"`
	RegistryRequired bool   `mapstructure:"registry_required" yaml:"registry_required"`
	// RegistryEmptyAction selects the failure mode when RegistryRequired is
	// true but Registry is empty (e.g., the operator hasn't populated the
	// allowlist yet, or YAML parse silently produced zero rules). It is
	// deliberately fail-closed by default ("deny") so that an empty
	// registry behaves like "no asset is approved" rather than silently
	// disabling the requirement. Set to "allow" to opt into the looser
	// behavior of falling through to Default when the registry is empty.
	RegistryEmptyAction string                `mapstructure:"registry_empty_action" yaml:"registry_empty_action,omitempty"`
	Registry            []AssetPolicyRule     `mapstructure:"registry"              yaml:"registry"`
	Allowed             []AssetPolicyRule     `mapstructure:"allowed"               yaml:"allowed"`
	Denied              []AssetPolicyRule     `mapstructure:"denied"                yaml:"denied"`
	RuntimeDetection    AssetRuntimeDetection `mapstructure:"runtime_detection"     yaml:"runtime_detection,omitempty"`
}

const (
	registryEmptyActionDeny  = "deny"
	registryEmptyActionAllow = "allow"
)

type AssetRuntimeDetection struct {
	Enabled            bool   `mapstructure:"enabled"              yaml:"enabled"`
	TerminalCommands   bool   `mapstructure:"terminal_commands"    yaml:"terminal_commands"`
	UnknownTerminalMCP string `mapstructure:"unknown_terminal_mcp" yaml:"unknown_terminal_mcp"`
}

// AssetPolicyRule is an exact-match rule. Non-empty fields are treated as
// additional constraints; there is deliberately no globbing or regex support
// because this surface gates code/tool execution.
type AssetPolicyRule struct {
	Name               string   `mapstructure:"name"                 yaml:"name,omitempty"`
	Connector          string   `mapstructure:"connector"            yaml:"connector,omitempty"`
	Reason             string   `mapstructure:"reason"               yaml:"reason,omitempty"`
	URL                string   `mapstructure:"url"                  yaml:"url,omitempty"`
	Command            string   `mapstructure:"command"              yaml:"command,omitempty"`
	ArgsPrefix         []string `mapstructure:"args_prefix"          yaml:"args_prefix,omitempty"`
	Transport          string   `mapstructure:"transport"            yaml:"transport,omitempty"`
	SourcePathContains []string `mapstructure:"source_path_contains" yaml:"source_path_contains,omitempty"`
}

type AssetPolicyInput struct {
	TargetType     string
	Name           string
	Connector      string
	SourcePath     string
	URL            string
	Command        string
	Args           []string
	Transport      string
	RuntimeSurface string
}

type AssetPolicyDecision struct {
	Enabled            bool
	Mode               string
	Action             string // allow | block
	RawAction          string // allow | block
	WouldBlock         bool
	Reason             string
	Source             string
	RegistryStatus     string // registered | unregistered | unknown
	RegistryConfigured bool
	// RegistrySource is the id of the registry source that promoted
	// the matched rule (read from AssetPolicyRule.Reason when it's
	// "registry:<id>"). Empty when the matched rule was added by
	// an operator directly. Surfaced in audit events and the TUI's
	// "approved-by: registry:<id>" badge so cross-links can
	// attribute the promotion back to its source.
	RegistrySource string
	TargetType     string
	TargetName     string
	Connector      string
	RuntimeSurface string
}

func DefaultAssetPolicy() AssetPolicyConfig {
	return AssetPolicyConfig{
		Enabled: false,
		Mode:    AssetPolicyModeObserve,
		MCP:     defaultAssetTypePolicy(true),
		Skill:   defaultAssetTypePolicy(false),
		Plugin:  defaultAssetTypePolicy(false),
	}
}

func defaultAssetTypePolicy(runtime bool) AssetTypePolicy {
	p := AssetTypePolicy{Default: "allow"}
	if runtime {
		p.RuntimeDetection = AssetRuntimeDetection{
			Enabled:            true,
			TerminalCommands:   true,
			UnknownTerminalMCP: AssetPolicyModeObserve,
		}
	}
	return p
}

func (c *Config) EvaluateAssetPolicy(in AssetPolicyInput) AssetPolicyDecision {
	targetType := normalizeAssetToken(in.TargetType)
	name := strings.TrimSpace(in.Name)
	if name == "" {
		name = "unknown"
	}
	out := AssetPolicyDecision{
		Enabled:        false,
		Mode:           AssetPolicyModeObserve,
		Action:         "allow",
		RawAction:      "allow",
		Source:         "asset-policy-disabled",
		RegistryStatus: "unknown",
		TargetType:     targetType,
		TargetName:     name,
		Connector:      strings.TrimSpace(in.Connector),
		RuntimeSurface: strings.TrimSpace(in.RuntimeSurface),
	}
	if c == nil || !c.AssetPolicy.Enabled {
		return out
	}

	p, ok := c.assetPolicyFor(in.Connector, targetType)
	if !ok {
		out.Enabled = true
		out.Source = "asset-policy-unsupported"
		return out
	}

	mode := normalizeAssetMode(c.EffectiveAssetPolicyModeForConnector(in.Connector))
	registryConfigured := assetRegistryConfigured(p.Registry)
	out.Enabled = true
	out.Mode = mode
	out.Source = "asset-policy"
	out.RegistryConfigured = registryConfigured

	if rule, ok := findAssetRule(p.Denied, in); ok {
		return assetPolicyViolation(out, mode, ruleReason(rule, fmt.Sprintf("%s %q is denied by asset policy", targetType, name)), "admin-deny")
	}
	if rule, ok := findAssetRule(p.Allowed, in); ok {
		out.Source = "admin-allow"
		out.RegistryStatus = registryStatus(p.Registry, in)
		out.Reason = ruleReason(rule, fmt.Sprintf("%s %q is explicitly allowed", targetType, name))
		return out
	}

	regStatus := registryStatus(p.Registry, in)
	out.RegistryStatus = regStatus
	if regStatus == "registered" {
		out.Source = "registry"
		out.Reason = fmt.Sprintf("%s %q is registered", targetType, name)
		// Surface the registry source id (parsed out of the matched
		// rule's Reason="registry:<id>") so the gateway audit event
		// and the TUI cross-link badge can point operators back to
		// the source that promoted the asset.
		if rule, ok := findAssetRule(p.Registry, in); ok {
			out.RegistrySource = ParseRegistrySourceID(rule.Reason)
		}
		return out
	}

	if p.RegistryRequired {
		if registryConfigured {
			return assetPolicyViolation(out, mode, fmt.Sprintf("%s %q is not in the approved registry", targetType, name), "registry-required")
		}
		// Registry is required but empty. Fail closed by default so that
		// the absence of approved assets does not silently downgrade to
		// allow-all. Operators can opt out via registry_empty_action="allow".
		if normalizeRegistryEmptyAction(p.RegistryEmptyAction) == registryEmptyActionDeny {
			return assetPolicyViolation(out, mode, fmt.Sprintf("%s %q is blocked because asset policy requires a registry but none is configured", targetType, name), "registry-required-empty")
		}
	}
	if normalizeAssetDefault(p.Default) == "deny" {
		return assetPolicyViolation(out, mode, fmt.Sprintf("%s %q is denied by default asset policy", targetType, name), "default-deny")
	}

	out.Source = "default-allow"
	out.Reason = fmt.Sprintf("%s %q allowed by default asset policy", targetType, name)
	return out
}

func assetRegistryConfigured(rules []AssetPolicyRule) bool {
	return len(rules) > 0
}

// assetPolicyFor resolves the effective per-type policy for a connector.
// It starts from the global per-type policy (withDefaults applied) and then
// overlays the connector's scalar overrides (default / registry_required /
// registry_empty_action) when a per-connector entry is present. Rule lists and
// runtime_detection are always the global policy's. An empty connector resolves
// to the global policy unchanged (single-connector / legacy behavior).
func (c *Config) assetPolicyFor(connector, targetType string) (AssetTypePolicy, bool) {
	if c == nil {
		return AssetTypePolicy{}, false
	}
	token := normalizeAssetToken(targetType)
	var p AssetTypePolicy
	switch token {
	case "mcp":
		p = c.AssetPolicy.MCP.withDefaults(true)
	case "skill":
		p = c.AssetPolicy.Skill.withDefaults(false)
	case "plugin":
		p = c.AssetPolicy.Plugin.withDefaults(false)
	default:
		return AssetTypePolicy{}, false
	}
	if override, ok := c.AssetPolicy.connectorTypeOverride(connector, token); ok {
		p = applyAssetTypeOverride(p, override)
	}
	return p, true
}

// EffectiveAssetTypePolicy is the exported resolver the gateway runtime (a
// different package) uses to read a connector's effective per-type policy — for
// example the per-connector MCP.Default consulted by the unknown-terminal-mcp
// downgrade guard.
func (c *Config) EffectiveAssetTypePolicy(connector, targetType string) (AssetTypePolicy, bool) {
	return c.assetPolicyFor(connector, targetType)
}

// connectorOverride returns the per-connector override block for the named
// connector, if configured. Mirrors GuardrailConfig.connectorOverride: an empty
// connector / nil receiver / empty map yields (zero, false); lookup is
// connector-name-insensitive (exact key first, then normalizeConnectorKey).
func (c *AssetPolicyConfig) connectorOverride(connector string) (PerConnectorAssetPolicy, bool) {
	if c == nil || connector == "" || len(c.Connectors) == 0 {
		return PerConnectorAssetPolicy{}, false
	}
	if pc, ok := c.Connectors[connector]; ok {
		return pc, true
	}
	want := normalizeConnectorKey(connector)
	if want == "" {
		return PerConnectorAssetPolicy{}, false
	}
	for name, pc := range c.Connectors {
		if normalizeConnectorKey(name) == want {
			return pc, true
		}
	}
	return PerConnectorAssetPolicy{}, false
}

// connectorTypeOverride returns the per-connector scalar block for one asset
// type, or (nil, false) when the connector has no override or no block for that
// type (inherit the global per-type policy entirely).
func (c *AssetPolicyConfig) connectorTypeOverride(connector, targetType string) (*PerConnectorAssetTypePolicy, bool) {
	pc, ok := c.connectorOverride(connector)
	if !ok {
		return nil, false
	}
	var o *PerConnectorAssetTypePolicy
	switch targetType {
	case "mcp":
		o = pc.MCP
	case "skill":
		o = pc.Skill
	case "plugin":
		o = pc.Plugin
	}
	if o == nil {
		return nil, false
	}
	return o, true
}

// EffectiveMode resolves the asset_policy mode for a connector:
// per-connector override (when non-empty) > global Mode > "observe".
func (c *AssetPolicyConfig) EffectiveMode(connector string) string {
	if c == nil {
		return AssetPolicyModeObserve
	}
	if pc, ok := c.connectorOverride(connector); ok {
		if m := strings.TrimSpace(pc.Mode); m != "" {
			return m
		}
	}
	if m := strings.TrimSpace(c.Mode); m != "" {
		return m
	}
	return AssetPolicyModeObserve
}

// applyAssetTypeOverride overlays the three per-connector scalars onto a copy of
// the global per-type policy. Only non-empty / non-nil fields override; the rule
// lists and runtime_detection on base are left untouched.
func applyAssetTypeOverride(base AssetTypePolicy, o *PerConnectorAssetTypePolicy) AssetTypePolicy {
	if o == nil {
		return base
	}
	if d := strings.TrimSpace(o.Default); d != "" {
		base.Default = d
	}
	if o.RegistryRequired != nil {
		base.RegistryRequired = *o.RegistryRequired
	}
	if a := strings.TrimSpace(o.RegistryEmptyAction); a != "" {
		base.RegistryEmptyAction = a
	}
	return base
}

func (c *Config) AssetRuntimeDetectionFor(targetType string) (AssetRuntimeDetection, bool) {
	// runtime_detection is always global (never per-connector), so resolve
	// with an empty connector.
	p, ok := c.assetPolicyFor("", targetType)
	if !ok {
		return AssetRuntimeDetection{}, false
	}
	return p.RuntimeDetection, true
}

func (p AssetTypePolicy) withDefaults(runtime bool) AssetTypePolicy {
	if strings.TrimSpace(p.Default) == "" {
		p.Default = "allow"
	}
	if runtime {
		if p.RuntimeDetection.UnknownTerminalMCP == "" {
			p.RuntimeDetection.UnknownTerminalMCP = AssetPolicyModeObserve
		}
		// Keep zero-value compatibility: when the operator did not specify
		// runtime_detection, the intended v1 default is enabled.
		if !p.RuntimeDetection.Enabled && !p.RuntimeDetection.TerminalCommands && p.RuntimeDetection.UnknownTerminalMCP == AssetPolicyModeObserve {
			p.RuntimeDetection.Enabled = true
			p.RuntimeDetection.TerminalCommands = true
		}
	}
	return p
}

func assetPolicyViolation(base AssetPolicyDecision, mode, reason, source string) AssetPolicyDecision {
	base.RawAction = "block"
	base.Reason = reason
	base.Source = source
	base.RegistryStatus = coalesceString(base.RegistryStatus, "unregistered")
	if mode == AssetPolicyModeAction {
		base.Action = "block"
		return base
	}
	base.Action = "allow"
	base.WouldBlock = true
	return base
}

func findAssetRule(rules []AssetPolicyRule, in AssetPolicyInput) (AssetPolicyRule, bool) {
	for _, rule := range rules {
		if assetRuleMatches(rule, in) {
			return rule, true
		}
	}
	return AssetPolicyRule{}, false
}

func registryStatus(rules []AssetPolicyRule, in AssetPolicyInput) string {
	if len(rules) == 0 {
		return "unknown"
	}
	if _, ok := findAssetRule(rules, in); ok {
		return "registered"
	}
	return "unregistered"
}

func assetRuleMatches(rule AssetPolicyRule, in AssetPolicyInput) bool {
	hasConstraint := false
	if rule.Name != "" {
		hasConstraint = true
		if !strings.EqualFold(strings.TrimSpace(rule.Name), strings.TrimSpace(in.Name)) {
			return false
		}
	}
	if rule.Connector != "" {
		hasConstraint = true
		if !strings.EqualFold(strings.TrimSpace(rule.Connector), strings.TrimSpace(in.Connector)) {
			return false
		}
	}
	if rule.URL != "" {
		hasConstraint = true
		if strings.TrimSpace(rule.URL) != strings.TrimSpace(in.URL) {
			return false
		}
	}
	if rule.Command != "" {
		hasConstraint = true
		if filepath.Base(strings.TrimSpace(rule.Command)) != filepath.Base(strings.TrimSpace(in.Command)) {
			return false
		}
	}
	if len(rule.ArgsPrefix) > 0 {
		hasConstraint = true
		if len(in.Args) < len(rule.ArgsPrefix) {
			return false
		}
		for i, want := range rule.ArgsPrefix {
			if strings.TrimSpace(want) != strings.TrimSpace(in.Args[i]) {
				return false
			}
		}
	}
	if rule.Transport != "" {
		hasConstraint = true
		if !strings.EqualFold(strings.TrimSpace(rule.Transport), strings.TrimSpace(in.Transport)) {
			return false
		}
	}
	if len(rule.SourcePathContains) > 0 {
		hasConstraint = true
		if !sourcePathMatches(rule.SourcePathContains, in.SourcePath) {
			return false
		}
	}
	return hasConstraint
}

func sourcePathMatches(needles []string, sourcePath string) bool {
	if sourcePath == "" {
		return false
	}
	normal := strings.ToLower(strings.ReplaceAll(sourcePath, "\\", "/"))
	for _, n := range needles {
		if strings.Contains(normal, strings.ToLower(strings.ReplaceAll(n, "\\", "/"))) {
			return true
		}
	}
	return false
}

func ruleReason(rule AssetPolicyRule, fallback string) string {
	if strings.TrimSpace(rule.Reason) != "" {
		return strings.TrimSpace(rule.Reason)
	}
	return fallback
}

func normalizeAssetMode(mode string) string {
	if strings.EqualFold(strings.TrimSpace(mode), AssetPolicyModeAction) {
		return AssetPolicyModeAction
	}
	return AssetPolicyModeObserve
}

func normalizeAssetDefault(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "deny", "block":
		return "deny"
	case "allow", "":
		return "allow"
	default:
		return "allow"
	}
}

// normalizeRegistryEmptyAction returns the configured action when
// RegistryRequired is true and the registry is empty. Default is "deny"
// (fail-closed): an unconfigured allowlist is treated as "no asset is
// approved" rather than silently relaxing the requirement. Operators
// must explicitly opt into "allow" to get fall-through-to-default.
//
// "warn" resolves to allow (fall-through-to-default), matching the Python
// admission preview (cli/defenseclaw/enforce/admission.py
// _normalize_registry_empty_action). This closes the prior Python↔Go
// divergence where the gateway collapsed "warn" into "deny" — both sides now
// treat "warn" as "log-but-don't-block at the empty-registry gate".
func normalizeRegistryEmptyAction(value string) string {
	switch strings.ToLower(strings.TrimSpace(value)) {
	case "allow", "warn":
		return registryEmptyActionAllow
	case "deny", "block", "":
		return registryEmptyActionDeny
	default:
		return registryEmptyActionDeny
	}
}

func normalizeAssetToken(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func coalesceString(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}

// ParseRegistrySourceID extracts the source id from a rule reason of
// the form "registry:<id>". Returns "" for any other shape (e.g. an
// operator-authored rule with a free-form Reason).
//
// The convention is owned by cli/defenseclaw/registries/sync.py —
// keep the prefix and validation in lockstep with both sides.
//
// Exported so the TUI ([internal/tui]) can rebuild "name -> source"
// attribution maps from the same Reason format the audit + admission
// paths emit.
func ParseRegistrySourceID(reason string) string {
	const prefix = "registry:"
	r := strings.TrimSpace(reason)
	if !strings.HasPrefix(r, prefix) {
		return ""
	}
	return strings.TrimSpace(r[len(prefix):])
}
