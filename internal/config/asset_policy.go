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
// install-time and runtime assets. It is intentionally connector-agnostic so
// MCP servers, skills, and plugins all share the same decision ordering.
type AssetPolicyConfig struct {
	Enabled bool            `mapstructure:"enabled" yaml:"enabled"`
	Mode    string          `mapstructure:"mode"    yaml:"mode"`
	MCP     AssetTypePolicy `mapstructure:"mcp"     yaml:"mcp"`
	Skill   AssetTypePolicy `mapstructure:"skill"   yaml:"skill"`
	Plugin  AssetTypePolicy `mapstructure:"plugin"  yaml:"plugin"`
}

type AssetTypePolicy struct {
	Default          string                `mapstructure:"default"           yaml:"default"`
	RegistryRequired bool                  `mapstructure:"registry_required" yaml:"registry_required"`
	Registry         []AssetPolicyRule     `mapstructure:"registry"          yaml:"registry"`
	Allowed          []AssetPolicyRule     `mapstructure:"allowed"           yaml:"allowed"`
	Denied           []AssetPolicyRule     `mapstructure:"denied"            yaml:"denied"`
	RuntimeDetection AssetRuntimeDetection `mapstructure:"runtime_detection" yaml:"runtime_detection,omitempty"`
}

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
	Enabled        bool
	Mode           string
	Action         string // allow | block
	RawAction      string // allow | block
	WouldBlock     bool
	Reason         string
	Source         string
	RegistryStatus string // registered | unregistered | unknown
	TargetType     string
	TargetName     string
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
	}
	if c == nil || !c.AssetPolicy.Enabled {
		return out
	}

	p, ok := c.assetPolicyFor(targetType)
	if !ok {
		out.Enabled = true
		out.Source = "asset-policy-unsupported"
		return out
	}

	mode := normalizeAssetMode(c.AssetPolicy.Mode)
	out.Enabled = true
	out.Mode = mode
	out.Source = "asset-policy"

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
		return out
	}

	if p.RegistryRequired {
		return assetPolicyViolation(out, mode, fmt.Sprintf("%s %q is not in the approved registry", targetType, name), "registry-required")
	}
	if normalizeAssetDefault(p.Default) == "deny" {
		return assetPolicyViolation(out, mode, fmt.Sprintf("%s %q is denied by default asset policy", targetType, name), "default-deny")
	}

	out.Source = "default-allow"
	out.Reason = fmt.Sprintf("%s %q allowed by default asset policy", targetType, name)
	return out
}

func (c *Config) assetPolicyFor(targetType string) (AssetTypePolicy, bool) {
	if c == nil {
		return AssetTypePolicy{}, false
	}
	switch normalizeAssetToken(targetType) {
	case "mcp":
		return c.AssetPolicy.MCP.withDefaults(true), true
	case "skill":
		return c.AssetPolicy.Skill.withDefaults(false), true
	case "plugin":
		return c.AssetPolicy.Plugin.withDefaults(false), true
	default:
		return AssetTypePolicy{}, false
	}
}

func (c *Config) AssetRuntimeDetectionFor(targetType string) (AssetRuntimeDetection, bool) {
	p, ok := c.assetPolicyFor(targetType)
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

func normalizeAssetToken(value string) string {
	return strings.ToLower(strings.TrimSpace(value))
}

func coalesceString(v, fallback string) string {
	if v != "" {
		return v
	}
	return fallback
}
