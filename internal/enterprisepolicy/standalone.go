// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"errors"
	"path"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

// windowsHookLaunchPath resolves the launch image of a Windows bin
// (GAP-0751); a seam so renderer tests stay pure.
var windowsHookLaunchPath = winpath.EnterpriseHookLaunchPath

// HookBinaryPath is the administrator-owned hook executable at its fixed
// path in bin (defenseclaw-hook, .exe on Windows). On Windows that is the
// transition image, which machine policy written by 1.0.9 names; it is
// pure, so the read-only and ownership checks (also those a hook process
// makes) never read an image. A policy written now names
// HookLaunchBinaryPath.
func HookBinaryPath(layout managed.StandaloneLayout) string {
	if layout.GOOS == "windows" {
		return strings.TrimRight(layout.BinDir, `\`) + `\defenseclaw-hook.exe`
	}
	return path.Join(layout.BinDir, "defenseclaw-hook")
}

// HookLaunchBinaryPath is the hook executable a machine policy entry
// written now invokes. On Windows it is the launch image
// <bin>\hooks\<d16>\defenseclaw-hook.exe once Setup staged it, so an upgrade
// never replaces the image an agent starts (GAP-0751), else the transition
// image. Linux and macOS: HookBinaryPath.
func HookLaunchBinaryPath(layout managed.StandaloneLayout) string {
	if layout.GOOS == "windows" {
		return windowsHookLaunchPath(strings.TrimRight(layout.BinDir, `\`))
	}
	return HookBinaryPath(layout)
}

// LayoutOptions derives the machine policy paths of a standalone layout
// with the secure default policy for every connector. The hook runtime,
// which cannot read the administrator's config, uses it directly;
// StandaloneOptions adds the configured per-connector policy.
func LayoutOptions(layout managed.StandaloneLayout, programFiles, programData string) Options {
	target := Options{GOOS: layout.GOOS}
	return Options{
		GOOS:                layout.GOOS,
		WindowsProgramFiles: programFiles,
		WindowsProgramData:  programData,
		HookBinary:          HookBinaryPath(layout),
		StateDir:            joinFor(target, layout.LifecycleDir, "machine-policy"),
		PublicPolicyPath:    PublicPolicyPathFor(layout),
		OpenCodePluginPath:  OpenCodeManagedPluginPath(layout),
	}
}

// PublicPolicyPathFor is where the public machine policy summary lives: next
// to the managed config on Linux and macOS, and in the user-readable hook
// runtime directory on Windows, whose state root standard users cannot read.
func PublicPolicyPathFor(layout managed.StandaloneLayout) string {
	target := Options{GOOS: layout.GOOS}
	if layout.GOOS == "windows" {
		return joinFor(target, layout.HookRuntimeDir, PublicPolicyFileName)
	}
	return joinFor(target, layout.ConfigDir, PublicPolicyFileName)
}

// StandaloneOptions derives Options from the fixed standalone layout and
// the loaded config so the lifecycle, the guardian and the `enterprise
// policy` commands resolve identical paths. programFiles and programData
// are the trusted Windows roots (ignored elsewhere).
func StandaloneOptions(layout managed.StandaloneLayout, programFiles, programData string, cfg *config.Config) (Options, error) {
	if cfg == nil || !cfg.StandaloneEnterprise() {
		return Options{}, errors.New("enterprise machine policy requires the standalone managed_enterprise profile")
	}
	opts := LayoutOptions(layout, programFiles, programData)
	// The lifecycle, the guardian and `enterprise policy` render machine
	// policy from these options: they name the launch image (GAP-0751).
	opts.HookBinary = HookLaunchBinaryPath(layout)
	opts.Policies = map[string]config.ResolvedConnectorPolicy{}
	for _, name := range withCompanions(StandaloneConnectors(cfg)) {
		opts.Policies[name] = cfg.Enterprise.MachinePolicy.PolicyFor(name)
	}
	opts.ClaudeVersionFloor = cfg.Enterprise.MachinePolicy.ClaudeVersionFloor()
	opts.WSL = cfg.Enterprise.MachinePolicy.WindowsWSL
	opts.CopilotHarnessPreference = cfg.Enterprise.MachinePolicy.CopilotHarnessPreference()
	opts.CopilotLocalHarness = cfg.Enterprise.MachinePolicy.CopilotLocalHarness()
	opts.CursorFailOpen = cfg.EffectiveHookFailModeForConnector(cursorConnector) == "open"
	return opts, opts.Validate()
}

// StandaloneConnectors is the connector set the standalone lifecycle
// protects: every active connector plus any connector the administrator
// configured under enterprise.machine_policy.connectors. A companion's key
// there (devincascade) configures the companion, not a connector. A
// connector that guardrail.connectors.<name>.enabled: false turns off is
// left out, as the enumerator leaves it out, so machine policy, enrollment
// and the no-connector check agree (GAP-0267).
func StandaloneConnectors(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	names := append([]string(nil), cfg.ActiveConnectors()...)
	// The singular connector remains enrolled when a plural connector map
	// is also present; ActiveConnectors alone selects the plural roster.
	names = append(names, cfg.Guardrail.Connector)
	for name := range cfg.Enterprise.MachinePolicy.Connectors {
		names = append(names, name)
	}
	enabled := names[:0]
	for _, name := range names {
		if cfg.Guardrail.EffectiveEnabled(name) {
			enabled = append(enabled, name)
		}
	}
	names = withoutCompanions(normalizeConnectors(enabled))

	sort.Strings(names)
	return names
}

// StandaloneConnectorPublished reports whether the standalone lifecycle
// protects connector name (StandaloneConnectors, with the companions of
// those connectors): the connectors the administrator's config publishes.
// A hook installed for any other connector gets no usable answer from the
// gateway, so every call of that agent is blocked (rel-1-0-3 GAP-0235).
func StandaloneConnectorPublished(cfg *config.Config, name string) bool {
	name = config.NormalizeConnectorName(name)
	if name == "" {
		return false
	}
	for _, published := range withCompanions(StandaloneConnectors(cfg)) {
		if published == name {
			return true
		}
	}
	return false
}
