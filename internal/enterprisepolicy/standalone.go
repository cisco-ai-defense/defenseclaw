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
)

// HookBinaryPath is the administrator-owned hook executable every machine
// policy entry invokes (defenseclaw-hook, .exe on Windows).
func HookBinaryPath(layout managed.StandaloneLayout) string {
	if layout.GOOS == "windows" {
		return strings.TrimRight(layout.BinDir, `\`) + `\defenseclaw-hook.exe`
	}
	return path.Join(layout.BinDir, "defenseclaw-hook")
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
	opts.Policies = map[string]config.ResolvedConnectorPolicy{}
	for _, name := range StandaloneConnectors(cfg) {
		opts.Policies[name] = cfg.Enterprise.MachinePolicy.PolicyFor(name)
	}
	opts.ClaudeVersionFloor = cfg.Enterprise.MachinePolicy.ClaudeVersionFloor()
	opts.WSL = cfg.Enterprise.MachinePolicy.WindowsWSL
	return opts, opts.Validate()
}

// StandaloneConnectors is the connector set the standalone lifecycle
// protects: every active connector plus any connector the administrator
// configured under enterprise.machine_policy.connectors.
func StandaloneConnectors(cfg *config.Config) []string {
	if cfg == nil {
		return nil
	}
	names := append([]string(nil), cfg.ActiveConnectors()...)
	for name := range cfg.Enterprise.MachinePolicy.Connectors {
		names = append(names, name)
	}
	names = normalizeConnectors(names)
	sort.Strings(names)
	return names
}
