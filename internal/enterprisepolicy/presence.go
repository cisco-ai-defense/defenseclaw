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
	"bytes"
	"fmt"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// MachinePolicyPresent reports whether DefenseClaw's own entries for
// connectorName are present in the vendor machine policy files, using the
// same owned-entry detection as Reconcile and Verify. The hook runtime uses
// it to tell an installed machine policy registration from a command a
// client cached before uninstall. It reads only the world-readable machine
// files (no higher-precedence sources, no subprocesses), so it is cheap
// enough for every hook invocation. Read, trust and parse errors are
// returned so the caller can fail closed. Connectors without a machine
// policy target report false.
func MachinePolicyPresent(opts Options, connectorName string) (bool, error) {
	name := strings.ToLower(strings.TrimSpace(connectorName))
	if err := opts.Validate(); err != nil {
		return false, err
	}
	switch name {
	case ConnectorCodex:
		return codexPresent(opts)
	case ConnectorClaudeCode:
		return claudePresent(opts)
	case ConnectorCursor:
		return cursorPresent(opts)
	case ConnectorCopilot:
		return copilotPresent(opts)
	case ConnectorOpenCode:
		return opencodePresent(opts)
	default:
		return false, nil
	}
}

// MachinePolicyMayRemain is the fail-closed leftover check the hook
// runtime makes when the runtime descriptor is gone: true when
// MachinePolicyPresent finds DefenseClaw's entries, when any of the
// target's machine files still names the hook binary (or the managed
// OpenCode plugin) even in a drifted entry, or when a file cannot be read,
// trusted or parsed. Only a clean uninstall reports false.
func MachinePolicyMayRemain(opts Options, connectorName string) bool {
	name := strings.ToLower(strings.TrimSpace(connectorName))
	target, ok := TargetFor(name)
	if !ok {
		return false
	}
	present, err := MachinePolicyPresent(opts, name)
	if err != nil || present {
		return true
	}
	paths, err := target.Paths(opts)
	if err != nil {
		return false
	}
	needles := [][]byte{[]byte(opts.HookBinary)}
	if opts.goos() != "windows" {
		// Codex TOML and JSON escaping never touch a unix path, but the
		// quoted shell form may.
		needles = append(needles, []byte(shellQuote(opts.HookBinary)))
	} else {
		needles = append(needles, []byte(strings.ReplaceAll(opts.HookBinary, `\`, `\\`)))
	}
	if name == ConnectorOpenCode && opts.OpenCodePluginPath != "" {
		needles = append(needles, []byte(opts.OpenCodePluginPath))
	}
	for _, path := range paths {
		data, exists, err := readPolicyFile(opts, path)
		if err != nil {
			return true
		}
		if !exists {
			continue
		}
		if ownedWholeFile(path) {
			return true
		}
		for _, needle := range needles {
			if len(needle) > 0 && bytes.Contains(data, needle) {
				return true
			}
		}
	}
	return false
}

// ownedWholeFile reports files DefenseClaw owns outright (its drop-ins
// and the Windows Cursor adapter); their mere presence is DefenseClaw policy.
func ownedWholeFile(path string) bool {
	base := path
	if index := strings.LastIndexAny(path, `/\`); index >= 0 {
		base = path[index+1:]
	}
	return base == DefenseClawDropInName || base == cursorWindowsAdapterName
}

func codexPresent(opts Options) (bool, error) {
	path, err := CodexRequirementsPath(opts)
	if err != nil {
		return false, err
	}
	raw, exists, err := readPolicyFile(opts, path)
	if err != nil || !exists || len(bytes.TrimSpace(raw)) == 0 {
		return false, err
	}
	cfg := map[string]any{}
	if err := connector.ParseCodexTOML(raw, &cfg); err != nil {
		return false, fmt.Errorf("parse Codex requirements: %w", err)
	}
	groups, err := connector.ManagedHookGroupsForOS(codexConnector, opts.agentVersion(codexConnector), opts.goos())
	if err != nil {
		return false, err
	}
	hooksCfg, _ := cfg[codexHooksTable].(map[string]any)
	for _, group := range groups {
		if countCodexOwnedGroups(hooksCfg[group.Event], group, codexHookCommandForEvent(opts, group.Event), opts) > 0 {
			return true, nil
		}
	}
	return false, nil
}

func claudePresent(opts Options) (bool, error) {
	sources, err := readClaudeFileSources(opts)
	if err != nil {
		return false, err
	}
	groups, err := connector.ManagedHookGroupsForOS(claudeConnector, opts.agentVersion(claudeConnector), opts.goos())
	if err != nil {
		return false, err
	}
	events := make([]string, 0, len(groups))
	for _, group := range groups {
		events = append(events, group.Event)
	}
	for _, source := range sources {
		hooks, _ := source.doc.get("hooks")
		if owned, _, _ := countClaudeHooks(opts, hooks, events); owned > 0 {
			return true, nil
		}
	}
	return false, nil
}

func cursorPresent(opts Options) (bool, error) {
	if opts.goos() == "windows" {
		hooksPath, adapterPath, err := windowsCursorPaths(opts)
		if err != nil {
			return false, err
		}
		current, exists, err := readPolicyFile(opts, hooksPath)
		if err != nil || !exists {
			return false, err
		}
		return connector.VerifyWindowsCursorEnterpriseHooks(current, adapterPath, "closed") == nil, nil
	}
	path, err := CursorEnterpriseHooksPath(opts)
	if err != nil {
		return false, err
	}
	current, exists, err := readPolicyFile(opts, path)
	if err != nil || !exists {
		return false, err
	}
	doc, err := decodeOrderedObject(current)
	if err != nil {
		return false, fmt.Errorf("parse Cursor enterprise hooks: %w", err)
	}
	return anyHandler(doc, func(item any) bool { return cursorEntryIsOwned(opts, item) }), nil
}

func copilotPresent(opts Options) (bool, error) {
	path, err := copilotDropInPath(opts)
	if err != nil {
		return false, err
	}
	current, exists, err := readPolicyFile(opts, path)
	if err != nil || !exists {
		return false, err
	}
	doc, err := decodeOrderedObject(current)
	if err != nil {
		return false, fmt.Errorf("parse Copilot policy drop-in: %w", err)
	}
	return anyHandler(doc, func(item any) bool { return copilotHandlerIsOwned(opts, item) }), nil
}

func opencodePresent(opts Options) (bool, error) {
	if !opts.openCodeArtifactInstalled() {
		return false, nil
	}
	path, err := OpenCodeManagedConfigPath(opts)
	if err != nil {
		return false, err
	}
	current, exists, err := readPolicyFile(opts, path)
	if err != nil || !exists {
		return false, err
	}
	doc, err := decodeOrderedObject(current)
	if err != nil {
		return false, fmt.Errorf("parse OpenCode managed config: %w", err)
	}
	value, _ := doc.get("plugin")
	list, _ := value.([]any)
	for _, item := range list {
		if opencodeEntryIsOwned(opts, item) {
			return true, nil
		}
	}
	return false, nil
}

// anyHandler reports whether any flat hooks.<event>[] entry satisfies owned.
func anyHandler(doc *object, owned func(any) bool) bool {
	hooksValue, _ := doc.get("hooks")
	hooks, _ := hooksValue.(*object)
	if hooks == nil {
		return false
	}
	for _, event := range hooks.keys {
		value, _ := hooks.get(event)
		list, _ := value.([]any)
		for _, item := range list {
			if owned(item) {
				return true
			}
		}
	}
	return false
}

// reconciledConnectors lists the machine-policy connectors whose DefenseClaw
// entries are actually in place after a reconcile or verify pass; the
// lifecycle records exactly this set in RuntimeDescriptor.MachinePolicyConnectors.
// Companion targets are not connectors and are left out.
func reconciledConnectors(states []State) []string {
	out := []string{}
	for _, state := range states {
		if state.Route == RouteMachinePolicy && state.OwnedEntries > 0 && !isCompanion(state.Connector) {
			out = append(out, state.Connector)
		}
	}
	return normalizeConnectors(out)
}
