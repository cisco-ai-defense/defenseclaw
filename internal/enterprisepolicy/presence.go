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

// MachinePolicyAbsent proves that no DefenseClaw hook for connectorName is
// registered in the vendor machine policy files: they were read and hold
// neither an owned entry nor any text that names DefenseClaw or its hook
// binary. MachinePolicyPresent answers the other question. It recognizes only
// an entry that matches the current registration exactly (command, arguments,
// timeout), so a registered hook whose timeout or arguments drifted is not
// present to it although the vendor still runs the command. False from
// MachinePolicyPresent is therefore not absence. A source that cannot be read,
// trusted or parsed proves nothing and is returned as an error. Connectors
// without a machine policy target have none to register.
func MachinePolicyAbsent(opts Options, connectorName string) (bool, error) {
	present, err := MachinePolicyPresent(opts, connectorName)
	if err != nil || present {
		return false, err
	}
	sources, err := machinePolicySources(opts, strings.ToLower(strings.TrimSpace(connectorName)))
	if err != nil {
		return false, err
	}
	markers := []string{"defenseclaw", "--enterprise-managed", opts.HookBinary, strings.ReplaceAll(opts.HookBinary, `\`, `\\`)}
	if opts.OpenCodePluginPath != "" {
		markers = append(markers, openCodePluginSpec(opts))
	}
	for _, source := range sources {
		text := strings.ToLower(string(source))
		for _, marker := range markers {
			if marker != "" && strings.Contains(text, strings.ToLower(marker)) {
				return false, nil
			}
		}
	}
	return true, nil
}

// machinePolicySources reads the vendor files MachinePolicyPresent reads for
// the connector, with the same trust checks. Copilot loads every effective
// JSON drop-in of policy.d, so all of them are read, not only the DefenseClaw
// one. A file that does not exist adds nothing.
func machinePolicySources(opts Options, name string) ([][]byte, error) {
	var paths []string
	var err error
	switch name {
	case ConnectorCodex:
		var path string
		path, err = CodexRequirementsPath(opts)
		paths = []string{path}
	case ConnectorClaudeCode:
		var claude []claudeSource
		if claude, err = readClaudeFileSources(opts); err != nil {
			return nil, err
		}
		out := make([][]byte, 0, len(claude))
		for _, source := range claude {
			encoded, encodeErr := encodeOrdered(source.doc)
			if encodeErr != nil {
				return nil, encodeErr
			}
			out = append(out, encoded)
		}
		return out, nil
	case ConnectorCursor:
		if opts.goos() == "windows" {
			var hooksPath, adapterPath string
			hooksPath, adapterPath, err = windowsCursorPaths(opts)
			paths = []string{hooksPath, adapterPath}
		} else {
			var path string
			path, err = CursorEnterpriseHooksPath(opts)
			paths = []string{path}
		}
	case ConnectorCopilot:
		var dir string
		var names []string
		if dir, names, err = copilotEffectiveDropIns(opts); err != nil {
			return nil, err
		}
		out := make([][]byte, 0, len(names))
		for _, name := range names {
			file := joinFor(opts, dir, name)
			raw, exists, readErr := readPolicyFile(opts, file)
			if readErr != nil {
				return nil, readErr
			}
			if !exists {
				continue
			}
			if _, parseErr := decodeOrderedObject(raw); parseErr != nil {
				return nil, fmt.Errorf("parse Copilot policy drop-in %s: %w", file, parseErr)
			}
			out = append(out, raw)
		}
		return out, nil
	case ConnectorOpenCode:
		if !opts.openCodeArtifactInstalled() {
			return nil, nil
		}
		var path string
		path, err = OpenCodeManagedConfigPath(opts)
		paths = []string{path}
	}
	if err != nil {
		return nil, err
	}
	var out [][]byte
	for _, path := range paths {
		raw, exists, readErr := readPolicyFile(opts, path)
		if readErr != nil {
			return nil, readErr
		}
		if exists {
			out = append(out, raw)
		}
	}
	return out, nil
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
	for _, source := range sources {
		hooks, _ := source.doc.get("hooks")
		if owned, _, _ := countClaudeHooks(opts, hooks, groups); owned > 0 {
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
		// A pre-upgrade policy that still registers a retired event
		// (afterAgentThought) is DefenseClaw's installed registration until
		// the next reconcile rewrites it.
		return connector.VerifyWindowsCursorEnterpriseHooksRegistered(current, adapterPath, "closed") == nil, nil
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
	for _, key := range []string{"plugin", "plugins"} {
		value, _ := doc.get(key)
		list, _ := value.([]any)
		for _, item := range list {
			if opencodeEntryIsOwned(opts, item) {
				return true, nil
			}
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
