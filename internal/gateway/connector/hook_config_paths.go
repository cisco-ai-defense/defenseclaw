// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"os"
	"path/filepath"
)

// HookConfigPathsForConnector returns the absolute agent config file path(s)
// that the given connector patches with DefenseClaw hook entries (e.g.
// ~/.cursor/hooks.json, ~/.claude/settings.json, ~/.codex/config.toml).
//
// It returns nil for proxy/plugin connectors that do not register lifecycle
// hooks in an agent hook file (openclaw, zeptoclaw). Those connectors do not
// implement HookScriptOwner, so the self-heal guard treats them as inert.
//
// The resolved paths come from ResolvedConnectorLocations, the same path
// contract captured into hook_contract_lock.json, so the guard watches
// exactly the files Setup writes.
func HookConfigPathsForConnector(conn Connector, opts SetupOpts) []string {
	if conn == nil {
		return nil
	}
	// Only connectors that own a vendor hook script register lifecycle
	// hooks in an agent config file. Proxy/plugin connectors (openclaw,
	// zeptoclaw) do not implement HookScriptOwner and must stay inert.
	if _, ok := conn.(HookScriptOwner); !ok {
		return nil
	}
	return uniqueNonEmptyStrings(ResolvedConnectorLocations(opts, conn).HookConfigPaths)
}

// ownedHookCommandNeedles returns the exact hook command string(s) the
// connector writes into its agent config. On Unix this is the absolute hook
// script path under <DataDir>/hooks/; on Windows it is the native
// `defenseclaw-gateway hook --connector <name>` invocation. These are the
// strings the JSON/TOML/YAML patchers insert, so a substring match against
// the live config file reliably reports whether our hook entry survives.
//
// Returns nil for connectors that own no vendor hook script (openclaw,
// zeptoclaw), keeping the self-heal guard inert for them.
func ownedHookCommandNeedles(opts SetupOpts, conn Connector) []string {
	owner, ok := conn.(HookScriptOwner)
	if !ok {
		return nil
	}
	hookDir := filepath.Join(opts.DataDir, "hooks")
	var needles []string
	for _, name := range owner.HookScriptNames(opts) {
		cmd := hookInvocationCommand(conn.Name(), filepath.Join(hookDir, name))
		if cmd != "" {
			needles = append(needles, cmd)
		}
	}
	return needles
}

// OwnedHooksPresent reports whether the connector's DefenseClaw hook entries
// are still present in every agent config file it patches. It returns false
// (heal needed) when any watched config file is missing entirely or no longer
// references our hook command.
//
// Connectors with no hook config paths or no owned hook command (proxy/plugin
// connectors) are reported as present so the guard never tries to heal them.
func OwnedHooksPresent(conn Connector, opts SetupOpts) (bool, error) {
	paths := HookConfigPathsForConnector(conn, opts)
	if len(paths) == 0 {
		return true, nil
	}
	needles := ownedHookCommandNeedles(opts, conn)
	if len(needles) == 0 {
		return true, nil
	}
	for _, path := range paths {
		present, err := configFileReferencesHook(path, needles)
		if err != nil {
			return false, err
		}
		if !present {
			return false, nil
		}
	}
	return true, nil
}

// configFileReferencesHook reports whether the file at path contains any of
// the owned hook command needles. A missing file reports false (not present)
// rather than an error: a deleted connector config is exactly the tamper case
// the guard re-installs. Any other read error is surfaced so the guard can log
// and skip rather than heal on incomplete information.
func configFileReferencesHook(path string, needles []string) (bool, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return false, nil
		}
		return false, err
	}
	for _, needle := range needles {
		if needle != "" && bytes.Contains(data, []byte(needle)) {
			return true, nil
		}
	}
	return false, nil
}
