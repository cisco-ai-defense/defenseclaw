// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"gopkg.in/yaml.v3"
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

// ownedHookCommandNeedles returns escaping-invariant marker string(s) that the
// connector writes into its agent config, used for a raw-bytes substring match
// against the live config file. See ownedHookCommandNeedlesFor for the
// platform rationale.
//
// Returns nil for connectors that own no vendor hook script (openclaw,
// zeptoclaw), keeping the self-heal guard inert for them.
func ownedHookCommandNeedles(opts SetupOpts, conn Connector) []string {
	return ownedHookCommandNeedlesFor(runtime.GOOS, opts, conn)
}

// ownedHookCommandNeedlesFor is the OS-parameterized core of
// ownedHookCommandNeedles, split out so the Windows marker can be exercised by
// tests on any host.
//
// The needle must survive serialization into the agent config file, because
// OwnedHooksPresent matches it against the raw file bytes (not a decoded
// value). That constraint differs by platform:
//
//   - Unix: the agent runs the bundled .sh hook, so the config stores the
//     absolute script path under <DataDir>/hooks/. Forward-slash paths contain
//     no characters JSON/TOML/YAML escape, so the path appears verbatim.
//
//   - Windows: the config stores the native invocation
//     (`"C:\...\defenseclaw-gateway.exe" hook --connector <name>`). The
//     absolute exe path's backslashes and the surrounding quotes ARE escaped on
//     serialization (`\"C:\\...\\..exe\"`), so the full command would never
//     match the raw bytes. We therefore key on `hook --connector <name>` — the
//     same distinctive marker isNativeHookCommand recognizes — which contains
//     no escaped characters and survives verbatim across JSON/TOML/YAML.
func ownedHookCommandNeedlesFor(goos string, opts SetupOpts, conn Connector) []string {
	owner, ok := conn.(HookScriptOwner)
	if !ok {
		return nil
	}
	if goos == "windows" {
		return []string{nativeHookFlag + conn.Name()}
	}
	hookDir := filepath.Join(opts.DataDir, "hooks")
	var needles []string
	for _, name := range owner.HookScriptNames(opts) {
		if path := filepath.Join(hookDir, name); path != "" {
			needles = append(needles, path)
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
	var decoded interface{}
	switch strings.ToLower(filepath.Ext(path)) {
	case ".json":
		decoder := json.NewDecoder(bytes.NewReader(data))
		decoder.UseNumber()
		if err := decoder.Decode(&decoded); err != nil {
			return false, fmt.Errorf("parse hook config %s: %w", path, err)
		}
	case ".yaml", ".yml":
		if err := yaml.Unmarshal(data, &decoded); err != nil {
			return false, fmt.Errorf("parse hook config %s: %w", path, err)
		}
	}
	if decoded != nil {
		return structuredHookCommandReferences(decoded, needles), nil
	}
	for _, needle := range needles {
		if needle != "" && bytes.Contains(data, []byte(needle)) {
			return true, nil
		}
	}
	return false, nil
}

func structuredHookCommandReferences(raw interface{}, needles []string) bool {
	switch value := raw.(type) {
	case []interface{}:
		for _, item := range value {
			if structuredHookCommandReferences(item, needles) {
				return true
			}
		}
	case map[string]interface{}:
		for key, item := range value {
			if key == "command" || key == "bash" {
				command, _ := item.(string)
				for _, needle := range needles {
					if needle != "" && strings.Contains(command, needle) {
						return true
					}
				}
			}
			if structuredHookCommandReferences(item, needles) {
				return true
			}
		}
	}
	return false
}
