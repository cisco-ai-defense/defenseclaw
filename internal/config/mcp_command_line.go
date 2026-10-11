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
	"encoding/json"
	"fmt"
	"path/filepath"
	"strings"
)

// CommandLineMCP is the MCP server a tool call names as the agent's own
// command line defines it.
type CommandLineMCP struct {
	// Entry is the definition, when Found.
	Entry MCPServerEntry
	Found bool
	// Exclusive means the command line is the agent's only MCP source
	// (claude --strict-mcp-config): a server it
	// does not define comes from nowhere the hook can read.
	Exclusive bool
}

// CommandLineMCPServer resolves the MCP server a tool call names (server, as
// the hook sees it) from the agent's command line, which takes precedence
// over every config file: Claude Code's --mcp-config files or JSON strings,
// and Codex's -c/--config mcp_servers.* overrides on top of its config.toml
// (GAP-0954). dir resolves a relative --mcp-config path; workspaceDir is the
// project Codex reads. present is false when the command line names no such
// source, so the files decide. An error means it names one that cannot be
// read, so the server's definition cannot be proven.
func CommandLineMCPServer(connector string, args []string, dir, workspaceDir, server string) (CommandLineMCP, bool, error) {
	switch normalizeConnectorKey(connector) {
	case "claudecode":
		configs, strict := claudeMCPConfigArgs(args)
		if len(configs) == 0 {
			return CommandLineMCP{Exclusive: strict}, strict, nil
		}
		entries, err := readClaudeMCPConfigArgs(configs, dir)
		if err != nil {
			return CommandLineMCP{}, true, err
		}
		entry, found := lookupMCPToolServer(connector, entries, server)
		return CommandLineMCP{Entry: entry, Found: found, Exclusive: strict}, true, nil
	case "codex":
		overrides := codexConfigOverrides(args)
		if len(overrides) == 0 {
			return CommandLineMCP{}, false, nil
		}
		base, _ := readMCPServersCodex(workspaceDir)
		entries, touched, exclusive, err := applyCodexMCPOverrides(base, overrides)
		if err != nil {
			return CommandLineMCP{}, true, err
		}
		entry, found := lookupMCPToolServer(connector, entries, server)
		if found && !exclusive && !touched[entry.Name] {
			// The overrides leave this server as the files define it.
			return CommandLineMCP{}, true, nil
		}
		return CommandLineMCP{Entry: entry, Found: found, Exclusive: exclusive}, true, nil
	default:
		return CommandLineMCP{}, false, nil
	}
}

// claudeMCPConfigArgs returns the --mcp-config values of a Claude Code
// command line and whether --strict-mcp-config is set. It parses as Claude
// Code's option parser does: "--mcp-config a b" takes every following value
// up to the next option, "--mcp-config=a" takes one, and "--" ends options.
func claudeMCPConfigArgs(args []string) ([]string, bool) {
	var configs []string
	strict, variadic := false, false
	for i := 1; i < len(args); i++ {
		arg := args[i]
		if arg == "--" {
			break
		}
		if variadic && !strings.HasPrefix(arg, "-") {
			configs = append(configs, arg)
			continue
		}
		variadic = false
		switch {
		case arg == "--strict-mcp-config":
			strict = true
		case arg == "--mcp-config":
			if i+1 < len(args) {
				i++
				configs = append(configs, args[i])
				variadic = true
			}
		case strings.HasPrefix(arg, "--mcp-config="):
			configs = append(configs, strings.TrimPrefix(arg, "--mcp-config="))
		}
	}
	return configs, strict
}

// readClaudeMCPConfigArgs reads the servers --mcp-config values define, as
// Claude Code does: a value that parses as JSON is the config itself, any
// other value names a file, relative to dir. A later value overrides an
// earlier one's server of the same name.
func readClaudeMCPConfigArgs(configs []string, dir string) ([]MCPServerEntry, error) {
	byName := map[string]MCPServerEntry{}
	var order []string
	for _, value := range configs {
		value = strings.TrimSpace(value)
		if value == "" {
			continue
		}
		data := []byte(value)
		if !json.Valid(data) {
			path := value
			if !filepath.IsAbs(path) {
				if strings.TrimSpace(dir) == "" {
					return nil, fmt.Errorf("--mcp-config %s is relative and the agent's folder is unknown", value)
				}
				path = filepath.Join(dir, path)
			}
			read, err := readMCPConfigFile(path, maxMCPConfigFileBytes)
			if err != nil {
				return nil, fmt.Errorf("--mcp-config %s: %w", value, err)
			}
			data = read
		}
		entries, err := parseDotMCPJSON(data)
		if err != nil {
			return nil, fmt.Errorf("--mcp-config %s: %w", value, err)
		}
		for _, entry := range entries {
			if _, seen := byName[entry.Name]; !seen {
				order = append(order, entry.Name)
			}
			byName[entry.Name] = entry
		}
	}
	out := make([]MCPServerEntry, 0, len(order))
	for _, name := range order {
		out = append(out, byName[name])
	}
	return out, nil
}

// codexConfigOverrides returns the key=value overrides a Codex command line
// passes with -c/--config ("-c k=v", "-ck=v", "--config k=v", "--config=k=v")
// whose key is in mcp_servers, in order. "--" ends options.
func codexConfigOverrides(args []string) []string {
	var out []string
	for i := 1; i < len(args); i++ {
		arg, value := args[i], ""
		switch {
		case arg == "--":
			return out
		case arg == "-c" || arg == "--config":
			if i+1 >= len(args) {
				return out
			}
			i++
			value = args[i]
		case strings.HasPrefix(arg, "--config="):
			value = strings.TrimPrefix(arg, "--config=")
		case strings.HasPrefix(arg, "-c") && !strings.HasPrefix(arg, "--"):
			value = strings.TrimPrefix(strings.TrimPrefix(arg, "-c"), "=")
		default:
			continue
		}
		key, _, _ := strings.Cut(value, "=")
		if root, _, _ := strings.Cut(strings.TrimSpace(key), "."); root == "mcp_servers" {
			out = append(out, value)
		}
	}
	return out
}

// applyCodexMCPOverrides applies mcp_servers overrides to the servers the
// Codex files define, as Codex does: the key is a dotted path, and a value
// that does not parse as TOML is a string. touched names the servers an
// override changed. Codex merges whole-table overrides with file entries.
func applyCodexMCPOverrides(base []MCPServerEntry, overrides []string) ([]MCPServerEntry, map[string]bool, bool, error) {
	servers := map[string]MCPServerEntry{}
	var order []string
	put := func(entry MCPServerEntry) {
		if _, seen := servers[entry.Name]; !seen {
			order = append(order, entry.Name)
		}
		servers[entry.Name] = entry
	}
	for _, entry := range base {
		put(entry)
	}
	touched := map[string]bool{}
	for _, override := range overrides {
		key, raw, ok := strings.Cut(override, "=")
		if !ok {
			return nil, nil, false, fmt.Errorf("codex -c %s has no value", override)
		}
		path := strings.Split(strings.TrimSpace(key), ".")
		value := codexOverrideValue(raw)
		switch {
		case len(path) == 1:
			table, ok := value.(map[string]any)
			if !ok {
				return nil, nil, false, fmt.Errorf("codex -c %s is not a table of servers", key)
			}
			for name, def := range table {
				entry, err := codexOverrideServer(name, def)
				if err != nil {
					return nil, nil, false, err
				}
				put(entry)
				touched[name] = true
			}
		case len(path) == 2:
			entry, err := codexOverrideServer(path[1], value)
			if err != nil {
				return nil, nil, false, err
			}
			put(entry)
			touched[path[1]] = true
		default:
			entry := servers[path[1]]
			entry.Name = path[1]
			if len(path) == 3 {
				if err := setCodexServerField(&entry, path[2], value); err != nil {
					return nil, nil, false, fmt.Errorf("codex -c %s: %w", key, err)
				}
			}
			put(entry)
			touched[path[1]] = true
		}
	}
	out := make([]MCPServerEntry, 0, len(order))
	for _, name := range order {
		out = append(out, servers[name])
	}
	return out, touched, false, nil
}

// codexOverrideValue parses an override value as Codex does: as a TOML
// value, or else as a literal string.
func codexOverrideValue(raw string) any {
	var doc map[string]any
	if err := tomlUnmarshal([]byte("v = "+strings.TrimSpace(raw)), &doc); err == nil {
		if value, ok := doc["v"]; ok {
			return value
		}
	}
	return strings.TrimSpace(raw)
}

func codexOverrideServer(name string, def any) (MCPServerEntry, error) {
	table, ok := def.(map[string]any)
	if !ok {
		return MCPServerEntry{}, fmt.Errorf("codex -c mcp_servers.%s is not a table", name)
	}
	entry := MCPServerEntry{Name: name}
	for field, value := range table {
		if err := setCodexServerField(&entry, field, value); err != nil {
			return MCPServerEntry{}, fmt.Errorf("codex -c mcp_servers.%s: %w", name, err)
		}
	}
	return entry, nil
}

// setCodexServerField sets the fields asset_policy matches on; other fields
// (env, enabled, timeouts) do not change where the server points.
func setCodexServerField(entry *MCPServerEntry, field string, value any) error {
	text, isText := value.(string)
	switch field {
	case "url", "command", "transport":
		if !isText {
			return fmt.Errorf("%s is not a string", field)
		}
		switch field {
		case "url":
			entry.URL = text
		case "command":
			entry.Command = text
		default:
			entry.Transport = text
		}
	case "args":
		list, ok := value.([]any)
		if !ok {
			return fmt.Errorf("args is not a list")
		}
		args := make([]string, 0, len(list))
		for _, item := range list {
			arg, ok := item.(string)
			if !ok {
				return fmt.Errorf("args holds a value that is not a string")
			}
			args = append(args, arg)
		}
		entry.Args = args
	}
	return nil
}
