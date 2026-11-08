// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"

	"github.com/defenseclaw/defenseclaw/internal/agentprocess"
	"github.com/defenseclaw/defenseclaw/internal/assetfacts"
	"github.com/defenseclaw/defenseclaw/internal/config"
)

// hookAssetFacts is the assetfacts.Header value of a standalone managed
// hook: the names the skill folders this event names or reaches into declare
// in their SKILL.md, the folders a skill selected by name (or typed as a
// Claude Code /name) exists in, and the definition of the MCP server a tool
// call names, read as the user (GAP-0570, GAP-0576, GAP-1212, GAP-0968).
// The gateway, a service account, may not read this home.
func hookAssetFacts(connector string, payload []byte) string {
	connector = strings.ToLower(strings.TrimSpace(connector))
	if connector != "claudecode" && connector != "codex" && connector != "copilot" {
		return ""
	}
	var event struct {
		ToolName      string          `json:"tool_name"`
		ToolNameCamel string          `json:"toolName"`
		ToolInput     map[string]any  `json:"tool_input"`
		ToolArgs      json.RawMessage `json:"toolArgs"`
		CWD           string          `json:"cwd"`
		Prompt        string          `json:"prompt"`
		MCPServerName string          `json:"mcp_server_name"`
		CommandName   string          `json:"command_name"`
	}
	if json.Unmarshal(payload, &event) != nil {
		return ""
	}
	if event.ToolName == "" {
		event.ToolName = event.ToolNameCamel
	}
	if event.ToolInput == nil {
		event.ToolInput = hookToolArgs(event.ToolArgs)
	}
	home, _ := os.UserHomeDir()
	var facts assetfacts.Facts
	addSkill := func(folder, dir string) {
		declared := assetfacts.DeclaredSkillName(dir)
		if declared != "" && !config.SameAssetName(declared, folder) {
			facts.Skills = append(facts.Skills, assetfacts.Skill{Folder: folder, Declared: declared})
		}
	}
	if name := hookInvokedSkillName(connector, event.ToolName, event.ToolInput, event.Prompt); name != "" {
		for _, root := range hookSkillRoots(connector, home, event.CWD) {
			dir := filepath.Join(root, name)
			addSkill(name, dir)
			if _, err := os.Lstat(dir); err == nil {
				facts.SkillDirs = append(facts.SkillDirs, dir)
			}
		}
	}
	for _, ref := range assetfacts.SkillFolderRefs(event.ToolInput, home, event.CWD) {
		addSkill(ref.Name, ref.Dir)
		if ref.Linked {
			// The gateway may not follow the link in this home; say where it
			// leads.
			facts.SkillLinks = append(facts.SkillLinks, ref.Dir)
		}
		if _, err := os.Lstat(ref.Dir); errors.Is(err, os.ErrNotExist) {
			for _, root := range hookSkillRoots(connector, home, event.CWD) {
				addSkill(ref.Name, filepath.Join(root, ref.Name))
			}
		}
	}
	if server := hookMCPServerName(event.ToolName, event.MCPServerName); server != "" && connector != "copilot" {
		entry, source, ok := hookCommandLineMCPServer(connector, event.CWD, server)
		switch {
		case source == unprovenMCPSource:
			facts.MCPUnproven = server
		case !ok && connector == "codex":
			// Codex runs a project definition only for a project its user
			// config trusts; an untrusted project file does not override the
			// server of that name in the user config (GAP-0686).
			entry, ok = config.LookupEffectiveCodexMCPToolServer(event.CWD, server)
		case !ok:
			entry, ok = (*config.Config)(nil).LookupMCPToolServerForConnector(connector, event.CWD, server)
		}
		if ok {
			facts.MCP = &assetfacts.MCPServer{
				Name: entry.Name, URL: entry.URL, Command: entry.Command, Args: entry.Args, Transport: entry.Transport,
				Source: source,
			}
			if connector == "codex" && source == "" && !entry.Bundled {
				facts.MCP.Relocated = entry.SourceScope == "user" && config.CodexHomeRelocated()
				facts.MCP.ProjectScope = entry.SourceScope == "project"
				if facts.MCP.Relocated || facts.MCP.ProjectScope {
					facts.MCP.Digest = config.MCPLaunchDigest(entry)
				}
			}
		}
	}
	facts.Contents = hookAssetContents(connector, home, event.ToolName, event.ToolInput, event.Prompt, event.CommandName, facts.SkillDirs)
	return assetfacts.Encode(facts)
}

// hookSkillRoots are the skill folders the agent loads from for this user:
// the connector's own and the ones its environment adds (Copilot's
// COPILOT_HOME and COPILOT_SKILLS_DIRS), which only a hook that runs as the
// user can see.
func hookSkillRoots(connector, home, cwd string) []string {
	roots := assetfacts.SkillRoots(connector, home, cwd)
	if connector == "copilot" && assetfacts.CopilotHomeSet() {
		// COPILOT_HOME replaces ~/.copilot as the home of Copilot: a skill left
		// in the default one is not loaded, and judging it would block the
		// skill of that name the agent does load.
		roots = slices.DeleteFunc(roots, func(root string) bool { return root == filepath.Join(home, ".copilot", "skills") })
	}
	for _, root := range assetfacts.EnvSkillRoots(connector, home, cwd, hookAgentWorkingDirectory) {
		if !slices.Contains(roots, root) {
			roots = append(roots, root)
		}
	}
	return roots
}

// hookToolArgs decodes the tool arguments of a hook that spells them toolArgs:
// Copilot CLI sends them as a JSON object or as a string holding one.
func hookToolArgs(raw json.RawMessage) map[string]any {
	var args map[string]any
	if len(raw) == 0 || string(raw) == "null" {
		return nil
	}
	if json.Unmarshal(raw, &args) == nil {
		return args
	}
	var text string
	if json.Unmarshal(raw, &text) == nil && json.Unmarshal([]byte(text), &args) == nil {
		return args
	}
	return nil
}

// hookAssetContents reads, as the user, the text of the skill folders a
// request selects and of the Claude Code plugin it belongs to (a plugin
// skill or command, or a tool of a server the plugin bundles). A managed
// Windows gateway reads nothing in a profile and judges this text instead
// (GAP-0699, GAP-0701). Nothing is read for a request that selects neither.
func hookAssetContents(connector, home, toolName string, toolInput map[string]any, prompt, commandName string, skillDirs []string) []assetfacts.Content {
	var out []assetfacts.Content
	for _, dir := range skillDirs {
		if content, ok := assetfacts.ReadContent(assetfacts.ContentSkill, filepath.Base(dir), dir); ok {
			out = append(out, content)
		} else {
			// A folder the hook found but cannot read is still a skill that
			// would run: say so, so the gateway refuses it as unscanned.
			out = append(out, assetfacts.UnreadContent(assetfacts.ContentSkill, filepath.Base(dir), dir))
		}
	}
	if connector != "claudecode" {
		return out
	}
	claudeDir := strings.TrimSpace(os.Getenv("CLAUDE_CONFIG_DIR"))
	if claudeDir == "" {
		claudeDir = filepath.Join(home, ".claude")
	}
	for _, plugin := range hookInvokedPluginNames(claudeDir, toolName, toolInput, prompt, commandName) {
		roots := assetfacts.ClaudePluginRoots(claudeDir, plugin)
		if len(roots) == 0 {
			// The request selects a plugin the registry does not give a folder
			// for (it is missing, unreadable, past the bound the hook reads, or
			// does not list the plugin): the same failure state, not silence.
			out = append(out, assetfacts.UnreadContent(assetfacts.ContentPlugin, plugin, ""))
		}
		for _, root := range roots {
			if content, ok := assetfacts.ReadContent(assetfacts.ContentPlugin, plugin, root); ok {
				out = append(out, content)
			} else {
				out = append(out, assetfacts.UnreadContent(assetfacts.ContentPlugin, plugin, root))
			}
		}
	}
	return out
}

// hookInvokedPluginNames are the plugins a Claude Code request belongs to: a
// Skill call or /command spelled plugin:name, or a tool of a bundled server
// (mcp__plugin_<plugin>_<server>__<tool>).
func hookInvokedPluginNames(claudeDir, toolName string, toolInput map[string]any, prompt, commandName string) []string {
	var names []string
	add := func(name string) {
		if name = strings.TrimSpace(name); name != "" && !slices.Contains(names, name) {
			names = append(names, name)
		}
	}
	qualified := func(spelled string) {
		if plugin, _, ok := strings.Cut(strings.TrimPrefix(strings.TrimSpace(spelled), "/"), ":"); ok {
			add(plugin)
		}
	}
	if strings.EqualFold(strings.TrimSpace(toolName), "Skill") {
		skill, _ := toolInput["skill"].(string)
		qualified(skill)
	}
	qualified(commandName)
	if fields := strings.Fields(prompt); len(fields) > 0 && strings.HasPrefix(fields[0], "/") {
		qualified(fields[0])
	}
	if rest, ok := strings.CutPrefix(strings.TrimSpace(toolName), "mcp__plugin_"); ok {
		server, _, _ := strings.Cut(rest, "__")
		// A plugin name and a server name may both hold an underscore: the
		// server kit_time of plugin r109 and the server time of plugin
		// r109_kit are one tool name. Every registered plugin the name can
		// start with is a candidate owner, as the gateway treats them, and
		// the text of each is sent; the nearest alone would leave another,
		// possibly the protected one, unjudged.
		found := false
		for _, plugin := range assetfacts.ClaudePluginNames(claudeDir) {
			if strings.HasPrefix(server, plugin+"_") && len(server) > len(plugin)+1 {
				add(plugin)
				found = true
			}
		}
		if !found {
			// No registered plugin name starts the server name: the plugin is
			// not known, so the whole server name stands for it and carries the
			// failure state (a plugin the registry cannot be read for).
			add(server)
		}
	}
	return names
}

// hookAgentCommandLine reads the agent process arguments; tests replace it.
var hookAgentCommandLine = agentprocess.CommandLine

// hookAgentWorkingDirectory reads the folder the agent process runs in, or ""
// when it cannot be read; tests replace it. The read walks the process table,
// so it is made once for a parent process: a request asks for it from every
// skill root list it builds, and the answer cannot change while the agent that
// started this hook is the same process.
var hookAgentWorkingDirectory = cachedPerParent(agentprocess.WorkingDirectory)

// cachedPerParent returns read, called again only when the parent process of
// this one is another process than at the last call.
func cachedPerParent(read func() string) func() string {
	var (
		mu     sync.Mutex
		parent int
		value  string
		have   bool
	)
	return func() string {
		mu.Lock()
		defer mu.Unlock()
		if now := os.Getppid(); !have || now != parent {
			parent, value, have = now, read(), true
		}
		return value
	}
}

const unprovenMCPSource = "unproven"

// hookCommandLineMCPServer resolves the MCP server a tool call names from
// the agent's command line, which overrides the config files: Claude Code
// started with --mcp-config FILE reached an unapproved URL under an approved
// server name while DefenseClaw judged the definition in ~/.claude.json
// (GAP-0954). The source is assetfacts.SourceCommandLine when the command
// line defines the server, unprovenMCPSource when the agent's arguments or a
// source they name cannot be read, or when --strict-mcp-config leaves the
// server without a definition, and "" when the files decide.
func hookCommandLineMCPServer(connector, cwd, server string) (config.MCPServerEntry, string, bool) {
	args, dir, err := hookAgentCommandLine()
	if errors.Is(err, agentprocess.ErrNoAgent) {
		return config.MCPServerEntry{}, "", false
	}
	if err != nil {
		return config.MCPServerEntry{}, unprovenMCPSource, false
	}
	if strings.TrimSpace(dir) == "" {
		dir = cwd
	}
	found, present, err := config.CommandLineMCPServer(connector, args, dir, cwd, server)
	switch {
	case !present:
		return config.MCPServerEntry{}, "", false
	case err != nil:
		return config.MCPServerEntry{}, unprovenMCPSource, false
	case found.Found && (strings.TrimSpace(found.Entry.URL) != "" || strings.TrimSpace(found.Entry.Command) != ""):
		return found.Entry, assetfacts.SourceCommandLine, true
	case found.Found:
		return config.MCPServerEntry{}, unprovenMCPSource, false
	case found.Exclusive:
		return config.MCPServerEntry{}, unprovenMCPSource, false
	default:
		return config.MCPServerEntry{}, "", false
	}
}

// hookInvokedSkillName is the skill a tool call, a Claude Code or Copilot
// /name prompt, or a Codex "$name" prompt selects, when it is a plain folder
// name. A tool call selects a skill under every spelling the gateway's probe
// recognizes (assetfacts.SkillNameFromInput), whatever the tool is called.
func hookInvokedSkillName(connector, toolName string, toolInput map[string]any, prompt string) string {
	name := assetfacts.SkillNameFromInput(toolInput)
	fields := strings.Fields(prompt)
	switch {
	case name != "":
	case strings.EqualFold(strings.TrimSpace(toolName), "Skill"):
	case len(fields) > 0 && strings.HasPrefix(fields[0], "$"):
		name = strings.TrimPrefix(fields[0], "$")
	case len(fields) > 0 && (connector == "claudecode" || connector == "copilot") && strings.HasPrefix(fields[0], "/"):
		name = strings.TrimPrefix(fields[0], "/")
	}
	name = strings.TrimSpace(name)
	if name == "" || name == "." || name == ".." || strings.ContainsAny(name, `/\:`) {
		return ""
	}
	return name
}

// hookMCPServerName is the MCP server a tool call names: mcp__<server>__<tool>
// or the event's mcp_server_name.
func hookMCPServerName(toolName, serverName string) string {
	if server := strings.TrimSpace(serverName); server != "" {
		return server
	}
	parts := strings.Split(strings.TrimSpace(toolName), "__")
	if len(parts) >= 3 && parts[0] == "mcp" && strings.TrimSpace(parts[1]) != "" {
		return strings.TrimSpace(parts[1])
	}
	return ""
}
