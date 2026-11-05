// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import "path/filepath"

// Formats of the agent files AgentHookConfigFiles lists: how the gateway
// reads a document to tell whether it still runs DefenseClaw's hooks.
const (
	// AgentHookConfigClaudeSettings is a Claude Code settings.json: hooks,
	// disableAllHooks and allowManagedHooksOnly.
	AgentHookConfigClaudeSettings = "claude-settings"
	// AgentHookConfigCopilotSettings is a Copilot CLI settings file, where
	// disableAllHooks switches every hook off.
	AgentHookConfigCopilotSettings = "copilot-settings"
	// AgentHookConfigJSONHooks is a JSON or JSONC file whose "hooks" member
	// holds DefenseClaw's hooks (Codex hooks.json, Cursor, Devin, Copilot).
	AgentHookConfigJSONHooks = "json-hooks"
	// AgentHookConfigCodexTOML is Codex's config.toml: [hooks] and the
	// [features] hooks switch.
	AgentHookConfigCodexTOML = "codex-toml"
	// AgentHookConfigOpenCodeConfig is an OpenCode config, whose "plugin"
	// list can name the bridge.
	AgentHookConfigOpenCodeConfig = "opencode-config"
	// AgentHookConfigBridge is the OpenCode bridge plugin DefenseClaw
	// installs: the file is the whole install.
	AgentHookConfigBridge = "bridge"
)

// AgentHookConfigFile is a per-user file of an agent that registers
// DefenseClaw's hooks, or that can switch them off (GAP-0048).
type AgentHookConfigFile struct {
	Connector string
	Path      string
	Format    string
}

// AgentHookConfigFiles lists the per-user hook files of the connectors
// with a hook config the account (and so its agent) owns, at the paths the
// per-user setup writes them, with the process's environment overrides
// (CLAUDE_CONFIG_DIR, CODEX_HOME, OPENCODE_CONFIG_DIR, COPILOT_HOME). The
// gateway guards edits of these files that turn DefenseClaw off.
func AgentHookConfigFiles() []AgentHookConfigFile {
	opts := SetupOpts{}
	claudeDir := claudeCodeConfigDir()
	files := []AgentHookConfigFile{
		{Connector: "claudecode", Path: claudeCodeSettingsPath(), Format: AgentHookConfigClaudeSettings},
		{Connector: "claudecode", Path: filepath.Join(claudeDir, "settings.local.json"), Format: AgentHookConfigClaudeSettings},
		{Connector: "codex", Path: codexConfigPath(), Format: AgentHookConfigCodexTOML},
		{Connector: "codex", Path: codexHooksJSONPath(), Format: AgentHookConfigJSONHooks},
		{Connector: "opencode", Path: opencodePluginPath(opts), Format: AgentHookConfigBridge},
		{Connector: "cursor", Path: cursorHooksPath(opts), Format: AgentHookConfigJSONHooks},
		{Connector: "devin", Path: devinHooksPath(opts), Format: AgentHookConfigJSONHooks},
		{Connector: "copilot", Path: copilotHooksPath(opts), Format: AgentHookConfigJSONHooks},
	}
	for _, name := range []string{"settings.json", "config.json"} {
		if path := copilotHomePath(name); path != "" {
			files = append(files, AgentHookConfigFile{Connector: "copilot", Path: path, Format: AgentHookConfigCopilotSettings})
		}
	}
	for _, path := range opencodeMCPReadPaths(opts) {
		files = append(files, AgentHookConfigFile{Connector: "opencode", Path: path, Format: AgentHookConfigOpenCodeConfig})
	}
	out := files[:0]
	for _, file := range files {
		if file.Path != "" && filepath.IsAbs(file.Path) {
			file.Path = filepath.Clean(file.Path)
			out = append(out, file)
		}
	}
	return out
}

// NormalizeAgentJSONC turns a JSONC agent file (comments, trailing commas)
// into JSON, as the agents that read JSONC do.
func NormalizeAgentJSONC(input []byte) ([]byte, error) {
	return normalizeCopilotJSONC(input)
}
