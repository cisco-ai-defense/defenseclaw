// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import "strings"

// Claude Cowork is a surface of the claudecode connector: Claude Desktop runs
// it with the Claude Code engine it bundles, and the engine runs Claude Code
// hooks on the device (hookexec.CoworkHeader). Cowork adds its own tools,
// most of them MCP tools of servers the engine hosts in process
// ("source":"sdk" in the hook payload's mcp_server). This file is the closed
// vocabulary DefenseClaw maps them with, measured on Claude Desktop 4.4212.0
// with engine CoworkVocabularyEngineVersion. A tool that is not listed keeps
// the generic MCP tool path: it is inspected like any MCP tool, never
// allowed without inspection.

// CoworkSurface is the surface value Cowork records carry.
const CoworkSurface = "cowork"

// CoworkVocabularyEngineVersion is the Claude Code engine the vocabulary was
// measured on. A test pins it so a change of the vocabulary names the build
// it was measured on.
const CoworkVocabularyEngineVersion = "2.1.309"

// CoworkToolClass is what a Cowork tool does, for inspection and audit.
type CoworkToolClass string

const (
	// CoworkToolShell runs a command in the Cowork VM's shell. It is
	// inspected exactly like Claude Code's Bash.
	CoworkToolShell CoworkToolClass = "shell"
	// CoworkToolFetch fetches a URL (server side). It is inspected like
	// Claude Code's WebFetch.
	CoworkToolFetch CoworkToolClass = "fetch"
	// CoworkToolBrowserNavigate opens a URL in the Desktop browser. Its URL
	// is inspected like a WebFetch URL.
	CoworkToolBrowserNavigate CoworkToolClass = "browser_navigate"
	// CoworkToolBrowserScript runs JavaScript in a browser tab.
	CoworkToolBrowserScript CoworkToolClass = "browser_script"
	// CoworkToolBrowserForm types values into a page's form.
	CoworkToolBrowserForm CoworkToolClass = "browser_form"
	// CoworkToolBrowser is any other browser action (read, find, tabs, ...).
	CoworkToolBrowser CoworkToolClass = "browser"
	// CoworkToolPersistence creates or changes a scheduled task, which runs
	// later without the user.
	CoworkToolPersistence CoworkToolClass = "persistence"
	// CoworkToolDestructive grants a file delete.
	CoworkToolDestructive CoworkToolClass = "destructive"
	// CoworkToolScopeChange asks for another connected folder.
	CoworkToolScopeChange CoworkToolClass = "scope_change"
	// CoworkToolSkillAdmission saves a skill.
	CoworkToolSkillAdmission CoworkToolClass = "skill_admission"
	// CoworkToolPluginAdmission suggests or lists plugins.
	CoworkToolPluginAdmission CoworkToolClass = "plugin_admission"
	// CoworkToolMCPAdmission reads or changes the MCP registry.
	CoworkToolMCPAdmission CoworkToolClass = "mcp_admission"
	// CoworkToolTranscriptAccess reads other sessions.
	CoworkToolTranscriptAccess CoworkToolClass = "transcript_access"
	// CoworkToolWorkspace is a workspace server tool this vocabulary does
	// not know: the generic MCP tool path.
	CoworkToolWorkspace CoworkToolClass = "workspace_unknown"
	// CoworkToolDesktop is any other tool of a Cowork server (skills,
	// widget context, scheduled-task listing): audited.
	CoworkToolDesktop CoworkToolClass = "desktop"
)

// coworkServers are the MCP servers the engine hosts for Cowork. A
// connector the user adds is mcp__<uuid>__*, which is not listed.
var coworkServers = map[string]CoworkToolClass{
	"workspace":       CoworkToolWorkspace,
	"Claude_Browser":  CoworkToolBrowser,
	"cowork":          CoworkToolDesktop,
	"scheduled-tasks": CoworkToolDesktop,
	"plugins":         CoworkToolPluginAdmission,
	"mcp-registry":    CoworkToolMCPAdmission,
	"session_info":    CoworkToolDesktop,
	"skills":          CoworkToolDesktop,
}

var coworkTools = map[string]CoworkToolClass{
	"mcp__workspace__bash":                        CoworkToolShell,
	"mcp__workspace__web_fetch":                   CoworkToolFetch,
	"mcp__Claude_Browser__navigate":               CoworkToolBrowserNavigate,
	"mcp__Claude_Browser__javascript_tool":        CoworkToolBrowserScript,
	"mcp__Claude_Browser__form_input":             CoworkToolBrowserForm,
	"mcp__cowork__allow_cowork_file_delete":       CoworkToolDestructive,
	"mcp__cowork__request_cowork_directory":       CoworkToolScopeChange,
	"mcp__cowork__save_skill":                     CoworkToolSkillAdmission,
	"mcp__scheduled-tasks__create_scheduled_task": CoworkToolPersistence,
	"mcp__scheduled-tasks__update_scheduled_task": CoworkToolPersistence,
	"mcp__plugins__suggest_plugin_install":        CoworkToolPluginAdmission,
	"mcp__session_info__read_transcript":          CoworkToolTranscriptAccess,
	"mcp__session_info__list_sessions":            CoworkToolTranscriptAccess,
}

// CoworkToolClassFor classifies a Cowork tool by its exact name. ok is false
// for a tool of no Cowork server (a built-in Claude Code tool such as Read,
// or a connector's mcp__<uuid>__* tool).
func CoworkToolClassFor(tool string) (CoworkToolClass, bool) {
	if class, ok := coworkTools[tool]; ok {
		return class, true
	}
	if !strings.HasPrefix(tool, "mcp__") {
		return "", false
	}
	parts := strings.Split(tool, "__")
	if len(parts) != 3 || parts[2] == "" {
		return "", false
	}
	class, ok := coworkServers[parts[1]]
	return class, ok
}

// CoworkSDKServer reports whether a hook payload's mcp_server object names
// the Cowork server of tool as one the engine hosts itself
// ({"name":"workspace","source":"sdk"}). A server a user configures has
// another source, so a user MCP server that reuses a Cowork server name is
// never taken for the built-in one.
func CoworkSDKServer(tool string, mcpServer map[string]interface{}) bool {
	if _, ok := CoworkToolClassFor(tool); !ok || mcpServer == nil {
		return false
	}
	name, _ := mcpServer["name"].(string)
	source, _ := mcpServer["source"].(string)
	parts := strings.Split(tool, "__")
	return len(parts) == 3 && name == parts[1] && source == "sdk"
}
