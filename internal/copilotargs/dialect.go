// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package copilotargs

import "strings"

// SurfaceVSCodeLocal is the --hook-surface value of a Copilot hook command
// registered for the VS Code Local harness. The hook forwards it in the
// X-DefenseClaw-Hook-Dialect header.
const SurfaceVSCodeLocal = "vscode-local"

// LocalDialect returns the event a Copilot hook body is judged as and
// whether the gateway reads it in the VS Code Local dialect (tool_name,
// tool_input) rather than the CLI dialect (toolName, toolArgs). Both inputs
// are bound to the registered hook command; no body field selects a route.
//
// A command of the vscode-local surface reads its bound event in the Local
// dialect. A CLI hook document stays bound to its CLI event and capabilities;
// the per-user shared profile can read either body shape under that binding.
// Mixed schemas remain unreadable.
func LocalDialect(surface, boundEvent string) (string, bool) {
	boundEvent = strings.TrimSpace(boundEvent)
	if strings.TrimSpace(surface) == SurfaceVSCodeLocal {
		return boundEvent, true
	}
	return boundEvent, false
}

// CLIHookLocalEvent matches a Local harness event delivered through the
// per-user CLI hook document to the event bound by that document's command.
// It does not infer an event from tool fields or accept a different event.
func CLIHookLocalEvent(boundEvent, bodyEvent string) (string, bool) {
	local := ""
	switch boundEvent {
	case "sessionStart":
		local = "SessionStart"
	case "userPromptSubmitted":
		local = "UserPromptSubmit"
	case "preToolUse":
		local = "PreToolUse"
	case "postToolUse":
		local = "PostToolUse"
	case "preCompact":
		local = "PreCompact"
	case "subagentStart":
		local = "SubagentStart"
	case "subagentStop":
		local = "SubagentStop"
	case "agentStop":
		local = "Stop"
	}
	return local, local != "" && bodyEvent == local
}

// CLIHookLocalForeignField identifies a CLI-only envelope field. A Local body
// delivered through the per-user CLI document cannot carry CLI fields beside
// its Local shape, even when the extra value is null.
func CLIHookLocalForeignField(key string) bool {
	switch key {
	case "hookName", "toolName", "toolArgs", "toolCalls", "toolInput",
		"tool_args", "args", "arguments", "sessionId", "permissionSuggestions":
		return true
	default:
		return false
	}
}
