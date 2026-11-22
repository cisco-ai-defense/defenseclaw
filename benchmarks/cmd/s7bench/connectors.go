// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build s7bench

package main

import (
	"encoding/json"
	"strings"
)

// Connectors the harness can drive. Each case is sent to the hook handler of its own connector, with that connector's
// real payload shape (tool names and argument keys as internal/gateway/connector/trusted_shell_tool_args.go and the
// s7/effects connector-parity tests list them).
var knownConnectors = map[string]bool{"claudecode": true, "codex": true, "opencode": true, "copilot": true, "cursor": true,
	"hermes": true, "kiro": true, "devin": true, "amp": true, "antigravity": true, "openclaw": true}

// connectorOf maps a case's strata.provider to the connector whose hook handler judges it.
// Providers that are not connectors (T3 Code, which hosts Claude and Codex sessions) are judged as Claude Code.
func connectorOf(flagValue, provider string) string {
	if flagValue != "" && flagValue != "auto" {
		return flagValue
	}
	p := strings.ToLower(strings.TrimSpace(provider))
	if knownConnectors[p] {
		return p
	}
	return "claudecode"
}

func mustJSON(v any) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// shellCall is the connector's native shell tool: its tool name and argument shape for one command.
func shellCall(connector, cmd, dialect string) (string, json.RawMessage) {
	ps := dialect == "powershell"
	switch connector {
	case "codex":
		return "Bash", mustJSON(map[string]any{"command": cmd}) // Codex hooks name its shell tool Bash; exec_command carries {"cmd"} and reduces to the same command
	case "opencode":
		return "bash", mustJSON(map[string]any{"command": cmd})
	case "copilot":
		if ps {
			return "powershell", mustJSON(map[string]any{"command": cmd})
		}
		return "bash", mustJSON(map[string]any{"command": cmd})
	case "cursor":
		return "Shell", mustJSON(map[string]any{"command": cmd})
	case "hermes":
		return "terminal", mustJSON(map[string]any{"command": cmd})
	case "kiro":
		if ps {
			return "execute_pwsh", mustJSON(map[string]any{"command": cmd})
		}
		return "execute_bash", mustJSON(map[string]any{"command": cmd})
	case "devin":
		return "exec", mustJSON(map[string]any{"command": cmd})
	case "amp":
		return "Bash", mustJSON(map[string]any{"cmd": cmd})
	case "antigravity":
		return "run_command", mustJSON(map[string]any{"CommandLine": cmd})
	case "openclaw":
		return "exec", mustJSON(map[string]any{"command": cmd})
	}
	if ps {
		return "PowerShell", mustJSON(map[string]any{"command": cmd}) // Claude Code on Windows
	}
	return "Bash", mustJSON(map[string]any{"command": cmd})
}

// buildCall projects a corpus event onto the connector's hook payload. For claudecode it is mapTool plus the PowerShell tool.
// For the other connectors: shell calls use the connector's shell tool, apply_patch keeps its name and {"command": patch text}
// (Codex, Copilot, OpenCode, Cursor), file tools use the connector's key shape where it is known, and everything else is an MCP-style call.
func buildCall(connector string, ev event) (string, json.RawMessage, string) {
	var args map[string]any
	_ = json.Unmarshal(ev.Args, &args)
	if args == nil {
		args = map[string]any{}
	}
	lower := strings.ToLower(strings.TrimSpace(ev.ToolName))
	cmd := ev.Command
	if cmd == "" {
		cmd = str(args, "command", "cmd", "script", "code", "commands", "input")
	}
	if shellTools[lower] || lower == "powershell" || lower == "pwsh" || lower == "shell_command" || lower == "exec_command" {
		if cmd != "" {
			dialect := ev.Dialect
			if lower == "powershell" || lower == "pwsh" {
				dialect = "powershell"
			}
			t, in := shellCall(connector, cmd, dialect)
			return t, in, "shell"
		}
	}
	if lower == "apply_patch" || lower == "applypatch" {
		patch := str(args, "command", "input", "patch", "content")
		if patch == "" {
			patch = cmd
		}
		if patch != "" {
			return "apply_patch", mustJSON(map[string]any{"command": patch}), "patch"
		}
	}
	if connector == "opencode" {
		p := str(args, "file_path", "path", "filePath", "filename")
		switch lower {
		case "write", "create_file", "write_file":
			if p != "" {
				return "write", mustJSON(map[string]any{"filePath": p, "content": str(args, "content", "text", "file_text")}), "write"
			}
		case "edit", "str_replace", "edit_file":
			if p != "" {
				return "edit", mustJSON(map[string]any{"filePath": p, "oldString": str(args, "old_string", "oldString", "old_str"), "newString": str(args, "new_string", "newString", "new_str", "content")}), "edit"
			}
		case "read", "read_file":
			if p != "" {
				return "read", mustJSON(map[string]any{"filePath": p}), "read"
			}
		}
	}
	return mapTool(ev)
}
