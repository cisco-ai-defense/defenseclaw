// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"encoding/json"
	"strings"
)

// Normalize maps one connector's tool call onto a surface-neutral Call, so the
// extractor never sees which connector sent it and the same command produces
// the same effects everywhere (EFFECTS.md section 8, review parity). It is the
// one place connector tool shapes are known; legitimate per-connector
// differences (a login shell, a working directory) are carried in Options by
// the caller, not branched here.
//
// This is the surface the gateway's trusted_action_dispatch per-connector
// branches collapse onto in the rules step; it is not a throwaway bridge.
func Normalize(connector, tool string, args json.RawMessage) Call {
	lt := strings.ToLower(strings.TrimSpace(tool))
	switch {
	case isShellTool(lt):
		cmd := shellCommandFromArgs(args)
		return Call{Surface: SurfaceShell, Tool: tool, Command: cmd}
	case lt == "apply_patch" || lt == "applypatch":
		return Call{Surface: SurfacePatch, Tool: tool, Args: args, Command: shellCommandFromArgs(args)}
	case isFileTool(lt):
		return Call{Surface: SurfaceFileTool, Tool: tool, Args: args}
	}
	return Call{Surface: SurfaceMCP, Tool: tool, Args: args}
}

var shellToolNames = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "shell": true, "command": true, "exec": true,
	"execute_command": true, "exec_command": true, "run_command": true, "run_shell_command": true, "run_terminal_cmd": true,
	"execute_bash": true, "execute_pwsh": true, "terminal": true, "shell_exec": true, "local_shell": true,
	"powershell": true, "cmd": true, "process": true, "send_command_input": true,
}

func isShellTool(t string) bool { return shellToolNames[t] }

func isFileTool(t string) bool {
	switch t {
	case "write", "edit", "multiedit", "read", "view", "create", "create_file", "write_file",
		"str_replace", "str_replace_editor", "str_replace_based_edit_tool", "notebookedit", "apply_diff",
		"edit_file", "read_file", "fs_write", "fs_read":
		return true
	}
	return false
}

// shellCommandFromArgs pulls the command string from the common shapes: a plain
// {"command":"..."} / {"cmd":...} / {"keystrokes":...}, or an argv array whose
// last element is a -c payload (Codex {"command":["bash","-lc","..."]}).
func shellCommandFromArgs(args json.RawMessage) string {
	if len(args) == 0 {
		return ""
	}
	var m map[string]any
	if err := json.Unmarshal(args, &m); err != nil {
		return ""
	}
	for _, k := range []string{"command", "cmd", "script", "code", "input", "keystrokes", "commandLine"} {
		v, ok := m[k]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case string:
			if t != "" {
				return t
			}
		case []any:
			if s := commandFromArgv(t); s != "" {
				return s
			}
		}
	}
	return ""
}

// commandFromArgv turns ["bash","-lc","CMD"] or ["sh","-c","CMD"] into CMD; a
// plain argv with no -c payload is joined with spaces.
func commandFromArgv(a []any) string {
	parts := make([]string, 0, len(a))
	for _, e := range a {
		if s, ok := e.(string); ok {
			parts = append(parts, s)
		}
	}
	for i := 0; i+1 < len(parts); i++ {
		if parts[i] == "-c" || parts[i] == "-lc" || parts[i] == "-Command" {
			return parts[i+1]
		}
	}
	return strings.Join(parts, " ")
}
