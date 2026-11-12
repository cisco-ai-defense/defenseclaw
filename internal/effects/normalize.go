// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"encoding/json"
	"strings"
)

// Normalize maps one connector's tool call onto a surface-neutral Call so the
// extractor never sees which connector sent it and the same command produces
// the same effects everywhere (EFFECTS.md section 8, review parity/SF-1/SF-3).
func Normalize(connector, tool string, args json.RawMessage) Call {
	lt := strings.ToLower(strings.TrimSpace(tool))
	switch {
	case isShellTool(lt):
		return shellCall(tool, args)
	case lt == "apply_patch" || lt == "applypatch":
		return Call{Surface: SurfacePatch, Tool: tool, Args: args, Command: shellStringArg(args)}
	case isFileTool(lt):
		return Call{Surface: SurfaceFileTool, Tool: tool, Args: args}
	}
	return Call{Surface: SurfaceMCP, Tool: tool, Args: args}
}

var shellToolNames = map[string]bool{
	"bash": true, "sh": true, "zsh": true, "shell": true, "command": true, "exec": true,
	"execute_command": true, "exec_command": true, "run_command": true, "run_shell_command": true,
	"run_terminal_cmd": true, "run_in_terminal": true, "execute_bash": true, "execute_pwsh": true,
	"terminal": true, "shell_exec": true, "local_shell": true, "powershell": true, "cmd": true,
	"process": true, "send_command_input": true,
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

var shellArgv0 = map[string]bool{"bash": true, "sh": true, "zsh": true, "dash": true, "ksh": true}

// shellCall builds a shell Call from the common arg shapes. A string command
// field is the command; an argv array whose argv[0] is a shell with a -c/-lc
// payload uses that payload; any other argv is kept structured as SurfaceArgv so
// an element like "/tmp/a b" is not re-split (review SF-3).
func shellCall(tool string, args json.RawMessage) Call {
	if len(args) == 0 {
		return Call{Surface: SurfaceShell, Tool: tool}
	}
	var m map[string]any
	if json.Unmarshal(args, &m) != nil {
		return Call{Surface: SurfaceShell, Tool: tool}
	}
	for _, k := range []string{"command", "cmd", "script", "code", "input", "keystrokes", "commandLine"} {
		v, ok := m[k]
		if !ok {
			continue
		}
		switch t := v.(type) {
		case string:
			if t != "" {
				return Call{Surface: SurfaceShell, Tool: tool, Command: t}
			}
		case []any:
			argv := toStrings(t)
			if len(argv) == 0 {
				continue
			}
			if len(argv) >= 2 && shellArgv0[baseName(argv[0])] {
				for i := 0; i+1 < len(argv); i++ {
					if argv[i] == "-c" || argv[i] == "-lc" {
						return Call{Surface: SurfaceShell, Tool: tool, Command: argv[i+1]}
					}
				}
			}
			return Call{Surface: SurfaceArgv, Tool: tool, Argv: argv}
		}
	}
	return Call{Surface: SurfaceShell, Tool: tool}
}

func shellStringArg(args json.RawMessage) string {
	var m map[string]any
	if len(args) == 0 || json.Unmarshal(args, &m) != nil {
		return ""
	}
	for _, k := range []string{"command", "cmd", "input", "patch", "content"} {
		if v, ok := m[k]; ok {
			if s, ok := v.(string); ok && s != "" {
				return s
			}
		}
	}
	return ""
}

func toStrings(a []any) []string {
	out := make([]string, 0, len(a))
	for _, e := range a {
		s, ok := e.(string)
		if !ok {
			return nil
		}
		out = append(out, s)
	}
	return out
}

func baseName(p string) string {
	p = strings.ReplaceAll(p, `\`, "/")
	if i := strings.LastIndex(p, "/"); i >= 0 {
		p = p[i+1:]
	}
	return strings.ToLower(p)
}
