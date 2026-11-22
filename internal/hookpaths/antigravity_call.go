// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"path/filepath"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/antigravityargs"
)

// antigravityCall reads an agy hook body's toolCall as the gateway's agy
// profile reads it (antigravityargs): the tool name, the arguments the
// trusted-action parser judges (TrustedShellArgs, else the literal args) and
// the command's directory (the call's Cwd, else the first workspace path, the
// directory the gateway places the call in). present is false for another
// connector or a body without a toolCall; ok is false for a toolCall the
// gateway refuses (malformed, duplicate or colliding keys).
func antigravityCall(connector string, envelope map[string]json.RawMessage, payload []byte) (tool string, args json.RawMessage, cwd string, present, ok bool) {
	if !strings.EqualFold(strings.TrimSpace(connector), "antigravity") {
		return "", nil, "", false, false
	}
	_, camel := envelope["toolCall"]
	_, snake := envelope["tool_call"]
	if !camel && !snake {
		return "", nil, "", false, false
	}
	name, raw, valid := antigravityargs.ToolCall(payload)
	if !valid {
		return "", nil, "", true, false
	}
	args = raw
	if projected, dir, projectedOK := antigravityargs.TrustedShellArgs(name, raw); projectedOK {
		args, cwd = projected, dir
	} else {
		// A refused projection still runs in the Cwd it names
		// (connector.ShellCommandCWD).
		var fields struct {
			Cwd string `json:"Cwd"`
		}
		if json.Unmarshal(raw, &fields) == nil && filepath.IsAbs(fields.Cwd) {
			cwd = fields.Cwd
		}
	}
	if cwd == "" {
		var workspaces []json.RawMessage
		_ = json.Unmarshal(envelope["workspacePaths"], &workspaces)
		for _, entry := range workspaces {
			var dir string
			if json.Unmarshal(entry, &dir) == nil && strings.TrimSpace(dir) != "" {
				cwd = strings.TrimSpace(dir)
				break
			}
		}
	}
	return name, args, cwd, true, true
}

// clientShellCommands are the shell commands a call's arguments carry, as
// the gateway reads them: the text under command and under cmd, or, for a
// shell execution tool with neither, the command under any key the
// trusted-action parser reads as the command (actionfacts.ShellCommandArgument,
// the gateway's reading: agy run_command's CommandLine, GAP-1132).
func clientShellCommands(tool string, toolArgs map[string]json.RawMessage, args json.RawMessage) []string {
	var commands []string
	for _, key := range []string{"command", "cmd"} {
		var command string
		if json.Unmarshal(toolArgs[key], &command) == nil && command != "" {
			commands = append(commands, command)
		}
	}
	if len(commands) == 0 && actionfacts.IsImmediateShellExecutionTool(tool) {
		if command, ok := actionfacts.ShellCommandArgument(args); ok && command != "" {
			commands = append(commands, command)
		}
	}
	return commands
}
