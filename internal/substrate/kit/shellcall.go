// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package kit

import (
	"bytes"
	"encoding/json"
	"slices"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/copilotargs"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// ShellCommandOf returns the shell command a connector's hook call runs, as
// the connector registry reads that connector's shell tools
// (connector.ShellCommandArgs: Claude Code's and Codex's Bash command, Codex's
// exec_command and Amp's Bash cmd, OpenCode's bash, Copilot's bash and
// powershell, agy's run_command CommandLine, and the rest), or the command of
// a Cursor beforeShellExecution event, which names no tool
// (connector.CursorShellCommandArgs). workdir is the working directory the
// call names for the command, "" for the session's. ok is false for a call
// that runs no shell command. The kit makes its shell proofs for this command
// and the gateway binds them to the same command (substrate-1 GAP-0545).
func ShellCommandOf(connectorName, event string, payload []byte) (command, workdir string, ok bool) {
	var envelope map[string]json.RawMessage
	if json.Unmarshal(payload, &envelope) != nil {
		return "", "", false
	}
	if event == "" {
		_ = json.Unmarshal(envelope["hook_event_name"], &event)
	}
	name := strings.ToLower(strings.TrimSpace(connectorName))
	var reduced json.RawMessage
	if name == "cursor" {
		reduced, _ = connector.CursorShellCommandArgs(event, payload)
	}
	if reduced == nil {
		tool, args := hookToolCall(name, envelope)
		var found bool
		if reduced, found = connector.ShellCommandArgs(name, tool, args); !found {
			return "", "", false
		}
		workdir = connector.ShellCommandCWD(name, tool, args)
		if _, cwd, projected := connector.TrustedShellArgs(name, tool, args); workdir == "" && projected {
			workdir = cwd
		}
		if workdir == "" && name == "codex" && tool == "exec_command" {
			// Codex runs exec_command in its workdir argument (the gateway's
			// Codex hook resolves it before proving the command).
			var fields struct {
				Workdir string `json:"workdir"`
			}
			_ = json.Unmarshal(args, &fields)
			workdir = fields.Workdir
		}
	}
	var fields map[string]json.RawMessage
	if json.Unmarshal(reduced, &fields) != nil {
		return "", "", false
	}
	for _, key := range []string{"command", "cmd", "CommandLine"} {
		var text string
		if raw, present := fields[key]; present && json.Unmarshal(raw, &text) == nil &&
			strings.TrimSpace(text) != "" && !strings.ContainsRune(text, 0) {
			return text, workdir, true
		}
	}
	return "", "", false
}

// ToolArgsOf returns the arguments of a connector's hook call as the
// gateway judges them: tool_input or its spellings (hookToolCall), Copilot's
// CLI toolArgs, and the file a Cursor beforeReadFile event names, which has
// no tool_input ({"file_path": ...}, connector.CursorTrustedReadArgs). The
// kit lists the facts of these arguments under "tool_input.<key>" and the
// gateway binds them to the same arguments (substrate-1 GAP-0545).
func ToolArgsOf(connectorName, event string, payload []byte) json.RawMessage {
	var envelope map[string]json.RawMessage
	if json.Unmarshal(payload, &envelope) != nil {
		return nil
	}
	if event == "" {
		_ = json.Unmarshal(envelope["hook_event_name"], &event)
	}
	name := strings.ToLower(strings.TrimSpace(connectorName))
	if name == "cursor" {
		if args, ok := connector.CursorTrustedReadArgs(event, payload); ok {
			return args
		}
	}
	_, args := hookToolCall(name, envelope)
	return args
}

// hookToolCall is the tool name and arguments of a hook call: tool_name and
// tool_input or their spellings (toolName, toolInput, tool_args, toolArgs,
// args, arguments), and for Copilot its CLI toolArgs, a JSON string, as the
// gateway's Copilot profile projects it (copilotargs.CLIToolArgs).
func hookToolCall(name string, envelope map[string]json.RawMessage) (string, json.RawMessage) {
	first := func(keys ...string) json.RawMessage {
		for _, key := range keys {
			if raw := bytes.TrimSpace(envelope[key]); len(raw) != 0 && !bytes.Equal(raw, []byte("null")) {
				return raw
			}
		}
		return nil
	}
	var tool string
	_ = json.Unmarshal(first("tool_name", "toolName"), &tool)
	tool = strings.TrimSpace(tool)
	args := first("tool_input", "toolInput", "tool_args", "toolArgs", "args", "arguments")
	if name == "copilot" {
		var value any
		if json.Unmarshal(args, &value) == nil {
			args = copilotargs.CLIToolArgs(tool, value)
		}
	}
	return tool, args
}

// shellProofEvent reports an event on which the connector's hook contracts
// carry a tool call before it runs (connector.StructuredActionEvents).
func shellProofEvent(connectorName, event string) bool {
	return event != "" && slices.Contains(connector.StructuredActionEvents(connectorName), event)
}
