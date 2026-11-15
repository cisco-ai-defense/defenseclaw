// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"strings"
)

// A command an agent shows only as text (rel-1-0-10:GAP-0619).
//
// Most ACP agents report a command they run in rawInput, which the report
// judge reads as a shell call. Hermes does not: its terminal tool sends the
// command only as the text it displays for the call (hermes-agent
// acp_adapter/tools.py: the content block "$ <command>", and the title
// "terminal: <preview>"); rawInput is set only for a tool Hermes has no
// display for. Read as "a report with no input names no action", a command
// Hermes had already run was judged by the content rules alone, so a rule
// of the pack that reads a tool call (tool_call_only) never saw it: no
// finding, no alert, nothing in the audit.
//
// Hermes also runs its tools itself and asks the editor a permission only for
// the dangerous commands its own approval policy names, so the guard cannot
// refuse a normal command: the report is the one place it is seen, and its
// block is an alert that would have blocked (acpFrameAction.enforceable
// false). The gateway still has to judge it as the shell call it is.

// acpDisplayedCommandConnector is the connector whose ACP reports show a
// command only as text.
const acpDisplayedCommandConnector = "hermes"

// acpTerminalToolName is the name Hermes gives its shell tool, and starts the
// title of its report.
const acpTerminalToolName = "terminal"

// acpDisplayedShellCall reads the first report of a command from an agent
// that shows commands only as text. ok is false for any other report: other
// agents, a report that carries its input, an update, a tool that is not the
// terminal. For the agent's terminal tool the call is the command its text
// shows; a terminal report that shows no command is an unread call (unknown,
// never clean), as a permission that shows no action is.
func acpDisplayedShellCall(connector string, update json.RawMessage) (call acpToolCall, ok bool) {
	if connector != acpDisplayedCommandConnector {
		return acpToolCall{}, false
	}
	var report struct {
		SessionUpdate string          `json:"sessionUpdate"`
		Kind          string          `json:"kind"`
		Title         string          `json:"title"`
		RawInput      json.RawMessage `json:"rawInput"`
		Content       []struct {
			Type    string `json:"type"`
			Content struct {
				Type string `json:"type"`
				Text string `json:"text"`
			} `json:"content"`
		} `json:"content"`
	}
	if json.Unmarshal(update, &report) != nil || report.SessionUpdate != "tool_call" || report.Kind != "execute" {
		return acpToolCall{}, false
	}
	if input := strings.TrimSpace(string(report.RawInput)); input != "" && input != "null" {
		return acpToolCall{}, false // the input is read as for any agent
	}
	title := strings.TrimSpace(report.Title)
	if title != acpTerminalToolName && !strings.HasPrefix(title, acpTerminalToolName+":") {
		return acpToolCall{}, false
	}
	for _, block := range report.Content {
		if block.Type != "content" || block.Content.Type != "text" {
			continue
		}
		if command, shown := strings.CutPrefix(block.Content.Text, "$ "); shown && strings.TrimSpace(command) != "" {
			return acpToolCall{tool: "shell", args: acpCommandArgs(command)}, true
		}
	}
	return acpToolCall{tool: "shell", unread: true}, true
}
