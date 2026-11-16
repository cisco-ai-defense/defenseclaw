// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookruntime

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"
)

// The stable launcher stays small enough for MaxHookLauncherBytes. Keep this
// emergency answer local instead of linking the full gateway hook runner.
// Its normal path still delegates every byte to the verified full hook.
func answerUnavailableDelegation(args []string, stdin io.Reader, stdout, stderr io.Writer, reason string) int {
	fmt.Fprintln(stderr, "defenseclaw: "+reason)
	if len(args) == 0 || args[0] != "hook" {
		return 2
	}
	var connector, event, surface, contract string
	for index := 1; index < len(args); index++ {
		key, value, bound := strings.Cut(args[index], "=")
		if !bound && index+1 < len(args) {
			value = args[index+1]
		}
		switch key {
		case "--connector":
			connector = value
		case "--event":
			event = value
		case "--hook-surface":
			surface = value
		case "--hook-contract":
			contract = value
		default:
			continue
		}
		if !bound {
			index++
		}
	}
	if event == "" && stdin != nil {
		payload, err := io.ReadAll(io.LimitReader(stdin, 1<<20+1))
		if err == nil && len(payload) <= 1<<20 {
			var envelope struct {
				HookEventName string `json:"hook_event_name"`
				Event         string `json:"event"`
			}
			if json.Unmarshal(payload, &envelope) == nil &&
				(envelope.HookEventName == "" || envelope.Event == "" || strings.EqualFold(envelope.HookEventName, envelope.Event)) {
				event = envelope.HookEventName
				if event == "" {
					event = envelope.Event
				}
			}
		}
	}
	message := "DefenseClaw blocked this tool call: its installed hook is unavailable. Run `defenseclaw doctor` and try again."
	write := func(body any, code int) int {
		if err := json.NewEncoder(stdout).Encode(body); err != nil {
			fmt.Fprintf(stderr, "defenseclaw: write closed hook response: %v\n", err)
			return 2
		}
		return code
	}
	switch connector {
	case "copilot":
		if surface == "vscode-local" {
			switch event {
			case "PreToolUse", "":
				return write(map[string]any{"hookSpecificOutput": map[string]any{
					"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": message,
				}}, 0)
			case "UserPromptSubmit":
				return write(map[string]any{"continue": false, "stopReason": message}, 0)
			}
			return 2
		}
		if event == "permissionRequest" {
			return write(map[string]any{"behavior": "deny", "message": message}, 0)
		}
		if event == "preToolUse" || event == "" {
			return write(map[string]any{"permissionDecision": "deny", "permissionDecisionReason": message}, 0)
		}
		return 2
	case "hermes":
		return write(map[string]any{"action": "block", "message": message}, 0)
	case "antigravity":
		if event == "PreToolUse" || event == "" {
			return write(map[string]any{"decision": "deny", "reason": "DefenseClaw policy service is unavailable."}, 0)
		}
		return 2
	case "cursor":
		switch strings.ToLower(event) {
		case "beforesubmitprompt":
			return write(map[string]any{"continue": false, "user_message": message}, 2)
		case "beforetabfileread":
			return write(map[string]any{"permission": "deny"}, 2)
		case "subagentstart", "beforereadfile":
			return write(map[string]any{"permission": "deny", "user_message": message}, 2)
		case "pretooluse", "beforeshellexecution", "beforemcpexecution", "":
			return write(map[string]any{"permission": "deny", "user_message": message, "agent_message": message}, 2)
		}
		return 2
	case "opencode":
		return write(map[string]any{"hook_output": map[string]any{"decision": "deny", "reason": message}}, 2)
	case "codex":
		if (event == "SessionStart" || event == "PreCompact" || event == "PostCompact") &&
			(contract == "codex-hooks-v3" || contract == "codex-hooks-v3-generic" || contract == "codex-hooks-v4") {
			return write(map[string]any{"continue": false, "stopReason": message}, 0)
		}
		switch event {
		case "PreToolUse", "":
			return write(map[string]any{"hookSpecificOutput": map[string]any{
				"hookEventName": "PreToolUse", "permissionDecision": "deny", "permissionDecisionReason": message,
			}}, 0)
		case "PermissionRequest":
			return write(map[string]any{"hookSpecificOutput": map[string]any{
				"hookEventName": "PermissionRequest", "decision": map[string]any{"behavior": "deny", "message": message},
			}}, 0)
		case "UserPromptSubmit", "PostToolUse", "SubagentStop", "Stop":
			return write(map[string]any{"decision": "block", "reason": message}, 0)
		}
		return 2
	case "devin":
		fmt.Fprintln(stdout, message)
		return 2
	default:
		// Claude Code, Kiro and Amp block on exit 2; unknown wiring also
		// exits loudly. There is no successful empty answer on this path.
		return 2
	}
}
