// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"encoding/json"
	"strings"
)

// GitHub Copilot in VS Code runs agent-mode hooks in its Local harness. That
// harness reads the same ~/.copilot/hooks and .github/hooks directories as
// the Copilot CLI, but it speaks a different dialect: PascalCase events, a
// snake_case stdin body (hook_event_name, session_id, tool_name, tool_input,
// tool_use_id, tool_response, prompt) and a hookSpecificOutput response in
// which "allow" auto-approves the call. The command a DefenseClaw hook file
// registers for that harness carries --hook-surface vscode-local; hookexec
// forwards it in HookDialectHeader and the gateway swaps the Copilot profile
// for CopilotVSCodeLocalProfile. Commands without the marker keep the Copilot
// CLI dialect byte for byte.
//
// Vendor sources (reviewed 2026-09):
//   - https://code.visualstudio.com/docs/copilot/customization/hooks
//   - https://code.visualstudio.com/docs/agents/reference/hooks-reference
//   - https://docs.github.com/en/copilot/reference/hooks-reference (the
//     Copilot CLI also accepts PascalCase events and then sends this
//     snake_case body)
//
// The Local harness publishes no list of built-in tool names ("tool names and
// arguments differ between harnesses"), so the projections below cover the
// VS Code agent tools DefenseClaw can judge exactly and pass every other tool
// or argument shape through unchanged, which ActionFacts parses as partial.

// CopilotHookSurfaceVSCodeLocal is the --hook-surface value of a hook command
// registered for the VS Code Local harness.
const CopilotHookSurfaceVSCodeLocal = "vscode-local"

// CopilotVSCodeLocalContractID names the VS Code Local dialect. It is a
// dialect contract, selected only by the hook command's surface marker:
// ResolveHookContract never returns it, because the agent version cache
// describes the Copilot CLI, not the VS Code extension.
const CopilotVSCodeLocalContractID = "copilot-vscode-local-v1"

// copilotVSCodeLocalEvents are the Local harness hook events.
var copilotVSCodeLocalEvents = []string{
	"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse",
	"PreCompact", "SubagentStart", "SubagentStop", "Stop",
}

// CopilotVSCodeLocalHookEvents are the events DefenseClaw registers in the
// Local harness hook file: the tool and prompt controls plus the lifecycle
// events that carry audit context.
var CopilotVSCodeLocalHookEvents = []string{
	"SessionStart", "UserPromptSubmit", "PreToolUse", "PostToolUse", "Stop",
}

// ValidCopilotVSCodeLocalHookEvent reports a Local harness event name.
func ValidCopilotVSCodeLocalHookEvent(event string) bool {
	return containsExact(copilotVSCodeLocalEvents, strings.TrimSpace(event))
}

// CopilotVSCodeLocalProfile is the Copilot profile for a request from the VS
// Code Local harness. Identity and compatibility fields stay those of base;
// events, capabilities, decoding, responses, lifecycle and correlation are
// the Local dialect's.
func CopilotVSCodeLocalProfile(base HookProfile) HookProfile {
	p := base
	p.ContractID = CopilotVSCodeLocalContractID
	p.SupportedEvents = append([]string(nil), copilotVSCodeLocalEvents...)
	p.ResponseFieldName = "hook_output"
	p.Capabilities = HookCapability{
		CanBlock:     true,
		CanAskNative: true,
		AskEvents:    []string{"PreToolUse"},
		// Stop and SubagentStop are not block events: a block there keeps
		// the agent running instead of denying anything.
		BlockEvents:        []string{"PreToolUse", "UserPromptSubmit"},
		SupportsFailClosed: true,
		Scope:              base.Capabilities.Scope,
		ConfigPath:         base.Capabilities.ConfigPath,
	}
	p.Decode = copilotVSCodeLocalDecode
	p.DecodeToolArgs = nil
	p.MapVerdict = hookOnlyProfileMapVerdict
	p.Respond = copilotVSCodeLocalRespond
	p.ToolCallLifecycle = copilotVSCodeLocalToolCallLifecycle()
	if spec, ok := CorrelationSpecForConnector("copilot", CopilotVSCodeLocalContractID); ok {
		p.Correlation = spec
	}
	return p
}

func copilotVSCodeLocalDecode(payload map[string]interface{}) HookProfileRequest {
	req := HookProfileRequest{
		ConnectorName: "copilot",
		HookEventName: hookFirstString(payload, "hook_event_name"),
		CWD:           hookFirstString(payload, "cwd"),
		ToolName:      hookFirstString(payload, "tool_name"),
		Payload:       payload,
	}
	switch req.HookEventName {
	case "PreToolUse", "PostToolUse":
		if input, ok := payload["tool_input"]; ok {
			req.ToolArgsAuthoritative = true
			req.ToolArgs = copilotVSCodeLocalToolArgs(req.ToolName, input)
		}
		if req.HookEventName == "PostToolUse" {
			req.Content = cursorHookContent(payload["tool_response"])
			req.Direction = "tool_result"
		}
	case "UserPromptSubmit":
		req.Content = hookFirstString(payload, "prompt")
		req.Direction = "prompt"
	}
	return req
}

// copilotVSCodeLocalProjection maps one VS Code agent tool onto the canonical
// ActionFacts tool and argument names. keys is the closed set of argument
// names the tool is known to send; fields maps the ones DefenseClaw judges.
type copilotVSCodeLocalProjection struct {
	action string
	keys   []string
	fields map[string]string
}

var copilotVSCodeLocalProjections = map[string]copilotVSCodeLocalProjection{
	"run_in_terminal": {
		action: "shell",
		keys:   []string{"command", "explanation", "goal", "isBackground", "timeout"},
		fields: map[string]string{"command": "command"},
	},
	"read_file": {
		action: "read_file",
		keys:   []string{"filePath", "startLine", "endLine", "offset", "limit"},
		fields: map[string]string{"filePath": "path"},
	},
	"list_dir": {
		action: "list_directory",
		keys:   []string{"path"},
		fields: map[string]string{"path": "path"},
	},
	"create_file": {
		action: "create_file",
		keys:   []string{"filePath", "content"},
		fields: map[string]string{"filePath": "path", "content": "content"},
	},
	"replace_string_in_file": {
		action: "edit_file",
		keys:   []string{"filePath", "oldString", "newString", "explanation"},
		fields: map[string]string{"filePath": "path", "newString": "content"},
	},
	"insert_edit_into_file": {
		action: "edit_file",
		keys:   []string{"filePath", "code", "explanation"},
		fields: map[string]string{"filePath": "path", "code": "content"},
	},
}

// CopilotVSCodeLocalActionTool is the ActionFacts tool name for a VS Code
// Local tool: its projection's canonical name, or the native name.
func CopilotVSCodeLocalActionTool(toolName string) string {
	toolName = strings.TrimSpace(toolName)
	if toolName == "fetch_webpage" {
		return "web_fetch"
	}
	if p, ok := copilotVSCodeLocalProjections[toolName]; ok {
		return p.action
	}
	return toolName
}

// copilotVSCodeLocalToolArgs projects a known tool's arguments onto canonical
// names. An unknown tool, an unknown argument name, or a non-string judged
// value keeps the native object, so ActionFacts sees the shape it cannot
// prove instead of a projection that drops part of the call.
func copilotVSCodeLocalToolArgs(toolName string, input interface{}) json.RawMessage {
	native, err := json.Marshal(input)
	if err != nil {
		return nil
	}
	args, ok := input.(map[string]interface{})
	if !ok {
		return native
	}
	toolName = strings.TrimSpace(toolName)
	if toolName == "fetch_webpage" {
		// One URL is one fetch; a list or a query-only call stays native.
		urls, ok := args["urls"].([]interface{})
		if !ok || len(urls) != 1 || !copilotVSCodeLocalOnlyKeys(args, "urls", "query") {
			return native
		}
		url, ok := urls[0].(string)
		if !ok || strings.TrimSpace(url) == "" {
			return native
		}
		out, _ := json.Marshal(map[string]string{"url": url})
		return out
	}
	p, ok := copilotVSCodeLocalProjections[toolName]
	if !ok || !copilotVSCodeLocalOnlyKeys(args, p.keys...) {
		return native
	}
	out := make(map[string]string, len(p.fields))
	for from, to := range p.fields {
		value, present := args[from]
		if !present {
			continue
		}
		text, ok := value.(string)
		if !ok {
			return native
		}
		out[to] = text
	}
	encoded, err := json.Marshal(out)
	if err != nil {
		return native
	}
	return encoded
}

func copilotVSCodeLocalOnlyKeys(args map[string]interface{}, keys ...string) bool {
	for key := range args {
		if !containsExact(keys, key) {
			return false
		}
	}
	return true
}

// copilotVSCodeLocalRespond renders the Local harness response. An allow is
// no output at all: the harness treats permissionDecision "allow" as an
// auto-approval that skips its own confirmation, which DefenseClaw never
// grants. Deny and ask are the documented PreToolUse decisions, and a
// blocked prompt stops the turn with continue=false.
func copilotVSCodeLocalRespond(in HookRespondInput) HookRespondOutput {
	reason := connectorReasonForProfile(in.Req.ConnectorName, in.Action, in.Req.ToolName, in.Reason)
	return HookRespondOutput{
		FieldName: "hook_output",
		Output:    CopilotVSCodeLocalHookOutput(in.Req.HookEventName, in.Action, reason, in.AdditionalContext),
	}
}

// CopilotVSCodeLocalHookOutput is the Local harness stdout object for an
// event and final action, or nil for no output.
func CopilotVSCodeLocalHookOutput(event, action, reason, additional string) map[string]interface{} {
	switch event {
	case "PreToolUse":
		decision := ""
		switch action {
		case "block":
			decision = "deny"
		case "confirm":
			decision = "ask"
		default:
			return nil
		}
		return map[string]interface{}{"hookSpecificOutput": map[string]interface{}{
			"hookEventName":            "PreToolUse",
			"permissionDecision":       decision,
			"permissionDecisionReason": reason,
		}}
	case "UserPromptSubmit":
		if action == "block" {
			return map[string]interface{}{"continue": false, "stopReason": reason}
		}
	case "SessionStart", "PostToolUse", "SubagentStart":
		if additional != "" {
			return map[string]interface{}{"hookSpecificOutput": map[string]interface{}{
				"hookEventName":     event,
				"additionalContext": additional,
			}}
		}
	}
	return nil
}

func copilotVSCodeLocalToolCallLifecycle() ToolCallLifecycleContract {
	return ToolCallLifecycleContract{
		Version:                           ToolCallLifecycleContractVersion,
		PreProposalEvents:                 []string{"PreToolUse"},
		AuthoritativeSuccessEvents:        []string{"PostToolUse"},
		AuthoritativeFailureEvents:        []string{},
		AuthoritativeDenialEvents:         []string{},
		AuthoritativePendingDiscardEvents: []string{"Stop"},
		AuthoritativeTerminalEvents:       []string{},
		InvocationIDAuthority:             ToolInvocationIDNone,
		OutcomeAuthority:                  ToolOutcomeEventKind,
		StatefulEnforcementLevel:          StatefulToolDetectionOnly,
		Routing: ToolEventRouting{
			StructuredActionEvents: []string{"PreToolUse"},
			ResultContentEvents:    []string{"PostToolUse"},
			StateTransitionEvents:  []string{},
			AuditOnlyEvents:        []string{"SessionStart", "PreCompact", "SubagentStart", "SubagentStop", "Stop"},
		},
		CoveredToolSurfaces: []ToolSurface{
			ToolSurfaceGeneric, ToolSurfaceShell, ToolSurfaceFileRead,
			ToolSurfaceFileWrite, ToolSurfaceFileEdit, ToolSurfaceMCP,
		},
		OfficialSourceURLs: []string{
			"https://code.visualstudio.com/docs/copilot/customization/hooks",
			"https://code.visualstudio.com/docs/agents/reference/hooks-reference",
		},
		Limitations: []string{
			"The Local harness publishes no built-in tool list; unprojected tools and argument shapes are judged as partial.",
			"tool_use_id is reported but PostToolUse carries no failure status, so tool state remains detection-only.",
		},
	}
}
