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
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/copilotargs"
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
// The tool and argument projection is copilotargs.LocalToolArgs, shared with
// the hook-side write-target resolver.

// CopilotHookSurfaceVSCodeLocal is the --hook-surface value of a hook command
// registered for the VS Code Local harness.
const CopilotHookSurfaceVSCodeLocal = copilotargs.SurfaceVSCodeLocal

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
			req.ToolArgs = copilotargs.LocalToolArgs(req.ToolName, input)
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
