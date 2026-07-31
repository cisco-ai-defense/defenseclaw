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
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	HookCompatibilityKnown       = "known"
	HookCompatibilityUnversioned = "unversioned"
	HookCompatibilityUnknown     = "unknown"
	HookCompatibilityNotGated    = "not-gated"
)

// HookContractNeedsActionOverride reports whether an action-mode setup must
// stop unless the operator explicitly accepts hook-contract drift. Unknown
// means unsupported; unversioned means DefenseClaw can choose a default
// contract but cannot prove the installed connector matches it.
func HookContractNeedsActionOverride(resolution HookContractResolution) bool {
	switch resolution.Status {
	case HookCompatibilityUnknown, HookCompatibilityUnversioned:
		return true
	default:
		return false
	}
}

// HookContract is the versioned, reproducible hook surface DefenseClaw
// knows how to install, decode, evaluate, and respond to for one connector.
//
// A connector may publish multiple contracts as upstream agent CLIs add,
// rename, or remove hook events. Runtime code must resolve a contract before
// deciding whether a hook event is blockable/askable/AID-eligible; it should
// never assume that "latest connector code" describes every installed agent.
type HookContract struct {
	Connector  string
	ContractID string
	// ExactAgentVersions pins date-hash or other non-semver upstream builds
	// without inventing a compatible range. When populated, exact-token
	// matching takes precedence over MinAgentVersion/MaxAgentVersion.
	ExactAgentVersions      []string
	MinAgentVersion         string
	MaxAgentVersion         string
	DefaultForUnversioned   bool
	HookScriptVersion       string
	HookConfigPathTemplates []string
	ResponseFieldName       string
	Events                  []string
	AIDSurfaces             []string
	Capabilities            HookCapability
	SupportsTraceparent     bool
	NativeOTLP              bool
	// ContentEnvelopeKey names the single nested payload object this
	// connector hides inspectable content in (hermes: "extra"). Empty
	// for flat-payload connectors. See HookProfile.ContentEnvelopeKey
	// for the generic-decoder semantics and the no-recursive-scan
	// rationale.
	ContentEnvelopeKey string
	Notes              []string
}

// HookContractResolution records how a raw agent --version string mapped to a
// deterministic hook contract. RawVersion is kept verbatim for audit/debugging;
// NormalizedVersion is a semver-ish value used only for local range matching.
type HookContractResolution struct {
	Connector         string
	RawVersion        string
	NormalizedVersion string
	Status            string
	Reason            string
	Contract          HookContract
}

var versionNumberRE = regexp.MustCompile(`(?i)(?:^|[^0-9])v?([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?`)

var proxyConnectorsWithoutHookGate = map[string]bool{
	"openclaw":  true,
	"zeptoclaw": true,
}

var copilotLegacyHookEvents = []string{
	"sessionStart",
	"sessionEnd",
	"userPromptSubmitted",
	"preToolUse",
	"postToolUse",
	"permissionRequest",
	"agentStop",
	"subagentStart",
	"subagentStop",
	"postToolUseFailure",
	"errorOccurred",
	"preCompact",
	"notification",
}

var copilotCurrentHookEvents = append(
	append([]string(nil), copilotLegacyHookEvents[:3]...),
	append([]string{"userPromptTransformed"}, copilotLegacyHookEvents[3:]...)...,
)

// ValidCopilotHookEvent accepts only event identities which DefenseClaw binds
// to a concrete Copilot registration. Native camelCase Copilot payloads do not
// carry an event discriminator, so the launcher forwards one of these values
// out-of-band after Setup has selected a reviewed, versioned hook contract.
func ValidCopilotHookEvent(event string) bool {
	for _, candidate := range copilotCurrentHookEvents {
		if event == candidate {
			return true
		}
	}
	return false
}

var builtinHookContracts = map[string][]HookContract{
	"codex": {{
		Connector:               "codex",
		ContractID:              "codex-hooks-v1",
		MinAgentVersion:         "0.124.0",
		MaxAgentVersion:         "0.129.0",
		HookScriptVersion:       "v6",
		HookConfigPathTemplates: []string{"~/.codex/config.toml", "~/.codex/managed_config.toml"},
		ResponseFieldName:       "codex_output",
		Events: []string{
			"SessionStart",
			"UserPromptSubmit",
			"PreToolUse",
			"PermissionRequest",
			"PostToolUse",
			"Stop",
		},
		AIDSurfaces: []string{"prompt", "tool_call", "tool_result"},
		Capabilities: HookCapability{
			CanBlock:     true,
			CanAskNative: false,
			BlockEvents: []string{
				"UserPromptSubmit",
				"PreToolUse",
				"PermissionRequest",
				"PostToolUse",
				"Stop",
			},
			SupportsFailClosed: true,
			Scope:              "user",
		},
		SupportsTraceparent: true,
		NativeOTLP:          true,
		Notes: []string{
			"Codex 0.124.0 through 0.128.x expose six stable hook events. They have no hooks/list trust introspection and ignore hooks.state; validate them only as legacy no-bypass execution.",
			"DefenseClaw may preseed inert hook state for upgrade continuity, but does not describe 0.124.0 through 0.128.x as trust-certified.",
			"Codex has no native hook-side ask surface in this contract; confirm verdicts render as alert/systemMessage.",
		},
	}, {
		Connector:               "codex",
		ContractID:              "codex-hooks-v2",
		MinAgentVersion:         "0.129.0",
		MaxAgentVersion:         "0.133.0",
		HookScriptVersion:       "v6",
		HookConfigPathTemplates: []string{"~/.codex/config.toml", "~/.codex/managed_config.toml"},
		ResponseFieldName:       "codex_output",
		Events: []string{
			"SessionStart",
			"UserPromptSubmit",
			"PreToolUse",
			"PermissionRequest",
			"PostToolUse",
			"PreCompact",
			"PostCompact",
			"Stop",
		},
		AIDSurfaces: []string{"prompt", "tool_call", "tool_result"},
		Capabilities: HookCapability{
			CanBlock:     true,
			CanAskNative: false,
			BlockEvents: []string{
				"UserPromptSubmit",
				"PreToolUse",
				"PermissionRequest",
				"PostToolUse",
				"Stop",
			},
			SupportsFailClosed: true,
			Scope:              "user",
		},
		SupportsTraceparent: true,
		NativeOTLP:          true,
		Notes: []string{
			"Codex 0.129.x through 0.132.x add PreCompact and PostCompact plus hooks/list trust introspection, for eight supported events.",
			"On native Windows the generic and command_windows values must remain byte-identical so 0.129.x and newer clients derive the same trusted hook identity.",
			"Codex has no native hook-side ask surface in this contract; confirm verdicts render as alert/systemMessage.",
		},
	}, {
		Connector:               "codex",
		ContractID:              "codex-hooks-v3",
		MinAgentVersion:         "0.133.0",
		MaxAgentVersion:         "0.145.0",
		HookScriptVersion:       "v6",
		HookConfigPathTemplates: []string{"~/.codex/config.toml", "~/.codex/managed_config.toml"},
		ResponseFieldName:       "codex_output",
		Events: []string{
			"SessionStart",
			"UserPromptSubmit",
			"PreToolUse",
			"PermissionRequest",
			"PostToolUse",
			"SubagentStart",
			"SubagentStop",
			"PreCompact",
			"PostCompact",
			"Stop",
		},
		AIDSurfaces: []string{"prompt", "tool_call", "tool_result"},
		Capabilities: HookCapability{
			CanBlock:     true,
			CanAskNative: false,
			BlockEvents: []string{
				"SessionStart",
				"UserPromptSubmit",
				"PreToolUse",
				"PermissionRequest",
				"PostToolUse",
				"SubagentStop",
				"PreCompact",
				"PostCompact",
				"Stop",
			},
			SupportsFailClosed: true,
			Scope:              "user",
		},
		SupportsTraceparent: true,
		NativeOTLP:          true,
		Notes: []string{
			"Codex 0.133.0 through 0.144.x expose the versioned ten-event DefenseClaw matrix, adding SubagentStart and SubagentStop.",
			"SessionStart, PreCompact, and PostCompact blocks render continue=false to stop the current turn, stop before compaction, or stop after compaction respectively. SubagentStop blocks render decision=block to continue the subagent flow.",
			"Stop decision=block continues Codex with a new continuation prompt. PostToolUse block cannot undo the completed tool side effect; its feedback replaces the result flow and rejects the tool promise in code mode.",
			"Release certification requires authentic packaged plus official-client evidence that hooks/list reports every owned handler enabled and trusted without a manual approval step; no such Windows record is attached, so this contract remains preview.",
			"Codex has no native hook-side ask surface in this contract; confirm verdicts render as alert/systemMessage.",
		},
	}, {
		Connector:               "codex",
		ContractID:              "codex-hooks-v4",
		MinAgentVersion:         "0.145.0",
		DefaultForUnversioned:   true,
		HookScriptVersion:       "v6",
		HookConfigPathTemplates: []string{"~/.codex/config.toml", "~/.codex/managed_config.toml"},
		ResponseFieldName:       "codex_output",
		Events: []string{
			"SessionStart",
			"UserPromptSubmit",
			"PreToolUse",
			"PermissionRequest",
			"PostToolUse",
			"SubagentStart",
			"SubagentStop",
			"PreCompact",
			"PostCompact",
			"Stop",
			"SessionEnd",
		},
		AIDSurfaces: []string{"prompt", "tool_call", "tool_result"},
		Capabilities: HookCapability{
			CanBlock:     true,
			CanAskNative: false,
			BlockEvents: []string{
				"SessionStart",
				"UserPromptSubmit",
				"PreToolUse",
				"PermissionRequest",
				"PostToolUse",
				"SubagentStop",
				"PreCompact",
				"PostCompact",
				"Stop",
			},
			SupportsFailClosed: true,
			Scope:              "user",
		},
		SupportsTraceparent: true,
		NativeOTLP:          true,
		Notes: []string{
			"Codex 0.145.0 adds SessionEnd to the ten-event 0.133.0 through 0.144.x matrix.",
			"SessionEnd is a best-effort observation and telemetry event; it is not a block or native ask surface.",
			"SessionStart, PreCompact, and PostCompact blocks render continue=false to stop the current turn, stop before compaction, or stop after compaction respectively. SubagentStop blocks render decision=block to continue the subagent flow.",
			"Stop decision=block continues Codex with a new continuation prompt. PostToolUse block cannot undo the completed tool side effect; its feedback replaces the result flow and rejects the tool promise in code mode.",
			"Release certification requires authentic packaged plus official-client evidence that hooks/list reports every owned handler enabled and trusted without a manual approval step; no such Windows record is attached, so this contract remains preview.",
			"Codex has no native hook-side ask surface in this contract; confirm verdicts render as alert/systemMessage.",
		},
	}},
	"claudecode": {{
		Connector:               "claudecode",
		ContractID:              "claudecode-hooks-v1",
		MinAgentVersion:         "2.1.154",
		DefaultForUnversioned:   true,
		HookScriptVersion:       "v7",
		HookConfigPathTemplates: []string{"~/.claude/settings.json"},
		ResponseFieldName:       "claude_code_output",
		Events: []string{
			"SessionStart",
			"UserPromptSubmit",
			"UserPromptExpansion",
			"MessageDisplay",
			"PreToolUse",
			"PermissionRequest",
			"PermissionDenied",
			"PostToolUse",
			"PostToolUseFailure",
			"PostToolBatch",
			"Stop",
			"StopFailure",
			"SubagentStart",
			"SubagentStop",
			"SessionEnd",
			"InstructionsLoaded",
			"ConfigChange",
			"CwdChanged",
			"FileChanged",
			"WorktreeRemove",
			"TaskCreated",
			"TaskCompleted",
			"TeammateIdle",
			"PreCompact",
			"PostCompact",
			"Elicitation",
			"ElicitationResult",
			"Notification",
		},
		AIDSurfaces: []string{"prompt", "tool_call", "tool_result", "event_content"},
		Capabilities: HookCapability{
			CanBlock:     true,
			CanAskNative: true,
			AskEvents:    []string{"PreToolUse"},
			BlockEvents: []string{
				"UserPromptSubmit",
				"UserPromptExpansion",
				"PreToolUse",
				"PermissionRequest",
				"PostToolBatch",
				"TaskCreated",
				"TaskCompleted",
				"TeammateIdle",
				"Stop",
				"SubagentStop",
				"ConfigChange",
				"PreCompact",
				"Elicitation",
				"ElicitationResult",
			},
			SupportsFailClosed: true,
			Scope:              "user",
		},
		SupportsTraceparent: true,
		NativeOTLP:          true,
		Notes: []string{
			"Pinned to Claude Code 2.1.154: 2.1.152 introduced MessageDisplay and 2.1.154 added the plugin defaultEnabled semantics required by inventory.",
			"Claude Code PreToolUse supports native HITL via permissionDecision=ask.",
			"PostToolUse findings are advisory because the inspected tool side effects have already occurred.",
			"PostToolBatch can block continuation before the next model call, but cannot undo completed batch side effects.",
			"ConfigChange is blockable except when source=policy_settings, where Claude Code ignores blocking decisions.",
		},
	}},
	"hermes": {{
		Connector:               "hermes",
		ContractID:              "hermes-hooks-v1",
		MinAgentVersion:         "0.19.0",
		DefaultForUnversioned:   true,
		HookScriptVersion:       "v6",
		HookConfigPathTemplates: []string{"$HERMES_HOME/config.yaml", "%LOCALAPPDATA%/hermes/config.yaml", "~/.hermes/config.yaml"},
		ResponseFieldName:       "hook_output",
		// Hermes' v0.19 shell-hook surface (config.yaml `hooks:` block).
		// VALID_HOOKS membership alone does not grant response authority:
		// the shell bridge parses a block only at pre_tool_call, context
		// at pre_llm_call, and continue-at-stop at pre_verify. Transform,
		// gateway, approval, API, Kanban, and ordinary lifecycle events
		// are registered for attributed audit but cannot be changed by
		// DefenseClaw's shell-hook JSON response.
		Events: []string{
			"pre_tool_call",
			"post_tool_call",
			"transform_terminal_output",
			"transform_tool_result",
			"transform_llm_output",
			"pre_llm_call",
			"post_llm_call",
			"pre_verify",
			"pre_api_request",
			"post_api_request",
			"api_request_error",
			"on_session_start",
			"on_session_end",
			"on_session_finalize",
			"on_session_reset",
			"subagent_start",
			"subagent_stop",
			"pre_gateway_dispatch",
			"pre_approval_request",
			"post_approval_response",
			"kanban_task_claimed",
			"kanban_task_completed",
			"kanban_task_blocked",
		},
		// pre_llm_call → prompt; pre/post_tool_call → tool_call/tool_result;
		// session + subagent lifecycle → event_content (audit envelope).
		AIDSurfaces: []string{"prompt", "tool_call", "tool_result", "event_content"},
		Capabilities: HookCapability{
			CanBlock:     true,
			CanAskNative: false,
			// Only pre_tool_call honors a blocking stdout response.
			// pre_llm_call injects context and pre_verify can continue a
			// bounded verification loop, but neither is a tool veto.
			// Hermes never blocks on exit code or hook timeout, so
			// SupportsFailClosed stays false.
			BlockEvents:        []string{"pre_tool_call"},
			SupportsFailClosed: false,
			Scope:              "user",
		},
		SupportsTraceparent: true,
		// Hermes nests inspectable content (prompt, tool result, model
		// response, child summary) inside the per-event `extra` object;
		// the generic decoder opens this one declared envelope when
		// every top-level content lookup misses.
		ContentEnvelopeKey: "extra",
		Notes: []string{
			"Covers all 23 Hermes v0.19 VALID_HOOKS events. Hermes nests inspectable event content under the per-event `extra` envelope; the generic decoder lifts declared fields into the canonical lifecycle. Events whose official schema is not documented remain partial, attributed audit rather than inferred enforcement.",
			"pre_tool_call is the only blockable event: Hermes accepts both {\"action\":\"block\",\"message\"} (canonical) and {\"decision\":\"block\",\"reason\"} (Claude-Code style) and normalizes internally. pre_llm_call injects {\"context\":...}; pre_verify accepts {\"action\":\"continue\",\"message\"} to keep the bounded verification loop going. Transform hooks require Python string returns, pre_gateway_dispatch requires skip/rewrite/allow plugin results, and approval/API/Kanban/lifecycle return values are ignored or undocumented by the shell lane, so DefenseClaw audits them without claiming mutation. Confirm verdicts are recorded and alerted without hook output. Non-zero exit codes and hook timeouts only warn upstream, so there is no fail-closed surface; Hermes remains live-smoke pending (https://cisco-ai-defense.github.io/defenseclaw/docs/connectors/hermes/).",
			"Multi-event registration requires hooks_auto_accept in the effective config.yaml on non-TTY/gateway runs (the upstream hook guide calls this cli-config.yaml); otherwise Hermes prompts for per-(event,command) consent on first use and silently skips unaccepted hooks. Setup writes hooks_auto_accept so all events register, and the managed-backup heals it.",
		},
	}},
	"cursor": {{
		Connector:               "cursor",
		ContractID:              "cursor-hooks-v1",
		ExactAgentVersions:      []string{"2026.07.23-e383d2b"},
		DefaultForUnversioned:   true,
		HookScriptVersion:       "v8",
		HookConfigPathTemplates: []string{"~/.cursor/hooks.json"},
		ResponseFieldName:       "hook_output",
		Events: []string{
			"sessionStart",
			"sessionEnd",
			"preToolUse",
			"postToolUse",
			"postToolUseFailure",
			"subagentStart",
			"subagentStop",
			"beforeShellExecution",
			"afterShellExecution",
			"beforeMCPExecution",
			"afterMCPExecution",
			"beforeReadFile",
			"afterFileEdit",
			"beforeTabFileRead",
			"afterTabFileEdit",
			"beforeSubmitPrompt",
			"preCompact",
			"stop",
			"afterAgentResponse",
			"afterAgentThought",
			"workspaceOpen",
		},
		AIDSurfaces: []string{"prompt", "tool_call", "tool_result"},
		Capabilities: HookCapability{
			CanBlock:     true,
			CanAskNative: true,
			AskEvents: []string{
				"beforeShellExecution",
				"beforeMCPExecution",
			},
			BlockEvents: []string{
				"preToolUse",
				"subagentStart",
				"beforeShellExecution",
				"beforeMCPExecution",
				"beforeReadFile",
				"beforeTabFileRead",
				"beforeSubmitPrompt",
			},
			SupportsFailClosed: true,
			Scope:              "user",
		},
		SupportsTraceparent: true,
		Notes: []string{
			"Cursor 1.7 introduced beta hooks for the agent loop, but Cursor does not publish per-event introduction versions for the current 21-event reference. This preview contract is pinned only to the exact Cursor Agent build 2026.07.23-e383d2b published by the official native Windows installer inspected on 2026-07-30; it does not treat the separate Cursor Desktop 3.13 release as an Agent CLI version.",
			"Cursor Agent uses agent as its primary CLI command; cursor-agent remains a compatibility alias.",
			"Cursor native ask is enforced only for beforeShellExecution and beforeMCPExecution. preToolUse and subagentStart expose allow/deny only; DefenseClaw never emits ask for them.",
			"Command hooks fail open by default. An explicit action-mode closed fail mode writes failClosed=true so crashes, timeouts, and invalid JSON block.",
			"sessionStart and sessionEnd are fire-and-forget policy-wise; sessionStart documents only env/additional_context output and sessionEnd has no output. stop and subagentStop accept only followup_message; none is a block or ask gate.",
			"Every command-hook invocation returns a JSON object. beforeSubmitPrompt uses continue; the six permission gates use only their documented permission/message fields; postToolUse, preCompact, sessionStart, stop, subagentStop, and workspaceOpen retain their event-specific outputs; unsupported output events return {}.",
		},
	}},
	"windsurf": {{
		Connector:               "windsurf",
		ContractID:              "windsurf-hooks-v1",
		MinAgentVersion:         "1.12.41",
		DefaultForUnversioned:   true,
		HookScriptVersion:       "v7",
		HookConfigPathTemplates: []string{"~/.codeium/windsurf/hooks.json"},
		ResponseFieldName:       "hook_output",
		Events: []string{
			"pre_user_prompt",
			"pre_read_code",
			"post_read_code",
			"pre_write_code",
			"post_write_code",
			"pre_run_command",
			"post_run_command",
			"pre_mcp_tool_use",
			"post_mcp_tool_use",
			"post_cascade_response",
			"post_cascade_response_with_transcript",
			"post_setup_worktree",
		},
		AIDSurfaces: []string{"prompt", "tool_call", "tool_result"},
		Capabilities: HookCapability{
			CanBlock:           true,
			CanAskNative:       false,
			BlockEvents:        []string{"pre_user_prompt", "pre_read_code", "pre_write_code", "pre_run_command", "pre_mcp_tool_use"},
			SupportsFailClosed: true,
			Scope:              "user",
		},
		SupportsTraceparent: true,
		Notes: []string{
			"Windsurf 1.12.41 added Cascade hooks on user prompts, completing the pre-hook set used by this contract.",
			"Only the five pre_* events are blocking, and Windsurf treats exit code 2 as the blocking decision; other non-zero exit codes continue.",
			"Post hooks do not block Cascade, post_cascade_response hooks run asynchronously, and Restricted Mode disables hooks.",
		},
	}},
	"geminicli": {{
		Connector:               "geminicli",
		ContractID:              "geminicli-hooks-v1",
		MinAgentVersion:         "0.26.0",
		DefaultForUnversioned:   true,
		HookScriptVersion:       "v6",
		HookConfigPathTemplates: []string{"~/.gemini/settings.json"},
		ResponseFieldName:       "hook_output",
		Events: []string{
			"SessionStart",
			"BeforeAgent",
			"BeforeModel",
			"BeforeToolSelection",
			"BeforeTool",
			"AfterTool",
			"AfterModel",
			"AfterAgent",
			"PreCompress",
			"Notification",
			"SessionEnd",
		},
		AIDSurfaces: []string{"prompt", "tool_call", "tool_result"},
		Capabilities: HookCapability{
			CanBlock:     true,
			CanAskNative: false,
			BlockEvents: []string{
				"BeforeAgent",
				"BeforeModel",
				"BeforeTool",
				"AfterTool",
				"AfterAgent",
			},
			SupportsFailClosed: true,
			Scope:              "user",
		},
		SupportsTraceparent: true,
		NativeOTLP:          true,
		Notes: []string{
			"Gemini CLI 0.26.0 enabled hooks by default.",
			"Gemini CLI consumer/free/Google AI Pro/Ultra service ended on 2026-06-18; this contract applies only to continuing enterprise, Google Cloud, and paid API-key access.",
		},
	}},
	"copilot": {
		{
			Connector:               "copilot",
			ContractID:              "copilot-hooks-v1",
			MinAgentVersion:         "1.0.18",
			MaxAgentVersion:         "1.0.76",
			HookScriptVersion:       "v7",
			HookConfigPathTemplates: []string{"~/.copilot/hooks/defenseclaw.json", "<workspace>/.github/hooks/defenseclaw.json"},
			ResponseFieldName:       "hook_output",
			Events:                  append([]string(nil), copilotLegacyHookEvents...),
			AIDSurfaces:             []string{"prompt", "tool_call", "tool_result"},
			Capabilities: HookCapability{
				CanBlock:     true,
				CanAskNative: true,
				AskEvents:    []string{"preToolUse"},
				BlockEvents: []string{
					"preToolUse",
					"permissionRequest",
					"agentStop",
					"subagentStop",
				},
				SupportsFailClosed: false,
				Scope:              "user,workspace",
			},
			SupportsTraceparent: true,
			Notes: []string{
				"GitHub Copilot CLI shipped preToolUse earlier, but the full DefenseClaw contract also needs postToolUseFailure, permissionRequest, and notification hooks; notification landed in 1.0.18.",
				"Copilot CLI native ask is limited to preToolUse / PreToolUse hooks.",
				"postToolUseFailure is advisory-only and can provide recovery additionalContext; it cannot block the failed tool.",
			},
		},
		{
			Connector:               "copilot",
			ContractID:              "copilot-hooks-v2",
			MinAgentVersion:         "1.0.76",
			DefaultForUnversioned:   true,
			HookScriptVersion:       "v7",
			HookConfigPathTemplates: []string{"~/.copilot/hooks/defenseclaw.json", "<workspace>/.github/hooks/defenseclaw.json"},
			ResponseFieldName:       "hook_output",
			Events:                  append([]string(nil), copilotCurrentHookEvents...),
			AIDSurfaces:             []string{"prompt", "tool_call", "tool_result"},
			Capabilities: HookCapability{
				CanBlock:     true,
				CanAskNative: true,
				AskEvents:    []string{"preToolUse"},
				BlockEvents: []string{
					"preToolUse",
					"permissionRequest",
					"agentStop",
					"subagentStop",
				},
				SupportsFailClosed: false,
				Scope:              "user,workspace",
			},
			SupportsTraceparent: true,
			Notes: []string{
				"Current GitHub Copilot CLI documentation includes the mutation-only userPromptTransformed event; DefenseClaw returns no modification.",
				"GitHub Copilot CLI 1.0.76 is the conservative reviewed floor for this current 14-event contract.",
				"Copilot CLI native ask is limited to preToolUse / PreToolUse hooks.",
				"postToolUseFailure is advisory-only and can provide recovery additionalContext; it cannot block the failed tool.",
			},
		},
	},
	"antigravity": {{
		Connector:               "antigravity",
		ContractID:              "antigravity-hooks-v2",
		MinAgentVersion:         "1.1.8",
		DefaultForUnversioned:   true,
		HookScriptVersion:       "v8",
		HookConfigPathTemplates: []string{"~/.gemini/config/hooks.json"},
		ResponseFieldName:       "hook_output",
		// Antigravity 2.0 lifecycle events per the published spec.
		// Order matches chronological lifecycle order so the contract
		// reads as a sequence: PreInvocation → PreToolUse →
		// PostToolUse → PostInvocation → Stop.
		Events: []string{
			"PreInvocation",
			"PreToolUse",
			"PostToolUse",
			"PostInvocation",
			"Stop",
		},
		// Only PreToolUse carries documented inspectable tool-call content.
		// Other lifecycle inputs expose counters, error state, and common
		// metadata that remain available in the event-content audit envelope.
		AIDSurfaces: []string{"tool_call", "event_content"},
		Capabilities: HookCapability{
			CanBlock:           true,
			CanAskNative:       true,
			AskEvents:          []string{"PreToolUse"},
			BlockEvents:        []string{"PreToolUse"},
			SupportsFailClosed: false,
			Scope:              "user",
		},
		SupportsTraceparent: true,
		Notes: []string{
			"Antigravity 2.0 documents five lifecycle events. PreToolUse and PostToolUse use matcher groups with nested handlers; PreInvocation, PostInvocation, and Stop use direct handler lists.",
			"Hard blocking is claimed only for synchronous PreToolUse stdout {\"decision\":\"deny\"}. decision=ask provides native confirmation. Google does not document non-zero hook exit codes as an enforcement interface.",
			"PostToolUse output is {}. PreInvocation and PostInvocation may return injectSteps; DefenseClaw uses ephemeralMessage only for context. Stop requires a decision, where continue re-enters the loop and any other value permits stopping; DefenseClaw returns allow and does not claim Stop blocking.",
			"Setup writes only ~/.gemini/config/hooks.json. Antigravity also discovers <workspace>/.agents/hooks.json. Gemini CLI shares the global config namespace, but its connector registration, lifecycle schema, gateway route, token, and teardown ownership remain separate.",
		},
	}},
	"openhands": {{
		Connector:               "openhands",
		ContractID:              "openhands-hooks-v1",
		MinAgentVersion:         "0.0.0",
		DefaultForUnversioned:   true,
		HookScriptVersion:       "v6",
		HookConfigPathTemplates: []string{"~/.openhands/hooks.json", "<workspace>/.openhands/hooks.json"},
		ResponseFieldName:       "hook_output",
		Events: []string{
			"pre_tool_use",
			"post_tool_use",
			"user_prompt_submit",
			"stop",
			"session_start",
			"session_end",
		},
		AIDSurfaces: []string{"prompt", "tool_call", "tool_result", "event_content"},
		Capabilities: HookCapability{
			CanBlock:     true,
			CanAskNative: false,
			BlockEvents: []string{
				"pre_tool_use",
				"user_prompt_submit",
				"stop",
			},
			SupportsFailClosed: true,
			Scope:              "user,workspace",
		},
		SupportsTraceparent: true,
		Notes: []string{
			"OpenHands hooks use native snake_case event keys and install to ~/.openhands/hooks.json by default, with repo-local .openhands/hooks.json when a workspace is pinned.",
			"Validated with OpenHands CLI 1.16.0; the contract stays unbounded because upstream documents the hooks as a config contract rather than a versioned hook API floor.",
			"OpenHands blocks by exit code 2 and optional decision=deny JSON; no native ask/permission prompt surface is documented, so confirm verdicts are downgraded to additionalContext alerts.",
		},
	}},
	"opencode": {{
		Connector:               "opencode",
		ContractID:              "opencode-hooks-v1",
		MinAgentVersion:         "0.0.0",
		DefaultForUnversioned:   true,
		HookScriptVersion:       "v6",
		HookConfigPathTemplates: []string{"~/.config/opencode/plugins/defenseclaw.js"},
		ResponseFieldName:       "hook_output",
		// opencode exposes plugin hooks (not shell hooks). DefenseClaw's
		// bridge plugin wires tool.execute.before (block) and
		// tool.execute.after (observe). opencode has no hook-driven ask
		// or context-injection channel, so blocking is the only active
		// verdict and it is delivered by throwing inside the plugin.
		Events: []string{
			"session.created", "session.updated", "session.status", "session.idle",
			"session.compacted", "session.error", "session.deleted",
			"tool.execute.before", "tool.execute.after",
		},
		AIDSurfaces: []string{"tool_call", "tool_result"},
		Capabilities: HookCapability{
			CanBlock:     true,
			CanAskNative: false,
			BlockEvents:  []string{"tool.execute.before"},
			// The thrown Error is authoritative — opencode aborts the
			// tool — so the bridge can fail closed on an unreachable
			// gateway when the operator selects fail-closed.
			SupportsFailClosed: true,
			Scope:              "user",
		},
		// The JS bridge POSTs JSON over fetch and does not propagate the
		// W3C traceparent the shell hooks forward via _hardening.sh.
		SupportsTraceparent: false,
		Notes: []string{
			"opencode (https://opencode.ai) auto-loads JS/TS plugins from ~/.config/opencode/plugins/ — there is no command-hook config file to patch. DefenseClaw writes a dependency-free bridge plugin (defenseclaw.js) whose tool.execute.before POSTs to /api/v1/opencode/hook and throws new Error(reason) on a block decision, aborting the tool.",
			"Block is the only active verdict: opencode has no hook-driven ask or context-injection surface. tool.execute.after is observe-only. The bridge honors fail-closed by throwing when the gateway is unreachable and FAIL_MODE=closed.",
			"Contract is unbounded (min 0.0.0): the plugin hook API is documented as a stable contract rather than a versioned floor, matching the OpenHands precedent.",
		},
	}},
	"omnigent": {{
		Connector:               "omnigent",
		ContractID:              "omnigent-custom-policy-v1",
		MinAgentVersion:         "0.7.0",
		DefaultForUnversioned:   true,
		HookScriptVersion:       "v1",
		HookConfigPathTemplates: []string{"$OMNIGENT_CONFIG_HOME/config.yaml", "~/.omnigent/config.yaml"},
		ResponseFieldName:       "",
		Events: []string{
			"UserPromptSubmit",
			"PreToolUse",
			"PostToolUse",
			"AfterAgentResponse",
			"BeforeModel",
			"AfterModel",
		},
		AIDSurfaces: []string{"prompt", "tool_call", "tool_result", "event_content"},
		Capabilities: HookCapability{
			CanBlock:           true,
			CanAskNative:       true,
			AskEvents:          []string{"UserPromptSubmit", "PreToolUse", "BeforeModel"},
			BlockEvents:        []string{"UserPromptSubmit", "PreToolUse", "PostToolUse", "AfterAgentResponse", "BeforeModel", "AfterModel"},
			SupportsFailClosed: true,
			Scope:              "user",
		},
		SupportsTraceparent: true,
		NativeOTLP:          true,
		Notes: []string{
			"OmniGent invokes DefenseClaw through its documented custom Python policy API; the installed callable translates DefenseClaw allow, confirm, and block verdicts to ALLOW, ASK, and DENY.",
			"The bridge covers request, tool_call, tool_result, response, llm_request, and llm_response phases exposed by OmniGent's PolicyEvent schema.",
			"DENY is authoritative on all six phases. Pre-action DENY prevents the action; post-phase DENY uses OmniGent's denial/sentinel behavior to suppress or replace onward-visible content but cannot roll back completed tool or model work. The bridge does not return custom replacement data.",
			"ASK is native only for OmniGent's pre-action request, tool_call, and llm_request phases; post-phase confirm findings remain attributed audit and continue without an approval pause.",
			"The in-process Python bridge forwards an active OpenTelemetry W3C trace context when present; otherwise DefenseClaw starts a new trace.",
			"Optional native OTLP is inactive until the OmniGent launch process exports the standard environment variables; the base/default dependency set includes the required OpenTelemetry packages.",
		},
	}},
}

func KnownHookContracts(connectorName string) []HookContract {
	name := normalizeConnectorName(connectorName)
	contracts := builtinHookContracts[name]
	out := make([]HookContract, len(contracts))
	copy(out, contracts)
	return out
}

func hookContractByID(connectorName, contractID string) (HookContract, bool) {
	contractID = strings.TrimSpace(contractID)
	if contractID == "" {
		return HookContract{}, false
	}
	for _, contract := range KnownHookContracts(connectorName) {
		if contract.ContractID == contractID {
			return contract, true
		}
	}
	return HookContract{}, false
}

func ResolveHookContract(connectorName, rawVersion string) HookContractResolution {
	name := normalizeConnectorName(connectorName)
	if proxyConnectorsWithoutHookGate[name] {
		raw := strings.TrimSpace(rawVersion)
		return HookContractResolution{
			Connector:         name,
			RawVersion:        raw,
			NormalizedVersion: NormalizeAgentVersion(name, raw),
			Status:            HookCompatibilityNotGated,
			Reason:            "proxy/chat connector; no hook contract gate",
		}
	}
	contracts := KnownHookContracts(name)
	if len(contracts) == 0 {
		return HookContractResolution{
			Connector:  name,
			RawVersion: strings.TrimSpace(rawVersion),
			Status:     HookCompatibilityUnknown,
			Reason:     "no hook contract registered for connector",
		}
	}
	raw := strings.TrimSpace(rawVersion)
	normalized := NormalizeAgentVersion(name, raw)
	if raw == "" {
		return HookContractResolution{
			Connector:         name,
			RawVersion:        "",
			NormalizedVersion: "",
			Status:            HookCompatibilityUnversioned,
			Reason:            "agent version not probed; using connector default hook contract",
			Contract:          defaultHookContract(contracts),
		}
	}
	if normalized == "" {
		return HookContractResolution{
			Connector:         name,
			RawVersion:        raw,
			NormalizedVersion: "",
			Status:            HookCompatibilityUnknown,
			Reason:            "could not normalize agent version",
		}
	}
	for _, contract := range contracts {
		if contractMatchesAgentVersion(contract, raw, normalized) {
			return HookContractResolution{
				Connector:         name,
				RawVersion:        raw,
				NormalizedVersion: normalized,
				Status:            HookCompatibilityKnown,
				Reason:            fmt.Sprintf("matched hook contract %s", contract.ContractID),
				Contract:          contract,
			}
		}
	}
	return HookContractResolution{
		Connector:         name,
		RawVersion:        raw,
		NormalizedVersion: normalized,
		Status:            HookCompatibilityUnknown,
		Reason:            "no hook contract matches normalized agent version",
	}
}

func contractMatchesAgentVersion(contract HookContract, raw, normalized string) bool {
	if len(contract.ExactAgentVersions) != 0 {
		return exactAgentVersionMatch(raw, contract.ExactAgentVersions)
	}
	return versionInRange(normalized, contract.MinAgentVersion, contract.MaxAgentVersion)
}

func exactAgentVersionMatch(raw string, expected []string) bool {
	fields := strings.Fields(strings.TrimSpace(raw))
	if len(fields) == 0 || len(fields) > 2 {
		return false
	}
	token := fields[len(fields)-1]
	if len(fields) == 2 {
		command := strings.ToLower(strings.TrimSpace(fields[0]))
		if command != "agent" && command != "cursor-agent" {
			return false
		}
	}
	if len(token) > 1 && (token[0] == 'v' || token[0] == 'V') {
		token = token[1:]
	}
	for _, candidate := range expected {
		if strings.EqualFold(token, strings.TrimSpace(candidate)) {
			return true
		}
	}
	return false
}

func defaultHookContract(contracts []HookContract) HookContract {
	for _, contract := range contracts {
		if contract.DefaultForUnversioned {
			return contract
		}
	}
	return contracts[0]
}

func NormalizeAgentVersion(_ string, raw string) string {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return ""
	}
	match := versionNumberRE.FindStringSubmatch(raw)
	if len(match) == 0 {
		return ""
	}
	parts := []string{match[1], match[2], match[3]}
	for i, part := range parts {
		if part == "" {
			parts[i] = "0"
		}
		n, err := strconv.Atoi(parts[i])
		if err != nil || n < 0 {
			return ""
		}
		parts[i] = strconv.Itoa(n)
	}
	return strings.Join(parts, ".")
}

func ApplyHookContract(profile HookProfile, opts SetupOpts) HookProfile {
	resolution := ResolveHookContract(profile.Name, opts.AgentVersion)
	if pinnedID := strings.TrimSpace(opts.HookContractID); pinnedID != "" {
		pinned, ok := hookContractByID(profile.Name, pinnedID)
		switch {
		case !ok:
			resolution.Status = HookCompatibilityUnknown
			resolution.Reason = fmt.Sprintf("pinned hook contract %s is not registered", pinnedID)
			resolution.Contract = HookContract{}
		case resolution.Contract.ContractID != "" && pinnedID != resolution.Contract.ContractID:
			resolution.Status = HookCompatibilityUnknown
			resolution.Reason = fmt.Sprintf("pinned hook contract %s does not match resolved contract %s", pinnedID, resolution.Contract.ContractID)
			resolution.Contract = pinned
		default:
			resolution.Contract = pinned
		}
	}
	profile.AgentVersion = resolution.RawVersion
	profile.NormalizedAgentVersion = resolution.NormalizedVersion
	profile.CompatibilityStatus = resolution.Status
	profile.CompatibilityReason = resolution.Reason
	if resolution.Contract.ContractID == "" {
		profile.Correlation = ExplicitCanonicalCorrelationSpec(profile.Name)
		return profile
	}
	contract := resolution.Contract
	profile.ContractID = contract.ContractID
	profile.HookScriptVersion = contract.HookScriptVersion
	profile.HookConfigPathTemplates = append([]string(nil), contract.HookConfigPathTemplates...)
	profile.SupportedEvents = append([]string(nil), contract.Events...)
	profile.AIDSurfaces = append([]string(nil), contract.AIDSurfaces...)
	profile.SupportsTraceparent = contract.SupportsTraceparent
	profile.ResponseFieldName = contract.ResponseFieldName
	profile.ContentEnvelopeKey = contract.ContentEnvelopeKey
	if spec, ok := CorrelationSpecForConnector(profile.Name, contract.ContractID); ok {
		profile.Correlation = spec
	} else {
		// Unknown/mismatched contracts fail closed for identity mapping. The
		// hook can still be inspected, but only exact canonical IDs are read.
		profile.Correlation = ExplicitCanonicalCorrelationSpec(profile.Name)
	}

	contractCaps := contract.Capabilities
	if profile.Capabilities.ConfigPath != "" && contractCaps.ConfigPath == "" {
		contractCaps.ConfigPath = profile.Capabilities.ConfigPath
	}
	if profile.Capabilities.Scope != "" && contractCaps.Scope == "" {
		contractCaps.Scope = profile.Capabilities.Scope
	}
	profile.Capabilities = contractCaps
	return profile
}

func HookProfileAIDSurfaceEnabled(profile HookProfile, surface string) bool {
	surface = strings.TrimSpace(strings.ToLower(surface))
	if surface == "" {
		return false
	}
	for _, candidate := range profile.AIDSurfaces {
		if strings.EqualFold(strings.TrimSpace(candidate), surface) {
			return true
		}
	}
	return false
}

func normalizeConnectorName(name string) string {
	name = strings.TrimSpace(strings.ToLower(name))
	switch name {
	case "claude", "claude-code", "claude_code":
		return "claudecode"
	case "gemini", "gemini-cli", "gemini_cli":
		return "geminicli"
	case "open-hands", "open_hands":
		return "openhands"
	default:
		return name
	}
}

func versionInRange(version, minVersion, maxVersion string) bool {
	if version == "" {
		return false
	}
	if minVersion != "" && compareVersion(version, minVersion) < 0 {
		return false
	}
	if maxVersion != "" && compareVersion(version, maxVersion) >= 0 {
		return false
	}
	return true
}

func compareVersion(a, b string) int {
	av := versionTuple(a)
	bv := versionTuple(b)
	for i := 0; i < 3; i++ {
		if av[i] < bv[i] {
			return -1
		}
		if av[i] > bv[i] {
			return 1
		}
	}
	return 0
}

func versionTuple(v string) [3]int {
	var out [3]int
	parts := strings.Split(NormalizeAgentVersion("", v), ".")
	for i := 0; i < len(parts) && i < 3; i++ {
		n, _ := strconv.Atoi(parts[i])
		out[i] = n
	}
	return out
}
