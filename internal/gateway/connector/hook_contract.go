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
	Connector               string
	ContractID              string
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

var builtinHookContracts = map[string][]HookContract{
	"codex": {{
		Connector:               "codex",
		ContractID:              "codex-hooks-v1",
		MinAgentVersion:         "0.124.0",
		DefaultForUnversioned:   true,
		HookScriptVersion:       "v6",
		HookConfigPathTemplates: []string{"~/.codex/config.toml"},
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
			"Codex hooks were made stable in 0.124.0. DefenseClaw leaves the upper bound open until upstream publishes a breaking hook change.",
			"Codex has no native hook-side ask surface in this contract; confirm verdicts render as alert/systemMessage.",
		},
	}},
	"claudecode": {{
		Connector:               "claudecode",
		ContractID:              "claudecode-hooks-v1",
		MinAgentVersion:         "2.1.152",
		DefaultForUnversioned:   true,
		HookScriptVersion:       "v6",
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
			"Pinned to the documented Claude Code hook surface as of 2.1.152, which introduced MessageDisplay; older releases exposed smaller hook event sets.",
			"Claude Code PreToolUse supports native HITL via permissionDecision=ask.",
			"PostToolUse findings are advisory because the inspected tool side effects have already occurred.",
			"PostToolBatch can block continuation before the next model call, but cannot undo completed batch side effects.",
			"ConfigChange is blockable except when source=policy_settings, where Claude Code ignores blocking decisions.",
		},
	}},
	"hermes": {{
		Connector:               "hermes",
		ContractID:              "hermes-hooks-v1",
		MinAgentVersion:         "0.11.0",
		DefaultForUnversioned:   true,
		HookScriptVersion:       "v6",
		HookConfigPathTemplates: []string{"$HERMES_HOME/config.yaml", "%LOCALAPPDATA%/hermes/config.yaml", "~/.hermes/config.yaml"},
		ResponseFieldName:       "hook_output",
		// Hermes' shell-hook surface (cli-config.yaml `hooks:` block).
		// Only pre_tool_call can block; pre_llm_call injects context;
		// the remaining events are observe-only telemetry decoded for
		// inspection/audit. Order follows the agent lifecycle.
		Events: []string{
			"pre_llm_call",
			"pre_tool_call",
			"post_tool_call",
			"post_llm_call",
			"on_session_start",
			"on_session_end",
			"on_session_finalize",
			"on_session_reset",
			"subagent_start",
			"subagent_stop",
		},
		// pre_llm_call → prompt; pre/post_tool_call → tool_call/tool_result;
		// session + subagent lifecycle → event_content (audit envelope).
		AIDSurfaces: []string{"prompt", "tool_call", "tool_result", "event_content"},
		Capabilities: HookCapability{
			CanBlock:     true,
			CanAskNative: false,
			// Only pre_tool_call honors a blocking stdout response;
			// pre_llm_call can inject context but cannot veto, and the
			// post/session/subagent events are read-only on Hermes' side
			// (their stdout is ignored). Hermes never blocks on exit code
			// or hook timeout, so SupportsFailClosed stays false.
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
			"Covers the documented shell-hook lifecycle including session start/end/finalize/reset and subagent start/stop telemetry. Hermes nests prompt/result and delegation identity under the per-event `extra` envelope; the generic decoder lifts those fields into the canonical lifecycle.",
			"pre_tool_call is the only blockable event: Hermes accepts both {\"action\":\"block\",\"message\"} (canonical) and {\"decision\":\"block\",\"reason\"} (Claude-Code style) and normalizes internally. pre_llm_call injects via {\"context\":...}. Confirm verdicts (no native ask surface) downgrade to a {\"systemMessage\":...} alert via the shared responder epilogue. Non-zero exit codes and hook timeouts only log a warning upstream, so there is no fail-closed surface; hermes remains live-smoke pending (docs/CONNECTOR-MATRIX.md).",
			"Multi-event registration requires hooks_auto_accept in cli-config.yaml on non-TTY/gateway runs; otherwise Hermes prompts for per-(event,command) consent on first use and silently skips unaccepted hooks. Setup writes hooks_auto_accept so all events register, and the managed-backup heals it.",
		},
	}},
	"cursor": {{
		Connector:               "cursor",
		ContractID:              "cursor-hooks-v1",
		MinAgentVersion:         "1.7.0",
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
				"beforeShellExecution",
				"beforeMCPExecution",
				"beforeReadFile",
				"beforeTabFileRead",
				"beforeSubmitPrompt",
				"stop",
			},
			SupportsFailClosed: true,
			Scope:              "user",
		},
		SupportsTraceparent: true,
		Notes: []string{
			"Cursor 1.7 introduced beta hooks for the agent loop.",
			"Cursor native ask is limited to beforeShellExecution and beforeMCPExecution.",
			"Every command-hook invocation returns a non-empty JSON object; beforeSubmitPrompt uses continue while permission gates use permission.",
		},
	}},
	"windsurf": {{
		Connector:               "windsurf",
		ContractID:              "windsurf-hooks-v1",
		MinAgentVersion:         "1.12.41",
		DefaultForUnversioned:   true,
		HookScriptVersion:       "v6",
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
			SupportsFailClosed: false,
			Scope:              "user",
		},
		SupportsTraceparent: true,
		Notes: []string{
			"Windsurf 1.12.41 added Cascade hooks on user prompts, completing the pre-hook set used by this contract.",
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
		},
	}},
	"copilot": {{
		Connector:               "copilot",
		ContractID:              "copilot-hooks-v1",
		MinAgentVersion:         "1.0.18",
		DefaultForUnversioned:   true,
		HookScriptVersion:       "v6",
		HookConfigPathTemplates: []string{"~/.copilot/hooks/defenseclaw.json", "<workspace>/.github/hooks/defenseclaw.json"},
		ResponseFieldName:       "hook_output",
		Events: []string{
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
		},
		AIDSurfaces: []string{"prompt", "tool_call", "tool_result"},
		Capabilities: HookCapability{
			CanBlock:     true,
			CanAskNative: true,
			AskEvents:    []string{"preToolUse"},
			BlockEvents: []string{
				"preToolUse",
				"permissionRequest",
				"agentStop",
				"subagentStop",
				"postToolUseFailure",
			},
			SupportsFailClosed: false,
			Scope:              "user,workspace",
		},
		SupportsTraceparent: true,
		Notes: []string{
			"GitHub Copilot CLI shipped preToolUse earlier, but the full DefenseClaw contract also needs postToolUseFailure, permissionRequest, and notification hooks; notification landed in 1.0.18.",
			"Copilot CLI native ask is limited to preToolUse / PreToolUse hooks.",
		},
	}},
	"antigravity": {{
		Connector:               "antigravity",
		ContractID:              "antigravity-hooks-v2",
		MinAgentVersion:         "1.0.0",
		DefaultForUnversioned:   true,
		HookScriptVersion:       "v7",
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
		// AIDSurfaces covers the inspection target categories
		// DefenseClaw exposes for this connector. PreInvocation
		// inspects the prompt; PreToolUse inspects the tool call;
		// PostToolUse + PostInvocation inspect tool / model results.
		// Stop has no inspection target (audit-only).
		AIDSurfaces: []string{"prompt", "tool_call", "tool_result"},
		Capabilities: HookCapability{
			CanBlock:     true,
			CanAskNative: true,
			// Ask is meaningful only on Pre* events — by the time
			// Post* events fire, the action / response has already
			// happened and prompting the user adds no value.
			AskEvents: []string{"PreInvocation", "PreToolUse"},
			// Block on Stop is the spec's "block-terminating the
			// agent if validation checks fail" use case (Stop hooks
			// can prevent loop termination). Block on Post* is
			// excluded — the inspected action has already executed.
			BlockEvents:        []string{"PreInvocation", "PreToolUse", "Stop"},
			SupportsFailClosed: false,
			Scope:              "user",
		},
		SupportsTraceparent: true,
		Notes: []string{
			"Hooks v2 expands to all five Antigravity 2.0 lifecycle events (PreInvocation, PreToolUse, PostToolUse, PostInvocation, Stop) per the published spec; v1 covered PreToolUse only. PreToolUse remains the only event empirically verified against agy v1.0.1 — the other four event branches are spec-conformant but gated on upstream agy implementation parity.",
			"agy returning decision=ask bypasses --dangerously-skip-permissions, which is the strongest user-prompt primitive any DefenseClaw connector currently exposes. AskEvents covers PreInvocation and PreToolUse; agy does not recognize a literal \"force_ask\" decision so DefenseClaw emits \"ask\".",
			"Stop's wire decision verb is \"block\" (matching agy's Claude-Code lineage) rather than the \"deny\" verb used by Pre* events; this aligns with the spec's \"block-terminating the agent if validation checks fail\" phrasing. PostToolUse and PostInvocation NEVER block — findings surface as additionalContext for next-turn ingestion.",
			"Setup writes only the global ~/.gemini/config/hooks.json (the path agy v1.0.x actually evaluates; the marketing-facing ~/.gemini/antigravity-cli/hooks.json is silently ignored at runtime). agy merges all discovered hooks files (global, project, legacy ~/.gemini/hooks.json), so multiple writes cause duplicate firing. Doctor warns when defenseclaw-managed entries appear in more than one merged location, and separately warns when the legacy antigravity-cli path still holds defenseclaw-managed entries from a pre-v0.5.0 install.",
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
		MinAgentVersion:         "0.0.0",
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
			"ASK is native only for OmniGent's pre-action request, tool_call, and llm_request phases; post-action confirm verdicts use DefenseClaw's explicit fallback.",
			"The in-process Python bridge forwards an active OpenTelemetry W3C trace context when present; otherwise DefenseClaw starts a new trace.",
			"Optional native OTLP is inactive until the OmniGent launch process exports the standard environment variables; native traces require its optional tracing extra.",
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
		if versionInRange(normalized, contract.MinAgentVersion, contract.MaxAgentVersion) {
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
