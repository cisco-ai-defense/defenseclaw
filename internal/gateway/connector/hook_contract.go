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
	"runtime"
	"strconv"
	"strings"
	"sync/atomic"
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
	// without inventing a compatible range. When both exact pins and a
	// min/max range are set, a version matches if either clause matches.
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
	// ToolCallLifecycle declares which hook events are safe inputs to the
	// structured, stateful tool-call path. Its nested version is independent
	// of this vendor hook contract's version.
	ToolCallLifecycle ToolCallLifecycleContract
	// ContentEnvelope names the one nested payload object this connector
	// puts inspectable content in, and the field inside it for each event
	// (hermes: "extra"). Zero for flat-payload connectors. See
	// HookProfile.ContentEnvelope for the decoder semantics and the
	// no-recursive-scan rationale.
	ContentEnvelope ContentEnvelope
	Notes           []string
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
	// UntestedVersion marks a Known resolution for an agent version newer
	// than every tested range: no known-broken entry matches, so the newest
	// contract applies. NewestTestedVersion names the bound it passed.
	UntestedVersion     bool
	NewestTestedVersion string
	// Warning is the reason and issue link of the WarnOnly known-broken
	// entry a Known version falls in: the version keeps its contract, and
	// Setup says what its hooks do not guard.
	Warning string
}

// UntestedNewerVersionReasonPrefix starts the Reason of an untested newer
// agent version. Status and verify surfaces show it as "untested newer
// version".
const UntestedNewerVersionReasonPrefix = "untested newer version"

// KnownBrokenAgentVersion is one agent version (Exact) or half-open range
// [Min, Max) that DefenseClaw refuses, inside a contract's range or newer
// than every tested one. Reason and Issue are required so the refusal
// explains itself. A HostOnly entry applies to the agent on the host, not to
// the pinned build an OpenShell sandbox image runs. A WarnOnly entry is not
// refused: its hooks still guard the agent's main interface, so the version
// keeps its contract and the resolution's Warning names what they miss.
type KnownBrokenAgentVersion struct {
	Exact    string
	Min      string
	Max      string
	Reason   string
	Issue    string
	HostOnly bool
	WarnOnly bool
}

// hermesTUIWithoutShellHooks is the warning for Hermes before 0.21.1: its
// TUI (hermes --tui, a separate tui_gateway process) and dashboard chat
// build their agent without registering the config.yaml shell hooks, so a
// terminal call ran with no pre_tool_call and was neither blocked nor
// audited (GAP-0978). Hermes 0.21.1 (v2026.9.7) registers them where every
// agent is built. The classic interface, cron, ACP and the messaging gateway
// run them in every release, so these releases are set up with this warning:
// refusing them left those sessions unguarded as well.
const hermesTUIWithoutShellHooks = "its TUI (hermes --tui) and dashboard chat run tools without the shell hooks DefenseClaw registers; " +
	"Hermes 0.21.1 (v2026.9.7) is the first release that runs them there, so update Hermes (hermes update)"

const hermesTUIShellHooksFix = "https://github.com/NousResearch/hermes-agent/commit/3094cde5138bd2bc28134d060345081ab5099d25"

// knownBrokenAgentVersions lists agent versions whose hook surface is known
// not to work with DefenseClaw. It must match the known_broken_versions
// lists in cli/defenseclaw/inventory/hook_contracts.json. A version is
// release-style (0.19.0) or a release date (2026.7.20, what a Hermes git
// install reports); each scheme needs its own range.
var knownBrokenAgentVersions = map[string][]KnownBrokenAgentVersion{
	// The OpenShell image pins Hermes 0.19.0 (the newest on PyPI); its
	// launcher and a root-owned shim refuse that TUI instead (GAP-1036).
	"hermes": {
		{Min: "0.19.0", Max: "0.21.1", Reason: hermesTUIWithoutShellHooks, Issue: hermesTUIShellHooksFix, HostOnly: true, WarnOnly: true},
		{Min: "2026.7.20", Max: "2026.9.7", Reason: hermesTUIWithoutShellHooks, Issue: hermesTUIShellHooksFix, HostOnly: true, WarnOnly: true},
	},
}

// gitBuildReleaseDateRE reads the release date a source build prints after
// its commit ("Hermes Agent vgit.5bba024 (2026.9.24)").
var gitBuildReleaseDateRE = regexp.MustCompile(`\(([0-9]{4}\.[0-9]{1,2}\.[0-9]{1,2})(?:\.[0-9]+)?\)`)

// strictHookContractResolution restores exact-range matching: a version
// outside every tested range stays unknown. The Secure Client profile sets
// it so its version gating does not change.
var strictHookContractResolution atomic.Bool

// SetStrictHookContractResolution turns exact-range hook contract matching
// on for this process. The config loader sets it for the Secure Client
// profile.
func SetStrictHookContractResolution(enabled bool) {
	strictHookContractResolution.Store(enabled)
}

// StrictHookContractResolution reports whether this process refuses agent
// versions newer than every tested range.
func StrictHookContractResolution() bool {
	return strictHookContractResolution.Load()
}

// gitBuildVersionRE matches source-build version strings such as Hermes
// "Hermes Agent vgit.5bba024 (2026.9.24)".
var gitBuildVersionRE = regexp.MustCompile(`(?i)(?:^|[^a-z0-9])v?git[.+-]?[0-9a-f]{7,40}(?:[^a-z0-9]|$)`)

// gitBuildCompareVersion stands in for a git build when it is compared
// with release-style (non-date) tested bounds.
const gitBuildCompareVersion = "999.999.999"

var versionNumberRE = regexp.MustCompile(`(?i)(?:^|[^0-9])v?([0-9]+)(?:\.([0-9]+))?(?:\.([0-9]+))?`)

var proxyConnectorsWithoutHookGate = map[string]bool{
	"openclaw":  true,
	"zeptoclaw": true,
}

// catalogedOnlyConnectorsWithoutHookGate are regular connectors whose hook
// contract is not version-gated. Empty hook contracts must not fail
// action-mode setup as "unknown". Kiro still installs native hooks.
var catalogedOnlyConnectorsWithoutHookGate = map[string]bool{
	"kiro": true,
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
		ToolCallLifecycle:   codexToolCallLifecycle(false, false, false),
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
		ToolCallLifecycle:   codexToolCallLifecycle(false, false, false),
		Notes: []string{
			"Codex 0.129.x through 0.132.x add PreCompact and PostCompact plus hooks/list trust introspection, for eight supported events.",
			"On native Windows the generic and command_windows values must remain byte-identical so 0.129.x and newer clients derive the same trusted hook identity.",
			"Codex has no native hook-side ask surface in this contract; confirm verdicts render as alert/systemMessage.",
		},
	}, {
		Connector:               "codex",
		ContractID:              "codex-hooks-v3",
		MinAgentVersion:         "0.133.0",
		MaxAgentVersion:         "0.135.0",
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
		ToolCallLifecycle:   codexToolCallLifecycle(false, true, false),
		Notes: []string{
			"Codex 0.133.0 through 0.134.x expose the versioned ten-event DefenseClaw matrix, adding SubagentStart and SubagentStop while retaining the selective local-function hook payload.",
			"SessionStart, PreCompact, and PostCompact blocks render continue=false to stop the current turn, stop before compaction, or stop after compaction respectively. SubagentStop blocks render decision=block to continue the subagent flow.",
			"Stop decision=block continues Codex with a new continuation prompt. PostToolUse block cannot undo the completed tool side effect; its feedback replaces the result flow and rejects the tool promise in code mode.",
			"Release validation requires authentic packaged plus official-client evidence that hooks/list reports every owned handler enabled and trusted without a manual approval step; supported Windows availability does not claim that evidence and validated_versions remains empty/live=false.",
			"Codex has no native hook-side ask surface in this contract; confirm verdicts render as alert/systemMessage.",
		},
	}, {
		Connector:               "codex",
		ContractID:              "codex-hooks-v3-generic",
		MinAgentVersion:         "0.135.0",
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
		ToolCallLifecycle:   codexToolCallLifecycle(true, true, false),
		Notes: []string{
			"Codex 0.135.0 extends PreToolUse and PostToolUse to generic local function tools while retaining the ten-event hook matrix.",
			"SessionStart, PreCompact, and PostCompact blocks render continue=false to stop the current turn, stop before compaction, or stop after compaction respectively. SubagentStop blocks render decision=block to continue the subagent flow.",
			"Stop decision=block continues Codex with a new continuation prompt. PostToolUse block cannot undo the completed tool side effect; its feedback replaces the result flow and rejects the tool promise in code mode.",
			"Release validation requires authentic packaged plus official-client evidence that hooks/list reports every owned handler enabled and trusted without a manual approval step; supported Windows availability does not claim that evidence and validated_versions remains empty/live=false.",
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
		ToolCallLifecycle:   codexToolCallLifecycle(true, true, true),
		Notes: []string{
			"Codex 0.145.0 adds SessionEnd for main-thread teardown to the ten-event 0.135.0 through 0.144.x generic-local-tool matrix; Stop remains a turn boundary and does not end the session.",
			"SessionEnd is a best-effort observation and telemetry event; it is not a block or native ask surface.",
			"SessionStart, PreCompact, and PostCompact blocks render continue=false to stop the current turn, stop before compaction, or stop after compaction respectively. SubagentStop blocks render decision=block to continue the subagent flow.",
			"Stop decision=block continues Codex with a new continuation prompt. PostToolUse block cannot undo the completed tool side effect; its feedback replaces the result flow and rejects the tool promise in code mode.",
			"Release validation requires authentic packaged plus official-client evidence that hooks/list reports every owned handler enabled and trusted without a manual approval step; supported Windows availability does not claim that evidence and validated_versions remains empty/live=false.",
			"Codex has no native hook-side ask surface in this contract; confirm verdicts render as alert/systemMessage.",
		},
	}},
	"claudecode": {{
		Connector:               "claudecode",
		ContractID:              "claudecode-hooks-v1",
		MinAgentVersion:         "2.1.154",
		MaxAgentVersion:         "2.1.219",
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
		ToolCallLifecycle:   claudeCodeToolCallLifecycle(),
		Notes: []string{
			"Pinned to Claude Code >=2.1.154,<2.1.219: 2.1.152 introduced MessageDisplay and 2.1.154 added the plugin defaultEnabled semantics required by inventory.",
			"Claude Code PreToolUse supports native HITL via permissionDecision=ask.",
			"PostToolUse findings are advisory because the inspected tool side effects have already occurred.",
			"PostToolBatch can block continuation before the next model call, but cannot undo completed batch side effects.",
			"ConfigChange is blockable except when source=policy_settings, where Claude Code ignores blocking decisions.",
		},
	}, {
		Connector:               "claudecode",
		ContractID:              "claudecode-hooks-v2",
		MinAgentVersion:         "2.1.219",
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
			"DirectoryAdded",
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
		AIDSurfaces:         []string{"prompt", "tool_call", "tool_result", "event_content"},
		SupportsTraceparent: true,
		NativeOTLP:          true,
		ToolCallLifecycle:   claudeCodeToolCallLifecycle(),
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
		Notes: []string{
			"Pinned to Claude Code >=2.1.219: 2.1.219 added DirectoryAdded after a working directory is registered mid-session.",
			"DirectoryAdded is a synchronous 30-second observation with no matcher and no block, ask, or decision authority; the directory has already been added when the hook runs.",
			"Claude Code PreToolUse supports native HITL via permissionDecision=ask.",
			"PostToolUse and PostToolBatch findings are advisory because their payloads are returned bytes, not typed action requests; command/path enforcement stays on PreToolUse.",
			"ConfigChange is blockable except when source=policy_settings, where Claude Code ignores blocking decisions.",
		},
	}},
	"hermes": {
		// A Hermes git install prints no release, only the date of the
		// release it is on ("Hermes Agent vunknown (2026.9.24)"), and
		// discovery reads that date. Each pin is the date tag of an
		// official release in this range (v2026.7.20 is 0.19.0, v2026.8.27
		// is 0.20.6, read from pyproject.toml at each tag). A date below
		// the first pin, or between the two contracts' pins, has no
		// contract; a date after the newest pin of v2 is an untested
		// newer version (GAP-0151).
		{
			Connector:               "hermes",
			ContractID:              "hermes-hooks-v1",
			ExactAgentVersions:      []string{"2026.7.20", "2026.7.30", "2026.8.3", "2026.8.13", "2026.8.16", "2026.8.16.2", "2026.8.18", "2026.8.19", "2026.8.27"},
			MinAgentVersion:         "0.19.0",
			MaxAgentVersion:         "0.21.0",
			DefaultForUnversioned:   false,
			HookScriptVersion:       "v6",
			HookConfigPathTemplates: []string{"$HERMES_HOME/config.yaml", "%LOCALAPPDATA%/hermes/config.yaml", "~/.hermes/config.yaml"},
			ResponseFieldName:       "hook_output",
			// Hermes' source-verified v0.19-v0.20 shell-hook surface
			// (config.yaml `hooks:` block).
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
			ToolCallLifecycle:   hermesToolCallLifecycle(),
			ContentEnvelope:     hermesContentEnvelope(),
			Notes: []string{
				"Covers the identical exact 23-event VALID_HOOKS set verified from official Hermes Agent tags v2026.7.20 (0.19.0), v2026.7.30 (0.19.1), and v2026.8.3 (0.20.0). The reviewed range is bounded to >=0.19.0,<0.21.0; later versions require new source evidence. Hermes puts tool_name, tool_input, session_id, cwd and profile at the top level and every other hook argument under extra (agent/shell_hooks.py _payload_fields); events whose official schema is not documented remain partial, attributed audit rather than inferred enforcement.",
				"pre_tool_call is the only blockable event: Hermes accepts both {\"action\":\"block\",\"message\"} (canonical) and {\"decision\":\"block\",\"reason\"} (Claude-Code style) and normalizes internally. pre_llm_call injects {\"context\":...}; pre_verify accepts {\"action\":\"continue\",\"message\"} to keep the bounded verification loop going. Transform hooks require Python string returns, pre_gateway_dispatch requires skip/rewrite/allow plugin results, and approval/API/Kanban/lifecycle return values are ignored or undocumented by the shell lane, so DefenseClaw audits them without claiming mutation. Confirm verdicts are recorded and alerted without hook output. Non-zero exit codes and hook timeouts only warn upstream, so there is no fail-closed surface; Hermes remains live-smoke pending (https://cisco-ai-defense.github.io/defenseclaw/docs/connectors/hermes/).",
				"Setup preserves the operator's hooks_auto_accept value and owns only the exact DefenseClaw (event, command) approvals in shell-hooks-allowlist.json. Running Hermes processes cache callbacks, so registration and revocation remain live=false/pending-reload until every affected CLI, gateway, desktop, or service host is reloaded or restarted; Windows teardown leaves an exact direct-native disabled tombstone for stale callbacks.",
				"The v1 connector covers only the resolved default HERMES_HOME profile. Named-profile homes and multiplex gateways are unsupported. Default-profile inventory includes skills.external_dirs, SOUL.md, built-in memory plus memory.provider provenance, and bundled/Nix, user, and pip plugins; named-profile and project-conditional sources remain explicitly unverified.",
			},
		},
		// Release-date pins (see hermes-hooks-v1): v2026.8.31 is 0.21.0
		// and v2026.9.24 is 0.21.5.
		{
			Connector:               "hermes",
			ContractID:              "hermes-hooks-v2",
			ExactAgentVersions:      []string{"2026.8.31", "2026.9.7", "2026.9.11", "2026.9.14", "2026.9.21", "2026.9.24"},
			MinAgentVersion:         "0.21.0",
			MaxAgentVersion:         "0.22.0",
			DefaultForUnversioned:   true,
			HookScriptVersion:       "v6",
			HookConfigPathTemplates: []string{"$HERMES_HOME/config.yaml", "%LOCALAPPDATA%/hermes/config.yaml", "~/.hermes/config.yaml"},
			ResponseFieldName:       "hook_output",
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
			AIDSurfaces: []string{"prompt", "tool_call", "tool_result", "event_content"},
			Capabilities: HookCapability{
				CanBlock:           true,
				CanAskNative:       false,
				BlockEvents:        []string{"pre_tool_call"},
				SupportsFailClosed: false,
				Scope:              "user",
			},
			SupportsTraceparent: true,
			ToolCallLifecycle:   hermesToolCallLifecycleV2(),
			ContentEnvelope:     hermesContentEnvelope(),
			Notes: []string{
				"Same 23 claimed shell-hook events as hermes-hooks-v1. Official Hermes 0.21.x, rechecked at v0.21.3 (v2026.9.14, commit 345cd2b057a452236de401d3534b8502a7465e8d), added observer-only VALID_HOOKS that DefenseClaw does not register or claim. The payload shape is unchanged: the prompt, tool result and model response are under extra (verified on v0.21.5).",
				"pre_tool_call remains the only blockable event: Hermes accepts both {\"action\":\"block\",\"message\"} (canonical) and {\"decision\":\"block\",\"reason\"} (Claude-Code style) and normalizes internally. Setup sets fail_closed on the pre_tool_call entry, so a spawn error, timeout or unparseable nonempty stdout blocks in the reviewed >=0.21.0,<0.22.0 range. A killed hook can still fail open because Hermes treats its non-2 exit and empty stdout as no decision, so SupportsFailClosed remains false. Secure Client keeps its existing registration. Other events cannot block.",
				"Setup preserves the operator's hooks_auto_accept value and owns only the exact DefenseClaw (event, command) approvals in shell-hooks-allowlist.json. Running Hermes processes cache callbacks, so registration and revocation remain live=false/pending-reload until every affected CLI, gateway, desktop, or service host is reloaded or restarted; Windows teardown leaves an exact direct-native disabled tombstone for stale callbacks.",
				"The v2 connector covers only the resolved default HERMES_HOME profile. Named-profile homes and multiplex gateways are unsupported. Default-profile inventory includes skills.external_dirs, SOUL.md, built-in memory plus memory.provider provenance, and bundled/Nix, user, and pip plugins; named-profile and project-conditional sources remain explicitly unverified.",
			},
		},
	},
	"cursor": {{
		Connector:               "cursor",
		ContractID:              "cursor-hooks-v1",
		ExactAgentVersions:      []string{"2026.07.23-e383d2b"},
		MinAgentVersion:         "2.4.0",
		MaxAgentVersion:         "4.0.0",
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
			CanAskNative: false,
			BlockEvents: []string{
				"preToolUse", "subagentStart", "beforeShellExecution",
				"beforeMCPExecution", "beforeReadFile", "beforeTabFileRead",
				"beforeSubmitPrompt",
			},
			SupportsFailClosed: true,
			Scope:              "user",
		},
		SupportsTraceparent: true,
		ToolCallLifecycle:   cursorToolCallLifecycle(),
		Notes: []string{
			"Cursor Desktop is the hook host for the 21-event user hooks.json surface. This contract accepts Desktop application versions >=2.4.0 and <4.0.0, plus the reviewed Agent CLI exact build 2026.07.23-e383d2b. Later Agent CLI date-hash builds are not accepted without a matching hook-surface review. The event payload cursor_version field is the Cursor application/Desktop version.",
			"Cursor Agent uses agent as its primary CLI command; cursor-agent remains a compatibility alias.",
			"Cursor runs all matching hooks and merges conflicting responses in Enterprise > Team > Project > User priority. DefenseClaw owns the ordinary user hook and Cursor exposes no safe API for detecting an actual higher-priority conflict, so setup does not infer one. Doctor and status report that detection limitation rather than claiming enterprise authority.",
			"Action mode emits the documented native deny response on supported pre-action events and registers failClosed=true; observe maps policy blocks to would-block and registers failClosed=false. DefenseClaw does not emit Cursor's native ask response or claim human-approval support.",
			"sessionStart and sessionEnd are fire-and-forget policy-wise; sessionStart documents only env/additional_context output and sessionEnd has no output. stop and subagentStop accept only followup_message; none is a block or ask gate.",
			"The decoder preserves beforeMCPExecution tool_input and URL/command, derives a stable digest identity without inventing a server vendor, and boundedly lifts tool_output, error_message, output, result_json, edits, text, and summary from the documented post/result events.",
			"Every command-hook invocation returns a JSON object. The event roster includes subagentStart; event-native response shapes remain registered for direct adapter compatibility while unsupported output events return {}.",
		},
	}},
	"devin": {{
		Connector:               "devin",
		ContractID:              "devin-hooks-v1",
		ExactAgentVersions:      []string{"3000.4.25", "3000.11.3"},
		DefaultForUnversioned:   true,
		HookScriptVersion:       "v7",
		HookConfigPathTemplates: []string{"%APPDATA%/devin/config.json", "~/.config/devin/config.json", "<workspace>/.devin/hooks.v1.json"},
		ResponseFieldName:       "hook_output",
		Events:                  append([]string(nil), devinHookEvents...),
		AIDSurfaces:             []string{"prompt", "tool_call", "tool_result"},
		Capabilities: HookCapability{
			CanBlock:           true,
			CanAskNative:       false,
			BlockEvents:        append([]string(nil), devinBlockEvents...),
			SupportsFailClosed: true,
			Scope:              "user,workspace",
		},
		SupportsTraceparent: true,
		ToolCallLifecycle:   devinToolCallLifecycle(),
		Notes: []string{
			"The reviewed native contract is pinned to Devin CLI 3000.4.25, and on Linux also to 3000.11.3, which delivers SessionStart, UserPromptSubmit, PreToolUse, PostToolUse, Stop and SessionEnd under these event names and honors exit-code-2 blocks on UserPromptSubmit and PreToolUse (PermissionRequest and PostCompaction are not verified). It uses user config.json or the recommended project .devin/hooks.v1.json.",
			"Devin Desktop's default Devin Local agent shares the Devin CLI harness and hook config. Devin Desktop 3.9.19 removed the legacy Cascade agent; builds before it run Cascade under a separate contract that is not registered.",
			"Exit code 2 blocks; every other hook error is logged by Devin and fails open. Responses use top-level decision/reason and event-tagged hookSpecificOutput only where documented.",
			"Restricted Mode disables hooks and agents. Cloud Devin, proxy/ACP integrations, and native OTLP are excluded. DefenseClaw registers no plugin hooks; under the standalone enterprise profile the foreign-hook guard checks the hooks of installed Devin plugins.",
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
				CanAskNative: false,
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
			ToolCallLifecycle:   copilotToolCallLifecycle(),
			Notes: []string{
				"GitHub Copilot CLI shipped preToolUse earlier, but the full DefenseClaw contract also needs postToolUseFailure, permissionRequest, and notification hooks; notification landed in 1.0.18.",
				"Copilot CLI can ask on preToolUse, but its hook input does not prove prompt availability; DefenseClaw denies confirms there until the vendor exposes it.",
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
				CanAskNative: false,
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
			ToolCallLifecycle:   copilotToolCallLifecycle(),
			Notes: []string{
				"Current GitHub Copilot CLI documentation includes the mutation-only userPromptTransformed event; DefenseClaw returns no modification, except that the Windows Secure Client profile replaces a prompt the guardrail blocks.",
				"GitHub Copilot CLI 1.0.76 is the conservative reviewed floor for this current 14-event contract.",
				"Copilot CLI can ask on preToolUse, but its hook input does not prove prompt availability; DefenseClaw denies confirms there until the vendor exposes it.",
				"postToolUseFailure is advisory-only and can provide recovery additionalContext; it cannot block the failed tool.",
				"Copilot documents optional native OpenTelemetry metrics and traces on POSIX hosts. DefenseClaw records that upstream surface but does not configure, launch, or certify the exporter; every DefenseClaw contract remains hook-only.",
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
		ToolCallLifecycle:   antigravityToolCallLifecycle(),
		Notes: []string{
			"Antigravity 2.0 documents five lifecycle events. PreToolUse and PostToolUse use matcher groups with nested handlers; PreInvocation, PostInvocation, and Stop use direct handler lists.",
			"Hard blocking is claimed only for synchronous PreToolUse stdout {\"decision\":\"deny\"}. decision=ask provides native confirmation. Google does not document non-zero hook exit codes as an enforcement interface.",
			"PostToolUse output is {}. PreInvocation and PostInvocation may return injectSteps; DefenseClaw uses ephemeralMessage only for context. Stop requires a decision, where continue re-enters the loop and any other value permits stopping; DefenseClaw returns allow and does not claim Stop blocking.",
			"Setup writes only ~/.gemini/config/hooks.json. Antigravity also discovers <workspace>/.agents/hooks.json.",
		},
	}},
	"opencode": {{
		Connector:               "opencode",
		ContractID:              "opencode-hooks-v1",
		MinAgentVersion:         "1.18.10",
		MaxAgentVersion:         "1.19.0",
		DefaultForUnversioned:   false,
		HookScriptVersion:       "v7",
		HookConfigPathTemplates: []string{"~/.config/opencode/plugins/defenseclaw.js"},
		ResponseFieldName:       "hook_output",
		// opencode exposes plugin hooks (not shell hooks). DefenseClaw's
		// bridge plugin wires tool.execute.before (block) and
		// tool.execute.after (observe). OpenCode v1.18.10-v1.18.33 also exposes
		// permission.ask and chat/context mutation hooks; this focused bridge
		// intentionally does not implement those surfaces.
		Events: []string{
			"defenseclaw.plugin.loaded",
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
		ToolCallLifecycle:   openCodeToolCallLifecycle(),
		Notes: []string{
			"opencode (https://opencode.ai) auto-loads JS/TS plugins from ~/.config/opencode/plugins/ — there is no command-hook config file to patch. DefenseClaw writes a dependency-free bridge plugin (defenseclaw.js) whose tool.execute.before POSTs to /api/v1/opencode/hook and throws new Error(reason) on a block decision, aborting the tool.",
			"DefenseClaw intentionally implements block plus observe-only tool/lifecycle telemetry. OpenCode v1.18.10-v1.18.33 exposes permission.ask and chat/context mutation hooks, but this connector does not implement or claim them. The bridge honors fail-closed by throwing when the gateway is unreachable and FAIL_MODE=closed.",
			"Source-reviewed range is >=1.18.10,<1.19.0 with current pin 1.18.33. The v1.18.33 Hooks entries used by this contract (config, event, tool.execute.before, tool.execute.after) match the v1.18.19 signatures; a thrown Error from tool.execute.before remains the block surface. The bridge refuses ambiguous MCP identity and action-mode allow claims when a later plugin can mutate args.",
		},
	}},
	"amp": {{
		Connector:               "amp",
		ContractID:              "amp-plugin-v1",
		MinAgentVersion:         "0.0.1785334225",
		DefaultForUnversioned:   true,
		HookScriptVersion:       "v2",
		HookConfigPathTemplates: []string{"~/.config/amp/plugins/defenseclaw.ts", "%USERPROFILE%\\.config\\amp\\plugins\\defenseclaw.ts"},
		ResponseFieldName:       "",
		Events: []string{
			"session.start",
			"agent.start",
			"tool.call",
			"tool.result",
			"agent.end",
		},
		AIDSurfaces: []string{"prompt", "tool_call", "tool_result", "event_content"},
		Capabilities: HookCapability{
			CanBlock:           true,
			CanAskNative:       true,
			AskEvents:          []string{"tool.call", "tool.result"},
			BlockEvents:        []string{"tool.call", "tool.result"},
			SupportsFailClosed: true,
			Scope:              "user",
		},
		SupportsTraceparent: false,
		NativeOTLP:          false,
		ToolCallLifecycle:   ampToolCallLifecycle(),
		Notes: []string{
			"Amp auto-loads system TypeScript plugins from ~/.config/amp/plugins on macOS/Linux and %USERPROFILE%\\.config\\amp\\plugins on Windows. DefenseClaw installs a dependency-free owner-only policy plugin there.",
			"tool.call is synchronous before execution; tool.result can replace unsafe output before model delivery but cannot undo completed side effects. Both support native confirmation only for the active foreground thread and reject safely when UI is unavailable.",
			"session.start, agent.start, tool.call, tool.result, and agent.end feed Agent360, Galileo, audit, and generated hook telemetry. Amp documents no session.end or dedicated subagent lifecycle plugin event.",
			"The plugin reports Amp's first-class custom-agent name/display/declared model or built-in mode when available; this metadata is not a stable agent ID, model request ID, trace context, or parent-thread link.",
			"Oracle, Task/subagent launchers, MCP tools, and plugin tools remain policy-controlled at the tool.call delegation boundary. Child-thread events are ingested under their reported thread ID when Amp emits them.",
			"Amp does not document arbitrary model-endpoint proxying, native customer OTLP, or W3C trace propagation from plugins.",
			"Headless `amp -x` action-mode launches require `--plugin-ready-timeout 30` to guarantee plugin readiness and complete lifecycle capture before the turn; fail-closed cannot protect work that starts before Amp loads the plugin.",
			"0.0.1785334225 is DefenseClaw's certification floor pinned to the current @ampcode/cli package build used for this contract snapshot; it is not an upstream-declared minimum plugin version.",
		},
	}},
}

func KnownHookContracts(connectorName string) []HookContract {
	return hookContractsForOS(connectorName, runtime.GOOS)
}

func hookContractsForOS(connectorName, goos string) []HookContract {
	name := normalizeConnectorName(connectorName)
	contracts := builtinHookContracts[name]
	out := make([]HookContract, len(contracts))
	for i, contract := range contracts {
		contract.ExactAgentVersions = append([]string(nil), contract.ExactAgentVersions...)
		contract.HookConfigPathTemplates = append([]string(nil), contract.HookConfigPathTemplates...)
		contract.Events = append([]string(nil), contract.Events...)
		contract.AIDSurfaces = append([]string(nil), contract.AIDSurfaces...)
		contract.Notes = append([]string(nil), contract.Notes...)

		// Windows and macOS stay on the Devin build they were reviewed
		// against; the extra pin covers Linux only.
		if (goos == "windows" || goos == "darwin") && contract.ContractID == "devin-hooks-v1" {
			contract.ExactAgentVersions = []string{"3000.4.25"}
		}
		out[i] = contract
	}
	return out
}

func hookContractByID(connectorName, contractID string) (HookContract, bool) {
	return hookContractByIDForOS(connectorName, contractID, runtime.GOOS)
}

func hookContractByIDForOS(connectorName, contractID, goos string) (HookContract, bool) {
	contractID = strings.TrimSpace(contractID)
	if contractID == "" {
		return HookContract{}, false
	}
	for _, contract := range hookContractsForOS(connectorName, goos) {
		if contract.ContractID == contractID {
			return contract, true
		}
	}
	// A managed Windows Kiro footprint pins its reviewed managed contract;
	// the gateway serving it resolves the pin without the managed flag.
	if managedKiroOnOS(connectorName, goos) {
		for _, contract := range kiroWindowsManagedHookContracts() {
			if contract.ContractID == contractID {
				return contract, true
			}
		}
	}
	// A sandbox binding pins the sandbox-only contract its image was built
	// for; every OpenShell sandbox runs Linux.
	if goos == "linux" {
		for _, contract := range sandboxOnlyHookContracts(connectorName) {
			if contract.ContractID == contractID {
				return contract, true
			}
		}
	}
	return HookContract{}, false
}

func ResolveHookContract(connectorName, rawVersion string) HookContractResolution {
	return resolveHookContractForOS(connectorName, rawVersion, runtime.GOOS)
}

// ResolveHookContractStrict resolves like ResolveHookContract with
// exact-range matching, whatever this process's mode: an agent version
// outside every tested range is unknown.
func ResolveHookContractStrict(connectorName, rawVersion string) HookContractResolution {
	return resolveHookContractForOSMode(connectorName, rawVersion, runtime.GOOS, true)
}

func resolveHookContractForOS(connectorName, rawVersion, goos string) HookContractResolution {
	return resolveHookContractForOSMode(connectorName, rawVersion, goos, StrictHookContractResolution())
}

func resolveHookContractForOSMode(connectorName, rawVersion, goos string, strict bool) HookContractResolution {
	return resolveHookContractForOSModeIn(connectorName, rawVersion, goos, strict, false)
}

// resolveHookContractForOSModeIn is resolveHookContractForOSMode for the agent
// on the host (sandbox false) or the pinned build of an OpenShell image.
func resolveHookContractForOSModeIn(connectorName, rawVersion, goos string, strict, sandbox bool) HookContractResolution {
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
	if catalogedOnlyConnectorsWithoutHookGate[name] {
		raw := strings.TrimSpace(rawVersion)
		return HookContractResolution{
			Connector:         name,
			RawVersion:        raw,
			NormalizedVersion: NormalizeAgentVersion(name, raw),
			Status:            HookCompatibilityNotGated,
			Reason:            "connector has no hook contract gate",
		}
	}
	contracts := hookContractsForOS(name, goos)
	if strict && name == "opencode" {
		// The strict profile ships the frozen v1 bridge. Preserve its
		// pre-v2 catalog even as standalone/per-user support moves forward.
		contracts = openCodeContractsForVersion(contracts, "1.0.0")
	}
	resolution := resolveHookContractAgainstIn(name, rawVersion, contracts, sandbox)
	if strict {
		return strictHookContractResolutionOf(resolution)
	}
	return resolution
}

// strictHookContractResolutionOf turns an untested newer version back into
// the exact-range answer: unknown, no contract.
func strictHookContractResolutionOf(resolution HookContractResolution) HookContractResolution {
	if !resolution.UntestedVersion {
		return resolution
	}
	resolution.Status = HookCompatibilityUnknown
	resolution.Reason = "no hook contract matches normalized agent version"
	resolution.Contract = HookContract{}
	resolution.UntestedVersion = false
	resolution.NewestTestedVersion = ""
	resolution.Warning = ""
	return resolution
}

// resolveHookContractAgainst matches rawVersion against contracts, the
// registered contracts of connector name. A version on the known-broken
// list is unknown. A version newer than every tested range resolves to the
// newest contract with UntestedVersion set, and so does one between two
// exact pins of one contract; versions below a floor, between ranges or next
// to an exact pin of the same build stay unknown.
func resolveHookContractAgainst(name, rawVersion string, contracts []HookContract) HookContractResolution {
	return resolveHookContractAgainstIn(name, rawVersion, contracts, false)
}

// resolveHookContractAgainstIn is resolveHookContractAgainst for the agent on
// the host (sandbox false) or in an OpenShell image, which skips the
// HostOnly known-broken entries. A Known version carries the Warning of the
// WarnOnly entry it falls in.
func resolveHookContractAgainstIn(name, rawVersion string, contracts []HookContract, sandbox bool) HookContractResolution {
	resolution := resolveHookContractMatch(name, rawVersion, contracts, sandbox)
	if resolution.Status == HookCompatibilityKnown {
		resolution.Warning = knownVersionWarning(name, strings.TrimSpace(rawVersion), sandbox)
	}
	return resolution
}

func resolveHookContractMatch(name, rawVersion string, contracts []HookContract, sandbox bool) HookContractResolution {
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
			Contract:          bestEffortHookContract(contracts),
		}
	}
	if name != "opencode" && gitBuildVersionRE.MatchString(raw) {
		// A source build (Hermes "vgit.5bba024 (2026.9.24)") has no release
		// version: its digits are a commit hash or a date. Treat it as newer
		// than every tested range instead of reading a version out of the hash,
		// unless the release date it prints is known broken.
		if match := gitBuildReleaseDateRE.FindStringSubmatch(raw); match != nil {
			date := NormalizeAgentVersion(name, match[1])
			if broken, ok := knownBrokenAgentVersion(name, raw, date, sandbox); ok {
				return HookContractResolution{
					Connector:         name,
					RawVersion:        raw,
					NormalizedVersion: date,
					Status:            HookCompatibilityUnknown,
					Reason:            fmt.Sprintf("agent version %s is known broken: %s (%s)", date, broken.Reason, broken.Issue),
				}
			}
		}
		if contract, newest, ok := newestContractBelow(contracts, gitBuildCompareVersion); ok {
			return HookContractResolution{
				Connector:           name,
				RawVersion:          raw,
				Status:              HookCompatibilityKnown,
				Reason:              fmt.Sprintf("%s: git build with no release version, treated as newer than the tested versions (%s); no known problems; using hook contract %s", UntestedNewerVersionReasonPrefix, newest, contract.ContractID),
				Contract:            contract,
				UntestedVersion:     true,
				NewestTestedVersion: newest,
			}
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
	if broken, ok := knownBrokenAgentVersion(name, raw, normalized, sandbox); ok {
		return HookContractResolution{
			Connector:         name,
			RawVersion:        raw,
			NormalizedVersion: normalized,
			Status:            HookCompatibilityUnknown,
			Reason:            fmt.Sprintf("agent version %s is known broken: %s (%s)", normalized, broken.Reason, broken.Issue),
		}
	}
	if name == "opencode" {
		contracts = openCodeContractsForVersion(contracts, normalized)
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
	if contract, newest, ok := newestContractBelow(contracts, normalized); ok {
		return HookContractResolution{
			Connector:           name,
			RawVersion:          raw,
			NormalizedVersion:   normalized,
			Status:              HookCompatibilityKnown,
			Reason:              fmt.Sprintf("%s: %s is newer than the tested versions (%s); no known problems; using hook contract %s", UntestedNewerVersionReasonPrefix, normalized, newest, contract.ContractID),
			Contract:            contract,
			UntestedVersion:     true,
			NewestTestedVersion: newest,
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

// newestContractBelow returns the contract with the highest tested bound
// when normalized is newer than every bound of its version scheme: at or
// above each range's exclusive maximum and above an exact pin of each
// pinned contract (between two pins of one contract counts). An
// open-ended range means nothing is newer than it (a version at or above
// its minimum already matches). Date-style builds (major >= 1000, such as
// Cursor agent 2026.07.23 or Devin 3000.11.3) are compared only with bounds
// of the same style so a desktop 4.x release is not measured against a
// dated preview pin.
func newestContractBelow(contracts []HookContract, normalized string) (HookContract, string, bool) {
	dateStyle := func(v string) bool { return versionTuple(v)[0] >= 1000 }
	scheme := dateStyle(normalized)
	var best HookContract
	newest, label := "", ""
	for _, contract := range contracts {
		bounds, pinsAbove := 0, 0
		upper, upperLabel := "", ""
		for _, pin := range contract.ExactAgentVersions {
			pinNorm := NormalizeAgentVersion("", pin)
			if pinNorm == "" || dateStyle(pinNorm) != scheme {
				continue
			}
			switch cmp := compareVersion(normalized, pinNorm); {
			case cmp == 0:
				return HookContract{}, "", false
			case cmp < 0:
				pinsAbove++
				continue
			}
			bounds++
			if upper == "" || compareVersion(pinNorm, upper) > 0 {
				upper, upperLabel = pinNorm, pin
			}
		}
		// A version between two exact pins of one contract (Devin on Linux:
		// 3000.4.25 and 3000.11.3) is an untested version of that contract;
		// one below all of its pins is under its floor.
		if pinsAbove > 0 && bounds == 0 {
			return HookContract{}, "", false
		}
		if contract.MinAgentVersion != "" || contract.MaxAgentVersion != "" {
			edge := contract.MaxAgentVersion
			if edge == "" {
				edge = contract.MinAgentVersion
			}
			if dateStyle(edge) == scheme {
				if contract.MaxAgentVersion == "" || compareVersion(normalized, contract.MaxAgentVersion) < 0 {
					return HookContract{}, "", false
				}
				bounds++
				if upper == "" || compareVersion(contract.MaxAgentVersion, upper) > 0 {
					upper, upperLabel = contract.MaxAgentVersion, "<"+contract.MaxAgentVersion
				}
			}
		}
		if bounds > 0 && (newest == "" || compareVersion(upper, newest) >= 0) {
			best, newest, label = contract, upper, upperLabel
		}
	}
	if newest == "" {
		return HookContract{}, "", false
	}
	return best, label, true
}

// knownBrokenAgentVersion is the refusing (not WarnOnly) entry a version
// falls in.
func knownBrokenAgentVersion(name, raw, normalized string, sandbox bool) (KnownBrokenAgentVersion, bool) {
	return matchKnownBrokenAgentVersion(name, raw, normalized, sandbox, false)
}

// knownVersionWarning is the reason and issue of the WarnOnly entry a
// version falls in, matched like a refusing one: a git build by the release
// date it prints.
func knownVersionWarning(name, raw string, sandbox bool) string {
	normalized := NormalizeAgentVersion(name, raw)
	if gitBuildVersionRE.MatchString(raw) {
		normalized = ""
		if match := gitBuildReleaseDateRE.FindStringSubmatch(raw); match != nil {
			normalized = NormalizeAgentVersion(name, match[1])
		}
	}
	if entry, ok := matchKnownBrokenAgentVersion(name, raw, normalized, sandbox, true); ok {
		return fmt.Sprintf("%s (%s)", entry.Reason, entry.Issue)
	}
	return ""
}

func matchKnownBrokenAgentVersion(name, raw, normalized string, sandbox, warnOnly bool) (KnownBrokenAgentVersion, bool) {
	for _, entry := range knownBrokenAgentVersions[name] {
		if entry.WarnOnly != warnOnly || (sandbox && entry.HostOnly) {
			continue
		}
		if entry.Exact != "" {
			if exactAgentVersionMatch(raw, []string{entry.Exact}) {
				return entry, true
			}
			continue
		}
		if (entry.Min != "" || entry.Max != "") && versionInRange(normalized, entry.Min, entry.Max) {
			return entry, true
		}
	}
	return KnownBrokenAgentVersion{}, false
}

func contractMatchesAgentVersion(contract HookContract, raw, normalized string) bool {
	if len(contract.ExactAgentVersions) != 0 && exactAgentVersionMatch(raw, contract.ExactAgentVersions) {
		return true
	}
	// Empty min/max would otherwise accept any normalized version.
	if contract.MinAgentVersion != "" || contract.MaxAgentVersion != "" {
		return versionInRange(normalized, contract.MinAgentVersion, contract.MaxAgentVersion)
	}
	return false
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

// BestEffortHookContract returns the reviewed contract DefenseClaw may wire
// when version evidence is unavailable or unsupported. Runtime and response
// semantics come from the connector's default_for_unversioned contract, while
// its event list is the stable union of every registered contract.
// The compatibility status remains unchanged: callers must not describe this
// fallback as version-verified.
func BestEffortHookContract(resolution HookContractResolution) HookContract {
	if resolution.Status == HookCompatibilityKnown && resolution.Contract.ContractID != "" {
		return resolution.Contract
	}
	return bestEffortHookContract(KnownHookContracts(resolution.Connector))
}

func defaultHookContract(contracts []HookContract) HookContract {
	for _, contract := range contracts {
		if contract.DefaultForUnversioned {
			return contract
		}
	}
	return contracts[0]
}

func bestEffortHookContract(contracts []HookContract) HookContract {
	if len(contracts) == 0 {
		return HookContract{}
	}
	fallback := defaultHookContract(contracts)
	// Union only contracts the default may stand in for: those not gated
	// entirely above the default's tested range. A newer contract's events
	// (Claude Code v2's DirectoryAdded) are unknown to the agents the default
	// describes, and the union keeps the default's ContractID, so including
	// them would render a matrix that a pin of that ID rejects (the managed
	// policy runtime verifier and the v1 guardian expect the v1 event set).
	eligible := make([]HookContract, 0, len(contracts))
	for _, contract := range contracts {
		if !hookContractGatedAbove(contract, fallback) {
			eligible = append(eligible, contract)
		}
	}
	fallback.Events = unionHookContractStrings(fallback.Events, eligible, func(contract HookContract) []string {
		return contract.Events
	})
	return fallback
}

// hookContractGatedAbove reports whether contract applies only to agent
// versions at or above base's exclusive upper bound.
func hookContractGatedAbove(contract, base HookContract) bool {
	upper := strings.TrimSpace(base.MaxAgentVersion)
	lower := strings.TrimSpace(contract.MinAgentVersion)
	return upper != "" && lower != "" && compareVersion(lower, upper) >= 0
}

func unionHookContractStrings(
	preferred []string,
	contracts []HookContract,
	values func(HookContract) []string,
) []string {
	out := make([]string, 0, len(preferred))
	seen := make(map[string]struct{}, len(preferred))
	appendUnique := func(items []string) {
		for _, item := range items {
			item = strings.TrimSpace(item)
			if item == "" {
				continue
			}
			if _, exists := seen[item]; exists {
				continue
			}
			seen[item] = struct{}{}
			out = append(out, item)
		}
	}
	appendUnique(preferred)
	for _, contract := range contracts {
		appendUnique(values(contract))
	}
	return out
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

func resolveHookContractForOptions(
	connectorName string,
	opts SetupOpts,
) HookContractResolution {
	goos := opts.profileGOOS()
	pinnedID := strings.TrimSpace(opts.HookContractID)
	var resolution HookContractResolution
	if managedKiroOnOS(connectorName, goos) && (opts.ManagedEnterprise || kiroWindowsManagedHookContractID(pinnedID)) {
		resolution = ResolveWindowsManagedKiroHookContract(opts.AgentVersion)
	} else {
		resolution = resolveHookContractForOS(connectorName, opts.AgentVersion, goos)
	}
	if connectorName == "opencode" && pluginSecureClientProfile(opts) {
		resolution = resolveHookContractForOSMode(connectorName, opts.AgentVersion, goos, true)
	}
	if pinnedID != "" {
		pinned, ok := hookContractByIDForOS(connectorName, pinnedID, goos)
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
	if resolution.Status != HookCompatibilityKnown && resolution.Contract.DefaultForUnversioned {
		resolution.Contract = BestEffortHookContract(resolution)
	}
	return resolution
}

// profileGOOS is the operating system a profile is resolved for: opts.GOOS
// when the agent runs elsewhere (a sandbox), otherwise this host.
func (opts SetupOpts) profileGOOS() string {
	if goos := strings.ToLower(strings.TrimSpace(opts.GOOS)); goos != "" {
		return goos
	}
	return runtime.GOOS
}

func ApplyHookContract(profile HookProfile, opts SetupOpts) HookProfile {
	resolution := resolveHookContractForOptions(profile.Name, opts)
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
	profile.ContentEnvelope = contract.ContentEnvelope.clone()
	profile.ToolCallLifecycle = cloneToolCallLifecycleContract(contract.ToolCallLifecycle)
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

// hermesContentEnvelope is where Hermes puts hook content. Its shell-hook
// payload (agent/shell_hooks.py _payload_fields, v0.19-v0.21.5) promotes
// only tool_name, tool_input (from args), session_id, cwd and profile to
// the top level; every other hook argument, the prompt included, is under
// extra. Each event names the one field read: post_llm_call carries both
// user_message and assistant_response, so a shared key list would read the
// prompt as the model's response.
func hermesContentEnvelope() ContentEnvelope {
	return ContentEnvelope{Key: "extra", Fields: map[string]string{
		"pre_llm_call":   "user_message",
		"post_llm_call":  "assistant_response",
		"post_tool_call": "result",
		"subagent_stop":  "child_summary",
	}}
}
