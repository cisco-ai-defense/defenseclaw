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
)

// HookContract is the versioned, reproducible hook surface DefenseClaw
// knows how to install, decode, evaluate, and respond to for one connector.
//
// A connector may publish multiple contracts as upstream agent CLIs add,
// rename, or remove hook events. Runtime code must resolve a contract before
// deciding whether a hook event is blockable/askable/AID-eligible; it should
// never assume that "latest connector code" describes every installed agent.
type HookContract struct {
	Connector           string
	ContractID          string
	MinAgentVersion     string
	MaxAgentVersion     string
	HookScriptVersion   string
	ResponseFieldName   string
	Events              []string
	AIDSurfaces         []string
	Capabilities        HookCapability
	SupportsTraceparent bool
	NativeOTLP          bool
	Notes               []string
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

var builtinHookContracts = map[string][]HookContract{
	"codex": {{
		Connector:         "codex",
		ContractID:        "codex-hooks-v1",
		MinAgentVersion:   "0.0.0",
		MaxAgentVersion:   "1.0.0",
		HookScriptVersion: "v6",
		ResponseFieldName: "codex_output",
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
			"Codex has no native hook-side ask surface in this contract; confirm verdicts render as alert/systemMessage.",
		},
	}},
	"claudecode": {{
		Connector:         "claudecode",
		ContractID:        "claudecode-hooks-v1",
		MinAgentVersion:   "0.0.0",
		MaxAgentVersion:   "2.0.0",
		HookScriptVersion: "v6",
		ResponseFieldName: "claude_code_output",
		Events: []string{
			"SessionStart",
			"UserPromptSubmit",
			"UserPromptExpansion",
			"PreToolUse",
			"PermissionRequest",
			"PermissionDenied",
			"PostToolUse",
			"PostToolUseFailure",
			"PostToolBatch",
			"Stop",
			"SubagentStop",
			"SessionEnd",
			"InstructionsLoaded",
			"ConfigChange",
			"FileChanged",
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
				"PostToolUse",
				"PostToolBatch",
				"TaskCreated",
				"TaskCompleted",
				"TeammateIdle",
				"Stop",
				"SubagentStop",
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
			"Claude Code PreToolUse supports native HITL via permissionDecision=ask.",
		},
	}},
	"hermes": {{
		Connector:         "hermes",
		ContractID:        "hermes-hooks-v1",
		HookScriptVersion: "v6",
		ResponseFieldName: "hook_output",
		Events:            []string{"pre_tool_call"},
		AIDSurfaces:       []string{"tool_call"},
		Capabilities: HookCapability{
			CanBlock:           true,
			CanAskNative:       false,
			BlockEvents:        []string{"pre_tool_call"},
			SupportsFailClosed: false,
			Scope:              "user",
		},
		SupportsTraceparent: true,
	}},
	"cursor": {{
		Connector:         "cursor",
		ContractID:        "cursor-hooks-v1",
		HookScriptVersion: "v6",
		ResponseFieldName: "hook_output",
		Events: []string{
			"preToolUse",
			"beforeShellExecution",
			"beforeMCPExecution",
			"beforeReadFile",
			"beforeTabFileRead",
			"beforeSubmitPrompt",
			"stop",
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
	}},
	"windsurf": {{
		Connector:         "windsurf",
		ContractID:        "windsurf-hooks-v1",
		HookScriptVersion: "v6",
		ResponseFieldName: "hook_output",
		Events: []string{
			"pre_user_prompt",
			"pre_read_code",
			"pre_write_code",
			"pre_run_command",
			"pre_mcp_tool_use",
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
	}},
	"geminicli": {{
		Connector:         "geminicli",
		ContractID:        "geminicli-hooks-v1",
		HookScriptVersion: "v6",
		ResponseFieldName: "hook_output",
		Events: []string{
			"BeforeAgent",
			"BeforeModel",
			"BeforeTool",
			"AfterTool",
			"AfterAgent",
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
	}},
	"copilot": {{
		Connector:         "copilot",
		ContractID:        "copilot-hooks-v1",
		HookScriptVersion: "v6",
		ResponseFieldName: "hook_output",
		Events: []string{
			"preToolUse",
			"PreToolUse",
			"permissionRequest",
			"PermissionRequest",
			"agentStop",
			"Stop",
			"subagentStop",
			"SubagentStop",
			"postToolUseFailure",
			"PostToolUseFailure",
			"notification",
			"Notification",
		},
		AIDSurfaces: []string{"prompt", "tool_call", "tool_result"},
		Capabilities: HookCapability{
			CanBlock:     true,
			CanAskNative: true,
			AskEvents:    []string{"preToolUse", "PreToolUse"},
			BlockEvents: []string{
				"preToolUse",
				"PreToolUse",
				"permissionRequest",
				"PermissionRequest",
				"agentStop",
				"Stop",
				"subagentStop",
				"SubagentStop",
				"postToolUseFailure",
				"PostToolUseFailure",
			},
			SupportsFailClosed: false,
			Scope:              "workspace",
		},
		SupportsTraceparent: true,
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
			Contract:          contracts[0],
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
	profile.SupportedEvents = append([]string(nil), contract.Events...)
	profile.AIDSurfaces = append([]string(nil), contract.AIDSurfaces...)
	profile.SupportsTraceparent = contract.SupportsTraceparent
	profile.ResponseFieldName = contract.ResponseFieldName

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
