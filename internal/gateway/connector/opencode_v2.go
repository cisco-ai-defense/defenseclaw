// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import "strings"

const openCodeV2ContractID = "opencode-hooks-v2"

func init() {
	// Both vendor APIs use one connector, endpoint and deployment footprint.
	// The bridge translates v2 events into the existing gateway envelope.
	v2 := builtinHookContracts["opencode"][0]
	v2.ContractID = openCodeV2ContractID
	v2.MinAgentVersion = "2.0.0"
	v2.MaxAgentVersion = "2.2.0"
	v2.Events = []string{"defenseclaw.plugin.loaded", "session.created", "session.status", "session.idle", "session.error", "session.deleted", "tool.execute.before", "tool.execute.after"}
	v2.ToolCallLifecycle = openCodeV2ToolCallLifecycle()
	v2.Notes = []string{
		"OpenCode v2 uses a default plugin definition with id and setup(ctx); ctx.tool.hook registers awaited execute.before and execute.after callbacks. The dependency-free bridge preserves the v1 server entrypoint.",
		"Source reviewed at v2.0.0 (63f7ceecbed2d7d9a627518d935dd963b9d4ac9f) and dev/2.1.4 (f669c46c9604ea3d70b8a7ed1f0c10f3a5ac1f61): packages/plugin/src/promise/tool.ts and packages/core/src/tool.ts. https://opencode.ai/v2/docs/build/plugins/migrate-v1",
		"Before awaiting a verdict, the bridge detaches and deeply freezes the inspected arguments and freezes the event. Later hooks cannot substitute an uninspected tool or input. Context and MCP identity are resolved through the local plugin API with a bounded timeout.",
		"The v2 result status, content and structured output are forwarded without inventing v1 output strings. After-hook and lifecycle events are observe-only. No native approval or model-traffic interception is claimed.",
		"Configured local plugins are directories in v2. Managed installs register a directory with an index.js entrypoint. The Secure Client profile retains its pinned v1 plugin and does not admit v2.",
	}
	builtinHookContracts["opencode"] = append(builtinHookContracts["opencode"], v2)
}

func openCodeV2ToolCallLifecycle() ToolCallLifecycleContract {
	lifecycle := openCodeToolCallLifecycle()
	lifecycle.AuthoritativeFailureEvents = []string{"tool.execute.after"}
	lifecycle.Routing.AuditOnlyEvents = []string{"session.created", "session.status", "session.idle", "session.error", "session.deleted"}
	lifecycle.OfficialSourceURLs = []string{
		"https://github.com/anomalyco/opencode/blob/f669c46c9604ea3d70b8a7ed1f0c10f3a5ac1f61/packages/plugin/src/promise/tool.ts",
		"https://github.com/anomalyco/opencode/blob/f669c46c9604ea3d70b8a7ed1f0c10f3a5ac1f61/packages/core/src/tool.ts",
	}
	lifecycle.Limitations = []string{
		"The v2 bridge binds event.id to tool_call_id and forwards completed/error status. Missing or malformed results never prove success.",
		"Lifecycle delivery is best-effort and disposed on plugin unload; it is not an enforcement boundary.",
	}
	return lifecycle
}

// OpenCode deliberately broke the plugin API across majors. New minors can
// reuse their own major's contract as untested; a future major cannot silently
// fall back to v1 or v2. Other connectors keep their existing version policy.
func openCodeContractsForVersion(contracts []HookContract, normalized string) []HookContract {
	if normalized == "" {
		return contracts
	}
	var matched []HookContract
	for _, contract := range contracts {
		if versionTuple(contract.MinAgentVersion)[0] == versionTuple(normalized)[0] {
			matched = append(matched, contract)
		}
	}
	return matched
}

// V2 reports explicit errors and structured tool results. A returned shell
// result can still represent a running job, timeout, signal, or nonzero exit.
func classifyOpenCodeV2Result(payload, result map[string]interface{}) ToolLifecycleOutcome {
	status, _ := result["opencode_v2_status"].(string)
	if status == "error" {
		return ToolLifecycleOutcomeFailure
	}
	if status != "completed" {
		return ToolLifecycleOutcomeUnknown
	}
	tool, _ := firstPresent(payload, "tool_name", "toolName")
	name, _ := tool.(string)
	if strings.EqualFold(strings.TrimSpace(name), "shell") {
		output, ok := nestedMap(result, "output")
		if !ok || output["status"] == "running" {
			return ToolLifecycleOutcomeUnknown
		}
		if output["timeout"] == true || hasErrorValue(output["signal"]) {
			return ToolLifecycleOutcomeFailure
		}
		exitCode, ok := numericInt64(output["exit"])
		if !ok {
			return ToolLifecycleOutcomeUnknown
		}
		if exitCode != 0 {
			return ToolLifecycleOutcomeFailure
		}
	}
	if value, ok := result["content"]; ok {
		switch value.(type) {
		case string, []interface{}:
			return ToolLifecycleOutcomeSuccess
		}
	}
	if value, ok := result["output"]; ok && value != nil {
		return ToolLifecycleOutcomeSuccess
	}
	return ToolLifecycleOutcomeUnknown
}
