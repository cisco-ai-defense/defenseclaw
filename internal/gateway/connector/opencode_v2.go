// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"fmt"
	"strings"
)

const openCodeV2ContractID = "opencode-hooks-v2"

// RequireOpenCodeV2 rejects a detected unsupported major independently of
// exploratory contract drift. Unreadable versions retain the existing
// unversioned admission policy; they never select a V1 implementation.
func RequireOpenCodeV2(name, rawVersion string) error {
	if normalizeConnectorName(name) != "opencode" {
		return nil
	}
	version := NormalizeAgentVersion("opencode", rawVersion)
	if version != "" && versionTuple(version)[0] != 2 {
		return fmt.Errorf("OpenCode V2 is required; detected %s. Install @opencode/cli@2, rerun defenseclaw setup opencode, and restart OpenCode", version)
	}
	return nil
}

// Only V2 can reuse its reviewed contract for an untested newer minor.
// V1 and future majors never inherit a V2 plugin contract.
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
