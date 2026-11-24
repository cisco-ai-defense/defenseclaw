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

package gateway

import (
	"fmt"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/guardrail/bounded"
)

// gap1105Decide is the verdict of one MCP tool call on a hook route.
func gap1105Decide(t *testing.T, api *APIServer, connector string, input map[string]interface{}) (string, []string) {
	t.Helper()
	if connector == "claudecode" {
		resp := api.evaluateClaudeCodeHook(t.Context(), claudeCodeHookRequest{
			HookEventName: "PreToolUse", SessionID: "gap1105", CWD: t.TempDir(),
			ToolName: "mcp__ops__run", ToolInput: input,
		})
		return resp.Action, resp.Findings
	}
	resp := api.evaluateCodexHook(t.Context(), codexHookRequest{
		HookEventName: "PreToolUse", SessionID: "gap1105", CWD: t.TempDir(),
		ToolName: "mcp__ops__run", ToolInput: input,
	})
	return resp.Action, resp.Findings
}

// TestGAP1105MCPConflictingCommandKeysJudgeEveryValue: an MCP tool call
// whose argument keys name the command field with two values is judged on
// each value, on the Claude Code and Codex hook routes in the five tiers. At
// befff79e53 (and a64bfdb931) the call read only the first key in order, so
// {"command":"x","scripT":CMD} was allowed with no finding where {"scripT":CMD}
// alone is blocked (substrate-1:GAP-1105).
func TestGAP1105MCPConflictingCommandKeysJudgeEveryValue(t *testing.T) {
	const cmd = "rm -rf /"
	attacks := []struct {
		name  string
		alone map[string]interface{}
		call  map[string]interface{}
	}{
		{"command x + scripT", map[string]interface{}{"scripT": cmd}, map[string]interface{}{"command": "x", "scripT": cmd}},
		{"cmd echo + script", map[string]interface{}{"script": cmd}, map[string]interface{}{"cmd": "echo hi", "script": cmd}},
		{"Command x + command", map[string]interface{}{"command": cmd}, map[string]interface{}{"Command": "x", "command": cmd}},
		{"command + scripT x", map[string]interface{}{"command": cmd}, map[string]interface{}{"command": cmd, "scripT": "x"}},
		{"command x + input command", map[string]interface{}{"input": map[string]interface{}{"command": cmd}},
			map[string]interface{}{"command": "x", "input": map[string]interface{}{"command": cmd}}},
		{"input cmd x + script", map[string]interface{}{"input": map[string]interface{}{"script": cmd}},
			map[string]interface{}{"input": map[string]interface{}{"cmd": "x", "script": cmd}}},
	}
	benign := []struct {
		name string
		call map[string]interface{}
	}{
		{"one command", map[string]interface{}{"command": "echo hi"}},
		{"two keys, one value", map[string]interface{}{"command": "echo hi", "cmd": "echo hi"}},
		{"two keys, two benign values", map[string]interface{}{"command": "echo hi", "cmd": "ls"}},
		{"no command", map[string]interface{}{"query": "status"}},
	}
	for _, tier := range boundedTestTiers {
		for _, connector := range []string{"claudecode", "codex"} {
			api := gap0589TierAPI(t, connector, tier.posture, tier.managed, tier.tier)
			useDefaultEffectsLane(t)
			for _, row := range attacks {
				aloneAction, aloneFindings := gap1105Decide(t, api, connector, row.alone)
				if aloneAction != "block" || !gap0589HasRule(aloneFindings, "CMD-RM-RF") {
					t.Fatalf("%s %s %s alone: %s %v, want the block of CMD-RM-RF", tier.name, connector, row.name, aloneAction, aloneFindings)
				}
				action, findings := gap1105Decide(t, api, connector, row.call)
				if boundedParse(action) != boundedParse(aloneAction) || !gap0589HasRule(findings, "CMD-RM-RF") {
					t.Errorf("%s %s %s: %s %v, want the value alone %s with CMD-RM-RF", tier.name, connector, row.name, action, findings, aloneAction)
				}
			}
			for _, row := range benign {
				if action, findings := gap1105Decide(t, api, connector, row.call); action != "allow" {
					t.Errorf("%s %s benign %s: %s %v, want allow", tier.name, connector, row.name, action, findings)
				}
			}
		}
	}
}

// TestGAP1105MCPConflictingCommandKeysPastTheBoundFloor: past
// maxBesideCallConflictCandidates candidates the call is not fully read, so
// it takes at least the unknown tier (TRUNCATED, cap items), as on the MCP
// bridge; a value it does judge keeps its rule.
func TestGAP1105MCPConflictingCommandKeysPastTheBoundFloor(t *testing.T) {
	// Three keys with three values are nine candidates, past the bound of 8.
	call := map[string]interface{}{"command": "echo a", "cmd": "echo b", "script": "rm -rf /"}
	for _, tier := range boundedTestTiers {
		for _, connector := range []string{"claudecode", "codex"} {
			api := gap0589TierAPI(t, connector, tier.posture, tier.managed, tier.tier)
			useDefaultEffectsLane(t)
			for _, row := range []struct {
				name string
				call map[string]interface{}
				want bounded.Action
			}{
				{"one value rm", call, bounded.Stricter(bounded.Unknown(tier.tier), boundedParse("block"))},
				{"three echo values", map[string]interface{}{"command": "echo a", "cmd": "echo b", "script": "echo c"}, bounded.Unknown(tier.tier)},
			} {
				action, findings := gap1105Decide(t, api, connector, row.call)
				name := fmt.Sprintf("%s %s %s", tier.name, connector, row.name)
				if got := boundedParse(action); got != row.want {
					t.Errorf("%s: %s %v, want %s", name, action, findings, row.want)
				}
				if !boundedHasLimit(findings, bounded.Items, true) {
					t.Errorf("%s: not TRUNCATED (no %s naming cap=items): %v", name, evaluationLimitRuleID, findings)
				}
			}
		}
	}
}
