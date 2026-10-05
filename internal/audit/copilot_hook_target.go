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

package audit

import "strings"

// copilotCLIToLocalHookEvent maps the Copilot CLI hook event names to the
// Claude-style names the VS Code Local harness stores for the same hook point
// (PreToolUse vs preToolUse). Mirrors copilotCLIHookFileLocalEvents in
// internal/gateway/connector/hook_only_copilot_vscode.go and
// _COPILOT_LOCAL_TO_CLI_EVENT in cli/defenseclaw/alert_semantics.py.
var copilotCLIToLocalHookEvent = map[string]string{
	"sessionStart":        "SessionStart",
	"userPromptSubmitted": "UserPromptSubmit",
	"preToolUse":          "PreToolUse",
	"postToolUse":         "PostToolUse",
	"agentStop":           "Stop",
	"subagentStop":        "SubagentStop",
}

// copilotHookEventSpellings returns the CLI and Local spellings of a Copilot
// hook event given either one, or ok=false for any other name.
func copilotHookEventSpellings(event string) ([]string, bool) {
	event = strings.TrimSpace(event)
	if local, ok := copilotCLIToLocalHookEvent[event]; ok {
		return []string{event, local}, true
	}
	for cli, local := range copilotCLIToLocalHookEvent {
		if local == event {
			return []string{cli, local}, true
		}
	}
	return nil, false
}

// alertTargetPredicateSQL is the --target filter of alert review. Alerts
// show one Copilot hook target for both harnesses (copilot:preToolUse), so
// that value also selects the alerts stored as copilot:PreToolUse; a bare
// event name matches both spellings on copilot rows only (GAP-2619). Any
// other target is compared exactly. Values are bound as SQL parameters.
func alertTargetPredicateSQL(target string) (string, []any) {
	head, event, prefixed := strings.Cut(target, ":")
	if prefixed && strings.EqualFold(strings.TrimSpace(head), "copilot") {
		if spellings, ok := copilotHookEventSpellings(event); ok {
			return `event.target IN (?,?,?)`, []any{target, head + ":" + spellings[0], head + ":" + spellings[1]}
		}
	}
	if !prefixed {
		if spellings, ok := copilotHookEventSpellings(target); ok {
			return `(event.target = ? OR (LOWER(COALESCE(event.connector,'')) = 'copilot' AND event.target IN (?,?)))`,
				[]any{target, spellings[0], spellings[1]}
		}
	}
	return `event.target = ?`, []any{target}
}
