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

package cli

import "testing"

func TestWindowsConfigCodexTargetNeedsReconcile(t *testing.T) {
	const withCodex = "config_version: 9\nguardrail:\n  connectors:\n    codex: {}\n    claudecode: {}\n"
	const claudeOnly = "config_version: 9\nguardrail:\n  connectors:\n    claudecode: {}\n"
	for _, tc := range []struct {
		name, config, metadata string
		want                   bool
	}{
		{"discovered after install", withCodex, `{"codex_target_enabled":false}`, true},
		{"stale enabled record", claudeOnly, `{"codex_target_enabled":true}`, true},
		{"matching enabled", withCodex, `{"codex_target_enabled":true}`, false},
		{"matching disabled", claudeOnly, `{"codex_target_enabled":false}`, false},
		{"old release missing field", withCodex, `{}`, true},
		{"missing disabled evidence", claudeOnly, `{}`, true},
		{"null", withCodex, `{"codex_target_enabled":null}`, true},
		{"wrong type", withCodex, `{"codex_target_enabled":"true"}`, true},
		{"invalid metadata", withCodex, `{`, true},
		{"invalid config", "guardrail: [codex]", `{"codex_target_enabled":false}`, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := windowsConfigCodexTargetNeedsReconcile([]byte(tc.config), []byte(tc.metadata)); got != tc.want {
				t.Fatalf("needs reconcile = %t, want %t", got, tc.want)
			}
		})
	}
}

// GAP-0033: a config change that turns Codex protection on or off is the
// upgrade transaction's on Windows; every other connector change is not.
func TestWindowsConfigCodexTargetChanged(t *testing.T) {
	const claudeOnly = "config_version: 9\nguardrail:\n  block_at: MEDIUM\n  connectors:\n    claudecode:\n      enabled: true\n"
	const withCodex = "config_version: 9\nguardrail:\n  block_at: LOW\n  connectors:\n    claudecode:\n      enabled: true\n    codex:\n      enabled: true\n"
	for _, tc := range []struct {
		name, installed, supplied string
		want                      bool
	}{
		{"F-W03 restart bundle enables Codex", claudeOnly, withCodex, true},
		{"bundle turns Codex off", withCodex, claudeOnly, true},
		{"policy change keeps Codex on", withCodex, "config_version: 9\nguardrail:\n  block_at: HIGH\n  connectors:\n    claudecode:\n      enabled: true\n    codex:\n      enabled: true\n", false},
		{"policy change keeps Claude only", claudeOnly, "config_version: 9\nguardrail:\n  block_at: LOW\n  connectors:\n    claudecode:\n      enabled: true\n", false},
		{"another connector", claudeOnly, claudeOnly + "    cursor: {}\n", false},
		{"empty entry enables Codex", claudeOnly, claudeOnly + "    codex: {}\n", true},
		{"null entry enables Codex", claudeOnly, claudeOnly + "    codex:\n", true},
		{"names compare case-insensitively", claudeOnly, claudeOnly + "    Codex: {}\n", true},
		{"explicitly disabled stays off", claudeOnly, claudeOnly + "    codex:\n      enabled: false\n", false},
		{"disable an enabled Codex", withCodex, claudeOnly + "    codex:\n      enabled: false\n", true},
		{"scalar connector", "config_version: 9\nguardrail:\n  connector: claudecode\n", "config_version: 9\nguardrail:\n  connector: codex\n", true},
		{"map disable wins over the scalar", "config_version: 9\nguardrail:\n  connector: codex\n  connectors:\n    codex:\n      enabled: false\n", "config_version: 9\nguardrail:\n  connector: claudecode\n", false},
		{"unreadable supplied config", claudeOnly, "guardrail:\n  connectors: [codex]\n", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := windowsConfigCodexTargetChanged([]byte(tc.installed), []byte(tc.supplied)); got != tc.want {
				t.Fatalf("windowsConfigCodexTargetChanged = %t, want %t", got, tc.want)
			}
		})
	}
}
