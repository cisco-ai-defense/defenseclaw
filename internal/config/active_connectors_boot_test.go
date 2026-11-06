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

package config

import (
	"reflect"
	"testing"
)

// TestActiveConnectors_OneEntryForAnotherConnectorKeepsThePrimary pins the
// shared boot rule (GAP-0588, GAP-0707): fewer than two guardrail.connectors
// keys boot exactly the connector the singular selection names, so a stored
// setting for another connector never becomes the active set. Two or more keys
// still select the multi-connector roster.
func TestActiveConnectors_OneEntryForAnotherConnectorKeepsThePrimary(t *testing.T) {
	enabled := true
	tests := []struct {
		name       string
		connectors map[string]PerConnectorGuardrailConfig
		connector  string
		want       []string
	}{
		{"one_setting_entry_for_another_connector", map[string]PerConnectorGuardrailConfig{"codex": {RulePack: "permissive"}}, "kiro", []string{"kiro"}},
		{"one_enabled_entry_for_another_connector", map[string]PerConnectorGuardrailConfig{"cursor": {Enabled: &enabled}}, "claudecode", []string{"claudecode"}},
		{"one_entry_naming_the_primary_by_alias", map[string]PerConnectorGuardrailConfig{"claude_code": {}}, "claude-code", []string{"claudecode"}},
		{"one_misspelled_entry", map[string]PerConnectorGuardrailConfig{"kiroo": {}}, "kiro", []string{"kiro"}},
		{"one_entry_without_a_primary_is_the_roster", map[string]PerConnectorGuardrailConfig{"codex": {}}, "", []string{"codex"}},
		{"two_entries_are_the_roster", map[string]PerConnectorGuardrailConfig{"codex": {}, "cursor": {}}, "kiro", []string{"codex", "cursor"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.Guardrail.Connectors = tt.connectors
			cfg.Guardrail.Connector = tt.connector
			if got := cfg.ActiveConnectors(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("ActiveConnectors() = %v, want %v", got, tt.want)
			}
		})
	}
}
