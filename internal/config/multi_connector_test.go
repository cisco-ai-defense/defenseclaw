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
	"strings"
	"testing"
)

// TestActiveConnectors_Precedence pins the multi-connector resolution
// order: a non-empty guardrail.connectors map wins (keys sorted), else
// the singular guardrail.connector, else claw.mode, else an empty roster
// for a zero-config install.
func TestActiveConnectors_Precedence(t *testing.T) {
	tests := []struct {
		name       string
		connectors map[string]PerConnectorGuardrailConfig
		connector  string
		clawMode   ClawMode
		want       []string
	}{
		{
			name:       "plural_map_wins_sorted",
			connectors: map[string]PerConnectorGuardrailConfig{"codex": {}, "antigravity": {}},
			connector:  "claudecode",
			clawMode:   "openclaw",
			want:       []string{"antigravity", "codex"},
		},
		{
			name:      "singular_when_no_map",
			connector: "claudecode",
			clawMode:  "openclaw",
			want:      []string{"claudecode"},
		},
		{
			name:     "claw_mode_when_no_connector",
			clawMode: "zeptoclaw",
			want:     []string{"zeptoclaw"},
		},
		{
			name: "zero_config_empty_roster",
			want: nil,
		},
		{
			name:       "whitespace_keys_dropped_then_fallback",
			connectors: map[string]PerConnectorGuardrailConfig{"  ": {}},
			connector:  "codex",
			want:       []string{"codex"},
		},
		{
			name: "normalizes_map_keys",
			connectors: map[string]PerConnectorGuardrailConfig{
				"  Codex  ":  {},
				"open-hands": {},
			},
			want: []string{"codex", "openhands"},
		},
		{
			name: "dedupes_normalized_aliases",
			connectors: map[string]PerConnectorGuardrailConfig{
				"openhands":  {},
				"open_hands": {},
			},
			want: []string{"openhands"},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{}
			cfg.Guardrail.Connectors = tt.connectors
			cfg.Guardrail.Connector = tt.connector
			cfg.Claw.Mode = tt.clawMode
			if got := cfg.activeConnectors(); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("activeConnectors() = %v, want %v", got, tt.want)
			}
		})
	}
}

// TestActiveConnector_UnchangedByMap proves activeConnector() keeps its
// original precedence (guardrail.connector → claw.mode → "openclaw") and
// is NOT influenced by the new guardrail.connectors map: the plural
// activeConnectors() is purely additive on top of the untouched singular
// reader, so legacy single-connector call sites behave exactly as before.
func TestActiveConnector_UnchangedByMap(t *testing.T) {
	cfg := &Config{}
	cfg.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{
		"codex":       {},
		"antigravity": {},
	}
	// Map present but no singular connector / mode → singular reader
	// falls back to "openclaw" exactly like before multi-connector.
	if got := cfg.activeConnector(); got != "openclaw" {
		t.Errorf("activeConnector() = %q, want openclaw (map must not affect singular reader)", got)
	}
	// The plural reader is the additive surface that sees the map.
	if got := cfg.activeConnectors(); !reflect.DeepEqual(got, []string{"antigravity", "codex"}) {
		t.Errorf("activeConnectors() = %v, want [antigravity codex]", got)
	}
}

func TestActiveConnectors_NilSafe(t *testing.T) {
	var cfg *Config
	if got := cfg.activeConnectors(); !reflect.DeepEqual(got, []string(nil)) {
		t.Errorf("nil cfg activeConnectors() = %v, want nil", got)
	}
}

// TestEffectiveResolvers_Precedence checks per-connector override >
// global > safe fallback across all five resolvers.
func TestEffectiveResolvers_Precedence(t *testing.T) {
	g := &GuardrailConfig{
		Mode:         "observe",
		HookFailMode: "open",
		BlockMessage: "global-msg",
		RulePackDir:  "/global/rules",
		HILT:         HILTConfig{Enabled: false, MinSeverity: "HIGH"},
		Connectors: map[string]PerConnectorGuardrailConfig{
			"codex": {
				Mode:         "action",
				HookFailMode: "closed",
				BlockMessage: "codex-msg",
				RulePackDir:  "/codex/rules",
				HILT:         &HILTConfig{Enabled: true, MinSeverity: "LOW"},
			},
			"empty": {}, // all fields inherit
		},
	}

	// Per-connector override wins.
	if got := g.EffectiveMode("codex"); got != "action" {
		t.Errorf("EffectiveMode(codex) = %q, want action", got)
	}
	if got := g.EffectiveHookFailModeFor("codex"); got != "closed" {
		t.Errorf("EffectiveHookFailModeFor(codex) = %q, want closed", got)
	}
	if got := g.EffectiveBlockMessage("codex"); got != "codex-msg" {
		t.Errorf("EffectiveBlockMessage(codex) = %q, want codex-msg", got)
	}
	if got := g.EffectiveRulePackDir("codex"); got != "/codex/rules" {
		t.Errorf("EffectiveRulePackDir(codex) = %q, want /codex/rules", got)
	}
	if got := g.EffectiveHILT("codex"); !got.Enabled || got.MinSeverity != "LOW" {
		t.Errorf("EffectiveHILT(codex) = %+v, want {Enabled:true MinSeverity:LOW}", got)
	}

	// Empty override block inherits global.
	if got := g.EffectiveMode("empty"); got != "observe" {
		t.Errorf("EffectiveMode(empty) = %q, want observe", got)
	}
	if got := g.EffectiveHookFailModeFor("empty"); got != "open" {
		t.Errorf("EffectiveHookFailModeFor(empty) = %q, want open", got)
	}
	if got := g.EffectiveBlockMessage("empty"); got != "global-msg" {
		t.Errorf("EffectiveBlockMessage(empty) = %q, want global-msg", got)
	}
	if got := g.EffectiveRulePackDir("empty"); got != "/global/rules" {
		t.Errorf("EffectiveRulePackDir(empty) = %q, want /global/rules", got)
	}
	if got := g.EffectiveHILT("empty"); got.Enabled || got.MinSeverity != "HIGH" {
		t.Errorf("EffectiveHILT(empty) = %+v, want global {false HIGH}", got)
	}

	// Unknown connector falls through to global.
	if got := g.EffectiveMode("nope"); got != "observe" {
		t.Errorf("EffectiveMode(nope) = %q, want observe", got)
	}
	// Empty connector name resolves the global value (legacy callers).
	if got := g.EffectiveHookFailModeFor(""); got != "open" {
		t.Errorf("EffectiveHookFailModeFor(\"\") = %q, want open", got)
	}
	// The original no-arg global resolver is untouched and still works.
	if got := g.EffectiveHookFailMode(); got != "open" {
		t.Errorf("EffectiveHookFailMode() = %q, want open", got)
	}
}

// TestEffectiveResolvers_SafeFallbacks ensures resolvers return safe
// defaults when global fields are unset.
func TestEffectiveResolvers_SafeFallbacks(t *testing.T) {
	g := &GuardrailConfig{}
	if got := g.EffectiveMode(""); got != "observe" {
		t.Errorf("EffectiveMode empty = %q, want observe", got)
	}
	// An observe-only connector with no explicit override retains the
	// historical fail-open behavior on every platform.
	if got := g.EffectiveHookFailModeFor(""); got != "open" {
		t.Errorf("EffectiveHookFailModeFor empty = %q, want open", got)
	}
	if got := g.EffectiveBlockMessage(""); got != "" {
		t.Errorf("EffectiveBlockMessage empty = %q, want empty", got)
	}
	if got := g.EffectiveRulePackDir(""); got != "" {
		t.Errorf("EffectiveRulePackDir empty = %q, want empty", got)
	}

	// Nil receiver must not panic.
	var nilG *GuardrailConfig
	if got := nilG.EffectiveMode("x"); got != "observe" {
		t.Errorf("nil EffectiveMode = %q, want observe", got)
	}
	if got := nilG.EffectiveHILT("x"); got != (HILTConfig{}) {
		t.Errorf("nil EffectiveHILT = %+v, want zero", got)
	}
}

func TestEffectiveHookFailMode_ExplicitOverrideWinsInObserve(t *testing.T) {
	g := &GuardrailConfig{
		Mode:         "observe",
		HookFailMode: "closed",
		Connectors: map[string]PerConnectorGuardrailConfig{
			"codex":      {HookFailMode: "closed"},
			"claudecode": {},
		},
	}
	if got := g.EffectiveHookFailModeFor("codex"); got != "closed" {
		t.Fatalf("explicit connector fail mode = %q, want closed", got)
	}
	if got := g.EffectiveHookFailModeFor("claudecode"); got != "open" {
		t.Fatalf("unoverridden observe connector fail mode = %q, want open", got)
	}
}

// TestConnectorsEmptyMapEqualsAbsent confirms an empty map behaves
// exactly like an absent one (no override path taken).
func TestConnectorsEmptyMapEqualsAbsent(t *testing.T) {
	withEmpty := &GuardrailConfig{Mode: "action", Connectors: map[string]PerConnectorGuardrailConfig{}}
	withNil := &GuardrailConfig{Mode: "action"}
	if a, b := withEmpty.EffectiveMode("codex"), withNil.EffectiveMode("codex"); a != b || a != "action" {
		t.Errorf("empty map (%q) != absent (%q), want both action", a, b)
	}
}

// TestEffectiveEnabled covers the per-connector on/off resolver: default
// true everywhere, false only on an explicit `enabled: false` override.
func TestEffectiveEnabled(t *testing.T) {
	enabled := true
	disabled := false
	g := &GuardrailConfig{
		Mode: "action",
		Connectors: map[string]PerConnectorGuardrailConfig{
			"codex":      {Enabled: &disabled}, // explicitly off
			"claudecode": {Enabled: &enabled},  // explicitly on
			"cursor":     {},                   // present, unset pointer
		},
	}

	if g.EffectiveEnabled("codex") {
		t.Errorf("EffectiveEnabled(codex) = true, want false (explicit disable)")
	}
	if !g.EffectiveEnabled("claudecode") {
		t.Errorf("EffectiveEnabled(claudecode) = false, want true (explicit enable)")
	}
	if !g.EffectiveEnabled("cursor") {
		t.Errorf("EffectiveEnabled(cursor) = false, want true (unset pointer inherits default)")
	}
	// Unknown connector, empty name, and nil receiver all default true.
	if !g.EffectiveEnabled("windsurf") {
		t.Errorf("EffectiveEnabled(unknown) = false, want true (default)")
	}
	if !g.EffectiveEnabled("") {
		t.Errorf("EffectiveEnabled(empty) = false, want true (default)")
	}
	var nilG *GuardrailConfig
	if !nilG.EffectiveEnabled("codex") {
		t.Errorf("nil EffectiveEnabled = false, want true (default, no panic)")
	}
	// An empty Connectors map must behave exactly like an absent one
	// (single-connector installs): always enabled.
	single := &GuardrailConfig{Mode: "action", Connector: "codex"}
	if !single.EffectiveEnabled("codex") {
		t.Errorf("single-connector EffectiveEnabled(codex) = false, want true")
	}
}

// TestConnectorOverride_NameInsensitive confirms every Effective*()
// resolver finds a per-connector override even when the configured key
// differs from the requested name only by case or a hyphen/underscore
// alias. The boot loop keys connectors by their canonical registry name
// (e.g. "openhands"), while operators may hand-write "OpenHands" or
// "open-hands" in config.yaml; the lookup must reconcile the two so the
// override is honored instead of silently falling through to the global.
func TestConnectorOverride_NameInsensitive(t *testing.T) {
	disabled := false
	g := &GuardrailConfig{
		Mode:         "observe",
		BlockMessage: "global-msg",
		Connectors: map[string]PerConnectorGuardrailConfig{
			"Codex":      {Mode: "action", BlockMessage: "codex-msg"},
			"open-hands": {Mode: "action", Enabled: &disabled},
		},
	}

	// Case-insensitive: canonical "codex" must resolve the "Codex" entry.
	if got := g.EffectiveMode("codex"); got != "action" {
		t.Errorf("EffectiveMode(codex) = %q, want action (case-insensitive key)", got)
	}
	if got := g.EffectiveBlockMessage("codex"); got != "codex-msg" {
		t.Errorf("EffectiveBlockMessage(codex) = %q, want codex-msg", got)
	}
	if !g.HasConnector("CODEX") {
		t.Errorf("HasConnector(CODEX) = false, want true (case-insensitive)")
	}

	// Alias-insensitive: canonical "openhands" must resolve "open-hands".
	if got := g.EffectiveMode("openhands"); got != "action" {
		t.Errorf("EffectiveMode(openhands) = %q, want action (alias key)", got)
	}
	if g.EffectiveEnabled("openhands") {
		t.Errorf("EffectiveEnabled(openhands) = true, want false (alias key honored)")
	}
	if !g.HasConnector("openhands") {
		t.Errorf("HasConnector(openhands) = false, want true (alias)")
	}

	// Genuinely-absent connector still falls through to the global.
	if got := g.EffectiveMode("windsurf"); got != "observe" {
		t.Errorf("EffectiveMode(windsurf) = %q, want observe (no override)", got)
	}
	if g.HasConnector("windsurf") {
		t.Errorf("HasConnector(windsurf) = true, want false")
	}
}

// TestGuardrailValidate covers value invariants and named errors.
func TestGuardrailValidate(t *testing.T) {
	tests := []struct {
		name    string
		cfg     GuardrailConfig
		wantErr string // substring; "" = expect success
	}{
		{"empty_ok", GuardrailConfig{}, ""},
		// Global fields are intentionally NOT validated (they predate
		// multi-connector support and were never load-gated), so even an
		// odd global value passes — only the connectors map is checked.
		{"global_fields_not_validated", GuardrailConfig{Mode: "blarg", HookFailMode: "halfopen", HILT: HILTConfig{MinSeverity: "SPICY"}}, ""},
		{"ipv6_metadata_allowlist_rejected", GuardrailConfig{AllowPrivateUpstreams: []string{"fd00:ec2::254"}}, "cloud metadata address"},
		{
			name: "bad_connector_mode_named",
			cfg: GuardrailConfig{Connectors: map[string]PerConnectorGuardrailConfig{
				"codex": {Mode: "blarg"},
			}},
			wantErr: `guardrail.connectors["codex"]: invalid guardrail mode`,
		},
		{
			name: "bad_connector_failmode_named",
			cfg: GuardrailConfig{Connectors: map[string]PerConnectorGuardrailConfig{
				"codex": {HookFailMode: "halfopen"},
			}},
			wantErr: `guardrail.connectors["codex"]: invalid hook_fail_mode`,
		},
		{
			name: "bad_connector_severity_named",
			cfg: GuardrailConfig{Connectors: map[string]PerConnectorGuardrailConfig{
				"codex": {HILT: &HILTConfig{MinSeverity: "SPICY"}},
			}},
			wantErr: `guardrail.connectors["codex"]: invalid hilt.min_severity`,
		},
		{
			name: "empty_connector_name",
			cfg: GuardrailConfig{Connectors: map[string]PerConnectorGuardrailConfig{
				"  ": {},
			}},
			wantErr: "empty connector name is not allowed",
		},
		{
			name: "valid_connector",
			cfg: GuardrailConfig{Connectors: map[string]PerConnectorGuardrailConfig{
				"codex": {Mode: "action", HookFailMode: "open", HILT: &HILTConfig{MinSeverity: "CRITICAL"}},
			}},
			wantErr: "",
		},
		{
			name: "duplicate_normalized_alias",
			cfg: GuardrailConfig{Connectors: map[string]PerConnectorGuardrailConfig{
				"openhands":  {Mode: "action"},
				"open-hands": {Mode: "observe"},
			}},
			wantErr: "refer to the same connector",
		},
		{
			name: "duplicate_normalized_case",
			cfg: GuardrailConfig{Connectors: map[string]PerConnectorGuardrailConfig{
				"codex": {Mode: "action"},
				"Codex": {Mode: "observe"},
			}},
			wantErr: "refer to the same connector",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.cfg.Validate()
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("Validate() = %v, want nil", err)
				}
				return
			}
			if err == nil || !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("Validate() = %v, want error containing %q", err, tt.wantErr)
			}
		})
	}
}

// TestResolversArePure is the DN4 tripwire: the five Effective*
// resolvers must be pure lookups — single return value (no error), and
// repeated calls must not mutate the receiver. We assert via reflection
// that none of them has a second (error) return and that the config is
// unchanged after invoking each.
func TestResolversArePure(t *testing.T) {
	g := &GuardrailConfig{
		Mode:        "observe",
		RulePackDir: "/x",
		HILT:        HILTConfig{MinSeverity: "HIGH"},
		Connectors: map[string]PerConnectorGuardrailConfig{
			"codex": {Mode: "action"},
		},
	}
	before := *g

	methods := []string{
		"EffectiveMode", "EffectiveHookFailModeFor",
		"EffectiveBlockMessage", "EffectiveRulePackDir", "EffectiveHILT",
	}
	v := reflect.ValueOf(g)
	for _, name := range methods {
		m := v.MethodByName(name)
		if !m.IsValid() {
			t.Fatalf("resolver %s not found", name)
		}
		mt := m.Type()
		if mt.NumOut() != 1 {
			t.Errorf("%s returns %d values, want 1 (pure lookup, no error)", name, mt.NumOut())
		}
		if mt.NumOut() == 1 && mt.Out(0).Name() == "error" {
			t.Errorf("%s returns an error; resolvers must be pure lookups", name)
		}
		// Invoke for both a known and unknown connector.
		m.Call([]reflect.Value{reflect.ValueOf("codex")})
		m.Call([]reflect.Value{reflect.ValueOf("nope")})
	}
	if !reflect.DeepEqual(before, *g) {
		t.Errorf("resolver call mutated GuardrailConfig: before=%+v after=%+v", before, *g)
	}
}
