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
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// TestGuardrailLevelResolvers pins the block_at / alert_at precedence the
// gateway and the Python catalog both implement: the connector's own value,
// else the global value, else "" (the rule pack decides). Values come back
// canonical uppercase, and anything Validate would reject counts as unset.
func TestGuardrailLevelResolvers(t *testing.T) {
	g := &GuardrailConfig{
		BlockAt: "high",
		AlertAt: " Low ",
		Connectors: map[string]PerConnectorGuardrailConfig{
			"codex":       {BlockAt: "Critical", AlertAt: "MEDIUM"},
			"claude-code": {BlockAt: "medium"},
			"antigravity": {},
			"cursor":      {BlockAt: "SEVERE", AlertAt: "INFO"},
		},
	}
	tests := []struct {
		name      string
		g         *GuardrailConfig
		connector string
		wantBlock string
		wantAlert string
	}{
		{"nil config", nil, "codex", "", ""},
		{"nothing set", &GuardrailConfig{}, "codex", "", ""},
		{"global scope", g, "", "HIGH", "LOW"},
		{"connector values win", g, "codex", "CRITICAL", "MEDIUM"},
		{"alias key, alert inherited", g, "claudecode", "MEDIUM", "LOW"},
		{"empty override inherits", g, "antigravity", "HIGH", "LOW"},
		{"no override inherits", g, "opencode", "HIGH", "LOW"},
		{"invalid override falls back", g, "cursor", "HIGH", "LOW"},
		{"invalid global is unset", &GuardrailConfig{BlockAt: "severe", AlertAt: "none"}, "", "", ""},
		// The config layer never clamps; the gateway clamps alert to block
		// after resolving both against the rule pack.
		{"no clamp here", &GuardrailConfig{BlockAt: "LOW", AlertAt: "HIGH"}, "", "LOW", "HIGH"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.g.EffectiveBlockAt(tt.connector); got != tt.wantBlock {
				t.Errorf("EffectiveBlockAt(%q) = %q, want %q", tt.connector, got, tt.wantBlock)
			}
			if got := tt.g.EffectiveAlertAt(tt.connector); got != tt.wantAlert {
				t.Errorf("EffectiveAlertAt(%q) = %q, want %q", tt.connector, got, tt.wantAlert)
			}
		})
	}

	before := GuardrailConfig{BlockAt: g.BlockAt, AlertAt: g.AlertAt, Connectors: map[string]PerConnectorGuardrailConfig{}}
	for name, pc := range g.Connectors {
		before.Connectors[name] = pc
	}
	_ = g.EffectiveBlockAt("codex")
	_ = g.EffectiveAlertAt("claudecode")
	if !reflect.DeepEqual(*g, before) {
		t.Fatalf("level resolvers mutated the config:\n got %#v\nwant %#v", *g, before)
	}
}

// TestGuardrailValidateLevels covers the new value checks: the global pair
// and every per-connector override accept the four levels in any case (or
// empty) and reject anything else with a message naming the key.
func TestGuardrailValidateLevels(t *testing.T) {
	const levels = "must be one of CRITICAL, HIGH, MEDIUM, LOW"
	tests := []struct {
		name    string
		cfg     GuardrailConfig
		wantErr string // substring; "" = expect success
	}{
		{"empty ok", GuardrailConfig{}, ""},
		{"any case ok", GuardrailConfig{BlockAt: "high", AlertAt: "Low", Connectors: map[string]PerConnectorGuardrailConfig{
			"codex": {BlockAt: "CRITICAL", AlertAt: "medium"},
		}}, ""},
		{"global block_at", GuardrailConfig{BlockAt: "SEVERE"}, "guardrail.block_at: " + levels + ` (got "SEVERE")`},
		{"global alert_at", GuardrailConfig{AlertAt: "INFO"}, "guardrail.alert_at: " + levels},
		{"connector block_at", GuardrailConfig{Connectors: map[string]PerConnectorGuardrailConfig{
			"codex": {BlockAt: "none"},
		}}, `guardrail.connectors["codex"]: block_at: ` + levels},
		{"connector alert_at", GuardrailConfig{Connectors: map[string]PerConnectorGuardrailConfig{
			"codex": {AlertAt: "3"},
		}}, `guardrail.connectors["codex"]: alert_at: ` + levels},
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

// TestApplicationProtectionRejectsGuardrailLevels pins that the
// application_protection overlays, which share PerConnectorGuardrailConfig,
// refuse block_at / alert_at instead of silently ignoring them: the gateway
// reads the levels only from guardrail.* and guardrail.connectors.
func TestApplicationProtectionRejectsGuardrailLevels(t *testing.T) {
	base := DefaultApplicationProtectionConfig()
	if err := base.Validate(); err != nil {
		t.Fatalf("default application_protection invalid: %v", err)
	}

	global := DefaultApplicationProtectionConfig()
	global.Guardrail.BlockAt = "HIGH"
	if err := global.Validate(); err == nil ||
		!strings.Contains(err.Error(), "application_protection.guardrail: block_at is not supported") {
		t.Fatalf("overlay block_at: Validate() = %v", err)
	}

	scoped := DefaultApplicationProtectionConfig()
	scoped.Connectors = map[string]ApplicationProtectionConnectorConfig{
		"codex": {Guardrail: PerConnectorGuardrailConfig{AlertAt: "LOW"}},
	}
	if err := scoped.Validate(); err == nil ||
		!strings.Contains(err.Error(), `application_protection.connectors["codex"].guardrail: alert_at is not supported`) {
		t.Fatalf("connector overlay alert_at: Validate() = %v", err)
	}
}

// TestGuardrailLevelsLoadFromV8Config drives the new keys through the paths
// the gateway uses on boot and reload: the v8 compile step (which enforces the
// closed schema) accepts the levels in any case at both scopes, and the
// activation and reload-candidate loaders keep them through both decoders
// (Viper for the global block, YAML for guardrail.connectors).
func TestGuardrailLevelsLoadFromV8Config(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("DEFENSECLAW_HOME", filepath.Join(home, ".defenseclaw"))
	dataDir := filepath.Join(home, "state")
	raw := []byte(`config_version: 8
data_dir: ` + dataDir + `
guardrail:
  enabled: true
  mode: action
  block_at: high
  alert_at: LOW
  connectors:
    codex:
      block_at: Critical
    claudecode:
      alert_at: medium
observability: {}
`)
	if _, err := ParseCompileObservabilityV8("config.yaml", raw, ObservabilityV8CompileOptions{DefaultDataDir: dataDir}); err != nil {
		t.Fatalf("v8 schema/compile rejected the levels: %v", err)
	}
	loaders := map[string]func() (*Config, error){
		"activation": func() (*Config, error) { return LoadRuntimeV8FromBytes("config.yaml", raw) },
		"candidate":  func() (*Config, error) { return LoadRuntimeV8CandidateFromBytes("config.yaml", raw) },
	}
	for name, load := range loaders {
		t.Run(name, func(t *testing.T) {
			cfg, err := load()
			if err != nil {
				t.Fatal(err)
			}
			g := &cfg.Guardrail
			for _, c := range []struct{ connector, block, alert string }{
				{"", "HIGH", "LOW"},
				{"codex", "CRITICAL", "LOW"},
				{"claudecode", "HIGH", "MEDIUM"},
			} {
				if got := g.EffectiveBlockAt(c.connector); got != c.block {
					t.Errorf("EffectiveBlockAt(%q) = %q, want %q", c.connector, got, c.block)
				}
				if got := g.EffectiveAlertAt(c.connector); got != c.alert {
					t.Errorf("EffectiveAlertAt(%q) = %q, want %q", c.connector, got, c.alert)
				}
			}
		})
	}
}

// TestGuardrailLevelsRejectedBySchema pins that the closed v8 schema, which
// the gateway's boot and reload compile step enforces, rejects a value outside
// the four levels at both scopes, while the same document with a valid level
// compiles.
func TestGuardrailLevelsRejectedBySchema(t *testing.T) {
	options := ObservabilityV8CompileOptions{DefaultDataDir: filepath.Join(t.TempDir(), "state")}
	tests := []struct {
		name, block, path string
	}{
		{"global", "guardrail:\n  block_at: %s\n", "guardrail.block_at"},
		{"per-connector", "guardrail:\n  connectors:\n    codex:\n      alert_at: %s\n", "guardrail.connectors.codex.alert_at"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc := func(level string) []byte {
				return []byte("config_version: 8\n" + strings.Replace(tt.block, "%s", level, 1))
			}
			if _, err := ParseCompileObservabilityV8("config.yaml", doc("medium"), options); err != nil {
				t.Fatalf("valid level rejected: %v", err)
			}
			for _, bad := range []string{"SEVERE", "INFO", `" HIGH"`} {
				_, err := ParseCompileObservabilityV8("config.yaml", doc(bad), options)
				if err == nil || !strings.Contains(err.Error(), "[config_schema_invalid]") ||
					!strings.Contains(err.Error(), tt.path) {
					t.Fatalf("level %s: compile = %v, want a config_schema_invalid error at %s", bad, err, tt.path)
				}
			}
		})
	}
}

// TestGuardrailLevelsValidatedOnLoad pins that LoadFromFile runs the new checks on
// a path the v8 schema doesn't cover (a v7 file), so a bad level can't reach
// the gateway through it either.
func TestGuardrailLevelsValidatedOnLoad(t *testing.T) {
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("DEFENSECLAW_HOME", filepath.Join(home, ".defenseclaw"))
	path := filepath.Join(home, DefaultConfigName)
	raw := []byte("config_version: 7\ndata_dir: " + home + "\nguardrail:\n  block_at: severe\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := LoadFromFile(path)
	if err == nil || !strings.Contains(err.Error(), "guardrail.block_at: must be one of CRITICAL, HIGH, MEDIUM, LOW") {
		t.Fatalf("LoadFromFile = %v, want the guardrail.block_at error", err)
	}
}

// TestGuardrailLevelsYAMLRoundTrip pins the tags: both scopes marshal under
// block_at / alert_at and are omitted when empty, so writing a config that
// never set them doesn't add the keys.
func TestGuardrailLevelsYAMLRoundTrip(t *testing.T) {
	in := GuardrailConfig{
		BlockAt: "HIGH",
		AlertAt: "LOW",
		Connectors: map[string]PerConnectorGuardrailConfig{
			"codex": {BlockAt: "CRITICAL", AlertAt: "MEDIUM"},
		},
	}
	out, err := yaml.Marshal(in)
	if err != nil {
		t.Fatal(err)
	}
	var back GuardrailConfig
	if err := yaml.Unmarshal(out, &back); err != nil {
		t.Fatal(err)
	}
	if back.BlockAt != "HIGH" || back.AlertAt != "LOW" ||
		back.Connectors["codex"].BlockAt != "CRITICAL" || back.Connectors["codex"].AlertAt != "MEDIUM" {
		t.Fatalf("round trip lost the levels:\n%s", out)
	}

	empty, err := yaml.Marshal(GuardrailConfig{Connectors: map[string]PerConnectorGuardrailConfig{"codex": {Mode: "action"}}})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(empty), "block_at") || strings.Contains(string(empty), "alert_at") {
		t.Fatalf("empty levels were written:\n%s", empty)
	}
}
