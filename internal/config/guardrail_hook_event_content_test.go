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
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// rel-1-0-10:GAP-2161: guardrail.include_hook_event_content is an opt-in,
// off when config.yaml omits it, like the inventory content opt-ins.
func TestGuardrailIncludeHookEventContentLoad(t *testing.T) {
	if DefaultConfig().Guardrail.IncludeHookEventContent {
		t.Fatal("default config must not export hook event content")
	}
	for _, tc := range []struct {
		name, setting string
		want          bool
	}{
		{name: "omitted", want: false},
		{name: "enabled", setting: "  include_hook_event_content: true\n", want: true},
		{name: "disabled", setting: "  include_hook_event_content: false\n", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", dir)
			path := filepath.Join(dir, DefaultConfigName)
			raw := "config_version: 9\nguardrail:\n  enabled: true\n" + tc.setting
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			if err := ValidateV8SchemaBytes("config.yaml", []byte(raw)); err != nil {
				t.Fatalf("schema refused %q: %v", tc.setting, err)
			}
			cfg, err := LoadFromFile(path)
			if err != nil {
				t.Fatalf("LoadFromFile: %v", err)
			}
			if got := cfg.Guardrail.IncludeHookEventContent; got != tc.want {
				t.Fatalf("include_hook_event_content = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestGuardrailIncludeHookEventContentSavesOnlyWhenOn(t *testing.T) {
	for _, on := range []bool{false, true} {
		raw, err := yaml.Marshal(GuardrailConfig{IncludeHookEventContent: on})
		if err != nil {
			t.Fatal(err)
		}
		if got := strings.Contains(string(raw), "include_hook_event_content: true"); got != on {
			t.Fatalf("on=%t: saved guardrail block %q", on, raw)
		}
		if !on && strings.Contains(string(raw), "include_hook_event_content") {
			t.Fatalf("default value written on save: %q", raw)
		}
	}
}

func TestGuardrailIncludeHookEventContentSchemaRejectsNonBoolean(t *testing.T) {
	for _, value := range []string{"\"true\"", "1", "null", "[]"} {
		t.Run(value, func(t *testing.T) {
			raw := "config_version: 9\nguardrail:\n  include_hook_event_content: " + value + "\n"
			if err := ValidateV8SchemaBytes("config.yaml", []byte(raw)); err == nil {
				t.Fatalf("schema accepted non-boolean include_hook_event_content: %s", value)
			}
		})
	}
}
