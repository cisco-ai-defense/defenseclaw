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

func TestAIDiscoverySkillContentHashesDefaults(t *testing.T) {
	if !(AIDiscoveryConfig{}).EffectiveIncludeSkillContentHashes() {
		t.Fatal("zero-value AI discovery config must preserve skill content hashing")
	}
	if !DefaultConfig().AIDiscovery.EffectiveIncludeSkillContentHashes() {
		t.Fatal("default config must enable skill content hashing")
	}
}

func TestAIDiscoverySkillContentHashesLoad(t *testing.T) {
	for _, tc := range []struct {
		name, setting string
		want          bool
	}{
		{name: "omitted", want: true},
		{name: "enabled", setting: "  include_skill_content_hashes: true\n", want: true},
		{name: "disabled", setting: "  include_skill_content_hashes: false\n", want: false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", dir)
			path := filepath.Join(dir, DefaultConfigName)
			raw := "config_version: 9\nai_discovery:\n  enabled: true\n" + tc.setting
			if err := os.WriteFile(path, []byte(raw), 0o600); err != nil {
				t.Fatal(err)
			}
			cfg, err := LoadFromFile(path)
			if err != nil {
				t.Fatalf("LoadFromFile: %v", err)
			}
			if got := cfg.AIDiscovery.EffectiveIncludeSkillContentHashes(); got != tc.want {
				t.Errorf("include_skill_content_hashes = %t, want %t", got, tc.want)
			}
		})
	}
}

func TestAIDiscoverySkillContentHashesYAMLRoundTrip(t *testing.T) {
	for _, setting := range []string{"", "include_skill_content_hashes: true\n", "include_skill_content_hashes: false\n"} {
		t.Run(strings.TrimSpace(setting), func(t *testing.T) {
			var before, after AIDiscoveryConfig
			if err := yaml.Unmarshal([]byte(setting), &before); err != nil {
				t.Fatal(err)
			}
			raw, err := yaml.Marshal(before)
			if err != nil {
				t.Fatal(err)
			}
			if setting != "" && !strings.Contains(string(raw), setting) {
				t.Fatalf("explicit setting lost on save: %s", raw)
			}
			if err := yaml.Unmarshal(raw, &after); err != nil {
				t.Fatal(err)
			}
			if before.EffectiveIncludeSkillContentHashes() != after.EffectiveIncludeSkillContentHashes() ||
				(before.IncludeSkillContentHashes == nil) != (after.IncludeSkillContentHashes == nil) {
				t.Fatal("skill content hashing setting changed on YAML round trip")
			}
		})
	}
}

func TestAIDiscoverySkillContentHashesSchemaRejectsNonBoolean(t *testing.T) {
	for _, value := range []string{"\"false\"", "0", "null", "[]"} {
		t.Run(value, func(t *testing.T) {
			raw := "config_version: 9\nai_discovery:\n  include_skill_content_hashes: " + value + "\n"
			if err := ValidateV8SchemaBytes("config.yaml", []byte(raw)); err == nil {
				t.Fatalf("schema accepted non-boolean include_skill_content_hashes: %s", value)
			}
		})
	}
}
