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
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

// GAP-1490: seeding a missing shipped pack staged it in the fixed sibling
// <dir>.seeding and removed that folder first, even when it held the
// operator's own files.
func TestSeedShippedRulePackKeepsAnExistingStagingSibling(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "policies", "guardrail", "default")
	marker := filepath.Join(dir+".seeding", "rules", "team.yaml")
	if err := os.MkdirAll(filepath.Dir(marker), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := seedShippedRulePack(dir, "default"); err != nil {
		t.Fatalf("seedShippedRulePack: %v", err)
	}
	if got, err := os.ReadFile(marker); err != nil || string(got) != "keep" {
		t.Fatalf("the existing %s.seeding folder was changed: %q, %v", dir, got, err)
	}
	if entries, err := os.ReadDir(dir); err != nil || len(entries) == 0 {
		t.Fatalf("seeded pack %s: %v (%d entries), want the shipped pack", dir, err, len(entries))
	}
	siblings, err := filepath.Glob(dir + ".seeding-*")
	if err != nil || len(siblings) != 0 {
		t.Fatalf("staging folders left behind: %v (%v)", siblings, err)
	}
}

// GAP-1490 through the upgrade: a custom pack the v8 config selects at
// <data_dir>/policies/guardrail/default.seeding stays pinned and on disk
// while the migration seeds the missing default pack beside it.
func TestMigrateV9SeedingKeepsTheSelectedCustomPack(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dir)
	custom := filepath.Join(dir, "policies", "guardrail", "default.seeding")
	rule := filepath.Join(custom, "rules", "team.yaml")
	if err := os.MkdirAll(filepath.Dir(rule), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(rule, []byte("rules: []\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	source := "config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  rule_pack_dir: " + custom + "\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := MigrateV9(context.Background(), MigrateV9Input{
		ConfigPath:     configPath,
		RulePackDigest: func(string) (string, error) { return strings.Repeat("a", 64), nil },
	})
	if err != nil {
		t.Fatalf("MigrateV9: %v", err)
	}
	var got struct {
		Guardrail struct {
			RulePack    string `yaml:"rule_pack"`
			CustomPacks map[string]struct {
				Path string `yaml:"path"`
			} `yaml:"custom_packs"`
		} `yaml:"guardrail"`
	}
	if err := yaml.Unmarshal(result.Migrated, &got); err != nil {
		t.Fatal(err)
	}
	if pinned := got.Guardrail.CustomPacks[got.Guardrail.RulePack].Path; pinned != custom {
		t.Fatalf("rule_pack %q pins %q, want %s:\n%s", got.Guardrail.RulePack, pinned, custom, result.Migrated)
	}
	if raw, err := os.ReadFile(rule); err != nil || string(raw) != "rules: []\n" {
		t.Fatalf("the selected custom pack lost %s: %q, %v", rule, raw, err)
	}
	pack := filepath.Join(dir, "policies", "guardrail", "default")
	if entries, err := os.ReadDir(pack); err != nil || len(entries) == 0 {
		t.Fatalf("default pack after the migration: %v (%d entries), want the shipped pack", err, len(entries))
	}
}
