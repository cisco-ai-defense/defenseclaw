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
	"database/sql"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

func TestMigrateV9MovesEveryV8Source(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	source := "config_version: 8\ndata_dir: " + dir + "\n" + `# keep this comment
update_check: false
skill_actions:
  high: {file: none, runtime: enable, install: block}
watch:
  allow_list_bypass_scan: true
guardrail:
  rule_pack_dir: ` + filepath.Join(dir, "policies", "guardrail", "strict") + `
scanners:
  skill_scanner:
    binary: skill-scanner
    use_virustotal: true
    virustotal_api_key_env: VT_KEY
  mcp_scanner:
    analyzers: auto,llm
observability: {}
`
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	dataJSON := filepath.Join(dir, "policies", "rego", "data.json")
	if err := os.MkdirAll(filepath.Dir(dataJSON), 0o700); err != nil {
		t.Fatal(err)
	}
	// scan_on_install is absent: v8 scanned. block_threshold 3 is looser than
	// the strict pack's MEDIUM, which governed the hook paths.
	data := `{"config": {"allow_list_bypass_scan": false, "policy_name": "x"},
	  "actions": {"HIGH": {"install": "none", "file": "none", "runtime": "allow"}},
	  "guardrail": {"block_threshold": 3, "alert_threshold": 1}}`
	if err := os.WriteFile(dataJSON, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
	auditDB := filepath.Join(dir, "audit.db")
	db, err := sql.Open("sqlite", auditDB)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE actions (id TEXT PRIMARY KEY, target_type TEXT NOT NULL, target_name TEXT NOT NULL,
		  source_path TEXT, actions_json TEXT NOT NULL DEFAULT '{}', reason TEXT, updated_at DATETIME NOT NULL,
		  connector TEXT NOT NULL DEFAULT '')`,
		`INSERT INTO actions VALUES ('1','skill','bad-skill','/s/bad','{"install":"block"}','operator','now','')`,
		`INSERT INTO actions VALUES ('2','tool','@codex/rm','','{"install":"block"}','','now','')`,
		`INSERT INTO actions VALUES ('3','skill','scanned','','{"install":"block","file":"quarantine"}','auto-block: watch detected HIGH findings','now','')`,
		`INSERT INTO actions VALUES ('4','skill','post','','{"install":"block"}','post-scan: 2 findings, max=HIGH','now','')`,
		`INSERT INTO actions VALUES ('5','mcp','fs','','{"install":"allow"}','scan clean or within policy','now','codex')`,
		`INSERT INTO actions VALUES ('6','plugin','ok','/p/ok','{"install":"allow"}','operator','now','')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	_ = db.Close()

	in := MigrateV9Input{ConfigPath: configPath, DataJSONPath: dataJSON, AuditDBPath: auditDB}
	dry := in
	dry.DryRun = true
	if _, err := MigrateV9(context.Background(), dry); err != nil {
		t.Fatalf("dry run: %v", err)
	}
	if raw, _ := os.ReadFile(configPath); string(raw) != source {
		t.Fatal("the dry run changed config.yaml")
	}

	result, err := MigrateV9(context.Background(), in)
	if err != nil {
		t.Fatalf("MigrateV9: %v", err)
	}
	migrated, _ := os.ReadFile(configPath)
	var doc map[string]any
	if err := yaml.Unmarshal(migrated, &doc); err != nil {
		t.Fatal(err)
	}
	get := func(path string) any {
		var cur any = doc
		for _, key := range strings.Split(path, ".") {
			m, _ := cur.(map[string]any)
			cur = m[key]
		}
		return cur
	}
	for path, want := range map[string]any{
		"config_version": 9,
		"update.check":   false,
		"admission.defaults.allow_list_bypass_scan":               false,
		"admission.skill.actions.high":                            "warn",
		"admission.skill.actions.critical":                        "quarantine",
		"guardrail.rule_pack":                                     "strict",
		"guardrail.block_at":                                      nil,
		"admission.defaults.scan_on_install":                      nil,
		"scanners.skill_scanner.analyzers.virustotal.enabled":     true,
		"scanners.skill_scanner.analyzers.virustotal.api_key_env": "VT_KEY",
		"asset_policy.skill.denied":                               []any{map[string]any{"name": "bad-skill", "reason": "operator"}},
		"asset_policy.plugin.allowed":                             []any{map[string]any{"name": "ok", "reason": "operator", "source_path_contains": []any{"/p/ok"}}},
		"asset_policy.mcp":                                        nil,
		"asset_policy.tool.denied":                                []any{map[string]any{"name": "rm", "connector": "codex"}},
	} {
		if got, _ := json.Marshal(get(path)); string(got) != mustJSON(t, want) {
			t.Errorf("%s = %s, want %s", path, got, mustJSON(t, want))
		}
	}
	if got := get("scanners.mcp_scanner.analyzers"); mustJSON(t, got) != `["yara","llm"]` {
		t.Errorf("mcp analyzers = %v", got)
	}
	for _, removed := range []string{"skill_actions", "update_check", "rule_pack_dir", "binary:", "use_virustotal", "watch:"} {
		if strings.Contains(string(migrated), removed) {
			t.Errorf("migrated config still has %s", removed)
		}
	}
	if !strings.Contains(string(migrated), "# keep this comment") {
		t.Error("the migration dropped a comment")
	}
	// strict posture is block MEDIUM / alert LOW: alert_threshold 1 matches.
	if get("guardrail.alert_at") != nil {
		t.Error("alert_at was written although data.json matched the pack default")
	}
	if len(result.Record.Conflicts) != 2 || result.Record.Conflicts[0].To != "admission.skill.actions.high" ||
		result.Record.Conflicts[1].To != "guardrail.block_at" {
		t.Errorf("conflicts = %+v", result.Record.Conflicts)
	}
	if result.Record.ActionsRowsMoved != 3 {
		t.Errorf("actions rows moved = %d, want 3", result.Record.ActionsRowsMoved)
	}
	if backup, _ := os.ReadFile(configPath + ConfigV8BackupSuffix); string(backup) != source {
		t.Error("config.yaml.v8.bak does not hold the v8 bytes")
	}
	if _, err := os.Stat(dataJSON + DataJSONMigratedSuffix); err != nil {
		t.Errorf("data.json was not renamed: %v", err)
	}
	if _, err := os.Stat(MigrationRecordPath(configPath)); err != nil {
		t.Errorf("migration-v9.json missing: %v", err)
	}
	db, _ = sql.Open("sqlite", auditDB)
	defer db.Close()
	var left int
	if err := db.QueryRow(`SELECT COUNT(*) FROM actions`).Scan(&left); err != nil || left != 3 {
		t.Errorf("actions rows left = %d (%v), want the three scan verdicts", left, err)
	}
	if again, err := MigrateV9(context.Background(), in); err != nil || len(again.Written) != 0 {
		t.Errorf("a second run = %+v, %v; want a no-op", again, err)
	}
}

func mustJSON(t *testing.T, value any) string {
	t.Helper()
	raw, err := json.Marshal(value)
	if err != nil {
		t.Fatal(err)
	}
	return string(raw)
}

// TestMigrateV9KeepsThePackPosture: selecting the strict pack in v8 left the
// shipped data.json thresholds alone, so they must not override the strict
// posture the hook paths used; and a strict-named pack outside
// <policy_dir>/guardrail is an edited copy, not the preset.
func TestMigrateV9KeepsThePackPosture(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	edited := filepath.Join(dir, "elsewhere", "guardrail", "strict")
	source := "config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  rule_pack_dir: " +
		filepath.Join(dir, "policies", "guardrail", "strict") + "\n  connectors:\n    codex:\n      rule_pack_dir: " +
		edited + "\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	dataJSON := filepath.Join(dir, "policies", "rego", "data.json")
	if err := os.MkdirAll(filepath.Dir(dataJSON), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataJSON, []byte(`{"guardrail": {"block_threshold": 4, "alert_threshold": 2}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("a", 64)
	result, err := MigrateV9(context.Background(), MigrateV9Input{
		ConfigPath: configPath, DataJSONPath: dataJSON, DryRun: true,
		RulePackDigest: func(string) (string, error) { return digest, nil },
	})
	if err != nil {
		t.Fatalf("MigrateV9: %v", err)
	}
	var doc struct {
		Guardrail struct {
			RulePack    string `yaml:"rule_pack"`
			BlockAt     string `yaml:"block_at"`
			AlertAt     string `yaml:"alert_at"`
			CustomPacks map[string]struct {
				Path string `yaml:"path"`
			} `yaml:"custom_packs"`
			Connectors map[string]struct {
				RulePack string `yaml:"rule_pack"`
			} `yaml:"connectors"`
		} `yaml:"guardrail"`
	}
	if err := yaml.Unmarshal(result.Migrated, &doc); err != nil {
		t.Fatal(err)
	}
	g := doc.Guardrail
	if g.RulePack != "strict" || g.BlockAt != "" || g.AlertAt != "" {
		t.Errorf("guardrail = rule_pack %q block_at %q alert_at %q; want strict with the pack posture", g.RulePack, g.BlockAt, g.AlertAt)
	}
	codex := g.Connectors["codex"].RulePack
	if codex == "strict" || g.CustomPacks[codex].Path != edited {
		t.Errorf("codex rule_pack = %q (custom_packs %+v); want a custom pack for %s", codex, g.CustomPacks, edited)
	}
}

func TestV9SecureClientDocumentKeepsRows(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	for source, want := range map[string]bool{
		"deployment_mode: managed_enterprise\nenterprise: {profile: secure_client}\n": true,
		"deployment_mode: managed_enterprise\nenterprise: {profile: standalone}\n":    false,
		"config_version: 8\n": false,
	} {
		var doc yaml.Node
		if err := yaml.Unmarshal([]byte(source), &doc); err != nil {
			t.Fatal(err)
		}
		if got := v9SecureClientDocument(v8DocumentRoot(&doc)); got != want {
			t.Errorf("v9SecureClientDocument(%q) = %v, want %v", source, got, want)
		}
	}
}
