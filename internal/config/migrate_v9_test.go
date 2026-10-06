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
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config/internal/cfgtxn"
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
    analyzers: auto,llm,prompt_defense
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
	// A pack installed in the folder v8 loaded implicitly.
	installedPack := filepath.Join(dir, "signature-packs", "custom.json")
	if err := os.MkdirAll(filepath.Dir(installedPack), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(installedPack, []byte(`{"version": 1, "signatures": []}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// init seeded the 1.0 admission.rego, which reads data.config.
	staleRego := filepath.Join(dir, "policies", "rego", "admission.rego")
	if err := os.WriteFile(staleRego, []byte("package defenseclaw.admission\n\nimport rego.v1\n\nverdict := \"allowed\" if data.config.scan_on_install == false\n"), 0o644); err != nil {
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
		"ai_discovery.signature_packs":                            []any{installedPack},
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
	if refreshed, _ := os.ReadFile(staleRego); v9LegacyRegoData.Match(refreshed) || !strings.Contains(string(refreshed), "input.admission") {
		t.Error("the pre-9 admission.rego was not replaced with the shipped module")
	}
	if _, err := os.Stat(staleRego + DataJSONMigratedSuffix); err != nil {
		t.Errorf("the pre-9 admission.rego was not kept: %v", err)
	}
	if _, err := os.Stat(MigrationRecordPath(configPath)); err != nil {
		t.Errorf("migration-v9.json missing: %v", err)
	}
	if !MigratedFrom(configPath, cfgtxn.SHA256Hex([]byte(source)), cfgtxn.SHA256Hex(migrated)) ||
		MigratedFrom(configPath, cfgtxn.SHA256Hex(migrated), cfgtxn.SHA256Hex(migrated)) {
		t.Error("MigratedFrom does not recognise the installed migration of the v8 source")
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

	// The edited copy keeps its folder's strict posture as a custom pack, so
	// a data.json HIGH, looser than its MEDIUM, must not become block_at.
	source = "config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  rule_pack_dir: " + edited + "\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataJSON, []byte(`{"guardrail": {"block_threshold": 3, "alert_threshold": 1}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err = MigrateV9(context.Background(), MigrateV9Input{
		ConfigPath: configPath, DataJSONPath: dataJSON, DryRun: true,
		RulePackDigest: func(string) (string, error) { return digest, nil },
	})
	if err != nil {
		t.Fatalf("MigrateV9 (custom strict copy): %v", err)
	}
	if strings.Contains(string(result.Migrated), "block_at") {
		t.Errorf("a data.json level looser than the custom strict pack became block_at:\n%s", result.Migrated)
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

// TestMigrateV8InMemory: the gateway runs an un-migrated v8 file as the
// migration would write it, reading data.json and writing nothing.
func TestMigrateV8InMemory(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	source := []byte("config_version: 8\ndata_dir: " + dir + "\nobservability: {}\n")
	dataJSON := filepath.Join(dir, "policies", "rego", "data.json")
	if err := os.MkdirAll(filepath.Dir(dataJSON), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataJSON, []byte(`{"actions": {"MEDIUM": {"install": "block", "file": "none", "runtime": "block"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	migrated, err := MigrateV8InMemory(configPath, source, nil)
	if err != nil {
		t.Fatalf("MigrateV8InMemory: %v", err)
	}
	if NeedsMigrationV9(migrated) || !strings.Contains(string(migrated), "medium: block") {
		t.Fatalf("migrated = %s", migrated)
	}
	if _, err := os.Stat(dataJSON); err != nil {
		t.Errorf("the in-memory migration touched data.json: %v", err)
	}
	if unchanged, err := MigrateV8InMemory(configPath, migrated, nil); err != nil || string(unchanged) != string(migrated) {
		t.Errorf("a config_version 9 source changed: %v", err)
	}

	// An inline VirusTotal key keeps working: the v9 document names its
	// variable, and the in-memory load sets it for this process.
	t.Setenv("VIRUSTOTAL_API_KEY", "")
	inline := []byte("config_version: 8\ndata_dir: " + dir + "\nscanners:\n  skill_scanner:\n    use_virustotal: true\n" +
		"    virustotal_api_key: vt-test-value\nobservability: {}\n")
	if _, err := MigrateV8InMemory(configPath, inline, nil); err != nil {
		t.Fatalf("MigrateV8InMemory(inline key): %v", err)
	}
	if got := os.Getenv("VIRUSTOTAL_API_KEY"); got != "vt-test-value" {
		t.Errorf("VIRUSTOTAL_API_KEY = %q after the in-memory load", got)
	}
}

// TestMigrateV9InlineKeyGoesToTheRuntimeDataDir: the inline VirusTotal key
// goes to the .env of the data_dir the runtime uses, and that data_dir's
// signature packs are listed: a "~/..." data_dir is under the home directory,
// and a DEFENSECLAW_CONFIG file outside an unset data_dir uses
// DEFENSECLAW_HOME, not the config's folder.
func TestMigrateV9InlineKeyGoesToTheRuntimeDataDir(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	dataDir := filepath.Join(home, ".dctest")
	if err := os.MkdirAll(filepath.Join(dataDir, "signature-packs"), 0o700); err != nil {
		t.Fatal(err)
	}
	pack := filepath.Join(dataDir, "signature-packs", "custom.json")
	if err := os.WriteFile(pack, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	inline := "scanners:\n  skill_scanner:\n    use_virustotal: true\n    virustotal_api_key: vt-test-value\nobservability: {}\n"
	for name, tc := range map[string]struct {
		configDir, dataDirKey string
		pinned                bool
	}{
		"tilde data_dir":               {configDir: dataDir, dataDirKey: "data_dir: ~/.dctest\n"},
		"DEFENSECLAW_CONFIG elsewhere": {configDir: filepath.Join(home, "srv"), pinned: true},
	} {
		t.Run(name, func(t *testing.T) {
			_ = os.Remove(filepath.Join(dataDir, ".env"))
			if err := os.MkdirAll(tc.configDir, 0o700); err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(tc.configDir, "config.yaml")
			t.Setenv("DEFENSECLAW_HOME", dataDir)
			t.Setenv("DEFENSECLAW_CONFIG", "")
			if tc.pinned {
				t.Setenv("DEFENSECLAW_CONFIG", configPath)
			}
			if err := os.WriteFile(configPath, []byte("config_version: 8\n"+tc.dataDirKey+inline), 0o600); err != nil {
				t.Fatal(err)
			}
			result, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath})
			if err != nil {
				t.Fatalf("MigrateV9: %v", err)
			}
			if env, err := os.ReadFile(filepath.Join(dataDir, ".env")); err != nil || !strings.Contains(string(env), "VIRUSTOTAL_API_KEY=vt-test-value") {
				t.Fatalf("data_dir .env = %q, %v", env, err)
			}
			if !strings.Contains(string(result.Migrated), pack) {
				t.Fatalf("signature pack %s not listed:\n%s", pack, result.Migrated)
			}
		})
	}
}

// TestMigrateV9ManagedToleratesAnUnreadableAuditDB: a managed host only
// counts the operator rows, so a corrupt audit.db does not fail the admin
// config's migration.
func TestMigrateV9ManagedToleratesAnUnreadableAuditDB(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	auditDB := filepath.Join(dir, "audit.db")
	if err := os.WriteFile(auditDB, []byte("not a database"), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := MigrateV9(context.Background(), MigrateV9Input{
		ConfigPath: filepath.Join(dir, "config.yaml"), Source: []byte("config_version: 8\nobservability: {}\n"),
		AuditDBPath: auditDB, Managed: true, InMemory: true,
	})
	if err != nil {
		t.Fatalf("MigrateV9: %v", err)
	}
	if notes := strings.Join(result.Record.Notes, "\n"); !strings.Contains(notes, LocalEnforcementEntriesIgnored) {
		t.Fatalf("notes = %q", notes)
	}
}

// TestMigrateV9ReportsAStricterProxyThreshold: block_at set in config wins,
// but the stricter data.json level the LLM proxy used is a recorded conflict.
func TestMigrateV9ReportsAStricterProxyThreshold(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	source := "config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  block_at: HIGH\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	dataJSON := filepath.Join(dir, "data.json")
	if err := os.WriteFile(dataJSON, []byte(`{"guardrail": {"block_threshold": 2}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath, DataJSONPath: dataJSON, DryRun: true})
	if err != nil {
		t.Fatalf("MigrateV9: %v", err)
	}
	if !strings.Contains(string(result.Migrated), "block_at: HIGH") || len(result.Record.Conflicts) != 1 ||
		result.Record.Conflicts[0].To != "guardrail.block_at" || !strings.HasSuffix(result.Record.Conflicts[0].Lost, ":MEDIUM") {
		t.Fatalf("conflicts = %+v\n%s", result.Record.Conflicts, result.Migrated)
	}
}

// TestMigrateV9DropsTheKeysTheRuntimeNoLongerHas: a 0.8.10-shaped v8 file with
// every key only an upgrade still understands (the three *_actions maps,
// update_check and the privacy: section) migrates to its v9 equivalent or is
// reported as dropped, and the same keys in a v9 file are plain unknown keys.
// The 0.x environment inputs (DEFENSECLAW_PERSIST_JUDGE,
// DEFENSECLAW_DISABLE_REDACTION) are read by the 0.x conversion in
// cli/defenseclaw/observability/v8_migration.py, which has its own tests.
func TestMigrateV9DropsTheKeysTheRuntimeNoLongerHas(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	source := "config_version: 8\ndata_dir: " + dir + `
update_check: false
privacy:
  disable_redaction: true
skill_actions:
  high: {file: none, runtime: enable, install: block}
mcp_actions:
  critical: {file: none, runtime: enable, install: none}
  medium: {file: none, runtime: enable, install: block}
plugin_actions:
  critical: {file: quarantine, runtime: disable, install: block}
observability: {}
`
	dataJSON := filepath.Join(dir, "data.json")
	if err := os.WriteFile(dataJSON, []byte(`{}`), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := MigrateV9(context.Background(), MigrateV9Input{
		ConfigPath: configPath, Source: []byte(source), DataJSONPath: dataJSON, DryRun: true,
	})
	if err != nil {
		t.Fatalf("MigrateV9: %v", err)
	}
	var doc map[string]any
	if err := yaml.Unmarshal(result.Migrated, &doc); err != nil {
		t.Fatal(err)
	}
	notes := strings.Join(result.Record.Notes, "\n")
	var wantConflicts []string
	for _, row := range []struct {
		key       string
		moved     string   // v9 key that carries the value, "" when dropped
		removed   string   // entry in the report's removed list, "" when moved
		conflicts []string // customised levels that data.json overrode
		note      string
	}{
		{key: "skill_actions", removed: "skill_actions", conflicts: []string{"admission.skill.actions.high"}},
		{key: "mcp_actions", removed: "mcp_actions",
			conflicts: []string{"admission.mcp.actions.critical", "admission.mcp.actions.medium"}},
		// Equal to what data.json enforced: nothing to report beyond the drop.
		{key: "plugin_actions", removed: "plugin_actions"},
		{key: "update_check", moved: "update.check"},
		{key: "privacy", removed: "privacy.disable_redaction", note: "privacy.disable_redaction"},
	} {
		if _, kept := doc[row.key]; kept {
			t.Errorf("%s is still in the migrated config", row.key)
		}
		if row.removed != "" && !slices.Contains(result.Record.Removed, row.removed) {
			t.Errorf("%s: removed = %v, want %s", row.key, result.Record.Removed, row.removed)
		}
		if row.moved != "" && !slices.ContainsFunc(result.Record.Moved, func(m MigrationMove) bool {
			return m.From == row.key && m.To == row.moved
		}) {
			t.Errorf("%s: moved = %+v, want %s", row.key, result.Record.Moved, row.moved)
		}
		if row.note != "" && !strings.Contains(notes, row.note) {
			t.Errorf("%s: notes = %q", row.key, notes)
		}
		wantConflicts = append(wantConflicts, row.conflicts...)

		// In a v9 file the key has no special handling: it is an unknown key.
		v9 := "config_version: 9\n" + row.key + ": {}\nobservability: {}\n"
		if err := ValidateCandidate(configPath, []byte(v9)); err == nil || !strings.Contains(err.Error(), row.key) {
			t.Errorf("%s in a v9 file: got %v, want an unknown-key error naming it", row.key, err)
		}
	}
	if update, _ := doc["update"].(map[string]any); update["check"] != false {
		t.Errorf("update = %v, want check: false", doc["update"])
	}
	var gotConflicts []string
	for _, c := range result.Record.Conflicts {
		gotConflicts = append(gotConflicts, c.To)
	}
	if !slices.Equal(gotConflicts, wantConflicts) {
		t.Errorf("conflicts = %v, want %v", gotConflicts, wantConflicts)
	}
}
