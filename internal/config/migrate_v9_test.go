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
	"crypto/sha256"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"
	"time"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config/internal/cfgtxn"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func TestMigrateV9NormalizesCursorActionFailMode(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	source := []byte("config_version: 8\ndata_dir: " + dir +
		"\nguardrail:\n  connector: cursor\n  mode: action\n  hook_fail_mode: open" +
		"\n  rule_pack_dir: \"\"\n  connectors:\n    cursor:" +
		"\n      mode: action\n      hook_fail_mode: open\nobservability: {}\n")
	migrated, err := MigrateV8InMemory(configPath, source, nil)
	if err != nil {
		t.Fatal(err)
	}
	var doc yaml.Node
	if err := yaml.Unmarshal(migrated, &doc); err != nil {
		t.Fatal(err)
	}
	root := v8DocumentRoot(&doc)
	stored := v8YAMLMapValue(v8YAMLMapValue(v8YAMLMapValue(root, "guardrail"), "connectors"), "cursor")
	if got := yamlScalarValue(v8YAMLMapValue(stored, "hook_fail_mode")); got != "closed" {
		t.Fatalf("migrated Cursor hook fail mode = %q, want closed", got)
	}
	cfg := &Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.HookFailMode = "open"
	cfg.Guardrail.Connectors = map[string]PerConnectorGuardrailConfig{"cursor": {Mode: "action", HookFailMode: "open"}}
	if got := cfg.EffectiveHookFailModeForConnector("cursor"); got != "closed" {
		t.Fatalf("effective Cursor action fail mode = %q, want closed", got)
	}
}

// An unreadable custom scanner policy must leave the v8 source intact so an
// upgrade can retry after access to the policy is restored.
func TestMigrateV9RetriesUnreadableCustomScannerPolicy(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dir)
	configPath := filepath.Join(dir, "config.yaml")
	policyPath := filepath.Join(dir, "custom-skill-policy.yaml")
	source := "config_version: 8\ndata_dir: " + dir + "\nscanners:\n  skill_scanner:\n    policy: " + policyPath + "\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	// A directory at the policy path gives a read error on every OS, even
	// when the test runs with elevated privileges.
	if err := os.Mkdir(policyPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath}); err == nil {
		t.Fatal("migration succeeded without reading the custom policy")
	}
	if got, err := os.ReadFile(configPath); err != nil || string(got) != source {
		t.Fatalf("v8 config after failed migration = %q (%v)", got, err)
	}
	if _, err := os.Stat(configPath + ConfigV8BackupSuffix); !os.IsNotExist(err) {
		t.Errorf("failed migration wrote a backup: %v", err)
	}
	if _, err := os.Stat(MigrationRecordPath(configPath)); !os.IsNotExist(err) {
		t.Errorf("failed migration wrote a record: %v", err)
	}

	if err := os.Remove(policyPath); err != nil {
		t.Fatal(err)
	}
	policy := []byte("rules: []\n")
	if err := os.WriteFile(policyPath, policy, 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("migration after policy access restored: %v", err)
	}
	if !strings.Contains(string(result.Migrated), "policy: custom") ||
		!strings.Contains(string(result.Migrated), "path: "+policyPath) ||
		!strings.Contains(string(result.Migrated), "sha256:"+cfgtxn.SHA256Hex(policy)) {
		t.Errorf("custom policy was not pinned on retry: %s", result.Migrated)
	}
}

// The installer snapshots only config.yaml when DEFENSECLAW_CONFIG is outside
// the data home. Its neighboring policy and audit files must keep their v8
// state so restoring config.yaml leaves rollback enforcement intact.
func TestMigrateV9LeavesPolicyDataOutsideTheRollbackCopy(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	home, elsewhere := t.TempDir(), t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	configPath := filepath.Join(elsewhere, "config.yaml")
	t.Setenv("DEFENSECLAW_CONFIG", configPath)
	source := "config_version: 8\ndata_dir: " + elsewhere + "\npolicy_dir: " + filepath.Join(elsewhere, "policies") +
		"\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	dataJSON := filepath.Join(elsewhere, "policies", "rego", "data.json")
	if err := os.MkdirAll(filepath.Dir(dataJSON), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataJSON, []byte(`{"actions": {"HIGH": {"install": "none", "file": "none", "runtime": "allow"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	auditDB := filepath.Join(elsewhere, "audit.db")
	db, err := sql.Open("sqlite", auditDB)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE actions (id TEXT PRIMARY KEY, target_type TEXT NOT NULL, target_name TEXT NOT NULL,
		  source_path TEXT, actions_json TEXT NOT NULL DEFAULT '{}', reason TEXT, updated_at DATETIME NOT NULL,
		  connector TEXT NOT NULL DEFAULT '')`,
		`INSERT INTO actions VALUES ('1','skill','bad-skill','','{"install":"block"}','operator','now','')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	_ = db.Close()
	// The 0.8 gateway a rollback restores still loads its Rego modules,
	// including the retired firewall module and a pre-9 one.
	firewall := filepath.Join(elsewhere, "policies", "rego", "firewall.rego")
	module := filepath.Join(elsewhere, "policies", "rego", "guardrail.rego")
	raw, err := os.ReadFile(filepath.Join("testdata", "rego_0_8_10", "firewall.rego"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(firewall, raw, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(module, []byte("package defenseclaw.guardrail\nblock := data.guardrail.block_threshold\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	result, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath, DataJSONPath: dataJSON, AuditDBPath: auditDB})
	if err != nil {
		t.Fatalf("MigrateV9: %v", err)
	}
	for _, path := range []string{dataJSON, firewall, module} {
		if _, err := os.Stat(path); err != nil {
			t.Errorf("%s outside the data home was moved: %v", path, err)
		}
	}
	db, _ = sql.Open("sqlite", auditDB)
	defer db.Close()
	var rows int
	if err := db.QueryRow(`SELECT COUNT(*) FROM actions`).Scan(&rows); err != nil || rows != 1 {
		t.Errorf("audit.db rows outside the data home = %d (%v), want the operator row kept", rows, err)
	}
	if migrated, _ := os.ReadFile(configPath); !strings.Contains(string(migrated), "bad-skill") {
		t.Error("the operator block was not copied into config.yaml")
	}
	var noted bool
	for _, note := range result.Record.Notes {
		noted = noted || strings.Contains(note, "outside the data home")
		if strings.Contains(note, "is removed") || strings.Contains(note, DataJSONMigratedSuffix) {
			t.Errorf("a note claims a file left in place was changed: %s", note)
		}
	}
	if !noted {
		t.Errorf("no note says what was left in place: %v", result.Record.Notes)
	}
}

// A policy_dir symlink within the data home can point at files the installer's
// rollback snapshot cannot restore.
func TestMigrateV9KeepsSymlinkedPolicyDataOutsideRollbackCopy(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	home, external := t.TempDir(), t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", home)
	policyDir := filepath.Join(home, "policies")
	if err := os.Symlink(external, policyDir); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}
	dataJSON := filepath.Join(policyDir, "rego", "data.json")
	if err := os.MkdirAll(filepath.Dir(dataJSON), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataJSON, []byte(`{"actions":{"HIGH":{"install":"block"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(home, "config.yaml")
	source := "config_version: 8\ndata_dir: " + home + "\npolicy_dir: " + policyDir + "\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath, DataJSONPath: dataJSON}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(dataJSON); err != nil {
		t.Fatalf("external data.json must survive rollback: %v", err)
	}
}

// A 0.8.x config with rule_pack_dir: "" (the 0.8.10 default: the embedded
// packs) on a home without the default pack folder upgrades to a config whose
// default pack exists: the migration writes the shipped pack, and a folder
// that is there is left alone (GAP-0150).
func TestMigrateV9SeedsAMissingDefaultRulePack(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dir)
	configPath := filepath.Join(dir, "config.yaml")
	source := "config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  rule_pack_dir: \"\"\n  connectors:\n    codex: {rule_pack_dir: \"\"}\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	strict := filepath.Join(dir, "policies", "guardrail", "strict")
	if err := os.MkdirAll(strict, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath}); err != nil {
		t.Fatalf("MigrateV9: %v", err)
	}
	pack := filepath.Join(dir, "policies", "guardrail", "default")
	if entries, err := os.ReadDir(pack); err != nil || len(entries) == 0 {
		t.Fatalf("default pack folder after the migration: %v (%d entries), want the shipped pack", err, len(entries))
	}
	if entries, _ := os.ReadDir(strict); len(entries) != 0 {
		t.Errorf("the existing strict folder was rewritten: %d entries", len(entries))
	}
}

// A v9 config must never be committed when its referenced shipped pack
// cannot be installed.
func TestMigrateV9RefusesFailedRulePackSeed(t *testing.T) {
	if runtime.GOOS == "windows" || os.Geteuid() == 0 {
		t.Skip("requires an unprivileged Unix user for read-only directory permissions")
	}
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dir)
	configPath := filepath.Join(dir, "config.yaml")
	source := []byte("config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  rule_pack_dir: \"\"\nobservability: {}\n")
	if err := os.WriteFile(configPath, source, 0o600); err != nil {
		t.Fatal(err)
	}
	packRoot := filepath.Join(dir, "policies", "guardrail")
	if err := os.MkdirAll(packRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(packRoot, 0o500); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(packRoot, 0o700)
	if _, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath}); err == nil {
		t.Fatal("migration committed despite a failed rule-pack seed")
	}
	if got, err := os.ReadFile(configPath); err != nil || string(got) != string(source) {
		t.Fatalf("config after failed migration = %q, %v", got, err)
	}
}

func TestMigrateV9MovesEveryV8Source(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dir)
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
observability:
  resource:
    attributes:
      deployment.environment: production
  trace_policy:
    compatibility_aliases: false
  destinations:
    - {name: collector, kind: otlp, endpoint: "https://otel.example.test"}
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
	  "guardrail": {"block_threshold": 3, "alert_threshold": 1},
	  "first_party_allow_list": [{"target_type": "skill", "target_name": "mine", "reason": "x"}]}`
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
	// A hand-written provider overlay (no _derived_from) with an inline CA.
	overlay := filepath.Join(dir, ProvidersOverlayFile)
	if err := os.WriteFile(overlay, []byte(`{"providers": [{"name": "acme", "domains": ["llm.acme.internal"],
	  "env_keys": ["ACME_KEY"], "tls": {"ca_cert_pem": "-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"}}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	// 0.8.x also seeded the firewall and audit modules, which 1.0 retires:
	// the unmodified copy goes, the edited one stays.
	retiredFirewall := filepath.Join(dir, "policies", "rego", "firewall.rego")
	editedAudit := filepath.Join(dir, "policies", "rego", "audit.rego")
	for src, dst := range map[string]string{"firewall.rego": retiredFirewall, "audit.rego": editedAudit} {
		raw, err := os.ReadFile(filepath.Join("testdata", "rego_0_8_10", src))
		if err != nil {
			t.Fatal(err)
		}
		if dst == editedAudit {
			raw = append(raw, []byte("# local edit\n")...)
		}
		if err := os.WriteFile(dst, raw, 0o644); err != nil {
			t.Fatal(err)
		}
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
		`INSERT INTO actions VALUES ('7','tool','filesystem/read','','{"install":"allow"}','','now','')`,
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
	if _, err := os.Stat(retiredFirewall); err != nil {
		t.Fatalf("the dry run removed firewall.rego: %v", err)
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
		// A <source>/<tool> row was audit-only: it keeps its whole name, so it
		// never allows every tool named "read".
		"asset_policy.tool.allowed": []any{map[string]any{"name": "filesystem/read"}},
		// A first-party entry without source_path_contains matched any path
		// but, with allow_list_bypass_scan false, v8 still scanned it.
		"asset_policy.skill.allowed": nil,
		"llm_providers.custom": []any{map[string]any{"name": "acme", "domains": []any{"llm.acme.internal"}, "env_keys": []any{"ACME_KEY"},
			"tls": map[string]any{"ca_cert_file": filepath.Join(dir, "provider-ca", v9ProviderCAName("acme"))}}},
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
	// Telemetry carries canonical names only: the alias switch is dropped and
	// reported, the retired environment spelling becomes the canonical one.
	attributes, _ := get("observability.resource.attributes").(map[string]any)
	if attributes["deployment.environment.name"] != "production" || attributes["deployment.environment"] != nil ||
		get("observability.trace_policy") != nil ||
		!slices.Contains(result.Record.Removed, "observability.trace_policy.compatibility_aliases") ||
		!strings.Contains(strings.Join(result.Record.Notes, "\n"), "no longer carries the alias attributes") {
		t.Errorf("telemetry aliases not migrated: attributes=%v removed=%v notes=%v",
			attributes, result.Record.Removed, result.Record.Notes)
	}
	if notes := strings.Join(result.Record.Notes, "\n"); !strings.Contains(notes, `"mine" has no source_path_contains and was dropped`) {
		t.Errorf("the dropped first-party entry is not reported: %q", notes)
	}
	// strict posture is block MEDIUM / alert LOW: alert_threshold 1 matches.
	if get("guardrail.alert_at") != nil {
		t.Error("alert_at was written although data.json matched the pack default")
	}
	if len(result.Record.Conflicts) != 2 || result.Record.Conflicts[0].To != "admission.skill.actions.high" ||
		result.Record.Conflicts[1].To != "guardrail.block_at" {
		t.Errorf("conflicts = %+v", result.Record.Conflicts)
	}
	if result.Record.ActionsRowsMoved != 4 {
		t.Errorf("actions rows moved = %d, want 4", result.Record.ActionsRowsMoved)
	}
	if backup, _ := os.ReadFile(configPath + ConfigV8BackupSuffix); string(backup) != source {
		t.Error("config.yaml.v8.bak does not hold the v8 bytes")
	}
	if _, err := os.Stat(dataJSON + DataJSONMigratedSuffix); err != nil {
		t.Errorf("data.json was not renamed: %v", err)
	}
	if _, err := os.Stat(overlay); !os.IsNotExist(err) {
		t.Errorf("the legacy custom-providers.json is still a live input: %v", err)
	}
	if pem, _ := os.ReadFile(filepath.Join(dir, "provider-ca", v9ProviderCAName("acme"))); !strings.Contains(string(pem), "BEGIN CERTIFICATE") {
		t.Error("the inline provider CA was not moved to provider-ca/acme.pem")
	}
	if refreshed, _ := os.ReadFile(staleRego); v9LegacyRegoData.Match(refreshed) || !strings.Contains(string(refreshed), "input.admission") {
		t.Error("the pre-9 admission.rego was not replaced with the shipped module")
	}
	if _, err := os.Stat(staleRego + DataJSONMigratedSuffix); err != nil {
		t.Errorf("the pre-9 admission.rego was not kept: %v", err)
	}
	if _, err := os.Stat(retiredFirewall); !os.IsNotExist(err) {
		t.Errorf("the unmodified 0.8 firewall.rego was not removed: %v", err)
	}
	if _, err := os.Stat(editedAudit); err != nil {
		t.Errorf("the edited audit.rego was removed: %v", err)
	}
	if notes := strings.Join(result.Record.Notes, "\n"); !strings.Contains(notes, editedAudit+" was changed after install and is kept") ||
		!strings.Contains(notes, retiredFirewall) {
		t.Errorf("the report does not name both retired files: %q", notes)
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

// A managed v8 host loaded packs from data_dir implicitly. The migrated
// config must pin each discovered file so managed validation can apply it,
// and also a pack the config already lists outside the data_dir (GAP-1287).
func TestMigrateV9PinsManagedSignaturePack(t *testing.T) {
	dir := t.TempDir()
	pack := filepath.Join(dir, "signature-packs", "custom.json")
	if err := os.MkdirAll(filepath.Dir(pack), 0o700); err != nil {
		t.Fatal(err)
	}
	raw := []byte(`{"version":1,"signatures":[]}`)
	if err := os.WriteFile(pack, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	external := filepath.Join(t.TempDir(), "vendor.json")
	externalRaw := []byte(`{"version":1,"signatures":[{"id":"vendor"}]}`)
	if err := os.WriteFile(external, externalRaw, 0o600); err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "config.yaml")
	source := fmt.Sprintf("config_version: 8\ndata_dir: %s\nai_discovery:\n  signature_packs: [%s]\nobservability: {}\n", dir, external)
	result, err := MigrateV9(context.Background(), MigrateV9Input{
		ConfigPath: configPath, Source: []byte(source), DataDir: dir,
		Managed: true, InMemory: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		AIDiscovery struct {
			SignaturePacks   []string          `yaml:"signature_packs"`
			SignatureDigests map[string]string `yaml:"signature_pack_digests"`
		} `yaml:"ai_discovery"`
	}
	if err := yaml.Unmarshal(result.Migrated, &doc); err != nil {
		t.Fatal(err)
	}
	wantDigest := fmt.Sprintf("sha256:%x", sha256.Sum256(raw))
	wantExternal := fmt.Sprintf("sha256:%x", sha256.Sum256(externalRaw))
	if !slices.Equal(doc.AIDiscovery.SignaturePacks, []string{external, pack}) ||
		doc.AIDiscovery.SignatureDigests[pack] != wantDigest ||
		doc.AIDiscovery.SignatureDigests[external] != wantExternal {
		t.Errorf("migrated signature packs = %v, digests = %v; want %s=%s and %s=%s",
			doc.AIDiscovery.SignaturePacks, doc.AIDiscovery.SignatureDigests, pack, wantDigest, external, wantExternal)
	}
}

// TestMigrateV9KeepsThePackPosture: selecting the strict pack in v8 left the
// shipped data.json thresholds alone, so they must not override the strict
// posture the hook paths used; and a strict-named pack outside
// <policy_dir>/guardrail is an edited copy, not the preset.
func TestMigrateV9TransliteratesANonASCIIPackFolder(t *testing.T) {
	// GAP-0390: "équipe sécu" became custom_packs.quipe-s-cu.
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	source := "config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  rule_pack_dir: " +
		filepath.Join(dir, "policies", "guardrail", "Équipe sécu") + "\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := MigrateV9(context.Background(), MigrateV9Input{
		ConfigPath: configPath, DryRun: true,
		RulePackDigest: func(string) (string, error) { return strings.Repeat("a", 64), nil },
	})
	if err != nil {
		t.Fatalf("MigrateV9: %v", err)
	}
	if got := string(result.Migrated); !strings.Contains(got, "rule_pack: equipe-secu") {
		t.Errorf("want the pack named equipe-secu:\n%s", got)
	}
}

func TestMigrateV9RefreshesRollbackBackupOnSecondMigration(t *testing.T) {
	// A second upgrade must leave the immediate pre-migration source at the
	// documented rollback path, while preserving the first source as history.
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dir)
	configPath := filepath.Join(dir, "config.yaml")
	pristine := []byte("config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  rule_pack_dir: \"\"\nobservability: {}\n")
	if err := os.WriteFile(configPath+ConfigV8BackupSuffix, pristine, 0o600); err != nil {
		t.Fatal(err)
	}
	record := []byte(`{"schema_version":1,"source_sha256":"aa","moved":[{"source":"data.json","from":"x","to":"y"}]}`)
	if err := os.WriteFile(MigrationRecordPath(configPath), record, 0o600); err != nil {
		t.Fatal(err)
	}
	updated := "config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  block_at: HIGH\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(updated), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath})
	if err != nil {
		t.Fatalf("MigrateV9: %v", err)
	}
	if backup, _ := os.ReadFile(configPath + ConfigV8BackupSuffix); string(backup) != updated {
		t.Errorf("rollback backup is not the latest v8 source:\n%s", backup)
	}
	sources, _ := filepath.Glob(configPath + ConfigV8BackupSuffix + ".*")
	records, _ := filepath.Glob(filepath.Join(dir, "migration-v9.*.json"))
	if len(sources) != 1 || len(records) != 1 {
		t.Fatalf("want one saved source and one earlier record, got %q %q", sources, records)
	}
	if saved, _ := os.ReadFile(sources[0]); string(saved) != string(pristine) {
		t.Errorf("the earlier source was not saved beside the backup:\n%s", saved)
	}
	if earlier, _ := os.ReadFile(records[0]); string(earlier) != string(record) {
		t.Errorf("the earlier migration record was not kept:\n%s", earlier)
	}
	if !slices.ContainsFunc(result.Record.Notes, func(note string) bool { return strings.Contains(note, "previous backup") }) {
		t.Errorf("no note says the previous backup was saved: %q", result.Record.Notes)
	}
}

func TestMigrateV9PinsTheRebasedCopyOfAZeroEightPack(t *testing.T) {
	// GAP-0360: a 0.8.x copy of the default pack was pinned as it was and
	// enforced nothing in 1.0; its rebased copy is written next to it and pinned.
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dir)
	configPath := filepath.Join(dir, "config.yaml")
	acme := filepath.Join(dir, "policies", "guardrail", "acme")
	source := "config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  rule_pack_dir: " + acme + "\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	digest := strings.Repeat("b", 64)
	result, err := MigrateV9(context.Background(), MigrateV9Input{
		ConfigPath:     configPath,
		RulePackDigest: func(string) (string, error) { return strings.Repeat("a", 64), nil },
		RebaseRulePack: func(string) (*RulePackRebasePlan, error) {
			return &RulePackRebasePlan{
				Files: map[string][]byte{"rules/commands.yaml": []byte("rebased\n")}, Digest: digest,
				Updated: 26, Carried: []string{"CMD-ACME-MARKER"},
				Expressed:     []string{"CUSTOM-CMD-RM-RF", "CMD-ACME-MARKER"},
				WholeArgument: []string{"CMD-ACME-MARKER"}, AlertOnly: []string{"CUSTOM-CMD-SUDO"},
				Renamed: []string{"CMD-RM-RF -> CUSTOM-CMD-RM-RF", "CMD-SUDO -> CUSTOM-CMD-SUDO"},
			}, nil
		},
	})
	if err != nil {
		t.Fatalf("MigrateV9: %v", err)
	}
	if got := string(result.Migrated); !strings.Contains(got, "path: "+acme+"-1.0") || !strings.Contains(got, "sha256:"+digest) {
		t.Errorf("want the rebased copy pinned:\n%s", got)
	}
	if data, err := os.ReadFile(filepath.Join(acme+"-1.0", "rules", "commands.yaml")); err != nil || string(data) != "rebased\n" {
		t.Errorf("rebased pack file: %q, %v", data, err)
	}
	if !slices.ContainsFunc(result.Record.Notes, func(note string) bool {
		return strings.Contains(note, "enforced nothing") && strings.Contains(note, "CMD-RM-RF -> CUSTOM-CMD-RM-RF")
	}) {
		t.Errorf("no note names the rebase and the renamed rules: %q", result.Record.Notes)
	}
	// GAP-1314: the upgrade output and doctor name every rule the rebase
	// changed, and a renamed built-in by both of its IDs.
	want := []string{
		"CUSTOM-CMD-RM-RF (your edited CMD-RM-RF; CMD-RM-RF is the shipped 1.0 rule): enforced as on 0.8.x (its " +
			"severity decides block or alert), with an expression derived from its literal pattern",
		"CMD-ACME-MARKER: blocks only a command argument equal to its literal (the pack's semantic cost budget was full)",
		"CUSTOM-CMD-SUDO (your edited CMD-SUDO; CMD-SUDO is the shipped 1.0 rule): alert-only for tool calls in 1.0 " +
			"(its pattern is not a literal); add an expression to block",
	}
	if got := MigratedRuleLines(result.Record); !slices.Equal(got, want) {
		t.Errorf("rule lines:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
}

func TestMigrateV9NamesCustomRulesThatNoLongerBlockToolCalls(t *testing.T) {
	// GAP-1225: a 0.8.x pack rule that blocked a tool call with its pattern
	// alone only records it in 1.0, and the upgrade said nothing.
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dir)
	configPath := filepath.Join(dir, "config.yaml")
	acme := filepath.Join(dir, "policies", "guardrail", "acme")
	source := "config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  rule_pack_dir: " + acme +
		"\n  connectors:\n    codex:\n      rule_pack_dir: " + acme + "\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := MigrateV9(context.Background(), MigrateV9Input{
		ConfigPath:     configPath,
		RulePackDigest: func(string) (string, error) { return strings.Repeat("a", 64), nil },
		RebaseRulePack: func(string) (*RulePackRebasePlan, error) {
			return &RulePackRebasePlan{AlertOnly: []string{"ACME-SPACED", "ACME-REGEX"}}, nil
		},
	})
	if err != nil {
		t.Fatalf("MigrateV9: %v", err)
	}
	if got := string(result.Migrated); !strings.Contains(got, "path: "+acme+"\n") || strings.Contains(got, acme+"-1.0") {
		t.Errorf("want the pack pinned as it is:\n%s", got)
	}
	if !slices.Equal(result.Record.DetectionOnlyRules, []string{"ACME-SPACED", "ACME-REGEX"}) {
		t.Errorf("detection-only rules %q, want each named once", result.Record.DetectionOnlyRules)
	}
	if !slices.ContainsFunc(result.Record.Notes, func(note string) bool {
		return strings.Contains(note, "2 custom rule(s) in "+acme+" now detection-only for tool calls: ACME-SPACED, ACME-REGEX")
	}) {
		t.Errorf("no note names the rules: %q", result.Record.Notes)
	}
}

func TestMigrateV9MergesRuleFilesThatShareACategory(t *testing.T) {
	// GAP-1339: 0.8.x took two rule files of one category and 1.0 refuses
	// them, so the upgrade stopped with no way forward. The 1.0 copy merges
	// them and the upgrade says so; a pack that can not be merged, or an
	// administrator's pack, fails with the edit to make.
	refused := errors.New("rule pack duplicate_category at rules/x.yaml: category repeats rules/commands.yaml; " +
		"categories must be unique: move the rules of rules/x.yaml into rules/commands.yaml and delete rules/x.yaml")
	cases := []struct {
		name    string
		managed bool
		rebase  func(string) (*RulePackRebasePlan, error)
		want    string
	}{
		{name: "merged", rebase: func(string) (*RulePackRebasePlan, error) {
			return &RulePackRebasePlan{
				Files: map[string][]byte{"rules/commands.yaml": []byte("merged\n")}, Digest: strings.Repeat("b", 64),
				Merged: []string{`rules/x.yaml (category "command") merged into rules/commands.yaml; 1 rule(s) kept`},
			}, nil
		}},
		{name: "merge refused", rebase: func(string) (*RulePackRebasePlan, error) {
			return nil, errors.New("rules/x.yaml (category \"command\") can not be merged into rules/commands.yaml, " +
				"which would then have more than 2048 rules. Categories must be unique in 1.0: move the rules of " +
				"rules/x.yaml into rules/commands.yaml and delete rules/x.yaml, then run the upgrade again")
		}, want: "Categories must be unique in 1.0: move the rules of rules/x.yaml into rules/commands.yaml"},
		{name: "administrator pack", managed: true, rebase: func(string) (*RulePackRebasePlan, error) {
			return nil, errors.New("a managed host's pack must not be rebased")
		}, want: "move the rules of rules/x.yaml into rules/commands.yaml and delete rules/x.yaml"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
			dir := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", dir)
			configPath := filepath.Join(dir, "config.yaml")
			acme := filepath.Join(dir, "policies", "guardrail", "acme")
			source := "config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  rule_pack_dir: " + acme + "\nobservability: {}\n"
			if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
				t.Fatal(err)
			}
			result, err := MigrateV9(context.Background(), MigrateV9Input{
				ConfigPath: configPath, Managed: tc.managed, RebaseRulePack: tc.rebase,
				RulePackDigest: func(string) (string, error) { return "", refused },
			})
			if tc.want != "" {
				if err == nil || !strings.Contains(err.Error(), tc.want) {
					t.Fatalf("MigrateV9 = %v, want an error naming the edit %q", err, tc.want)
				}
				return
			}
			if err != nil {
				t.Fatalf("MigrateV9: %v", err)
			}
			if got := string(result.Migrated); !strings.Contains(got, "path: "+acme+"-1.0") {
				t.Errorf("want the merged copy pinned:\n%s", got)
			}
			want := acme + `-1.0: rules/x.yaml (category "command") merged into rules/commands.yaml; 1 rule(s) kept`
			if !slices.Equal(result.Record.RuleFileMerges, []string{want}) {
				t.Errorf("rule file merges %q, want %q", result.Record.RuleFileMerges, want)
			}
			if !slices.ContainsFunc(result.Record.Notes, func(note string) bool { return strings.Contains(note, "share a category") }) {
				t.Errorf("no note names the merge: %q", result.Record.Notes)
			}
		})
	}
}

func TestWriteRebasedRulePackPreservesExistingStagingSibling(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "acme-1.0")
	sibling := dir + ".rebasing"
	if err := os.Mkdir(sibling, 0o700); err != nil {
		t.Fatal(err)
	}
	marker := filepath.Join(sibling, "operator-owned")
	if err := os.WriteFile(marker, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := writeRebasedRulePack(dir, map[string][]byte{"rules/new.yaml": []byte("rebased")}); err != nil {
		t.Fatal(err)
	}
	if got, err := os.ReadFile(marker); err != nil || string(got) != "keep" {
		t.Fatalf("existing sibling was changed: %q, %v", got, err)
	}
	if got, err := os.ReadFile(filepath.Join(dir, "rules/new.yaml")); err != nil || string(got) != "rebased" {
		t.Fatalf("rebased pack: %q, %v", got, err)
	}
}

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

	// A data.json HIGH stricter than the global default pack becomes the
	// global block_at, and a connector on a stricter pack keeps its MEDIUM.
	source = "config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  connectors:\n    codex:\n      rule_pack_dir: " +
		edited + "\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataJSON, []byte(`{"guardrail": {"block_threshold": 3, "alert_threshold": 2}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err = MigrateV9(context.Background(), MigrateV9Input{
		ConfigPath: configPath, DataJSONPath: dataJSON, DryRun: true,
		RulePackDigest: func(string) (string, error) { return digest, nil },
	})
	if err != nil {
		t.Fatalf("MigrateV9 (stricter connector pack): %v", err)
	}
	var pinned struct {
		Guardrail struct {
			BlockAt    string `yaml:"block_at"`
			Connectors map[string]struct {
				BlockAt string `yaml:"block_at"`
			} `yaml:"connectors"`
		} `yaml:"guardrail"`
	}
	if err := yaml.Unmarshal(result.Migrated, &pinned); err != nil {
		t.Fatal(err)
	}
	if pinned.Guardrail.BlockAt != "HIGH" || pinned.Guardrail.Connectors["codex"].BlockAt != "MEDIUM" {
		t.Errorf("block_at global %q codex %q; want HIGH and the strict pack's MEDIUM:\n%s",
			pinned.Guardrail.BlockAt, pinned.Guardrail.Connectors["codex"].BlockAt, result.Migrated)
	}

	// rule_pack wins over rule_pack_dir at one scope, so the directory is
	// dropped instead of replacing the selected pack.
	source = "config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  rule_pack: strict\n  rule_pack_dir: " +
		filepath.Join(dir, "policies", "guardrail", "default") + "\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err = MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath, DryRun: true})
	if err != nil {
		t.Fatalf("MigrateV9 (rule_pack and rule_pack_dir): %v", err)
	}
	if got := string(result.Migrated); !strings.Contains(got, "rule_pack: strict") || strings.Contains(got, "rule_pack: default") {
		t.Errorf("rule_pack_dir replaced the selected rule_pack:\n%s", got)
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

	// config set, policy activate and the TUI write admission: into a v8
	// file. Those values win over data.json, in memory and in the migration,
	// and each data.json value they replace is a conflict. With the bypass
	// kept on, a path-less first-party entry stays a name-only allow.
	if err := os.WriteFile(dataJSON, []byte(`{"config": {"allow_list_bypass_scan": false},
	  "actions": {"MEDIUM": {"install": "block", "file": "none", "runtime": "block"},
	    "LOW": {"install": "none", "file": "none", "runtime": "allow"}},
	  "first_party_allow_list": [{"target_type": "skill", "target_name": "helper"},
	    {"target_type": "skill", "target_name": "acme", "source_path_contains": [".claude/skills/acme"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	written := []byte("config_version: 8\ndata_dir: " + dir + "\nobservability: {}\nadmission:\n" +
		"  defaults: {allow_list_bypass_scan: true}\n  skill: {actions: {low: block}, first_party_allow_list: []}\n")
	migrated, err = MigrateV8InMemory(configPath, written, nil)
	if err != nil {
		t.Fatalf("MigrateV8InMemory(admission set): %v", err)
	}
	var got struct {
		Admission   AdmissionConfig           `yaml:"admission"`
		AssetPolicy map[string]map[string]any `yaml:"asset_policy"`
	}
	if err := yaml.Unmarshal(migrated, &got); err != nil {
		t.Fatal(err)
	}
	skill := got.Admission.Skill
	if skill.Actions.Low == nil || skill.Actions.Low.Shorthand != "block" || skill.Actions.Medium == nil ||
		skill.Actions.Medium.Shorthand != "block" || got.Admission.Defaults.AllowListBypassScan == nil ||
		!*got.Admission.Defaults.AllowListBypassScan || len(skill.FirstPartyAllowList) != 0 ||
		mustJSON(t, got.AssetPolicy["skill"]["allowed"]) != `[{"name":"helper"}]` {
		t.Errorf("the in-memory load overwrote what the v8 file set: %s", migrated)
	}
	result, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath, Source: written, DataJSONPath: dataJSON, DryRun: true})
	if err != nil {
		t.Fatalf("MigrateV9(admission set): %v", err)
	}
	var to []string
	for _, conflict := range result.Record.Conflicts {
		to = append(to, conflict.To)
	}
	if !slices.Equal(to, []string{"admission.defaults.allow_list_bypass_scan", "admission.skill.actions.low",
		"admission.skill.first_party_allow_list"}) || result.Record.Conflicts[1].Kept != "config:admission.skill.actions.low:block" ||
		result.Record.Conflicts[1].Lost != "data.json:actions.LOW:warn" {
		t.Errorf("conflicts = %+v", result.Record.Conflicts)
	}
}

// TestMigrateV8InMemoryReadsTheUnexpandedPolicyDir: 0.8.x wrote the policy
// data of a "~/team-policies" policy_dir under <home>/~/team-policies, so the
// strict levels it activated there carry forward, and the v9 file names the
// expanded folder the 1.0 gateway can read (GAP-1031).
func TestMigrateV8InMemoryReadsTheUnexpandedPolicyDir(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	for folder, rank := range map[string]string{"team-policies": "4", filepath.Join("~", "team-policies"): "2"} {
		dataJSON := filepath.Join(home, folder, "rego", "data.json")
		if err := os.MkdirAll(filepath.Dir(dataJSON), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(dataJSON, []byte(`{"guardrail": {"block_threshold": `+rank+`}}`), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	old := time.Now().Add(-time.Hour)
	if err := os.Chtimes(filepath.Join(home, "team-policies", "rego", "data.json"), old, old); err != nil {
		t.Fatal(err)
	}
	source := []byte("config_version: 8\ndata_dir: " + filepath.Join(home, ".defenseclaw") +
		"\npolicy_dir: ~/team-policies\nobservability: {}\n")
	migrated, err := MigrateV8InMemory(filepath.Join(home, ".defenseclaw", "config.yaml"), source, nil)
	if err != nil {
		t.Fatalf("MigrateV8InMemory: %v", err)
	}
	var got struct {
		PolicyDir string `yaml:"policy_dir"`
		Guardrail struct {
			BlockAt string `yaml:"block_at"`
		} `yaml:"guardrail"`
	}
	if err := yaml.Unmarshal(migrated, &got); err != nil {
		t.Fatal(err)
	}
	if got.Guardrail.BlockAt != "MEDIUM" || got.PolicyDir != filepath.Join(home, "team-policies") {
		t.Fatalf("block_at %q, policy_dir %q; want MEDIUM from the unexpanded folder and the expanded folder:\n%s",
			got.Guardrail.BlockAt, got.PolicyDir, migrated)
	}
}

func TestMigrateV9ReplacesEmptyDotEnvVirusTotalKey(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	source := "config_version: 8\ndata_dir: " + dir +
		"\nscanners:\n  skill_scanner:\n    use_virustotal: true\n    virustotal_api_key: vt-test-value\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	envPath := filepath.Join(dir, ".env")
	if err := os.WriteFile(envPath, []byte("VIRUSTOTAL_API_KEY=\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath}); err != nil {
		t.Fatalf("MigrateV9: %v", err)
	}
	if env, err := os.ReadFile(envPath); err != nil || string(env) != "VIRUSTOTAL_API_KEY=vt-test-value\n" {
		t.Errorf(".env did not retain the inline key: %q, %v", env, err)
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
	t.Setenv("USERPROFILE", home) // os.UserHomeDir on Windows
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

	// A committing managed migration (Windows ensure) leaves the admin's
	// data.json in place, so a rollback to the v8 config still finds it.
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("config_version: 8\ndata_dir: "+dir+"\nobservability: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	dataJSON := filepath.Join(dir, "data.json")
	if err := os.WriteFile(dataJSON, []byte(`{"actions": {"MEDIUM": {"install": "block"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath, DataJSONPath: dataJSON, Managed: true}); err != nil {
		t.Fatalf("MigrateV9 (managed commit): %v", err)
	}
	if _, err := os.Stat(dataJSON); err != nil {
		t.Errorf("the managed migration moved the admin data.json: %v", err)
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

	// v8 guardrail.rego gave the OpenClaw proxy the data.json levels whatever
	// openclaw's own pack or alert_at; v9 resolves the proxy for openclaw. Its
	// looser permissive pack must not loosen the strict block level, and its
	// own alert_at wins as a recorded conflict.
	policyDir := filepath.Join(dir, "policies")
	dataJSON = filepath.Join(policyDir, "rego", "data.json")
	if err := os.MkdirAll(filepath.Dir(dataJSON), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataJSON, []byte(`{"guardrail": {"block_threshold": 2, "alert_threshold": 1}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	source = "config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  connector: openclaw\n  rule_pack_dir: " +
		filepath.Join(policyDir, "guardrail", "strict") + "\n  connectors:\n    openclaw:\n      rule_pack_dir: " +
		filepath.Join(policyDir, "guardrail", "permissive") + "\n      alert_at: HIGH\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err = MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath, DataJSONPath: dataJSON, DryRun: true})
	if err != nil {
		t.Fatalf("MigrateV9 (proxy connector): %v", err)
	}
	var doc struct {
		Guardrail struct {
			BlockAt    string `yaml:"block_at"`
			Connectors map[string]struct {
				BlockAt string `yaml:"block_at"`
				AlertAt string `yaml:"alert_at"`
			} `yaml:"connectors"`
		} `yaml:"guardrail"`
	}
	if err := yaml.Unmarshal(result.Migrated, &doc); err != nil {
		t.Fatal(err)
	}
	openclaw := doc.Guardrail.Connectors["openclaw"]
	if doc.Guardrail.BlockAt != "" || openclaw.BlockAt != "MEDIUM" || openclaw.AlertAt != "HIGH" {
		t.Errorf("block_at global %q openclaw %q alert_at openclaw %q; want openclaw pinned to MEDIUM and its HIGH kept:\n%s",
			doc.Guardrail.BlockAt, openclaw.BlockAt, openclaw.AlertAt, result.Migrated)
	}
	if c := result.Record.Conflicts; len(c) != 1 || c[0].To != "guardrail.connectors.openclaw.alert_at" || !strings.HasSuffix(c[0].Lost, ":LOW") {
		t.Errorf("conflicts = %+v; want openclaw's alert_at over the data.json LOW", c)
	}
}

// TestMigrateV9NamesTheActionsAHostWithoutDataJSONDropped: a managed layout
// never has a data.json, so enforcement used the built-in defaults and a
// customised skill_actions key was never read. The migration removes the key,
// so each customised severity (and the watch bypass) is a recorded conflict
// instead of a silent drop.
func TestMigrateV9NamesTheActionsAHostWithoutDataJSONDropped(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	source := "config_version: 8\ndata_dir: " + dir + "\nskill_actions:\n  high: {install: block, file: none, runtime: disable}\n" +
		"watch:\n  allow_list_bypass_scan: false\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath, DryRun: true})
	if err != nil {
		t.Fatalf("MigrateV9: %v", err)
	}
	conflicts := result.Record.Conflicts
	if len(conflicts) != 2 || conflicts[0].To != "admission.defaults.allow_list_bypass_scan" || conflicts[0].Kept != "defaults:true" ||
		conflicts[1].To != "admission.skill.actions.high" || !strings.HasPrefix(conflicts[1].Kept, "defaults:") ||
		!strings.HasPrefix(conflicts[1].Lost, "skill_actions.high:") || !strings.Contains(conflicts[1].Reason, "no data.json") {
		t.Fatalf("conflicts = %+v", conflicts)
	}
}

// TestMigrateV9RecordsTheEmbeddedPackAnEmptyRulePackDirSelected: an explicit
// empty rule_pack_dir selected the embedded packs in v8; v9 has no such key,
// so the switch to the default pack folder is a recorded conflict, not silent.
func TestMigrateV9RecordsTheEmbeddedPackAnEmptyRulePackDirSelected(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("a standalone Windows host without policy_dir keeps the embedded packs")
	}
	source := "config_version: 8\nguardrail:\n  rule_pack_dir: \"\"\nobservability: {}\n"
	result, err := MigrateV9(context.Background(), MigrateV9Input{
		ConfigPath: filepath.Join(t.TempDir(), "config.yaml"), Source: []byte(source), InMemory: true,
	})
	if err != nil {
		t.Fatalf("MigrateV9: %v", err)
	}
	if strings.Contains(string(result.Migrated), "rule_pack_dir") || len(result.Record.Conflicts) != 1 ||
		result.Record.Conflicts[0].To != "guardrail.rule_pack" {
		t.Fatalf("conflicts = %+v\n%s", result.Record.Conflicts, result.Migrated)
	}
}

// A missing audit.db is optional, but a path that cannot be accessed must
// stop the persisted migration before it drops operator policy.
func TestMigrateV9RefusesAuditDBAccessError(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Windows reports a path under a regular file as not found, so this layout cannot produce an access error there")
	}
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dir)
	configPath := filepath.Join(dir, "config.yaml")
	source := []byte("config_version: 8\ndata_dir: " + dir + "\nobservability: {}\n")
	if err := os.WriteFile(configPath, source, 0o600); err != nil {
		t.Fatal(err)
	}
	parent := filepath.Join(dir, "blocked")
	if err := os.WriteFile(parent, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := MigrateV9(context.Background(), MigrateV9Input{
		ConfigPath: configPath, AuditDBPath: filepath.Join(parent, "audit.db"),
	})
	if err == nil {
		t.Fatal("migration committed without reading the configured audit.db")
	}
	if got, readErr := os.ReadFile(configPath); readErr != nil || string(got) != string(source) {
		t.Fatalf("config after failed migration = %q, %v", got, readErr)
	}
}

// TestMigrateV9InMemoryLeavesADamagedAuditDBToTheDaemon: a damaged audit.db
// is repaired by the daemon's store open, so the in-memory migration notes it
// and goes on; a persisted migration, which would lose the rows for good,
// still refuses.
func TestMigrateV9InMemoryLeavesADamagedAuditDBToTheDaemon(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	source := "config_version: 8\ndata_dir: " + dir + "\nobservability: {}\n"
	if err := os.WriteFile(configPath, []byte(source), 0o600); err != nil {
		t.Fatal(err)
	}
	auditDB := filepath.Join(dir, "audit.db")
	if err := os.WriteFile(auditDB, []byte(strings.Repeat("not a database ", 512)), 0o600); err != nil {
		t.Fatal(err)
	}
	input := MigrateV9Input{ConfigPath: configPath, Source: []byte(source), AuditDBPath: auditDB, InMemory: true}
	result, err := MigrateV9(context.Background(), input)
	if err != nil || len(result.Record.Notes) == 0 {
		t.Fatalf("in-memory migration of a damaged audit.db: err=%v notes=%v", err, result.Record.Notes)
	}
	input.InMemory = false
	if _, err := MigrateV9(context.Background(), input); err == nil {
		t.Fatal("a persisted migration must refuse a damaged audit.db")
	}
}

// TestMigrateV9KeepsTheShippedPackAPreset: a v8 rule_pack_dir naming the
// standalone layout's shipped strict pack, with policy_dir elsewhere, stays
// the strict preset (which resolves to that pack) instead of a custom pack
// pinned to files the next package replaces.
func TestMigrateV9KeepsTheShippedPackAPreset(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the shipped-pack preset serves the Linux and macOS standalone layouts; a Linux layout path is not absolute on Windows")
	}
	layout, err := managed.StandaloneLayoutFor("linux")
	if err != nil {
		t.Fatal(err)
	}
	policyDir := t.TempDir()
	shipped := path.Join(layout.VendorPolicyDir, "guardrail", "strict")
	source := "config_version: 8\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\npolicy_dir: " +
		policyDir + "\nguardrail:\n  rule_pack_dir: " + shipped + "\nobservability: {}\n"
	result, err := MigrateV9(context.Background(), MigrateV9Input{
		ConfigPath: layout.ConfigPath, Source: []byte(source), PolicyDir: policyDir, Managed: true, InMemory: true,
	})
	if err != nil {
		t.Fatalf("MigrateV9: %v", err)
	}
	if got := string(result.Migrated); !strings.Contains(got, "rule_pack: strict") || strings.Contains(got, "custom_packs") {
		t.Fatalf("the shipped strict pack did not stay the preset:\n%s", got)
	}
	cfg := &Config{PolicyDir: policyDir, ConfigFilePath: layout.ConfigPath, DeploymentMode: "managed_enterprise"}
	cfg.Enterprise.Profile = "standalone"
	if got := cfg.ResolveRulePackDir(RulePackRef{Name: "strict"}); got != shipped {
		t.Fatalf("strict resolves to %q, want the shipped %s while policy_dir has none", got, shipped)
	}
}

// TestMigrateV9LeavesTheShippedFirstPartyListUnpinned: the first-party list
// every 0.8.x data.json shipped (also after `policy activate strict`) is not an
// operator's choice, so it is not written to config.yaml: the 1.0 built-in
// list applies and `policy list` still finds the activated preset (GAP-0971).
func TestMigrateV9LeavesTheShippedFirstPartyListUnpinned(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	dir := t.TempDir()
	dataJSON := filepath.Join(dir, "data.json")
	if err := os.WriteFile(dataJSON, []byte(`{"first_party_allow_list": [
	  {"target_type": "plugin", "target_name": "defenseclaw", "source_path_contains": [".openclaw/extensions/defenseclaw",
	    ".zeptoclaw/extensions/defenseclaw", ".claude/extensions/defenseclaw", ".codex/extensions/defenseclaw"]},
	  {"target_type": "skill", "target_name": "codeguard", "source_path_contains": [".openclaw/workspace/skills/codeguard",
	    ".openclaw/skills/codeguard", ".zeptoclaw/skills/codeguard", ".claude/skills/codeguard", ".codex/skills/codeguard"]}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	result, err := MigrateV9(context.Background(), MigrateV9Input{
		ConfigPath: filepath.Join(dir, "config.yaml"), DataJSONPath: dataJSON, DryRun: true,
		Source: []byte("config_version: 8\ndata_dir: " + dir + "\nobservability: {}\n"),
	})
	if err != nil {
		t.Fatalf("MigrateV9: %v", err)
	}
	if strings.Contains(string(result.Migrated), "first_party_allow_list") {
		t.Fatalf("the 0.8.x shipped first-party list was pinned:\n%s", result.Migrated)
	}
}

// TestMigrateV9DropsTheKeysTheRuntimeNoLongerHas: a 0.8.10-shaped v8 file with
// every key only an upgrade still understands (the three *_actions maps,
// update_check and the privacy: section) migrates to its v9 equivalent or is
// reported as dropped, and the same keys in a v9 file are refused.
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
registries:
  sources:
    - {id: corp, kind: http_yaml, url: "https://registry.example.test/s.yaml", content: skill, enabled: true, auto_sync: true, sync_interval_hours: 12}
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

		// In a v9 file the key is refused.
		v9 := "config_version: 9\n" + row.key + ": {}\nobservability: {}\n"
		if err := ValidateCandidate(configPath, []byte(v9)); err == nil || !strings.Contains(err.Error(), row.key) {
			t.Errorf("%s in a v9 file: got %v, want an error naming it", row.key, err)
		}
	}
	// The reserved registry sync keys are dropped from each source (GAP-0227)
	// and refused in a v9 file.
	for _, key := range []string{"auto_sync", "sync_interval_hours"} {
		if !slices.Contains(result.Record.Removed, "registries.sources[0]."+key) {
			t.Errorf("removed = %v, want registries.sources[0].%s", result.Record.Removed, key)
		}
		v9 := "config_version: 9\nregistries:\n  sources:\n    - {id: corp, kind: file, " + key + ": 1}\nobservability: {}\n"
		if err := ValidateCandidate(configPath, []byte(v9)); err == nil || !strings.Contains(err.Error(), key) {
			t.Errorf("registries.sources[0].%s in a v9 file: got %v, want an error naming it", key, err)
		}
	}
	if sources, _ := doc["registries"].(map[string]any)["sources"].([]any); len(sources) != 1 ||
		sources[0].(map[string]any)["auto_sync"] != nil || sources[0].(map[string]any)["sync_interval_hours"] != nil {
		t.Errorf("registries = %v, want the source without auto_sync and sync_interval_hours", doc["registries"])
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

// A config_version 8 file that still carries the *_actions keys (1.0.0 wrote
// skill_actions from `policy activate`) must pass the strict parse and the
// runtime load the upgrade check and `enterprise ensure` run on the v8 bytes
// before the migration moves the keys; in a v9 file the keys name their
// replacement.
func TestV8SourceWithTheActionKeysIsAccepted(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	body := "data_dir: " + dir + "\nskill_actions:\n  high: {file: none, runtime: enable, install: block}\n" +
		"mcp_actions:\n  medium: {file: none, runtime: enable, install: block}\n" +
		"plugin_actions:\n  critical: {file: quarantine, runtime: disable, install: block}\nprivacy: {}\nobservability: {}\n"
	v8 := []byte("config_version: 8\n" + body)
	if _, err := ParseCompileObservabilityV8(configPath, v8, ObservabilityV8CompileOptions{DefaultDataDir: dir}); err != nil {
		t.Errorf("v8 source with the action keys: %v", err)
	}
	if _, err := LoadRuntimeV8InspectionCandidateFromBytes(configPath, v8); err != nil {
		t.Errorf("runtime load of the v8 source: %v", err)
	}
	_, err := ParseCompileObservabilityV8(configPath, []byte("config_version: 9\n"+body), ObservabilityV8CompileOptions{DefaultDataDir: dir})
	if err == nil || !strings.Contains(err.Error(), "admission.skill.actions") {
		t.Errorf("v9 source with skill_actions: got %v, want a pointer to admission.skill.actions", err)
	}
	// A Secure Client source (Windows and macOS) keeps the keys, read and
	// validated as on main (GAP-0279, issue #1092).
	if runtime.GOOS == "linux" {
		return
	}
	secureClient := "config_version: 8\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: secure_client\n" + body
	cfg, err := LoadRuntimeV8InspectionCandidateFromBytes(configPath, []byte(secureClient))
	if err != nil {
		t.Fatalf("Secure Client v8 load: %v", err)
	}
	if cfg.SecureClientV8Actions["skill_actions"][1].Install != InstallBlock ||
		cfg.SecureClientV8Actions["plugin_actions"][0].File != FileActionQuarantine {
		t.Fatalf("Secure Client v8 actions = %v", cfg.SecureClientV8Actions)
	}
	invalid := strings.Replace(secureClient, "install: block}\nmcp_actions", "install: blok}\nmcp_actions", 1)
	if _, err := LoadRuntimeV8InspectionCandidateFromBytes(configPath, []byte(invalid)); err == nil ||
		!strings.Contains(err.Error(), `skill_actions.high.install: invalid value "blok"`) {
		t.Fatalf("Secure Client invalid skill_actions: got %v", err)
	}
}

// The migration opens audit.db by a file: URI built from the path, so a '#'
// or '%' in a directory name (legal in a user profile) must stay in the path.
func TestMigrateV9ReadsAuditDBUnderAnAwkwardPath(t *testing.T) {
	auditDB := filepath.Join(t.TempDir(), "ops#1%41", "audit.db")
	if err := os.MkdirAll(filepath.Dir(auditDB), 0o700); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", auditDB)
	if err != nil {
		t.Fatal(err)
	}
	for _, stmt := range []string{
		`CREATE TABLE actions (id TEXT PRIMARY KEY, target_type TEXT NOT NULL, target_name TEXT NOT NULL,
		  source_path TEXT, actions_json TEXT NOT NULL DEFAULT '{}', reason TEXT, updated_at DATETIME NOT NULL,
		  connector TEXT NOT NULL DEFAULT '')`,
		`INSERT INTO actions VALUES ('1','skill','bad-skill','','{"install":"block"}','operator','now','')`,
	} {
		if _, err := db.Exec(stmt); err != nil {
			t.Fatal(err)
		}
	}
	_ = db.Close()
	rows, err := readV9ActionRows(auditDB)
	if err != nil || len(rows) != 1 {
		t.Fatalf("rows = %d, err = %v", len(rows), err)
	}
	if err := clearV9ActionRows(auditDB, rows); err != nil {
		t.Fatalf("clear: %v", err)
	}
	if rows, err = readV9ActionRows(auditDB); err != nil || len(rows) != 0 {
		t.Fatalf("rows after clear = %d, err = %v", len(rows), err)
	}
}

// A comment about the old data document does not make a custom Rego module
// depend on it. Migration must leave the operator's active rules in place.
func TestMigrateV9KeepsCustomRegoWithLegacyComment(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("config_version: 8\nobservability: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	module := filepath.Join(dir, "policies", "rego", "admission.rego")
	if err := os.MkdirAll(filepath.Dir(module), 0o700); err != nil {
		t.Fatal(err)
	}
	custom := []byte("package defenseclaw.admission\nimport rego.v1\n# old data.config was removed\nverdict := \"blocked\" if { input.target.name == \"marker\" }\n")
	if err := os.WriteFile(module, custom, 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath}); err != nil {
		t.Fatal(err)
	}
	got, err := os.ReadFile(module)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(custom) {
		t.Fatalf("custom admission module was replaced: %s", got)
	}
}

// A missing provider CA changes TLS trust. If its destination is obstructed,
// the v8 config and live overlay must still be the active inputs.
func TestMigrateV9RefusesMissingProviderCA(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("config_version: 8\nobservability: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(dir, ProvidersOverlayFile)
	if err := os.WriteFile(overlay, []byte(`{"providers":[{"name":"acme","domains":["llm.acme.internal"],"env_keys":["ACME_KEY"],"tls":{"ca_cert_pem":"-----BEGIN CERTIFICATE-----\nx\n-----END CERTIFICATE-----\n"}}]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "provider-ca"), []byte("obstruction"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath}); err == nil {
		t.Fatal("migration succeeded without writing the provider CA")
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "config_version: 8") {
		t.Fatalf("config committed without the provider CA: %s", raw)
	}
	if _, err := os.Stat(overlay); err != nil {
		t.Fatalf("legacy overlay was removed: %v", err)
	}
}

// A protected-* folder is still a mutable v8 pack. Its manifest does not
// prove the rule files match a rebuilt base plus protections.
func TestMigrateV9PinsEditedProtectedRulePack(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	pack := filepath.Join(dir, "policies", "guardrail", "protected-team", "strict")
	if err := os.MkdirAll(filepath.Join(pack, "rules"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pack, "defenseclaw-pack.json"),
		[]byte(`{"version":1,"base":"strict","protection":["privacy-high-assurance"]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pack, "rules", "operator.yaml"), []byte("operator rule"), 0o600); err != nil {
		t.Fatal(err)
	}
	source := "config_version: 8\nguardrail:\n  rule_pack_dir: " + pack + "\nobservability: {}\n"
	result, err := MigrateV9(context.Background(), MigrateV9Input{
		ConfigPath: filepath.Join(dir, "config.yaml"), Source: []byte(source), DryRun: true,
		RulePackDigest: func(got string) (string, error) {
			if got != pack {
				t.Fatalf("digest requested for %s, want %s", got, pack)
			}
			return strings.Repeat("a", 64), nil
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	var doc struct {
		Guardrail struct {
			RulePack    string `yaml:"rule_pack"`
			CustomPacks map[string]struct {
				Path   string `yaml:"path"`
				Digest string `yaml:"digest"`
			} `yaml:"custom_packs"`
		} `yaml:"guardrail"`
	}
	if err := yaml.Unmarshal(result.Migrated, &doc); err != nil {
		t.Fatal(err)
	}
	ref := doc.Guardrail.RulePack
	if ref == "strict" || doc.Guardrail.CustomPacks[ref].Path != pack ||
		doc.Guardrail.CustomPacks[ref].Digest != "sha256:"+strings.Repeat("a", 64) {
		t.Fatalf("edited protected pack was not pinned: %s", result.Migrated)
	}
}

// The record is required evidence for a committed v9 config. A record path
// failure must leave v8 in place so clearing the obstruction allows a retry.
func TestMigrateV9RecordFailureCanRetry(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("config_version: 8\nobservability: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	recordPath := MigrationRecordPath(configPath)
	if err := os.Mkdir(recordPath, 0o700); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath}); err == nil {
		t.Fatal("migration succeeded with an obstructed record path")
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(raw), "config_version: 8") {
		t.Fatalf("config committed before the record: %s", raw)
	}
	if err := os.Remove(recordPath); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath}); err != nil {
		t.Fatalf("retry: %v", err)
	}
	record, ok := readMigrationRecord(configPath)
	if !ok || record.ToVersion != ConfigVersionV9 || record.Pending {
		t.Fatalf("retry did not write a committed v9 migration record: %+v", record)
	}
	// An interruption after the config commit can leave a durable pending
	// record. Retrying the already-v9 file must finish that record.
	record.Pending = true
	if err := writeMigrationRecord(recordPath, record); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath}); err != nil {
		t.Fatalf("finish pending record: %v", err)
	}
	if record, ok := readMigrationRecord(configPath); !ok || record.Pending {
		t.Fatalf("pending record was not finished: %+v", record)
	}
}

// An interruption after config commit can leave a pending record and the
// original operator row. A retry must finish clearing the migrated row.
func TestMigrateV9RetryClearsPendingAuditRows(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	dir := t.TempDir()
	t.Setenv("DEFENSECLAW_HOME", dir)
	configPath, auditDB := filepath.Join(dir, "config.yaml"), filepath.Join(dir, "audit.db")
	if err := os.WriteFile(configPath, []byte("config_version: 8\nobservability: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	db, err := sql.Open("sqlite", auditDB)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE actions (id TEXT PRIMARY KEY, target_type TEXT, target_name TEXT, source_path TEXT, actions_json TEXT, reason TEXT, updated_at TEXT, connector TEXT)`); err != nil {
		t.Fatal(err)
	}
	insert := `INSERT INTO actions VALUES ('1', 'skill', 'restored-skill', '', '{"install":"block"}', 'operator', 'now', '')`
	if _, err := db.Exec(insert); err != nil {
		t.Fatal(err)
	}
	in := MigrateV9Input{ConfigPath: configPath, AuditDBPath: auditDB}
	if _, err := MigrateV9(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	record, ok := readMigrationRecord(configPath)
	if !ok || record.ActionsRowsMoved != 1 {
		t.Fatalf("missing migrated row record: %+v", record)
	}
	if _, err := db.Exec(insert); err != nil {
		t.Fatal(err)
	}
	record.Pending = true
	if err := writeMigrationRecord(MigrationRecordPath(configPath), record); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateV9(context.Background(), in); err != nil {
		t.Fatal(err)
	}
	var count int
	if err := db.QueryRow("SELECT COUNT(*) FROM actions WHERE id = '1'").Scan(&count); err != nil || count != 0 {
		t.Fatalf("pending migrated row remains: count=%d err=%v", count, err)
	}
}

// Watcher enforcement rows are a journal, including failed scans and failed
// quarantine attempts. They must not become permanent operator policy.
func TestMigrateV9LeavesWatcherBlocksInAuditJournal(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE actions (id TEXT PRIMARY KEY, target_type TEXT, target_name TEXT, source_path TEXT, actions_json TEXT, reason TEXT, updated_at TEXT, connector TEXT)`); err != nil {
		t.Fatal(err)
	}
	for _, item := range []struct{ name, reason string }{
		{"finding", "auto-block: watch detected HIGH findings (scanner=plugin): RULE suspicious title"},
		{"readmit", "auto-block: watch detected HIGH findings (scanner=plugin); rescan retained block"},
		{"scan-error", "scanner failure (fail-closed): scanner unavailable"},
		{"quarantine-error", "quarantine failed: permission denied"},
		{"link-error", "link removed: target changed"},
		{"operator", "scan: incident review"},
	} {
		if _, err := db.Exec(`INSERT INTO actions VALUES (?, 'skill', ?, '', '{"install":"block"}', ?, 'now', '')`, item.name, item.name, item.reason); err != nil {
			t.Fatal(err)
		}
	}
	rows, err := readV9ActionRows(path)
	if err != nil || len(rows) != 1 || rows[0].targetName != "operator" {
		t.Fatalf("operator rows = %v, err = %v; want only operator decision", rows, err)
	}
}

func TestMigrateV9KeepsOperatorReasonBeginningWithScan(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE actions (id TEXT PRIMARY KEY, target_type TEXT, target_name TEXT, source_path TEXT, actions_json TEXT, reason TEXT, updated_at TEXT, connector TEXT);
  INSERT INTO actions VALUES ('1', 'skill', 's1', '', '{"install":"block"}', 'scan: incident review', 'now', '')`); err != nil {
		t.Fatal(err)
	}
	rows, err := readV9ActionRows(path)
	if err != nil || len(rows) != 1 || rows[0].targetName != "s1" {
		t.Fatalf("operator scan reason omitted: rows=%v err=%v", rows, err)
	}
}

func TestMigrateV9RejectsChangedAuditSnapshot(t *testing.T) {
	path := filepath.Join(t.TempDir(), "audit.db")
	db, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()
	if _, err := db.Exec(`CREATE TABLE actions (id TEXT PRIMARY KEY, target_type TEXT, target_name TEXT, source_path TEXT, actions_json TEXT, reason TEXT, updated_at TEXT, connector TEXT);
  INSERT INTO actions VALUES ('1', 'skill', 's1', '', '{"install":"block"}', 'operator', 'now', '')`); err != nil {
		t.Fatal(err)
	}
	snapshot, err := readV9ActionRows(path)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := db.Exec(`UPDATE actions SET actions_json = '{"install":"allow"}' WHERE id = '1'`); err != nil {
		t.Fatal(err)
	}
	locked, err := lockV9ActionRows(context.Background(), path, snapshot)
	if locked != nil {
		_ = locked.Close()
	}
	if err == nil {
		t.Fatal("migration accepted a changed operator decision")
	}
	var state string
	if err := db.QueryRow(`SELECT actions_json FROM actions WHERE id = '1'`).Scan(&state); err != nil || state != `{"install":"allow"}` {
		t.Fatalf("changed decision lost: state=%q err=%v", state, err)
	}
}

func TestMigrateV9KeepsProviderCABundlesDistinct(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(configPath, []byte("config_version: 8\nobservability: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	overlay := filepath.Join(dir, ProvidersOverlayFile)
	if err := os.WriteFile(overlay, []byte(`{"providers":[
  {"name":"acme.foo","tls":{"ca_cert_pem":"first certificate"}},
  {"name":"acme_foo","tls":{"ca_cert_pem":"second certificate"}}
 ]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := MigrateV9(context.Background(), MigrateV9Input{ConfigPath: configPath}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var cfg struct {
		LLMProviders struct {
			Custom []struct {
				Name string `yaml:"name"`
				TLS  struct {
					CACertFile string `yaml:"ca_cert_file"`
				} `yaml:"tls"`
			} `yaml:"custom"`
		} `yaml:"llm_providers"`
	}
	if err := yaml.Unmarshal(raw, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.LLMProviders.Custom) != 2 {
		t.Fatalf("providers = %d", len(cfg.LLMProviders.Custom))
	}
	paths := map[string]string{}
	for _, provider := range cfg.LLMProviders.Custom {
		paths[provider.Name] = provider.TLS.CACertFile
	}
	if paths["acme.foo"] == paths["acme_foo"] {
		t.Fatal("distinct providers share a CA path")
	}
	for name, want := range map[string]string{"acme.foo": "first certificate", "acme_foo": "second certificate"} {
		got, err := os.ReadFile(paths[name])
		if err != nil || string(got) != want {
			t.Errorf("%s CA = %q, err = %v", name, got, err)
		}
	}
}

// An audit allow at a distinct source path must survive alongside the v8
// config allow for the same skill and connector.
func TestMigrateV9KeepsDistinctPathPinnedAllow(t *testing.T) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(`asset_policy:
  skill:
    allowed: [{name: acme, connector: codex, source_path_contains: [/trusted]}]
`), &doc); err != nil {
		t.Fatal(err)
	}
	m := &v9Migrator{}
	row := v9ActionRow{id: "2", targetType: AdmissionTypeSkill, targetName: "acme",
		connector: "codex", sourcePath: "/other"}
	if !m.appendAssetRule(v8DocumentRoot(&doc), row, "allowed") {
		t.Fatal("audit allow was not migrated")
	}
	root := v8DocumentRoot(&doc)
	rules := v9SeqItems(v8YAMLMapValue(v8YAMLMapValue(v8YAMLMapValue(root, "asset_policy"), "skill"), "allowed"))
	if len(rules) != 2 {
		t.Fatalf("allowed rules = %d, want both pinned paths", len(rules))
	}
	if path := v9SeqItems(v8YAMLMapValue(rules[1], "source_path_contains")); len(path) != 1 || yamlScalarValue(path[0]) != "/other" {
		t.Fatalf("migrated allow has source_path_contains = %v", path)
	}
}

// A v8 audit block applies to every URL, even when the v9 config already
// denies one URL for the same server name.
func TestMigrateV9KeepsNameWideDenyBesideURLDeny(t *testing.T) {
	var doc yaml.Node
	if err := yaml.Unmarshal([]byte(`asset_policy:
  mcp:
    denied: [{name: acme, connector: codex, url: https://one.example/mcp}]
`), &doc); err != nil {
		t.Fatal(err)
	}
	m := &v9Migrator{}
	row := v9ActionRow{id: "2", targetType: AdmissionTypeMCP, targetName: "acme", connector: "codex"}
	root := v8DocumentRoot(&doc)
	if !m.appendAssetRule(root, row, "denied") {
		t.Fatal("audit block was not migrated")
	}
	rules := v9SeqItems(v8YAMLMapValue(v8YAMLMapValue(v8YAMLMapValue(root, "asset_policy"), "mcp"), "denied"))
	if len(rules) != 2 || v8YAMLMapValue(rules[1], "url") != nil {
		t.Fatalf("migrated rules did not retain the name-wide block: %v", rules)
	}
}

// The Python upgrade step adds unscannable_mcp to migration-v9.json after the
// commit; marking the record read must keep it for doctor (GAP-1340).
func TestAcknowledgeMigrationV9KeepsUnscannableMCP(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), DefaultConfigName)
	raw := `{"schema_version":1,"from_version":8,"to_version":9,"source_sha256":"abc","moved":[],"conflicts":[],` +
		`"unscannable_mcp":[{"name":"u33a-mcp","connector":"codex","command":"/usr/bin/true","reason":"r",` +
		`"runtime_effect":"still runs","fix":"defenseclaw mcp set u33a-mcp --command npx --args <package>"}]}`
	if err := os.WriteFile(MigrationRecordPath(configPath), []byte(raw), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := AcknowledgeMigrationV9(configPath); err != nil {
		t.Fatal(err)
	}
	record, ok := readMigrationRecord(configPath)
	if !ok || !record.Acknowledged {
		t.Fatalf("record not acknowledged: %+v", record)
	}
	want := []MigrationUnscannableMCP{{
		Name: "u33a-mcp", Connector: "codex", Command: "/usr/bin/true", Reason: "r",
		RuntimeEffect: "still runs", Fix: "defenseclaw mcp set u33a-mcp --command npx --args <package>",
	}}
	if !slices.Equal(record.UnscannableMCP, want) {
		t.Fatalf("unscannable_mcp = %+v, want %+v", record.UnscannableMCP, want)
	}
}
