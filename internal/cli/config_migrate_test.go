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

import (
	"context"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	policyassets "github.com/defenseclaw/defenseclaw/policies"
)

func TestMigrateManagedStandaloneConfigRecordsStagedBundle(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	raw := []byte("config_version: 9\nobservability: {}\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := migrateManagedStandaloneConfig(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	saved := managedStandaloneBundleGeneration
	t.Cleanup(func() { managedStandaloneBundleGeneration = saved })
	const id = "b-01JA0000000000000000000039"
	managedStandaloneBundleGeneration = func(gotPath string, gotRaw []byte) (configwrite.Options, bool, error) {
		if gotPath != path || string(gotRaw) != string(raw) {
			t.Fatalf("bundle lookup got %s and %q", gotPath, gotRaw)
		}
		return configwrite.Options{Actor: "control-plane:acme/alice", Lifecycle: true,
			Reason: configwrite.BundleReason(id, 3, "guardrail pack update"),
			Bundle: configwrite.BundleRef{ID: id, Version: 3, SignerKeyID: "k1"}}, true, nil
	}
	if err := migrateManagedStandaloneConfig(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	got, ok := observabilityruntime.ReadBundleAttribution(path)
	if !ok || got.Principal != "control-plane:acme/alice" || got.ID != id || got.Version != 3 || got.SignerKeyID != "k1" {
		t.Fatalf("restart config.change.applied bundle attribution = %+v, ok=%v", got, ok)
	}
}

// The Windows standalone config step migrates a v8 config in place with the
// lifecycle actor, then only records an unrecorded config.
func TestMigrateManagedStandaloneConfig(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	v8 := []byte("config_version: 8\ndata_dir: " + dir + "\nobservability: {}\n")
	if err := os.WriteFile(path, v8, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := migrateManagedStandaloneConfig(context.Background(), path); err != nil {
		t.Fatalf("migrate: %v", err)
	}
	raw, _ := os.ReadFile(path)
	if config.NeedsMigrationV9(raw) {
		t.Fatal("config.yaml is still config_version 8")
	}
	if backup, _ := os.ReadFile(path + config.ConfigV8BackupSuffix); string(backup) != string(v8) {
		t.Fatal("config.yaml.v8.bak does not hold the v8 bytes")
	}
	state, err := configwrite.ReadGenerationState(path)
	if err != nil || state.Actor != configwrite.ActorLifecycle || state.ConfigSHA256 != configwrite.SHA256Hex(raw) {
		t.Fatalf("generation = %+v (%v)", state, err)
	}
	if err := migrateManagedStandaloneConfig(context.Background(), path); err != nil {
		t.Fatalf("second run: %v", err)
	}
	if again, _ := configwrite.ReadGenerationState(path); again.Generation != state.Generation {
		t.Fatalf("an unchanged config advanced the generation to %d", again.Generation)
	}
}

// The Windows config step restores a Cursor fail mode the 1.0.0-1.0.2
// migration rewrote to open, through the config writer, once; an open the
// administrator sets afterwards stays, and without a record nothing changes.
func TestMigrateManagedStandaloneConfigRestoresMigratedCursorFailMode(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	const key = "guardrail.connectors.cursor.hook_fail_mode"
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	open := []byte("config_version: 9\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\ndata_dir: " + dir +
		"\nobservability: {}\nguardrail:\n  mode: observe\n  connectors:\n    cursor:\n      hook_fail_mode: open\n")
	if err := os.WriteFile(path, open, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := migrateManagedStandaloneConfig(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(path); string(raw) != string(open) {
		t.Fatalf("no record, but the config changed:\n%s", raw)
	}
	record := config.MigrationRecord{
		SchemaVersion: config.MigrationRecordSchemaVersion, FromVersion: 8, ToVersion: 9, Actor: "lifecycle",
		SourceSHA256: strings.Repeat("c", 64), ResultSHA256: configwrite.SHA256Hex(open),
		Moved: []config.MigrationMove{{Source: "config", From: key, To: key, Value: "open"}},
	}
	if err := config.WriteMigrationRecord(path, record); err != nil {
		t.Fatal(err)
	}
	if err := migrateManagedStandaloneConfig(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	repaired, _ := os.ReadFile(path)
	if want := strings.Replace(string(open), "hook_fail_mode: open", "hook_fail_mode: closed", 1); string(repaired) != want {
		t.Fatalf("repaired config:\n%s", repaired)
	}
	state, err := configwrite.ReadGenerationState(path)
	if err != nil || state.Actor != configwrite.ActorLifecycle || state.ConfigSHA256 != configwrite.SHA256Hex(repaired) {
		t.Fatalf("generation = %+v (%v)", state, err)
	}
	if err := migrateManagedStandaloneConfig(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if again, _ := configwrite.ReadGenerationState(path); again.Generation != state.Generation {
		t.Fatal("the repair ran twice")
	}
	adminOpen := strings.Replace(string(repaired), "hook_fail_mode: closed", "hook_fail_mode: open", 1)
	if err := os.WriteFile(path, []byte(adminOpen), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := migrateManagedStandaloneConfig(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(path); string(raw) != adminOpen {
		t.Fatalf("an administrator open set after the repair was undone:\n%s", raw)
	}
}

// A rollback records the config it restored as a new generation and never
// takes a number back.
func TestRecordRestoredManagedStandaloneConfig(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("config_version: 9\nobservability: {}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recordRestoredManagedStandaloneConfig(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(configwrite.GenerationPath(path)); !os.IsNotExist(err) {
		t.Fatalf("a restored config with no record got one: %v", err)
	}
	if err := migrateManagedStandaloneConfig(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	installed, _ := configwrite.ReadGenerationState(path)
	if err := os.WriteFile(path, []byte("config_version: 9\nobservability:\n  enabled: false\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recordRestoredManagedStandaloneConfig(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	restored, _ := configwrite.ReadGenerationState(path)
	raw, _ := os.ReadFile(path)
	if restored.Generation <= installed.Generation || restored.ConfigSHA256 != configwrite.SHA256Hex(raw) {
		t.Fatalf("restored generation = %+v after %+v", restored, installed)
	}
	if err := recordRestoredManagedStandaloneConfig(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if again, _ := configwrite.ReadGenerationState(path); again.Generation != restored.Generation {
		t.Fatalf("an unchanged restore advanced the generation to %d", again.Generation)
	}
}

// A destination key kept only in the data directory's .env resolves while the
// migrated document is validated (GAP-0035).
func TestConfigMigrateResolvesCredentialsFromDotEnv(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	t.Setenv("P0_MIGRATE_DEST_KEY", "")
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	v8 := "config_version: 8\ndata_dir: " + dir + "\nobservability:\n  destinations:\n" +
		"    - name: remote\n      kind: otlp\n      endpoint: https://otel.example.test\n" +
		"      headers:\n        Authorization: {env: P0_MIGRATE_DEST_KEY}\n"
	if err := os.WriteFile(path, []byte(v8), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ".env"), []byte("P0_MIGRATE_DEST_KEY=secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	input, err := configMigrateV9Input(path)
	if err != nil {
		t.Fatal(err)
	}
	input.DryRun = true
	if _, err := config.MigrateV9(context.Background(), input); err != nil {
		t.Fatalf("dry-run migration with the key in .env: %v", err)
	}
}

// A Secure Client config stays on config_version 8: `config migrate` succeeds
// without writing anything (GAP-0110, issue #1092).
func TestConfigMigrateLeavesASecureClientConfigUnchanged(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	previousPath, previousTo := configMigratePath, configMigrateTo
	t.Cleanup(func() { configMigratePath, configMigrateTo = previousPath, previousTo })
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	v8 := []byte("config_version: 8\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: secure_client\ndata_dir: " + dir + "\nobservability: {}\n")
	if err := os.WriteFile(path, v8, 0o600); err != nil {
		t.Fatal(err)
	}
	configMigratePath, configMigrateTo = path, config.ConfigVersionV9
	if err := configMigrateCmd.RunE(configMigrateCmd, nil); err != nil {
		t.Fatalf("config migrate failed on a Secure Client config: %v", err)
	}
	entries, _ := os.ReadDir(dir)
	if raw, _ := os.ReadFile(path); string(raw) != string(v8) || len(entries) != 1 {
		t.Fatalf("config migrate changed the Secure Client directory: %d entries", len(entries))
	}
}

// A v8 policy_dir under the login home must be read by the CLI migration,
// just as the gateway's in-memory migration reads it.
func TestConfigMigrateReadsTildePolicyData(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	home := t.TempDir()
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	dataDir := t.TempDir()
	path := filepath.Join(dataDir, "config.yaml")
	source := []byte("config_version: 8\ndata_dir: " + dataDir + "\npolicy_dir: ~/policies\nobservability: {}\n")
	if err := os.WriteFile(path, source, 0o600); err != nil {
		t.Fatal(err)
	}
	dataJSON := filepath.Join(home, "policies", "rego", "data.json")
	if err := os.MkdirAll(filepath.Dir(dataJSON), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(dataJSON, []byte(`{"actions":{"MEDIUM":{"install":"block","file":"none","runtime":"block"}}}`), 0o600); err != nil {
		t.Fatal(err)
	}
	input, err := configMigrateV9Input(path)
	if err != nil {
		t.Fatal(err)
	}
	input.DryRun = true
	result, err := config.MigrateV9(context.Background(), input)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(result.Migrated), "medium: block") {
		t.Fatalf("migration missed policy data from %s", dataJSON)
	}
}

// The default pack that 0.8.x init seeds is edited in place, and 0.8.x init
// writes no rule_pack_dir. `config migrate` gives such a folder a 1.0 copy:
// a rule file that repeats the category of commands.yaml is merged into it
// instead of failing the upgrade (GAP-1479), and a pattern-only rule gets an
// expression from its literal, which still matches the prompt (GAP-1480).
func TestConfigMigrateRebasesTheDefaultPackEditedInPlace(t *testing.T) {
	const marker = "u6-block-marker-7f3c"
	cases := []struct {
		name, file, rule, id string
	}{
		{name: "rule file repeating a category", file: "rules/u6-custom.yaml", id: "CMD-U6-CUSTOM",
			rule: "version: 1\ncategory: command\nrules:\n  - id: CMD-U6-CUSTOM\n    pattern: u6-custom-marker-1d2e\n" +
				"    title: U6 custom\n    severity: HIGH\n    confidence: 0.9\n    tags: [marker]\n"},
		{name: "pattern-only rule in commands.yaml", file: "rules/commands.yaml", id: "CMD-U6-MARKER",
			rule: "  - id: CMD-U6-MARKER\n    pattern: " + marker + "\n    title: U6 marker\n    severity: CRITICAL\n" +
				"    confidence: 0.99\n    tags: [marker]\n"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
			t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
			dir := t.TempDir()
			t.Setenv("DEFENSECLAW_HOME", dir)
			pack := filepath.Join(dir, "policies", "guardrail", "default")
			files, err := policyassets.Files()
			if err != nil {
				t.Fatal(err)
			}
			for _, file := range files {
				if rel, ok := strings.CutPrefix(file.Path, "guardrail/default/"); ok {
					target := filepath.Join(pack, filepath.FromSlash(rel))
					if err := os.MkdirAll(filepath.Dir(target), 0o700); err != nil {
						t.Fatal(err)
					}
					if err := os.WriteFile(target, file.Data, 0o600); err != nil {
						t.Fatal(err)
					}
				}
			}
			edited := filepath.Join(pack, filepath.FromSlash(tc.file))
			old, _ := os.ReadFile(edited)
			if err := os.WriteFile(edited, append(old, tc.rule...), 0o600); err != nil {
				t.Fatal(err)
			}
			path := filepath.Join(dir, "config.yaml")
			v8 := "config_version: 8\ndata_dir: " + dir + "\nguardrail:\n  mode: action\n  connectors:\n" +
				"    claudecode:\n      rule_pack_dir: ''\nobservability: {}\n"
			if err := os.WriteFile(path, []byte(v8), 0o600); err != nil {
				t.Fatal(err)
			}
			input, err := configMigrateV9Input(path)
			if err != nil {
				t.Fatal(err)
			}
			result, err := config.MigrateV9(context.Background(), input)
			if err != nil {
				t.Fatalf("migrate the edited default pack: %v", err)
			}
			copyDir := pack + "-1.0"
			if got := string(result.Migrated); !strings.Contains(got, "rule_pack: custom-default") ||
				!strings.Contains(got, "path: "+copyDir) {
				t.Fatalf("want the 1.0 copy of the edited folder selected:\n%s", got)
			}
			if _, err := guardrail.LoadRulePack(copyDir); err != nil {
				t.Fatalf("the 1.0 copy does not load: %v", err)
			}
			if _, err := os.Stat(filepath.Join(copyDir, "rules", "u6-custom.yaml")); err == nil {
				t.Errorf("the 1.0 copy still has rules/u6-custom.yaml")
			}
			if tc.file != "rules/commands.yaml" && len(result.Record.RuleFileMerges) != 1 {
				t.Errorf("rule file merges %q, want the merge reported", result.Record.RuleFileMerges)
			}
			if !slices.Contains(result.Record.ExpressedRules, tc.id) {
				t.Errorf("expressed rules %q, want %s", result.Record.ExpressedRules, tc.id)
			}
			raw, err := os.ReadFile(filepath.Join(copyDir, "rules", "commands.yaml"))
			if err != nil {
				t.Fatal(err)
			}
			var commands guardrail.RulesFileYAML
			if err := yaml.Unmarshal(raw, &commands); err != nil {
				t.Fatal(err)
			}
			i := slices.IndexFunc(commands.Rules, func(rule guardrail.RuleDefYAML) bool { return rule.ID == tc.id })
			if i < 0 {
				t.Fatalf("rules/commands.yaml of the 1.0 copy has no %s", tc.id)
			}
			rule := commands.Rules[i]
			if !guardrail.MigratedLiteralRule(rule.Pattern, rule.Expression) {
				t.Errorf("%s: expression %q is not the literal form of %q", tc.id, rule.Expression, rule.Pattern)
			}
			if tc.id == "CMD-U6-MARKER" && !regexp.MustCompile(rule.Pattern).MatchString("run: echo "+marker) {
				t.Errorf("%s pattern %q no longer matches the prompt", tc.id, rule.Pattern)
			}
		})
	}
}
