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
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"runtime"
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
		MigratedAt:   "2026-09-01T00:00:00Z",
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

// --dry-run writes nothing, so --dry-run --ack is refused and leaves the
// pending record as it is (GAP-0627).
func TestConfigMigrateDryRunAckWritesNothing(t *testing.T) {
	previousPath, previousTo, previousDry, previousAck := configMigratePath, configMigrateTo, configMigrateDryRun, configMigrateAck
	t.Cleanup(func() {
		configMigratePath, configMigrateTo, configMigrateDryRun, configMigrateAck = previousPath, previousTo, previousDry, previousAck
	})
	dir := t.TempDir()
	path := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(path, []byte("config_version: 9\ndata_dir: "+dir+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	record := config.MigrationRecordPath(path)
	pending := []byte(`{"from_version":8,"to_version":9}`)
	if err := os.WriteFile(record, pending, 0o600); err != nil {
		t.Fatal(err)
	}
	configMigratePath, configMigrateTo, configMigrateDryRun, configMigrateAck = path, config.ConfigVersionV9, true, true
	err := configMigrateCmd.RunE(configMigrateCmd, nil)
	if err == nil || !strings.Contains(err.Error(), "use one of them") {
		t.Fatalf("config migrate --dry-run --ack = %v, want a refusal", err)
	}
	if raw, _ := os.ReadFile(record); string(raw) != string(pending) {
		t.Fatalf("config migrate --dry-run --ack changed %s: %s", record, raw)
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
			if !guardrail.MigratedLiteralRule(rule.Pattern, rule.Expression, rule.MigratedLiteral) {
				t.Errorf("%s: expression %q is not the literal form of %q", tc.id, rule.Expression, rule.Pattern)
			}
			if tc.id == "CMD-U6-MARKER" && !regexp.MustCompile(rule.Pattern).MatchString("run: echo "+marker) {
				t.Errorf("%s pattern %q no longer matches the prompt", tc.id, rule.Pattern)
			}
		})
	}
}

// Re-review P1: a signed policy bundle whose config bytes match an old v9
// migration result is the administrator's signed choice. Once it is
// confirmed (its config generation names the bundle, or the bundle store has
// a current bundle) the Windows config step never repairs its explicit open.
func TestMigrateManagedStandaloneConfigNeverRepairsABundleConfig(t *testing.T) {
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
	record := config.MigrationRecord{
		SchemaVersion: config.MigrationRecordSchemaVersion, FromVersion: 8, ToVersion: 9, Actor: "lifecycle",
		MigratedAt:   "2026-09-01T00:00:00Z",
		SourceSHA256: strings.Repeat("c", 64), ResultSHA256: configwrite.SHA256Hex(open),
		Moved: []config.MigrationMove{{Source: "config", From: key, To: key, Value: "open"}},
	}
	if err := config.WriteMigrationRecord(path, record); err != nil {
		t.Fatal(err)
	}
	// The confirmed bundle's generation attribution.
	generation := `{"generation":3,"config_sha256":"` + configwrite.SHA256Hex(open) +
		`","actor":"bundle","written_at":"2026-10-20T00:00:00Z","bundle_id":"acme-endpoints","bundle_version":4,"signer_key_id":"k1"}`
	if err := os.WriteFile(configwrite.GenerationPath(path), []byte(generation), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := migrateManagedStandaloneConfig(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(path); string(raw) != string(open) {
		t.Fatalf("a confirmed bundle's config was repaired:\n%s", raw)
	}

	// A current bundle in the store, whatever the generation record says.
	if err := os.Remove(configwrite.GenerationPath(path)); err != nil {
		t.Fatal(err)
	}
	previous := managedStandaloneBundleCurrent
	t.Cleanup(func() { managedStandaloneBundleCurrent = previous })
	managedStandaloneBundleCurrent = func() (bool, error) { return true, nil }
	if err := migrateManagedStandaloneConfig(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(path); string(raw) != string(open) {
		t.Fatalf("the config of a host with a current bundle was repaired:\n%s", raw)
	}

	// No bundle: the record's rewrite is repaired, as before.
	managedStandaloneBundleCurrent = func() (bool, error) { return false, nil }
	if err := os.Remove(configwrite.GenerationPath(path)); err != nil && !os.IsNotExist(err) {
		t.Fatal(err)
	}
	if err := migrateManagedStandaloneConfig(context.Background(), path); err != nil {
		t.Fatal(err)
	}
	if raw, _ := os.ReadFile(path); !strings.Contains(string(raw), "hook_fail_mode: closed") {
		t.Fatalf("without a bundle the migrated open must be repaired:\n%s", raw)
	}
}

// G-small loop 4, finding 2: the Windows config step reads the
// migration-v9.json beside the installed config. A record that is there but
// cannot be read or decoded is an error, not "no record": the step does not
// report the Cursor fail mode it may prove rewritten as settled, and the
// config stays as it is.
func TestMigrateManagedStandaloneConfigRefusesAMigrationRecordItCannotRead(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	for _, tc := range []struct {
		name  string
		place func(recordPath string) error
	}{
		{"undecodable", func(recordPath string) error { return os.WriteFile(recordPath, []byte(`{"moved":[`), 0o600) }},
		// G-small loop round 2: a record that decodes without the fields
		// every migration writes is not "no record".
		{"an empty object", func(recordPath string) error { return os.WriteFile(recordPath, []byte(`{}`), 0o600) }},
		{"null", func(recordPath string) error { return os.WriteFile(recordPath, []byte(`null`), 0o600) }},
		{"a directory", func(recordPath string) error { return os.Mkdir(recordPath, 0o700) }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			open := []byte("config_version: 9\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\ndata_dir: " + dir +
				"\nobservability: {}\nguardrail:\n  mode: observe\n  connectors:\n    cursor:\n      hook_fail_mode: open\n")
			if err := os.WriteFile(path, open, 0o600); err != nil {
				t.Fatal(err)
			}
			if err := tc.place(config.MigrationRecordPath(path)); err != nil {
				t.Fatal(err)
			}
			err := migrateManagedStandaloneConfig(context.Background(), path)
			if err == nil || !strings.Contains(err.Error(), config.MigrationV9RecordFile) {
				t.Fatalf("config step = %v, want an error naming %s", err, config.MigrationV9RecordFile)
			}
			if raw, _ := os.ReadFile(path); string(raw) != string(open) {
				t.Fatalf("the config changed under an unreadable record:\n%s", raw)
			}
		})
	}
}

// G-small: only nothing at the path of migration-v9.json means no record.
// A dangling link read through its path looked like a missing record, and a
// Windows ensure reported compliance while the Cursor correction it may prove
// stayed unapplied. A link (dangling or live), a directory, a record past the
// bound are errors that name the record.
func TestManagedMigrationRecordReadRefusesWhatIsNotAPlainFile(t *testing.T) {
	const limit = 64
	dir := t.TempDir()
	target := filepath.Join(dir, "elsewhere.json")
	if err := os.WriteFile(target, []byte(`{"schema_version":1}`), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name    string
		place   func(t *testing.T, recordPath string)
		want    string
		wantErr bool
	}{
		{name: "nothing there", place: func(*testing.T, string) {}},
		{name: "a plain record", place: func(t *testing.T, p string) {
			if err := os.WriteFile(p, []byte(`{"schema_version":1}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}, want: `{"schema_version":1}`},
		{name: "a directory", place: func(t *testing.T, p string) {
			if err := os.Mkdir(p, 0o700); err != nil {
				t.Fatal(err)
			}
		}, wantErr: true},
		{name: "past the bound", place: func(t *testing.T, p string) {
			if err := os.WriteFile(p, []byte(strings.Repeat(" ", limit+1)), 0o600); err != nil {
				t.Fatal(err)
			}
		}, wantErr: true},
		{name: "a dangling link", place: func(t *testing.T, p string) {
			symlinkOrSkip(t, filepath.Join(dir, "gone.json"), p)
		}, wantErr: true},
		{name: "a live link", place: func(t *testing.T, p string) { symlinkOrSkip(t, target, p) }, wantErr: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			recordPath := filepath.Join(t.TempDir(), config.MigrationV9RecordFile)
			tc.place(t, recordPath)
			raw, err := readManagedMigrationRecord(recordPath, limit)
			if (err != nil) != tc.wantErr || string(raw) != tc.want {
				t.Fatalf("read = %q, %v; want %q with error=%v", raw, err, tc.want, tc.wantErr)
			}
			if tc.wantErr && !strings.Contains(err.Error(), config.MigrationV9RecordFile) {
				t.Fatalf("error %q does not name %s", err, config.MigrationV9RecordFile)
			}
			if tc.want == "" && !tc.wantErr && raw != nil {
				t.Fatalf("no record read as %q", raw)
			}
		})
	}
}

// G-small: the Windows config step refuses a migration-v9.json that is a
// link, dangling or live, and leaves the config as it is: it neither reads a
// dangling link as no record nor follows a live one.
func TestMigrateManagedStandaloneConfigRefusesALinkedMigrationRecord(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	for _, live := range []bool{false, true} {
		dir := t.TempDir()
		path := filepath.Join(dir, "config.yaml")
		open := []byte("config_version: 9\ndeployment_mode: managed_enterprise\nenterprise:\n  profile: standalone\ndata_dir: " + dir +
			"\nobservability: {}\nguardrail:\n  mode: observe\n  connectors:\n    cursor:\n      hook_fail_mode: open\n")
		if err := os.WriteFile(path, open, 0o600); err != nil {
			t.Fatal(err)
		}
		target := filepath.Join(t.TempDir(), "record.json")
		if live {
			if err := os.WriteFile(target, []byte(`{"schema_version":1}`), 0o600); err != nil {
				t.Fatal(err)
			}
		}
		symlinkOrSkip(t, target, config.MigrationRecordPath(path))
		err := migrateManagedStandaloneConfig(context.Background(), path)
		if err == nil || !strings.Contains(err.Error(), config.MigrationV9RecordFile) {
			t.Fatalf("live=%v: config step = %v, want an error naming %s", live, err, config.MigrationV9RecordFile)
		}
		if raw, _ := os.ReadFile(path); string(raw) != string(open) {
			t.Fatalf("live=%v: the config changed under a linked record:\n%s", live, raw)
		}
	}
}

// symlinkOrSkip links link to target, or skips where the account may not
// create symbolic links (Windows without the privilege).
func symlinkOrSkip(t *testing.T, target, link string) {
	t.Helper()
	if err := os.Symlink(target, link); err != nil {
		if runtime.GOOS == "windows" {
			t.Skipf("symbolic links unavailable: %v", err)
		}
		t.Fatal(err)
	}
}

func TestMigrateManagedStandaloneConfigRefusesAnUnrecoverableGeneration(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	raw := []byte("config_version: 9\nobservability: {}\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	record := []byte("broken record")
	if err := os.WriteFile(configwrite.GenerationPath(path), record, 0o600); err != nil {
		t.Fatal(err)
	}
	err := migrateManagedStandaloneConfig(context.Background(), path)
	after, _ := os.ReadFile(configwrite.GenerationPath(path))
	if err == nil || !strings.Contains(err.Error(), "restore") || string(after) != string(record) {
		t.Fatalf("unrecoverable record: error=%v, bytes=%q", err, after)
	}
}

func TestManagedStandaloneConfigGenerationRecoveryRequiresProof(t *testing.T) {
	path := filepath.Join(t.TempDir(), "config.yaml")
	raw := []byte("config_version: 9\nobservability: {}\n")
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	record := []byte("broken record")
	if err := os.WriteFile(configwrite.GenerationPath(path), record, 0o600); err != nil {
		t.Fatal(err)
	}
	if changed, err := repairManagedStandaloneConfigGeneration(context.Background(), path, raw, 0); err == nil || changed {
		t.Fatalf("unproven counter accepted: %v, %v", changed, err)
	}
	after, _ := os.ReadFile(configwrite.GenerationPath(path))
	if string(after) != string(record) {
		t.Fatal("refused repair changed the record")
	}
	if changed, err := repairManagedStandaloneConfigGeneration(context.Background(), path, raw, 10); err != nil || !changed {
		t.Fatalf("proven counter refused: %v, %v", changed, err)
	}
	state, err := configwrite.ReadGenerationState(path)
	if err != nil || state.Generation != 11 || state.Actor != configwrite.ActorLifecycle {
		t.Fatalf("recovered record = %+v, %v", state, err)
	}
}

// W4b loop round 1: a Codex target repair (or an equal-byte first bundle
// upgrade) runs this step in the lifecycle child with the staged bundle
// matching the installed bytes. Over generation evidence that is there but
// unreadable it refuses before it migrates, records or re-permissions
// anything, for a config_version 9 and a config_version 8 install alike.
// Without a staged bundle the step still records the lifecycle as before.
func TestMigrateManagedStandaloneConfigRefusesBundleBindingOverUnreadableGeneration(t *testing.T) {
	t.Setenv("DEFENSECLAW_DEPLOYMENT_MODE", "")
	t.Setenv("DEFENSECLAW_ENTERPRISE_PROFILE", "")
	const id = "b-01JA0000000000000000000360"
	for _, tc := range []struct {
		name    string
		version int
		staged  bool
		link    bool
	}{
		{name: "v9 staged bundle", version: 9, staged: true},
		{name: "v8 staged bundle", version: 8, staged: true},
		{name: "v9 without a bundle", version: 9},
		// W4b loop round 2: a dangling link reads as a missing record.
		{name: "v9 staged bundle over a dangling link", version: 9, staged: true, link: true},
		{name: "v8 staged bundle over a dangling link", version: 8, staged: true, link: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "config.yaml")
			raw := []byte(fmt.Sprintf("config_version: %d\ndata_dir: %s\nobservability: {}\n", tc.version, dir))
			if err := os.WriteFile(path, raw, 0o600); err != nil {
				t.Fatal(err)
			}
			broken := []byte(`{"generation":4,"config_sha256":`)
			gone := filepath.Join(t.TempDir(), "gone.json")
			if tc.link {
				symlinkOrSkip(t, gone, configwrite.GenerationPath(path))
			} else if err := os.WriteFile(configwrite.GenerationPath(path), broken, 0o600); err != nil {
				t.Fatal(err)
			}
			saved := managedStandaloneBundleGeneration
			t.Cleanup(func() { managedStandaloneBundleGeneration = saved })
			managedStandaloneBundleGeneration = func(string, []byte) (configwrite.Options, bool, error) {
				if !tc.staged {
					return configwrite.Options{}, false, nil
				}
				return configwrite.Options{Actor: "control-plane:acme/alice", Lifecycle: true,
					Reason: configwrite.BundleReason(id, 1, "codex target"),
					Bundle: configwrite.BundleRef{ID: id, Version: 1, SignerKeyID: "k1"}}, true, nil
			}
			err := migrateManagedStandaloneConfig(context.Background(), path)
			if !tc.staged {
				// fix/r104-windows: an unreadable record is never reset to a
				// fresh lifecycle record; the step refuses and names the
				// backup restore (GAP-0236), bundle or not.
				if err == nil || !strings.Contains(err.Error(), "restore") {
					t.Fatalf("unreadable record without a bundle: %v", err)
				}
				if after, err := os.ReadFile(configwrite.GenerationPath(path)); err != nil || string(after) != string(broken) {
					t.Fatalf("the refusal rewrote the generation evidence: %q, %v", after, err)
				}
				return
			}
			if !errors.Is(err, configwrite.ErrUnprovenBundleBinding) || !strings.Contains(err.Error(), "enterprise bundle status --json") {
				t.Fatalf("bundle binding over unreadable generation: %v", err)
			}
			if tc.link {
				if got, err := os.Readlink(configwrite.GenerationPath(path)); err != nil || got != gone {
					t.Fatalf("the refusal replaced the dangling link: %q, %v", got, err)
				}
			} else if after, err := os.ReadFile(configwrite.GenerationPath(path)); err != nil || string(after) != string(broken) {
				t.Fatalf("the refusal rewrote the generation evidence: %q, %v", after, err)
			}
			if after, err := os.ReadFile(path); err != nil || string(after) != string(raw) {
				t.Fatalf("the refusal changed config.yaml: %q, %v", after, err)
			}
			for _, leftover := range []string{path + config.ConfigV8BackupSuffix, config.MigrationRecordPath(path)} {
				if _, err := os.Stat(leftover); !errors.Is(err, fs.ErrNotExist) {
					t.Fatalf("the refusal wrote %s: %v", leftover, err)
				}
			}
		})
	}
}
