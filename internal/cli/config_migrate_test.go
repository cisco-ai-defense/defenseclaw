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
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/config/configwrite"
)

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

// A Secure Client config stays on config_version 8: `config migrate` refuses
// it and writes nothing (GAP-0110, issue #1092).
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
	if err := configMigrateCmd.RunE(configMigrateCmd, nil); err == nil {
		t.Fatal("config migrate accepted a Secure Client config")
	}
	entries, _ := os.ReadDir(dir)
	if raw, _ := os.ReadFile(path); string(raw) != string(v8) || len(entries) != 1 {
		t.Fatalf("config migrate changed the Secure Client directory: %d entries", len(entries))
	}
}
